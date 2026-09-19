from datetime import datetime

from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_ACTIONS_EXECUTED, CH_ACTIONS_PROPOSED, CH_INCIDENTS_CLASSIFIED
from app.connectors.executor import get_executor
from app.models import ActionProposal, ApprovalRequest, ApprovalStatus, AutonomyTier, Severity, Tenant
from app.notifications.email import send_email
from app.policy.engine import classify_action


class ResponseAgent(Agent):
    """Agent 6: turns a classified incident into a concrete action, executed
    according to its autonomy tier, always through the Guardian's kill-switch
    check and always with a rollback plan attached."""

    name = "response"

    async def register(self) -> None:
        self.bus.subscribe(CH_INCIDENTS_CLASSIFIED, self.on_classified_incident)

    async def on_classified_incident(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        incident_id = payload["incident_id"]
        action_type = payload.get("recommended_action")
        severity = Severity(payload["severity"])

        if not action_type:
            return

        decision = classify_action(action_type, severity)

        async with self.session() as db:
            proposal = ActionProposal(
                tenant_id=tenant_id,
                incident_id=incident_id,
                action_type=action_type,
                parameters=self._parameters_for(action_type, payload.get("context", {})),
                tier=decision.tier,
                rationale=decision.reasoning,
                reversible=decision.reversible,
                rollback_plan=decision.rollback_plan,
            )
            db.add(proposal)
            await db.commit()
            await db.refresh(proposal)

        await self.publish(
            CH_ACTIONS_PROPOSED,
            {"tenant_id": tenant_id, "proposal_id": proposal.id, "severity": severity.value},
            tenant_id=tenant_id,
        )

        if decision.tier == AutonomyTier.TIER1_AUTO:
            await self._execute(proposal.id)
        else:
            await self._request_approval(proposal)

    @staticmethod
    def _parameters_for(action_type: str, context: dict) -> dict:
        if action_type == "block_ip" and context.get("src_ip"):
            return {"ip": context["src_ip"]}
        return {"context": context}

    async def _request_approval(self, proposal: ActionProposal) -> None:
        async with self.session() as db:
            approval = ApprovalRequest(tenant_id=proposal.tenant_id, action_proposal_id=proposal.id)
            db.add(approval)
            await db.commit()

        tap = "one tap" if proposal.tier == AutonomyTier.TIER2_ONE_TAP else "human decision required"
        await send_email(
            subject=f"Action needs your approval ({tap}): {proposal.action_type}",
            body=(
                f"Incident: {proposal.incident_id}\n"
                f"Proposed action: {proposal.action_type}\n"
                f"Tier: {proposal.tier.value}\n"
                f"Rationale: {proposal.rationale}\n"
                f"Reversible: {proposal.reversible} — {proposal.rollback_plan}\n\n"
                "Log in to the SentriMeshAstra console to approve or reject."
            ),
        )
        self.log("Requested approval for proposal %s (tier=%s)", proposal.id, proposal.tier.value)

    async def _execute(self, proposal_id: str) -> None:
        async with self.session() as db:
            result = await db.execute(select(ActionProposal).where(ActionProposal.id == proposal_id))
            proposal = result.scalar_one_or_none()
            if proposal is None or proposal.executed:
                return

            tenant_result = await db.execute(select(Tenant).where(Tenant.id == proposal.tenant_id))
            tenant = tenant_result.scalar_one_or_none()
            if tenant and tenant.kill_switch_engaged:
                self.log("BLOCKED by kill switch: proposal %s for tenant %s", proposal_id, proposal.tenant_id)
                await self.bus.audit(
                    actor=self.name,
                    action="execution_blocked_kill_switch",
                    payload={"proposal_id": proposal_id},
                    tenant_id=proposal.tenant_id,
                )
                return

            executor = get_executor(proposal.action_type)
            result = await executor.execute(proposal.action_type, proposal.parameters)

            proposal.executed = True
            proposal.executed_at = datetime.utcnow()
            proposal.execution_result = {"success": result.success, "detail": result.detail, "simulated": result.simulated}
            await db.commit()

        await self.publish(
            CH_ACTIONS_EXECUTED,
            {"tenant_id": proposal.tenant_id, "proposal_id": proposal.id, "result": proposal.execution_result},
            tenant_id=proposal.tenant_id,
        )
        self.log("Executed proposal %s: %s", proposal_id, result.detail)

    async def execute_approved(self, proposal_id: str) -> None:
        """Entry point used by the approvals API route once a human approves."""
        await self._execute(proposal_id)

    async def rollback(self, proposal_id: str) -> dict:
        """Entry point used by the API route when a human asks to undo an
        already-executed action. Only meaningful for executors that keep
        real state (e.g. IPTablesExecutor); DryRunExecutor's rollback is
        itself a no-op simulation."""
        async with self.session() as db:
            result = await db.execute(select(ActionProposal).where(ActionProposal.id == proposal_id))
            proposal = result.scalar_one_or_none()
            if proposal is None or not proposal.executed:
                return {"success": False, "detail": "Action was never executed — nothing to roll back."}

            executor = get_executor(proposal.action_type)
            outcome = await executor.rollback(proposal.action_type, proposal.parameters)

            proposal.execution_result = {
                **proposal.execution_result,
                "rolled_back": outcome.success,
                "rollback_detail": outcome.detail,
            }
            await db.commit()

        await self.bus.audit(
            actor=self.name,
            action="rollback",
            payload={"proposal_id": proposal_id, "success": outcome.success, "detail": outcome.detail},
            tenant_id=proposal.tenant_id,
        )
        self.log("Rolled back proposal %s: %s", proposal_id, outcome.detail)
        return {"success": outcome.success, "detail": outcome.detail}
