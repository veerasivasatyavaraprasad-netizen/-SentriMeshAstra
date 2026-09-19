from datetime import datetime, timedelta

from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_ACTIONS_PROPOSED, CH_GUARDIAN_ALERT
from app.models import ActionProposal, ConnectorConfig, Severity, Tenant
from app.policy.engine import classify_action

CONNECTOR_STALE_AFTER = timedelta(hours=6)


class GuardianAgent(Agent):
    """Agent 8: watches the other agents, not the customer's network.

    Independently re-derives the policy tier for every proposed action and
    raises an alert (and blocks execution) if what's stored doesn't match
    what the policy engine says it should be right now. It also holds the
    kill switch check and flags connectors that have gone quiet. This is
    the platform's self-check, separate from whatever it's protecting.
    """

    name = "guardian"

    async def register(self) -> None:
        self.bus.subscribe(CH_ACTIONS_PROPOSED, self.on_action_proposed)

    async def on_action_proposed(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        proposal_id = payload["proposal_id"]

        async with self.session() as db:
            result = await db.execute(select(ActionProposal).where(ActionProposal.id == proposal_id))
            proposal = result.scalar_one_or_none()
            if proposal is None:
                return

            severity = Severity(payload.get("severity")) if payload.get("severity") else Severity.LOW
            recheck = classify_action(proposal.action_type, severity)
            if recheck.tier != proposal.tier:
                await self.publish(
                    CH_GUARDIAN_ALERT,
                    {
                        "tenant_id": tenant_id,
                        "proposal_id": proposal_id,
                        "reason": "tier_mismatch",
                        "stored_tier": proposal.tier.value,
                        "recomputed_tier": recheck.tier.value,
                    },
                    tenant_id=tenant_id,
                )
                self.log(
                    "ALERT: tier mismatch on proposal %s (stored=%s, recomputed=%s)",
                    proposal_id, proposal.tier.value, recheck.tier.value,
                )

    @staticmethod
    async def kill_switch_engaged(db, tenant_id: str) -> bool:
        result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
        tenant = result.scalar_one_or_none()
        return bool(tenant and tenant.kill_switch_engaged)

    async def check_connector_health(self) -> list[dict]:
        """Called periodically by the agent runner. Returns tenants/connectors
        that have gone quiet, so coverage gaps surface instead of going
        unnoticed."""
        gaps = []
        threshold = datetime.utcnow() - CONNECTOR_STALE_AFTER
        async with self.session() as db:
            result = await db.execute(select(ConnectorConfig).where(ConnectorConfig.is_active == True))  # noqa: E712
            for connector in result.scalars():
                if connector.last_event_at and connector.last_event_at < threshold:
                    gaps.append(
                        {
                            "tenant_id": connector.tenant_id,
                            "connector_id": connector.id,
                            "connector_type": connector.connector_type,
                            "last_event_at": connector.last_event_at.isoformat(),
                        }
                    )
        for gap in gaps:
            await self.publish(CH_GUARDIAN_ALERT, {**gap, "reason": "connector_stale"}, tenant_id=gap["tenant_id"])
        return gaps
