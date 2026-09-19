from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_INCIDENTS_CLASSIFIED, CH_INCIDENTS_ENRICHED
from app.models import Incident
from app.policy.engine import severity_from_signals


def recommend_action(incident: Incident, context: dict) -> str | None:
    """Deterministic mapping from incident shape to a recommended response
    action. Deliberately simple and legible — this is the kind of decision
    a customer should be able to read and agree with, not a black box."""
    techniques = incident.mitre_techniques or []
    if any("T1110" in t for t in techniques):  # brute force
        if context.get("malicious_indicator"):
            return "block_ip"
        return "notify"
    if any("T1068" in t for t in techniques):  # privilege escalation
        return "disable_account"
    return "notify"


class OrchestratorAgent(Agent):
    """Agent 1: classifies severity, sets the plan, coordinates the other agents."""

    name = "orchestrator"

    async def register(self) -> None:
        self.bus.subscribe(CH_INCIDENTS_ENRICHED, self.on_enriched_incident)

    async def on_enriched_incident(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        incident_id = payload["incident_id"]
        context = payload.get("context", {})

        severity = severity_from_signals(
            failed_login_count=context.get("failed_login_count", 0),
            malicious_indicator=bool(context.get("malicious_indicator")),
            new_admin_activity=bool(context.get("new_admin_activity")),
        )

        async with self.session() as db:
            result = await db.execute(select(Incident).where(Incident.id == incident_id))
            incident = result.scalar_one_or_none()
            if incident is None:
                return
            incident.severity = severity
            await db.commit()
            await db.refresh(incident)
            action_type = recommend_action(incident, context)

        self.log("Classified incident %s as %s, recommending %s", incident_id, severity.value, action_type)
        await self.publish(
            CH_INCIDENTS_CLASSIFIED,
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "severity": severity.value,
                "recommended_action": action_type,
                "context": context,
            },
            tenant_id=tenant_id,
        )
