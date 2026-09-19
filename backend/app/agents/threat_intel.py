from sqlalchemy import select

from app.agents.base import Agent
from app.bus import CH_INCIDENTS_ENRICHED, CH_INCIDENTS_NEW
from app.connectors.threat_feed import lookup_ip
from app.models import Incident, ThreatIndicator


class ThreatIntelAgent(Agent):
    """Agent 4: enriches incidents with reputation data on IPs/domains/hashes/CVEs."""

    name = "threat_intel"

    async def register(self) -> None:
        self.bus.subscribe(CH_INCIDENTS_NEW, self.on_new_incident)

    async def on_new_incident(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        incident_id = payload["incident_id"]
        context = payload.get("context", {})
        src_ip = context.get("src_ip")

        enrichment_update: dict = {}
        malicious_indicator = False

        if src_ip:
            verdict = await lookup_ip(src_ip)
            malicious_indicator = verdict["verdict"] == "malicious"
            enrichment_update["ip_reputation"] = {src_ip: verdict}
            await self._cache_indicator(src_ip, verdict)

        async with self.session() as db:
            result = await db.execute(select(Incident).where(Incident.id == incident_id))
            incident = result.scalar_one_or_none()
            if incident is None:
                return
            merged = {**incident.enrichment, **enrichment_update}
            merged["context"] = {**incident.enrichment.get("context", {}), "malicious_indicator": malicious_indicator}
            incident.enrichment = merged
            await db.commit()

        self.log("Enriched incident %s (malicious_indicator=%s)", incident_id, malicious_indicator)
        await self.publish(
            CH_INCIDENTS_ENRICHED,
            {"tenant_id": tenant_id, "incident_id": incident_id, "context": merged["context"]},
            tenant_id=tenant_id,
        )

    async def _cache_indicator(self, ip: str, verdict: dict) -> None:
        async with self.session() as db:
            result = await db.execute(
                select(ThreatIndicator).where(ThreatIndicator.indicator_type == "ip", ThreatIndicator.value == ip)
            )
            indicator = result.scalar_one_or_none()
            if indicator is None:
                indicator = ThreatIndicator(indicator_type="ip", value=ip)
                db.add(indicator)
            indicator.verdict = verdict["verdict"]
            indicator.score = verdict["score"]
            indicator.details = verdict
            await db.commit()
