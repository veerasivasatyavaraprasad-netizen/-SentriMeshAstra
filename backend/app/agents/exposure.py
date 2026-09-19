from app.agents.base import Agent
from app.bus import CH_INCIDENTS_NEW
from app.connectors.exposure_scanner import scan_domain
from app.models import Incident, IncidentStatus, Severity

CH_EXPOSURE_SCAN_REQUESTED = "exposure.scan_requested"


class ExposureAgent(Agent):
    """Agent 5: scans the tenant's own registered attack surface (their
    verified domain only) for missing hardening — never third-party targets.
    Deeper authorized penetration testing is a scoped, contract-gated
    feature for later phases, not something this agent does on its own.
    """

    name = "exposure"

    async def register(self) -> None:
        self.bus.subscribe(CH_EXPOSURE_SCAN_REQUESTED, self.on_scan_requested)

    async def on_scan_requested(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        domain = payload["domain"]

        report = await scan_domain(domain)
        warnings = [f for f in report.findings if f.status == "warning"]
        severity = Severity.MEDIUM if warnings else Severity.LOW

        description_lines = [f"Exposure scan of {domain}:"]
        description_lines += [f"- [{f.status.upper()}] {f.check}: {f.detail}" for f in report.findings]

        async with self.session() as db:
            incident = Incident(
                tenant_id=tenant_id,
                title=f"Exposure scan: {domain} ({len(warnings)} finding(s))",
                description="\n".join(description_lines),
                severity=severity,
                status=IncidentStatus.RESOLVED if not warnings else IncidentStatus.OPEN,
                enrichment={"exposure_findings": [f.__dict__ for f in report.findings], "reachable": report.reachable},
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        self.log("Exposure scan of %s complete: %d warning(s)", domain, len(warnings))
        await self.publish(
            CH_INCIDENTS_NEW,
            {"tenant_id": tenant_id, "incident_id": incident.id, "context": {}},
            tenant_id=tenant_id,
        )
