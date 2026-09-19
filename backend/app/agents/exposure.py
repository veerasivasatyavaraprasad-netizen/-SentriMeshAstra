from app.agents.base import Agent
from app.bus import CH_INCIDENTS_NEW
from app.config import get_settings
from app.connectors.exposure_scanner import scan_domain, search_public_exposure
from app.connectors.vuln_scanner import check_package
from app.models import Incident, IncidentStatus, Severity

CH_EXPOSURE_SCAN_REQUESTED = "exposure.scan_requested"
CH_DEPENDENCY_SCAN_REQUESTED = "exposure.dependency_scan_requested"


class ExposureAgent(Agent):
    """Agent 5: scans the tenant's own registered attack surface (their
    verified domain, and their own declared dependencies) for missing
    hardening and known vulnerabilities — never third-party targets.
    Deeper authorized penetration testing is a scoped, contract-gated
    feature for later phases, not something this agent does on its own.
    """

    name = "exposure"

    async def register(self) -> None:
        self.bus.subscribe(CH_EXPOSURE_SCAN_REQUESTED, self.on_scan_requested)
        self.bus.subscribe(CH_DEPENDENCY_SCAN_REQUESTED, self.on_dependency_scan_requested)

    async def on_scan_requested(self, payload: dict) -> None:
        tenant_id = payload["tenant_id"]
        domain = payload["domain"]

        report = await scan_domain(domain)
        findings = list(report.findings)

        settings = get_settings()
        if settings.serpapi_api_key:
            findings += await search_public_exposure(domain, settings.serpapi_api_key)

        warnings = [f for f in findings if f.status == "warning"]
        severity = Severity.MEDIUM if warnings else Severity.LOW

        description_lines = [f"Exposure scan of {domain}:"]
        description_lines += [f"- [{f.status.upper()}] {f.check}: {f.detail}" for f in findings]

        async with self.session() as db:
            incident = Incident(
                tenant_id=tenant_id,
                title=f"Exposure scan: {domain} ({len(warnings)} finding(s))",
                description="\n".join(description_lines),
                severity=severity,
                status=IncidentStatus.RESOLVED if not warnings else IncidentStatus.OPEN,
                enrichment={"exposure_findings": [f.__dict__ for f in findings], "reachable": report.reachable},
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

    async def on_dependency_scan_requested(self, payload: dict) -> None:
        """Real known-vulnerability lookups (OSV.dev + GitHub Advisory
        Database) for a tenant-submitted list of {ecosystem, name,
        version} dependencies — never a package we inferred or guessed."""
        tenant_id = payload["tenant_id"]
        packages = payload["packages"]

        results = [await check_package(p["ecosystem"], p["name"], p["version"]) for p in packages]
        vulnerable = [r for r in results if r["vulnerabilities"]]
        worst_severity = self._worst_severity(vulnerable)

        description_lines = [f"Dependency scan of {len(packages)} package(s):"]
        for result in vulnerable:
            for vuln in result["vulnerabilities"]:
                description_lines.append(
                    f"- [{vuln['severity'].upper()}] {result['name']}@{result['version']}: "
                    f"{vuln.get('id')} — {vuln.get('summary') or 'no summary available'}"
                )
        if not vulnerable:
            description_lines.append("No known vulnerabilities found in any submitted package.")

        async with self.session() as db:
            incident = Incident(
                tenant_id=tenant_id,
                title=f"Dependency scan: {len(vulnerable)} vulnerable package(s) of {len(packages)} checked",
                description="\n".join(description_lines),
                severity=worst_severity,
                status=IncidentStatus.RESOLVED if not vulnerable else IncidentStatus.OPEN,
                enrichment={"dependency_findings": results},
            )
            db.add(incident)
            await db.commit()
            await db.refresh(incident)

        self.log("Dependency scan complete: %d/%d package(s) vulnerable", len(vulnerable), len(packages))
        await self.publish(
            CH_INCIDENTS_NEW,
            {"tenant_id": tenant_id, "incident_id": incident.id, "context": {}},
            tenant_id=tenant_id,
        )

    @staticmethod
    def _worst_severity(vulnerable: list[dict]) -> Severity:
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
        worst = 0
        for result in vulnerable:
            for vuln in result["vulnerabilities"]:
                worst = max(worst, rank.get(vuln.get("severity", "unknown"), 1))
        return {4: Severity.CRITICAL, 3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW, 0: Severity.LOW}[worst]
