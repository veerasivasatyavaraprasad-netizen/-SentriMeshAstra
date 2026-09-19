"""External attack-surface scanning — limited to a tenant's own registered
domain (the domain they verified ownership of during onboarding). This is
passive reconnaissance (TLS/header checks over a normal HTTPS request),
not intrusive testing. It never targets anything outside the tenant's own
`Tenant.domain`, and it is intentionally read-only: no exploitation, no
credential guessing, no payloads. Deeper authorized pentesting (per the
project plan's "Exposure" agent) is a scoped, contract-gated feature to
add later — see README.md roadmap — not something this scanner does.
"""
from dataclasses import dataclass, field

import httpx

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]


@dataclass
class ExposureFinding:
    check: str
    status: str  # "ok" | "warning" | "info"
    detail: str


@dataclass
class ExposureReport:
    domain: str
    reachable: bool
    findings: list[ExposureFinding] = field(default_factory=list)


async def scan_domain(domain: str) -> ExposureReport:
    findings: list[ExposureFinding] = []
    url = f"https://{domain}"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        return ExposureReport(
            domain=domain,
            reachable=False,
            findings=[ExposureFinding("connectivity", "warning", f"Could not reach {url}: {exc}")],
        )

    findings.append(ExposureFinding("tls", "ok", "Site served over HTTPS."))

    headers = {k.lower(): v for k, v in response.headers.items()}
    for header in SECURITY_HEADERS:
        if header in headers:
            findings.append(ExposureFinding(f"header:{header}", "ok", f"{header} present."))
        else:
            findings.append(
                ExposureFinding(f"header:{header}", "warning", f"{header} is missing from responses.")
            )

    server_header = headers.get("server")
    if server_header:
        findings.append(
            ExposureFinding(
                "info-disclosure",
                "info",
                f"Server header discloses: '{server_header}'. Consider suppressing it.",
            )
        )

    return ExposureReport(domain=domain, reachable=True, findings=findings)
