"""External attack-surface scanning — limited to a tenant's own registered
domain (the domain they verified ownership of during onboarding). This is
passive reconnaissance (TLS/header checks over a normal HTTPS request, or
a plain Google search of the tenant's own domain via SerpAPI), not
intrusive testing. It never targets anything outside the tenant's own
`Tenant.domain`, and it is intentionally read-only: no exploitation, no
credential guessing, no payloads. Deeper authorized pentesting (per the
project plan's "Exposure" agent) is a scoped, contract-gated feature to
add later — see README.md roadmap — not something this scanner does.
"""
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("sentrimesh.exposure_scanner")

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]

SERPAPI_URL = "https://serpapi.com/search"

# A single, real Google dork covering the most common accidental-exposure
# patterns (indexed env/config/log/SQL files, and a directory listing) —
# one request per scan, not one per term, to keep this cheap and because
# Google already ORs these clauses in one query.
_EXPOSURE_DORK = 'site:{domain} (filetype:env OR filetype:sql OR filetype:log OR intitle:"index of")'


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


async def search_public_exposure(domain: str, serpapi_key: str) -> list[ExposureFinding]:
    """One real Google search (via SerpAPI), restricted to the tenant's
    own domain, for the file types and directory-listing pattern that
    most commonly indicate an accidental public exposure. This queries
    Google about a domain the tenant already told us they own — the same
    non-intrusive technique real attack-surface-management tools use —
    never a third-party target, and never anything beyond a plain search.

    Returns [] (not a fabricated "nothing found") if SerpAPI itself fails;
    the caller only calls this when a key is configured in the first
    place, so "not configured" is handled by simply not calling this."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                SERPAPI_URL,
                params={"engine": "google", "q": _EXPOSURE_DORK.format(domain=domain), "api_key": serpapi_key, "num": 10},
            )
        if response.status_code != 200:
            logger.warning("SerpAPI returned %s for domain %s", response.status_code, domain)
            return []
        results = response.json().get("organic_results", [])
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("SerpAPI lookup failed for domain %s", domain, exc_info=True)
        return []

    if not results:
        return [ExposureFinding("public-search-exposure", "ok", "No indexed files or directory listings found for common exposure patterns.")]

    findings = []
    for result in results[:10]:
        title = result.get("title", "")
        link = result.get("link", "")
        snippet = result.get("snippet", "")
        findings.append(
            ExposureFinding(
                "public-search-exposure",
                "warning",
                f"Google has indexed a page matching an exposure pattern: \"{title}\" — {link} — {snippet}",
            )
        )
    return findings
