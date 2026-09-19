"""Software composition analysis: real known-vulnerability lookups for a
tenant's own declared dependencies (name/version/ecosystem they submit —
never a package we guessed at or inferred).

- OSV.dev (https://osv.dev) — Google-run, free, fully unauthenticated
  aggregator covering GitHub Security Advisories, PyPI/npm/Go/crates.io
  advisory databases, and more. No API key needed or supported.
- GitHub Advisory Database — GitHub's own REST API, publicly readable
  without a token (rate-limited to 60 req/hour unauthenticated; higher
  with a token, which isn't required here).

Both are queried for every submitted package; a real match from either
becomes a real finding (its own advisory ID, summary, and severity when
the source provides one). A network failure or non-200 response from one
source degrades to "no findings from that source" for that package,
logged, never silently fabricated as "no known vulnerabilities" — the
Exposure agent still reports what it *did* manage to check.
"""
import logging

import httpx

logger = logging.getLogger("sentrimesh.vuln_scanner")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"


async def _query_osv(ecosystem: str, name: str, version: str) -> list[dict] | None:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                OSV_QUERY_URL,
                json={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
            )
        if response.status_code != 200:
            logger.warning("OSV.dev returned %s for %s %s@%s", response.status_code, ecosystem, name, version)
            return None
        vulns = response.json().get("vulns", [])
        return [
            {
                "id": v.get("id"),
                "summary": v.get("summary") or v.get("details", "")[:200],
                "severity": _osv_severity(v),
                "source": "osv.dev",
            }
            for v in vulns
        ]
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("OSV.dev lookup failed for %s %s@%s", ecosystem, name, version, exc_info=True)
        return None


def _osv_severity(vuln: dict) -> str:
    for entry in vuln.get("severity") or []:
        # OSV's CVSS vector score, when present, is the real signal;
        # database_specific severity strings are a fallback for the many
        # advisories that only carry that.
        if entry.get("type") == "CVSS_V3" and "score" in entry:
            try:
                score = float(entry["score"])
            except (TypeError, ValueError):
                continue
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    db_specific = (vuln.get("database_specific") or {}).get("severity")
    if db_specific:
        return db_specific.lower()
    return "unknown"


# GitHub's advisory ecosystem names differ from OSV's for a few cases.
_GITHUB_ECOSYSTEM_MAP = {
    "pypi": "pip",
    "npm": "npm",
    "go": "go",
    "crates.io": "rust",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "packagist": "composer",
}


async def _query_github_advisories(ecosystem: str, name: str) -> list[dict] | None:
    gh_ecosystem = _GITHUB_ECOSYSTEM_MAP.get(ecosystem.lower())
    if gh_ecosystem is None:
        return []  # not a fabricated "no vulns" — just not a lookup GitHub's API supports for this ecosystem
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                GITHUB_ADVISORIES_URL,
                params={"ecosystem": gh_ecosystem, "affects": name, "per_page": 20},
                headers={"Accept": "application/vnd.github+json"},
            )
        if response.status_code != 200:
            logger.warning("GitHub Advisory Database returned %s for %s/%s", response.status_code, ecosystem, name)
            return None
        advisories = response.json()
        return [
            {
                "id": a.get("ghsa_id"),
                "summary": a.get("summary"),
                "severity": (a.get("severity") or "unknown").lower(),
                "source": "github-advisory-database",
                "cve_id": a.get("cve_id"),
            }
            for a in advisories
        ]
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("GitHub Advisory Database lookup failed for %s/%s", ecosystem, name, exc_info=True)
        return None


async def check_package(ecosystem: str, name: str, version: str) -> dict:
    """Real vulnerability findings for one package from every source that
    answered; each source that failed is named as unreachable rather than
    silently treated as 'no vulnerabilities found'."""
    osv_result = await _query_osv(ecosystem, name, version)
    github_result = await _query_github_advisories(ecosystem, name)

    findings = (osv_result or []) + (github_result or [])
    # Same real CVE/GHSA surfaced by both sources shouldn't count twice.
    deduped: dict[str, dict] = {}
    for finding in findings:
        key = finding.get("cve_id") or finding.get("id")
        if key and key not in deduped:
            deduped[key] = finding

    unreachable = []
    if osv_result is None:
        unreachable.append("osv.dev")
    if github_result is None:
        unreachable.append("github-advisory-database")

    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "vulnerabilities": list(deduped.values()),
        "sources_unreachable": unreachable,
    }
