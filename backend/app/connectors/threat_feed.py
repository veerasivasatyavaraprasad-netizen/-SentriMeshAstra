"""Threat intelligence lookups.

Two sources:

- A real AbuseIPDB lookup, used whenever ABUSEIPDB_API_KEY is set. This is
  a genuine outbound HTTP call to a real reputation database, not a mock.
- A small local demo blocklist (obviously-malicious-looking data plus
  RFC 5737 documentation ranges marked clean), used whenever no API key is
  configured, or if the live call fails for any reason — a network error,
  a timeout, a bad response — so a flaky third party never breaks the
  detection -> enrichment -> response pipeline. Every failure path falls
  back rather than raising.
"""
import ipaddress
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger("sentrimesh.threat_feed")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Small demo blocklist so the detection -> enrichment -> response pipeline
# has something real to react to without any external API key.
_DEMO_MALICIOUS_IPS = {
    "198.51.100.23": {"verdict": "malicious", "score": 92, "tags": ["credential-stuffing", "known-botnet"], "source": "local-demo"},
    "203.0.113.77": {"verdict": "malicious", "score": 85, "tags": ["scanning"], "source": "local-demo"},
}


def _local_lookup(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"verdict": "unknown", "score": 0, "tags": ["invalid-ip"], "source": "local-demo"}

    # Demo blocklist takes priority: its IPs are drawn from the RFC 5737
    # TEST-NET documentation ranges, which Python's ipaddress module also
    # classifies as "private" — so the private-range short-circuit below
    # must never run before this check, or the demo scenario goes dark.
    if ip in _DEMO_MALICIOUS_IPS:
        return _DEMO_MALICIOUS_IPS[ip]

    if addr.is_private or addr.is_loopback:
        return {"verdict": "clean", "score": 0, "tags": ["private-range"], "source": "local-demo"}

    return {"verdict": "unknown", "score": 0, "tags": [], "source": "local-demo"}


async def _abuseipdb_lookup(ip: str, api_key: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
        if response.status_code != 200:
            logger.warning("AbuseIPDB returned %s for %s, falling back to local list", response.status_code, ip)
            return None
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        if score >= 50:
            verdict = "malicious"
        elif score > 0 or total_reports > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "verdict": verdict,
            "score": score,
            "tags": [c.get("category") for c in data.get("reports", [])][:5] or ["abuseipdb"],
            "source": "abuseipdb",
            "total_reports": total_reports,
        }
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("AbuseIPDB lookup failed for %s, falling back to local list", ip, exc_info=True)
        return None


async def lookup_ip(ip: str) -> dict:
    settings = get_settings()
    if settings.abuseipdb_api_key:
        result = await _abuseipdb_lookup(ip, settings.abuseipdb_api_key)
        if result is not None:
            return result
    return _local_lookup(ip)


MITRE_MAP = {
    "bruteforce_login": ["T1110 - Brute Force"],
    "impossible_travel": ["T1078 - Valid Accounts"],
    "malware_signature": ["T1059 - Command and Scripting Interpreter"],
    "privilege_escalation": ["T1068 - Exploitation for Privilege Escalation"],
}
