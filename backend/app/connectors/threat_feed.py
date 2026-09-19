"""Threat intelligence lookups.

Every verdict here is either a real AbuseIPDB result or an honest
"unknown" — there is no local blocklist standing in as if it were real
data. If ABUSEIPDB_API_KEY isn't set, or the call fails for any reason
(timeout, bad response), enrichment returns "unknown" rather than
fabricating a verdict; the Orchestrator's severity scoring already
treats "not confirmed malicious" as exactly that, so a missing key
degrades detection confidence honestly instead of silently pretending to
have reputation data it doesn't.

The one thing still computed locally is whether an address is on a real
internal/corporate network (RFC 1918) or loopback — that's a real,
deterministic property of the address itself, not a claim about
reputation, so checking it locally isn't "mock data"; it just avoids
sending an internal IP to a public reputation API that could never have
an opinion on it anyway. This deliberately checks the specific RFC 1918
ranges rather than Python's broader `ipaddress.is_private`, which also
lumps in RFC 5737 documentation/test ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) — those are reserved, but they're not
"someone's internal network," and conflating the two would make every
one of them silently report "clean" without ever asking AbuseIPDB.
"""
import ipaddress
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger("sentrimesh.threat_feed")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_RFC1918_NETWORKS = [ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

UNKNOWN_NO_API_KEY = {"verdict": "unknown", "score": 0, "tags": ["no-abuseipdb-key-configured"], "source": "none"}
UNKNOWN_LOOKUP_FAILED = {"verdict": "unknown", "score": 0, "tags": ["abuseipdb-lookup-failed"], "source": "none"}
INVALID_IP = {"verdict": "unknown", "score": 0, "tags": ["invalid-ip"], "source": "none"}
INTERNAL_NETWORK = {"verdict": "clean", "score": 0, "tags": ["internal-network"], "source": "rfc1918"}


def _is_internal_network_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return addr.is_loopback or any(addr in net for net in _RFC1918_NETWORKS)


async def _abuseipdb_lookup(ip: str, api_key: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
        if response.status_code != 200:
            logger.warning("AbuseIPDB returned %s for %s — reporting unknown, not fabricating a verdict", response.status_code, ip)
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
        logger.warning("AbuseIPDB lookup failed for %s — reporting unknown, not fabricating a verdict", ip, exc_info=True)
        return None


async def lookup_ip(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return INVALID_IP

    if _is_internal_network_address(addr):
        return INTERNAL_NETWORK

    settings = get_settings()
    if not settings.abuseipdb_api_key:
        return UNKNOWN_NO_API_KEY

    result = await _abuseipdb_lookup(ip, settings.abuseipdb_api_key)
    return result if result is not None else UNKNOWN_LOOKUP_FAILED


MITRE_MAP = {
    "bruteforce_login": ["T1110 - Brute Force"],
    "impossible_travel": ["T1078 - Valid Accounts"],
    "malware_signature": ["T1059 - Command and Scripting Interpreter"],
    "privilege_escalation": ["T1068 - Exploitation for Privilege Escalation"],
}
