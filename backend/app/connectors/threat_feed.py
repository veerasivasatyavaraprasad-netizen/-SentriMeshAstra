"""Threat intelligence lookups.

Every verdict here comes from a real, configured source, or is an honest
"unknown" — there is no local blocklist standing in as if it were real
data. `lookup_ip` queries every source whose API key is set, in parallel,
and combines whatever comes back into one verdict. A source with no key
configured is simply skipped; a source whose call fails (timeout, bad
response, rate limit) degrades to "no data from this source" rather than
either fabricating a result or failing the whole lookup — the other
configured sources still get a say. If nothing is configured, or every
configured source's call fails, the aggregate is "unknown", and the
Orchestrator's severity scoring already treats "not confirmed malicious"
as exactly that.

Sources:
- AbuseIPDB — community-reported abuse confidence score.
- VirusTotal — how many of its ~90 partner engines flag the address.
- AlienVault OTX — how many open threat-intel "pulses" reference it.
- GreyNoise (Community API) — internet-wide scanner/opportunistic-noise
  classification, plus RIOT (a known-good business service, e.g. a cloud
  provider's own infrastructure) — the one source here that can turn a
  raw "looks suspicious" signal into a confident "actually fine."
- Shodan — what's actually running on the host (open ports, known CVEs
  on banners) — exposure context, not a reputation verdict on its own,
  so it never drives "malicious" by itself.
- ThreatFox (abuse.ch) — confirmed malware/botnet indicator-of-compromise
  matches, with the actual malware family name when known.

The one thing still computed locally is whether an address is on a real
internal/corporate network (RFC 1918) or loopback — that's a real,
deterministic property of the address itself, not a claim about
reputation, so checking it locally isn't "mock data"; it just avoids
sending an internal IP to public reputation APIs that could never have
an opinion on it anyway. This deliberately checks the specific RFC 1918
ranges rather than Python's broader `ipaddress.is_private`, which also
lumps in RFC 5737 documentation/test ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) — those are reserved, but they're not
"someone's internal network," and conflating the two would make every
one of them silently report "clean" without ever asking a real source.
"""
import asyncio
import ipaddress
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger("sentrimesh.threat_feed")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"
SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

_RFC1918_NETWORKS = [ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

UNKNOWN_NO_API_KEY = {"verdict": "unknown", "score": 0, "tags": ["no-source-configured"], "source": "none", "sources": {}}
INVALID_IP = {"verdict": "unknown", "score": 0, "tags": ["invalid-ip"], "source": "none", "sources": {}}
INTERNAL_NETWORK = {"verdict": "clean", "score": 0, "tags": ["internal-network"], "source": "rfc1918", "sources": {}}


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
            logger.warning("AbuseIPDB returned %s for %s", response.status_code, ip)
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
            "detail": f"AbuseIPDB confidence {score}/100 ({total_reports} report(s))",
            "raw": {"score": score, "total_reports": total_reports},
        }
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("AbuseIPDB lookup failed for %s", ip, exc_info=True)
        return None


async def _virustotal_lookup(ip: str, api_key: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(VIRUSTOTAL_URL.format(ip=ip), headers={"x-apikey": api_key})
        if response.status_code != 200:
            logger.warning("VirusTotal returned %s for %s", response.status_code, ip)
            return None
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        # A single vendor flag is noisy; two or more independent engines
        # agreeing is the real signal, matching how VirusTotal's own UI
        # visually distinguishes "a few" from "many" detections.
        if malicious >= 2:
            verdict = "malicious"
        elif malicious == 1 or suspicious >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "verdict": verdict,
            "detail": f"VirusTotal {malicious} malicious / {suspicious} suspicious engine(s)",
            "raw": {"malicious": malicious, "suspicious": suspicious},
        }
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("VirusTotal lookup failed for %s", ip, exc_info=True)
        return None


async def _otx_lookup(ip: str, api_key: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(OTX_URL.format(ip=ip), headers={"X-OTX-API-KEY": api_key})
        if response.status_code != 200:
            logger.warning("AlienVault OTX returned %s for %s", response.status_code, ip)
            return None
        pulse_count = int(response.json().get("pulse_info", {}).get("count", 0))
        if pulse_count >= 3:
            verdict = "malicious"
        elif pulse_count >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            "verdict": verdict,
            "detail": f"AlienVault OTX referenced in {pulse_count} threat-intel pulse(s)",
            "raw": {"pulse_count": pulse_count},
        }
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("AlienVault OTX lookup failed for %s", ip, exc_info=True)
        return None


async def _greynoise_lookup(ip: str, api_key: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(GREYNOISE_URL.format(ip=ip), headers={"key": api_key, "Accept": "application/json"})
        # GreyNoise's community endpoint returns 404 for an IP it has no
        # observations for at all — that's real "no data," not a failure.
        if response.status_code == 404:
            return {"verdict": "unknown", "detail": "GreyNoise has no observations for this IP", "raw": {}}
        if response.status_code != 200:
            logger.warning("GreyNoise returned %s for %s", response.status_code, ip)
            return None
        data = response.json()
        classification = data.get("classification", "unknown")
        riot = bool(data.get("riot", False))
        noise = bool(data.get("noise", False))
        name = data.get("name")
        if riot:
            # A known-good business service (a cloud provider's own
            # infrastructure, a well-known SaaS) — real, positive signal,
            # not just "we don't know."
            verdict = "clean"
        elif classification == "malicious":
            verdict = "malicious"
        elif classification == "benign":
            verdict = "clean"
        else:
            verdict = "unknown"
        detail = f"GreyNoise: {name or classification}" + (" (RIOT — known business service)" if riot else "") + (" (internet-wide scanner)" if noise else "")
        return {"verdict": verdict, "detail": detail, "raw": {"classification": classification, "riot": riot, "noise": noise}}
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("GreyNoise lookup failed for %s", ip, exc_info=True)
        return None


async def _shodan_lookup(ip: str, api_key: str) -> dict | None:
    """Shodan profiles what's running on a host, not whether it's
    malicious — it never drives an aggregate "malicious" verdict on its
    own, only "suspicious" when the host exposes services with known
    vulnerabilities, since that's a real, direct risk signal."""
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(SHODAN_URL.format(ip=ip), params={"key": api_key})
        if response.status_code == 404:
            return {"verdict": "unknown", "detail": "Shodan has no data for this IP", "raw": {}}
        if response.status_code != 200:
            logger.warning("Shodan returned %s for %s", response.status_code, ip)
            return None
        data = response.json()
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        verdict = "suspicious" if vulns else "unknown"
        detail = f"Shodan: {len(ports)} open port(s)" + (f", {len(vulns)} known CVE(s) on exposed services" if vulns else "")
        return {"verdict": verdict, "detail": detail, "raw": {"ports": ports, "vulns": list(vulns)[:10]}}
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("Shodan lookup failed for %s", ip, exc_info=True)
        return None


async def _threatfox_lookup(ip: str, auth_key: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.post(
                THREATFOX_URL,
                json={"query": "search_ioc", "search_term": ip},
                headers={"Auth-Key": auth_key},
            )
        if response.status_code != 200:
            logger.warning("ThreatFox returned %s for %s", response.status_code, ip)
            return None
        body = response.json()
        if body.get("query_status") != "ok":
            return {"verdict": "clean", "detail": "ThreatFox: no known IOC match", "raw": {}}
        matches = body.get("data") or []
        malware_names = sorted({m.get("malware_printable") for m in matches if m.get("malware_printable")})
        return {
            "verdict": "malicious",
            "detail": f"ThreatFox: confirmed IOC match ({', '.join(malware_names) or 'unattributed'})",
            "raw": {"malware": malware_names, "match_count": len(matches)},
        }
    except (httpx.HTTPError, ValueError, KeyError):
        logger.warning("ThreatFox lookup failed for %s", ip, exc_info=True)
        return None


# Function names (resolved from module globals at call time, not the
# function objects themselves) so that monkeypatching e.g.
# threat_feed._abuseipdb_lookup in a test actually takes effect — a
# dict built with the function objects directly would capture the
# original reference at import time and never see the patched one.
_SOURCE_LOOKUPS = {
    "abuseipdb": ("_abuseipdb_lookup", "abuseipdb_api_key"),
    "virustotal": ("_virustotal_lookup", "virustotal_api_key"),
    "otx": ("_otx_lookup", "otx_api_key"),
    "greynoise": ("_greynoise_lookup", "greynoise_api_key"),
    "shodan": ("_shodan_lookup", "shodan_api_key"),
    "threatfox": ("_threatfox_lookup", "abusech_auth_key"),
}

# Precedence used only to pick a single headline score/detail when several
# sources respond — every source's own verdict/detail still appears under
# "sources" regardless. Shodan is deliberately last: it's exposure
# context, not a reputation source.
_SCORE_ORDER = ["threatfox", "abuseipdb", "otx", "virustotal", "greynoise", "shodan"]


def _aggregate(per_source: dict[str, dict | None]) -> dict:
    reachable = {name: result for name, result in per_source.items() if result is not None}
    if not reachable:
        return {**UNKNOWN_NO_API_KEY, "tags": ["all-configured-sources-unreachable"]}

    verdicts = {result["verdict"] for result in reachable.values()}
    if "malicious" in verdicts:
        verdict = "malicious"
    elif "suspicious" in verdicts:
        verdict = "suspicious"
    elif "clean" in verdicts:
        verdict = "clean"
    else:
        verdict = "unknown"

    # AbuseIPDB is the one source here with a real 0-100 confidence
    # score; use it as the headline number when present, otherwise
    # synthesize a comparable one from the aggregate verdict so callers
    # that just threshold on `score` still get a sensible number.
    if "abuseipdb" in reachable:
        score = reachable["abuseipdb"]["raw"].get("score", 0)
    else:
        score = {"malicious": 80, "suspicious": 40, "clean": 0, "unknown": 0}[verdict]

    tags = [f"{name}: {result['detail']}" for name, result in reachable.items()]
    source = ",".join(name for name in _SCORE_ORDER if name in reachable)

    return {
        "verdict": verdict,
        "score": score,
        "tags": tags,
        "source": source,
        "sources": {name: {"verdict": r["verdict"], "detail": r["detail"], **r["raw"]} for name, r in reachable.items()},
    }


async def lookup_ip(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return INVALID_IP

    if _is_internal_network_address(addr):
        return INTERNAL_NETWORK

    settings = get_settings()
    configured = {
        name: getattr(settings, key_attr, None)
        for name, (_, key_attr) in _SOURCE_LOOKUPS.items()
        if getattr(settings, key_attr, None)
    }
    if not configured:
        return UNKNOWN_NO_API_KEY

    names = list(configured)
    results = await asyncio.gather(
        *(globals()[_SOURCE_LOOKUPS[name][0]](ip, configured[name]) for name in names)
    )
    return _aggregate(dict(zip(names, results)))


MITRE_MAP = {
    "bruteforce_login": ["T1110 - Brute Force"],
    "impossible_travel": ["T1078 - Valid Accounts"],
    "malware_signature": ["T1059 - Command and Scripting Interpreter"],
    "privilege_escalation": ["T1068 - Exploitation for Privilege Escalation"],
}
