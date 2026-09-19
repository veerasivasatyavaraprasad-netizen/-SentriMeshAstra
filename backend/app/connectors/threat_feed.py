"""Threat intelligence lookups.

Ships with a small local reputation list (obviously-malicious-looking demo
data plus RFC 5737/1918 documentation ranges marked clean) so the pipeline
is fully exercised offline. If ABUSEIPDB_API_KEY (or similar) is added
later, swap the body of `lookup_ip` for a real HTTP call — the call site
(app/agents/threat_intel.py) doesn't need to change.
"""
import ipaddress

# Small demo blocklist so the detection -> enrichment -> response pipeline
# has something real to react to without any external API key.
_DEMO_MALICIOUS_IPS = {
    "198.51.100.23": {"verdict": "malicious", "score": 92, "tags": ["credential-stuffing", "known-botnet"]},
    "203.0.113.77": {"verdict": "malicious", "score": 85, "tags": ["scanning"]},
}


def lookup_ip(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"verdict": "unknown", "score": 0, "tags": ["invalid-ip"]}

    # Demo blocklist takes priority: its IPs are drawn from the RFC 5737
    # TEST-NET documentation ranges, which Python's ipaddress module also
    # classifies as "private" — so the private-range short-circuit below
    # must never run before this check, or the demo scenario goes dark.
    if ip in _DEMO_MALICIOUS_IPS:
        return _DEMO_MALICIOUS_IPS[ip]

    if addr.is_private or addr.is_loopback:
        return {"verdict": "clean", "score": 0, "tags": ["private-range"]}

    return {"verdict": "unknown", "score": 0, "tags": []}


MITRE_MAP = {
    "bruteforce_login": ["T1110 - Brute Force"],
    "impossible_travel": ["T1078 - Valid Accounts"],
    "malware_signature": ["T1059 - Command and Scripting Interpreter"],
    "privilege_escalation": ["T1068 - Exploitation for Privilege Escalation"],
}
