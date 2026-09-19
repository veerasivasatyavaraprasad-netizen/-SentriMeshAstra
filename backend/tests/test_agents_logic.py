from app.agents.integration import normalize
from app.agents.orchestrator import recommend_action
from app.connectors.threat_feed import lookup_ip
from app.models import Incident, Severity


def test_normalize_maps_common_field_aliases():
    normalized = normalize("wazuh", "login_failed", {"source_ip": "1.2.3.4", "username": "bob"})
    assert normalized["src_ip"] == "1.2.3.4"
    assert normalized["user"] == "bob"


async def test_lookup_ip_flags_known_demo_malicious_ip():
    result = await lookup_ip("198.51.100.23")
    assert result["verdict"] == "malicious"


async def test_lookup_ip_treats_private_ranges_as_clean():
    result = await lookup_ip("10.0.0.5")
    assert result["verdict"] == "clean"


async def test_lookup_ip_unknown_for_unseen_public_ip():
    result = await lookup_ip("8.8.8.8")
    assert result["verdict"] == "unknown"


def test_recommend_action_blocks_ip_for_malicious_bruteforce():
    incident = Incident(mitre_techniques=["T1110 - Brute Force"])
    action = recommend_action(incident, {"malicious_indicator": True})
    assert action == "block_ip"


def test_recommend_action_only_notifies_for_unconfirmed_bruteforce():
    incident = Incident(mitre_techniques=["T1110 - Brute Force"])
    action = recommend_action(incident, {"malicious_indicator": False})
    assert action == "notify"


def test_recommend_action_disables_account_for_privilege_escalation():
    incident = Incident(mitre_techniques=["T1068 - Exploitation for Privilege Escalation"])
    action = recommend_action(incident, {})
    assert action == "disable_account"
