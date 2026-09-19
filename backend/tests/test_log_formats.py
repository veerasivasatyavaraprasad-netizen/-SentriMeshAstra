"""Tests the real per-vendor log parsers in app/connectors/log_formats.py
against sample payloads shaped exactly like each vendor's own documented
JSON schema — not our own invented format. Sources:

- Wazuh: the alert JSON shape Wazuh itself produces (rule.*, data.*,
  agent.*), including the rule.mitre.id/technique fields its ruleset
  populates for many rules.
- AWS CloudTrail: the event record fields documented at
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- Azure AD sign-in logs: the fields Microsoft documents for the sign-in
  log schema, including status.errorCode (0 = success; nonzero codes are
  real, documented failure codes — 50126 is "invalid username or
  password").
"""
from app.connectors.log_formats import normalize_for_connector_type


def test_wazuh_failed_login_uses_the_alerts_own_mitre_classification():
    alert = {
        "timestamp": "2024-01-01T00:00:00.000+0000",
        "rule": {
            "level": 10,
            "description": "Multiple authentication failures.",
            "id": "5710",
            "groups": ["authentication_failed", "authentication_failures"],
            "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        },
        "agent": {"id": "001", "name": "web-server-01"},
        "data": {"srcip": "203.0.113.5", "srcuser": "root"},
        "full_log": "Jan 1 00:00:00 host sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2",
    }
    result = normalize_for_connector_type("wazuh", None, alert)
    assert result.event_type == "login_failed"
    assert result.outcome == "failed"
    assert result.src_ip == "203.0.113.5"
    assert result.user == "root"
    assert result.mitre_techniques == ["T1110 - Brute Force"]
    assert result.extra["rule_id"] == "5710"
    assert result.extra["agent"] == "web-server-01"


def test_wazuh_successful_login_after_failures():
    alert = {
        "rule": {"level": 3, "description": "sshd: authentication success.", "id": "5715", "groups": ["authentication_success"]},
        "data": {"srcip": "203.0.113.5", "dstuser": "root"},
    }
    result = normalize_for_connector_type("wazuh", None, alert)
    assert result.event_type == "login_success"
    assert result.outcome == "success"
    assert result.user == "root"


def test_wazuh_privilege_escalation_rule_group():
    alert = {
        "rule": {"level": 12, "description": "User escalated privileges via sudo.", "id": "5402", "groups": ["privilege_escalation", "sudo"]},
        "data": {"srcuser": "alice", "dstuser": "root"},
    }
    result = normalize_for_connector_type("wazuh", None, alert)
    assert result.event_type == "privilege_escalation"


def test_wazuh_without_mitre_data_falls_back_to_empty_techniques():
    """Not every Wazuh rule carries rule.mitre — that's normal, not a bug;
    the incident still opens, just without vendor-supplied classification."""
    alert = {
        "rule": {"level": 5, "description": "Unknown event.", "id": "999", "groups": []},
        "data": {},
    }
    result = normalize_for_connector_type("wazuh", None, alert)
    assert result.mitre_techniques == []
    assert result.event_type == "other"


def test_wazuh_malware_detection_via_rootcheck_group():
    """Wazuh's real rootcheck integration flags rootkits/hidden processes
    under the "rootcheck" rule group — a standard, documented part of its
    ruleset, not an invented one."""
    alert = {
        "rule": {
            "level": 7,
            "description": "Rootcheck: Trojaned version of file '/usr/bin/find' detected.",
            "id": "510",
            "groups": ["rootcheck"],
        },
        "agent": {"id": "001", "name": "web-server-01"},
        "data": {},
    }
    result = normalize_for_connector_type("wazuh", None, alert)
    assert result.event_type == "malware_detected"
    assert result.extra["rule_description"] == "Rootcheck: Trojaned version of file '/usr/bin/find' detected."


def test_wazuh_malware_detection_via_description_keyword():
    """A rule outside the rootcheck/malware groups can still carry a
    description that plainly names a malware finding (e.g. a third-party
    antivirus integration's own alert text) — matched on keyword since
    there's no dedicated group for every such integration."""
    alert = {
        "rule": {"level": 12, "description": "Malware detected: Win32.Trojan.Generic", "id": "87401", "groups": ["virus"]},
        "data": {"srcip": "10.0.0.5"},
    }
    result = normalize_for_connector_type("wazuh", None, alert)
    assert result.event_type == "malware_detected"
    assert result.src_ip == "10.0.0.5"


def test_cloudtrail_console_login_failure():
    event = {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice", "userName": "alice"},
        "eventTime": "2024-01-01T00:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.9",
        "errorCode": "Failed authentication",
        "responseElements": {"ConsoleLogin": "Failure"},
    }
    result = normalize_for_connector_type("cloudtrail", None, event)
    assert result.event_type == "login_failed"
    assert result.outcome == "failed"
    assert result.src_ip == "203.0.113.9"
    assert result.user == "alice"
    assert result.extra["event_name"] == "ConsoleLogin"


def test_cloudtrail_console_login_success():
    event = {
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "203.0.113.9",
        "responseElements": {"ConsoleLogin": "Success"},
    }
    result = normalize_for_connector_type("cloudtrail", None, event)
    assert result.event_type == "login_success"
    assert result.outcome == "success"


def test_cloudtrail_privilege_escalation_event():
    event = {
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
        "eventName": "AttachUserPolicy",
        "sourceIPAddress": "203.0.113.9",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "alice"},
    }
    result = normalize_for_connector_type("cloudtrail", None, event)
    assert result.event_type == "privilege_escalation"


def test_azure_ad_sign_in_failure_uses_real_error_code():
    event = {
        "id": "example-id",
        "createdDateTime": "2024-01-01T00:00:00Z",
        "userPrincipalName": "alice@contoso.com",
        "appDisplayName": "Office 365",
        "ipAddress": "203.0.113.20",
        "status": {"errorCode": 50126, "failureReason": "Error validating credentials due to invalid username or password."},
        "location": {"city": "Bucharest", "countryOrRegion": "RO"},
    }
    result = normalize_for_connector_type("azure_ad", None, event)
    assert result.event_type == "login_failed"
    assert result.outcome == "failed"
    assert result.user == "alice@contoso.com"
    assert result.src_ip == "203.0.113.20"
    assert result.country == "RO"
    assert result.extra["error_code"] == 50126


def test_azure_ad_sign_in_success():
    event = {
        "userPrincipalName": "alice@contoso.com",
        "ipAddress": "203.0.113.20",
        "status": {"errorCode": 0},
        "location": {"city": "Seattle", "countryOrRegion": "US"},
    }
    result = normalize_for_connector_type("azure_ad", None, event)
    assert result.event_type == "login_success"
    assert result.outcome == "success"
    assert result.country == "US"


def test_unrecognized_connector_type_falls_back_to_generic_guessing():
    result = normalize_for_connector_type("some_custom_forwarder", "login_failed", {"src_ip": "9.9.9.9", "user": "bob"})
    assert result.event_type == "login_failed"
    assert result.src_ip == "9.9.9.9"
    assert result.mitre_techniques == []
