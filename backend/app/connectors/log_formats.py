"""Real, schema-accurate field mapping for the log formats a real security
stack actually produces — not a generic src_ip/user guess. Each function
here parses the vendor's own documented JSON shape:

- Wazuh alert JSON (rule.*, data.*, agent.*) — including rule.mitre.id/
  technique, which Wazuh's own ruleset populates with real MITRE ATT&CK
  technique IDs for many rules. When present, that vendor-supplied
  classification is used directly instead of our own heuristic guess —
  more accurate than anything we could infer from field names alone.
- AWS CloudTrail event records (eventName, userIdentity, errorCode, ...)
  per https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- Azure AD sign-in logs (ipAddress, userPrincipalName, status.errorCode,
  location.countryOrRegion, ...) per Microsoft's documented sign-in log
  schema. status.errorCode 0 means success; Microsoft documents the
  failure codes (e.g. 50126 = invalid username or password).

A connector declares its `connector_type` at creation (Settings → Add
connector); that authenticated type — never a free-text field the event
payload itself claims — decides which parser runs. A connector calling
itself "wazuh" can't get Wazuh-shaped trust by simply setting
data.source to "wazuh" in its JSON; the classification is keyed off what
the tenant actually registered it as.
"""
from dataclasses import dataclass, field


@dataclass
class NormalizedEvent:
    event_type: str  # "login_failed" | "login_success" | "privilege_escalation" | "other"
    src_ip: str | None
    user: str | None
    outcome: str | None  # "success" | "failed" | None
    mitre_techniques: list[str] = field(default_factory=list)  # vendor-supplied, when available
    country: str | None = None  # for impossible-travel cross-checks, when the vendor supplies it
    extra: dict = field(default_factory=dict)


def normalize_wazuh(data: dict) -> NormalizedEvent:
    rule = data.get("rule") or {}
    d = data.get("data") or {}
    mitre = rule.get("mitre") or {}
    groups = rule.get("groups") or []
    description = (rule.get("description") or "").lower()

    src_ip = d.get("srcip") or d.get("src_ip")
    user = d.get("srcuser") or d.get("dstuser") or d.get("user")

    if any(g in groups for g in ("authentication_failed", "authentication_failures")) or "failed" in description:
        event_type, outcome = "login_failed", "failed"
    elif "authentication_success" in groups or ("logon" in description and "success" in description):
        event_type, outcome = "login_success", "success"
    elif any(g in groups for g in ("privilege_escalation", "sudo")) or "privilege" in description:
        event_type, outcome = "privilege_escalation", None
    elif any(g in groups for g in ("rootcheck", "malware", "virus")) or any(
        w in description for w in ("trojan", "malware", "rootkit")
    ):
        # Wazuh's rootcheck/malware rule groups are real, standard parts
        # of its ruleset (rootcheck for rootkit/hidden-process detection,
        # its malware integrations for signature hits) — not a guess.
        event_type, outcome = "malware_detected", None
    else:
        event_type, outcome = "other", None

    mitre_ids = mitre.get("id") or []
    mitre_names = mitre.get("technique") or []
    mitre_techniques = [
        f"{tid} - {mitre_names[i]}" if i < len(mitre_names) and mitre_names[i] else tid
        for i, tid in enumerate(mitre_ids)
    ]

    return NormalizedEvent(
        event_type=event_type,
        src_ip=src_ip,
        user=user,
        outcome=outcome,
        mitre_techniques=mitre_techniques,
        extra={
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "agent": (data.get("agent") or {}).get("name"),
        },
    )


_CLOUDTRAIL_PRIVILEGE_EVENTS = {
    "CreateUser",
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "AttachRolePolicy",
    "CreateRole",
    "AddUserToGroup",
    "CreateLoginProfile",
}


def normalize_cloudtrail(data: dict) -> NormalizedEvent:
    event_name = data.get("eventName", "")
    error_code = data.get("errorCode")
    user_identity = data.get("userIdentity") or {}
    user = user_identity.get("userName") or user_identity.get("arn")
    src_ip = data.get("sourceIPAddress")
    response_elements = data.get("responseElements") or {}

    if event_name == "ConsoleLogin":
        failed = bool(error_code) or response_elements.get("ConsoleLogin") == "Failure"
        event_type, outcome = ("login_failed", "failed") if failed else ("login_success", "success")
    elif event_name in _CLOUDTRAIL_PRIVILEGE_EVENTS:
        event_type, outcome = "privilege_escalation", None
    else:
        event_type, outcome = "other", None

    return NormalizedEvent(
        event_type=event_type,
        src_ip=src_ip,
        user=user,
        outcome=outcome,
        extra={
            "event_name": event_name,
            "event_source": data.get("eventSource"),
            "aws_region": data.get("awsRegion"),
            "error_code": error_code,
        },
    )


def normalize_azure_ad(data: dict) -> NormalizedEvent:
    status = data.get("status") or {}
    error_code = status.get("errorCode")
    user = data.get("userPrincipalName")
    src_ip = data.get("ipAddress")
    location = data.get("location") or {}
    country = location.get("countryOrRegion")

    if error_code == 0:
        event_type, outcome = "login_success", "success"
    elif error_code is not None:
        event_type, outcome = "login_failed", "failed"
    else:
        event_type, outcome = "other", None

    return NormalizedEvent(
        event_type=event_type,
        src_ip=src_ip,
        user=user,
        outcome=outcome,
        country=country,
        extra={
            "app": data.get("appDisplayName"),
            "failure_reason": status.get("failureReason"),
            "error_code": error_code,
            "city": location.get("city"),
        },
    )


def normalize_generic(event_type: str | None, data: dict) -> NormalizedEvent:
    """For a connector_type without a dedicated parser: the caller-supplied
    event_type plus a best-effort guess at common field names. This is the
    only normalizer that trusts caller-supplied classification, since
    there's no known vendor schema to classify from instead."""
    return NormalizedEvent(
        event_type=event_type or "other",
        src_ip=data.get("src_ip") or data.get("source_ip"),
        user=data.get("user") or data.get("username"),
        outcome=data.get("outcome"),
        country=data.get("country"),
    )


_NORMALIZERS = {
    "wazuh": lambda event_type, data: normalize_wazuh(data),
    "cloudtrail": lambda event_type, data: normalize_cloudtrail(data),
    "aws_cloudtrail": lambda event_type, data: normalize_cloudtrail(data),
    "azure_ad": lambda event_type, data: normalize_azure_ad(data),
}


def normalize_for_connector_type(connector_type: str, event_type: str | None, data: dict) -> NormalizedEvent:
    parser = _NORMALIZERS.get(connector_type)
    if parser is not None:
        return parser(event_type, data)
    return normalize_generic(event_type, data)
