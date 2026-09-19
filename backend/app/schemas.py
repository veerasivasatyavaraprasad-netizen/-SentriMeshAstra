from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models import ApprovalStatus, AutonomyTier, IncidentStatus, Severity, UserRole


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    tenant_id: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TenantCreate(BaseModel):
    name: str
    domain: str
    sector: str = "general"


class TenantOut(BaseModel):
    id: str
    name: str
    domain: str
    sector: str
    kill_switch_engaged: bool
    created_at: datetime

    class Config:
        from_attributes = True


class SecurityHolderCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)
    full_name: str = ""
    tenant_id: str


class UserOut(BaseModel):
    id: str
    email: str
    role: UserRole
    tenant_id: str | None
    full_name: str
    is_active: bool

    class Config:
        from_attributes = True


class IngestEvent(BaseModel):
    """Shape accepted from connectors. `source` is a free-text label for
    display only (e.g. "prod-wazuh-01") — the authenticated connector's
    own registered connector_type, not this field, decides which log
    format parser runs (see app/connectors/log_formats.py). `event_type`
    is optional: a real Wazuh/CloudTrail/Azure AD payload is classified
    from its own real fields; only a connector_type without a dedicated
    parser needs the caller to say what kind of event this is."""

    source: str
    event_type: str | None = None
    occurred_at: datetime | None = None
    data: dict


class IncidentOut(BaseModel):
    id: str
    tenant_id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    mitre_techniques: list
    enrichment: dict
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ActionProposalOut(BaseModel):
    id: str
    tenant_id: str
    incident_id: str
    action_type: str
    parameters: dict
    tier: AutonomyTier
    rationale: str
    reversible: bool
    rollback_plan: str
    executed: bool
    executed_at: datetime | None
    execution_result: dict
    created_at: datetime

    class Config:
        from_attributes = True


class ApprovalOut(BaseModel):
    id: str
    tenant_id: str
    action_proposal_id: str
    status: ApprovalStatus
    decided_by_user_id: str | None
    decided_at: datetime | None
    decision_note: str
    created_at: datetime
    action: ActionProposalOut | None = None

    class Config:
        from_attributes = True


class ApprovalDecision(BaseModel):
    approve: bool
    note: str = ""


class AuditLogOut(BaseModel):
    id: str
    tenant_id: str | None
    actor: str
    action: str
    channel: str
    payload: dict
    created_at: datetime

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    id: str
    tenant_id: str
    report_type: str
    period_start: datetime
    period_end: datetime
    summary: str
    body: dict
    emailed: bool
    created_at: datetime

    class Config:
        from_attributes = True


class KillSwitchUpdate(BaseModel):
    engaged: bool
    reason: str = ""


class OverviewOut(BaseModel):
    tenant_id: str
    risk_score: int
    open_incidents: int
    critical_incidents: int
    pending_approvals: int
    kill_switch_engaged: bool
    connector_health: list[dict]
    last_report_at: datetime | None
