from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import (
    ApprovalRequest,
    ApprovalStatus,
    ConnectorConfig,
    Incident,
    IncidentStatus,
    Report,
    Severity,
    Tenant,
    User,
    UserRole,
)
from app.schemas import OverviewOut

router = APIRouter(prefix="/api/tenants/{tenant_id}/overview", tags=["overview"])

SEVERITY_WEIGHT = {Severity.LOW: 2, Severity.MEDIUM: 8, Severity.HIGH: 20, Severity.CRITICAL: 35}
CONNECTOR_STALE_AFTER = timedelta(hours=6)


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.get("", response_model=OverviewOut)
async def get_overview(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _check_tenant_access(user, tenant_id)

    tenant_result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    open_incidents_result = await db.execute(
        select(Incident).where(
            Incident.tenant_id == tenant_id,
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        )
    )
    open_incidents = list(open_incidents_result.scalars())

    risk_score = min(100, sum(SEVERITY_WEIGHT[i.severity] for i in open_incidents))
    critical_count = sum(1 for i in open_incidents if i.severity == Severity.CRITICAL)

    pending_result = await db.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.tenant_id == tenant_id, ApprovalRequest.status == ApprovalStatus.PENDING
        )
    )
    pending_count = len(list(pending_result.scalars()))

    connectors_result = await db.execute(select(ConnectorConfig).where(ConnectorConfig.tenant_id == tenant_id))
    now = datetime.utcnow()
    connector_health = [
        {
            "id": c.id,
            "type": c.connector_type,
            "name": c.display_name,
            "healthy": bool(c.last_event_at and now - c.last_event_at < CONNECTOR_STALE_AFTER) if c.last_event_at else None,
            "last_event_at": c.last_event_at.isoformat() if c.last_event_at else None,
        }
        for c in connectors_result.scalars()
    ]

    last_report_result = await db.execute(
        select(Report).where(Report.tenant_id == tenant_id).order_by(Report.created_at.desc()).limit(1)
    )
    last_report = last_report_result.scalar_one_or_none()

    return OverviewOut(
        tenant_id=tenant_id,
        risk_score=risk_score,
        open_incidents=len(open_incidents),
        critical_incidents=critical_count,
        pending_approvals=pending_count,
        kill_switch_engaged=tenant.kill_switch_engaged,
        connector_health=connector_health,
        last_report_at=last_report.created_at if last_report else None,
    )
