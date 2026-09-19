from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import Incident, User, UserRole
from app.schemas import IncidentOut

router = APIRouter(prefix="/api/tenants/{tenant_id}/incidents", tags=["incidents"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.get("", response_model=list[IncidentOut])
async def list_incidents(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _check_tenant_access(user, tenant_id)
    result = await db.execute(
        select(Incident).where(Incident.tenant_id == tenant_id).order_by(Incident.created_at.desc()).limit(200)
    )
    return list(result.scalars())


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(
    tenant_id: str,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _check_tenant_access(user, tenant_id)
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
