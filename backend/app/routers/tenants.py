from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_admin
from app.database import get_db
from app.models import ConnectorConfig, Tenant, User, UserRole
from app.schemas import KillSwitchUpdate, TenantCreate, TenantOut

router = APIRouter(prefix="/api/tenants", tags=["tenants"])


@router.post("", response_model=TenantOut)
async def create_tenant(payload: TenantCreate, db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    existing = await db.execute(select(Tenant).where(Tenant.domain == payload.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Domain already onboarded")

    tenant = Tenant(name=payload.name, domain=payload.domain, sector=payload.sector)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)

    # Register the synthetic demo connector automatically so a new tenant
    # has something to see in the console before wiring a real SIEM.
    db.add(ConnectorConfig(tenant_id=tenant.id, connector_type="synthetic_demo", display_name="Demo feed"))
    await db.commit()
    return tenant


@router.get("", response_model=list[TenantOut])
async def list_tenants(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == UserRole.ADMIN:
        result = await db.execute(select(Tenant))
    else:
        result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    return list(result.scalars())


@router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@router.post("/{tenant_id}/kill-switch", response_model=TenantOut)
async def set_kill_switch(
    tenant_id: str,
    payload: KillSwitchUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Either the admin or the company's own security holder can engage the
    kill switch (stop everything now); only the admin can disengage it, so a
    panic button can't be accidentally undone by the wrong hand."""
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")
    if not payload.engaged and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only the platform admin can disengage the kill switch")

    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.kill_switch_engaged = payload.engaged
    tenant.kill_switch_reason = payload.reason
    await db.commit()
    await db.refresh(tenant)

    from app.bus import CH_GUARDIAN_ALERT, get_bus

    bus = await get_bus()
    await bus.publish(
        CH_GUARDIAN_ALERT,
        {"tenant_id": tenant_id, "reason": "kill_switch_toggled", "engaged": payload.engaged, "by": user.email},
        actor="guardian",
        tenant_id=tenant_id,
    )
    return tenant
