from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import ConnectorConfig, User, UserRole
from pydantic import BaseModel

router = APIRouter(prefix="/api/tenants/{tenant_id}/connectors", tags=["connectors"])


class ConnectorOut(BaseModel):
    id: str
    connector_type: str
    display_name: str
    is_active: bool
    last_event_at: str | None = None

    class Config:
        from_attributes = True


class ConnectorCreate(BaseModel):
    connector_type: str
    display_name: str = ""
    config: dict = {}


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.get("", response_model=list[ConnectorOut])
async def list_connectors(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _check_tenant_access(user, tenant_id)
    result = await db.execute(select(ConnectorConfig).where(ConnectorConfig.tenant_id == tenant_id))
    connectors = list(result.scalars())
    return [
        ConnectorOut(
            id=c.id,
            connector_type=c.connector_type,
            display_name=c.display_name,
            is_active=c.is_active,
            last_event_at=c.last_event_at.isoformat() if c.last_event_at else None,
        )
        for c in connectors
    ]


@router.post("", response_model=ConnectorOut)
async def add_connector(
    tenant_id: str,
    payload: ConnectorCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Config only — no secrets are accepted here on purpose. Real connector
    credentials belong in a secrets vault (see README.md security roadmap),
    not in this JSON blob."""
    _check_tenant_access(user, tenant_id)
    connector = ConnectorConfig(
        tenant_id=tenant_id,
        connector_type=payload.connector_type,
        display_name=payload.display_name or payload.connector_type,
        config=payload.config,
    )
    db.add(connector)
    await db.commit()
    await db.refresh(connector)
    return ConnectorOut(
        id=connector.id,
        connector_type=connector.connector_type,
        display_name=connector.display_name,
        is_active=connector.is_active,
        last_event_at=None,
    )
