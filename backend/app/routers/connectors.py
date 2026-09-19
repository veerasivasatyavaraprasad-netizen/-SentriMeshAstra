from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.connector_auth import generate_token
from app.database import get_db
from app.models import ConnectorConfig, User, UserRole

router = APIRouter(prefix="/api/tenants/{tenant_id}/connectors", tags=["connectors"])


class ConnectorOut(BaseModel):
    id: str
    connector_type: str
    display_name: str
    is_active: bool
    has_token: bool
    last_event_at: str | None = None

    class Config:
        from_attributes = True


class ConnectorCreate(BaseModel):
    connector_type: str
    display_name: str = ""
    config: dict = {}


class ConnectorCreatedOut(ConnectorOut):
    token: str  # shown exactly once — the caller must copy it now


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


def _out(c: ConnectorConfig) -> ConnectorOut:
    return ConnectorOut(
        id=c.id,
        connector_type=c.connector_type,
        display_name=c.display_name,
        is_active=c.is_active,
        has_token=c.token_hash is not None,
        last_event_at=c.last_event_at.isoformat() if c.last_event_at else None,
    )


@router.get("", response_model=list[ConnectorOut])
async def list_connectors(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    _check_tenant_access(user, tenant_id)
    result = await db.execute(select(ConnectorConfig).where(ConnectorConfig.tenant_id == tenant_id))
    return [_out(c) for c in result.scalars()]


@router.post("", response_model=ConnectorCreatedOut)
async def add_connector(
    tenant_id: str,
    payload: ConnectorCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Config only — no secrets are accepted here on purpose. Real connector
    infrastructure credentials (e.g. a Wazuh API key) belong in a secrets
    vault (see README.md security roadmap), not in this JSON blob. What
    this DOES issue is SentriMeshAstra's own bearer token for the
    connector to authenticate its pushes with — see POST .../ingest."""
    _check_tenant_access(user, tenant_id)
    raw_token, token_hash = generate_token()
    connector = ConnectorConfig(
        tenant_id=tenant_id,
        connector_type=payload.connector_type,
        display_name=payload.display_name or payload.connector_type,
        config=payload.config,
        token_hash=token_hash,
    )
    db.add(connector)
    await db.commit()
    await db.refresh(connector)
    return ConnectorCreatedOut(**_out(connector).model_dump(), token=raw_token)


@router.post("/{connector_id}/rotate-token", response_model=ConnectorCreatedOut)
async def rotate_token(
    tenant_id: str,
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Issue a new token and immediately invalidate the old one — for a
    leaked credential, this is the whole remediation, not just half of it."""
    _check_tenant_access(user, tenant_id)
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.id == connector_id, ConnectorConfig.tenant_id == tenant_id)
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    raw_token, token_hash = generate_token()
    connector.token_hash = token_hash
    await db.commit()
    await db.refresh(connector)
    return ConnectorCreatedOut(**_out(connector).model_dump(), token=raw_token)
