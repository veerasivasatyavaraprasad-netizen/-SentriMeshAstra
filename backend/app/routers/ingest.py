from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.bus import CH_RAW_EVENTS, get_bus
from app.connector_auth import authenticate_connector
from app.database import get_db
from app.models import User, UserRole
from app.schemas import IngestEvent

router = APIRouter(prefix="/api", tags=["ingest"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.post("/tenants/{tenant_id}/ingest")
async def ingest_event(
    tenant_id: str,
    payload: IngestEvent,
    db: AsyncSession = Depends(get_db),
    authorization: str | None = Header(default=None),
):
    """Only a connector's own secret token authenticates this endpoint —
    see POST .../connectors for how to mint one, and app/connector_auth.py
    for how it's verified. Deliberately no human-JWT fallback: every event
    that enters the pipeline has to come from a data source the tenant
    actually registered and can revoke, never from someone hand-typing a
    payload into the console's own session."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing connector bearer token")
    token = authorization.split(" ", 1)[1].strip()

    connector = await authenticate_connector(token, tenant_id, db)
    if connector is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive connector token")

    bus = await get_bus()
    await bus.publish(
        CH_RAW_EVENTS,
        {
            "tenant_id": tenant_id,
            "connector_id": connector.id,
            "source": payload.source,
            "event_type": payload.event_type,
            "occurred_at": payload.occurred_at.isoformat() if payload.occurred_at else None,
            "data": payload.data,
        },
        actor=f"connector:{connector.display_name or connector.connector_type}",
        tenant_id=tenant_id,
    )
    return {"status": "accepted"}


@router.post("/tenants/{tenant_id}/exposure-scan")
async def request_exposure_scan(tenant_id: str, domain: str, user: User = Depends(get_current_user)):
    _check_tenant_access(user, tenant_id)
    bus = await get_bus()
    from app.agents.exposure import CH_EXPOSURE_SCAN_REQUESTED

    await bus.publish(
        CH_EXPOSURE_SCAN_REQUESTED,
        {"tenant_id": tenant_id, "domain": domain},
        actor="api",
        tenant_id=tenant_id,
    )
    return {"status": "scan_requested", "domain": domain}
