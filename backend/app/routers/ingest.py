from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, user_from_jwt
from app.bus import CH_RAW_EVENTS, get_bus
from app.connector_auth import authenticate_connector, is_connector_token
from app.connectors.sample_feed import brute_force_scenario
from app.database import get_db
from app.models import ConnectorConfig, User, UserRole
from app.schemas import IngestEvent

router = APIRouter(prefix="/api", tags=["ingest"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


async def _authenticate_ingest(tenant_id: str, authorization: str | None, db: AsyncSession) -> tuple[str, str | None]:
    """A real log forwarder (Wazuh, etc.) authenticates with a connector's
    own secret token (app/connector_auth.py), not a human's session JWT —
    see README.md. This one endpoint accepts either, telling them apart by
    the token's prefix, so the console's own "simulate attack" button
    (which sends a human JWT) and a real forwarder both work here.

    Returns (source_label, connector_id) — connector_id is set only for a
    connector-token caller, so the Integration agent can track that
    connector's health (last_event_at).
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()

    if is_connector_token(token):
        connector = await authenticate_connector(token, tenant_id, db)
        if connector is None:
            raise HTTPException(status_code=401, detail="Invalid or inactive connector token")
        return connector.display_name or connector.connector_type, connector.id

    user = await user_from_jwt(token, db)
    _check_tenant_access(user, tenant_id)
    return user.email, None


@router.post("/tenants/{tenant_id}/ingest")
async def ingest_event(
    tenant_id: str,
    payload: IngestEvent,
    db: AsyncSession = Depends(get_db),
    authorization: str | None = Header(default=None),
):
    """Generic webhook shape any connector (Wazuh, a custom script, etc.)
    can POST to, authenticated with that connector's own token — see
    POST .../connectors for how to mint one."""
    _, connector_id = await _authenticate_ingest(tenant_id, authorization, db)
    bus = await get_bus()
    await bus.publish(
        CH_RAW_EVENTS,
        {
            "tenant_id": tenant_id,
            "connector_id": connector_id,
            "source": payload.source,
            "event_type": payload.event_type,
            "occurred_at": payload.occurred_at.isoformat() if payload.occurred_at else None,
            "data": payload.data,
        },
        actor="connector",
        tenant_id=tenant_id,
    )
    return {"status": "accepted"}


@router.post("/tenants/{tenant_id}/demo/simulate-attack")
async def simulate_attack(tenant_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    """Fires a synthetic brute-force scenario through the real pipeline so
    you can see detection -> enrichment -> classification -> response -> a
    pending approval happen end to end, without any external log source."""
    _check_tenant_access(user, tenant_id)

    result = await db.execute(
        select(ConnectorConfig).where(
            ConnectorConfig.tenant_id == tenant_id, ConnectorConfig.connector_type == "synthetic_demo"
        )
    )
    demo_connector = result.scalar_one_or_none()

    bus = await get_bus()
    events = brute_force_scenario()
    for event in events:
        await bus.publish(
            CH_RAW_EVENTS,
            {"tenant_id": tenant_id, "connector_id": demo_connector.id if demo_connector else None, **event},
            actor="connector",
            tenant_id=tenant_id,
        )
    return {"status": "simulated", "events": len(events)}


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
