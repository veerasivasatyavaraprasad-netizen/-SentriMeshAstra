from fastapi import APIRouter, Depends, HTTPException

from app.auth import get_current_user
from app.bus import CH_RAW_EVENTS, get_bus
from app.connectors.sample_feed import brute_force_scenario
from app.models import User, UserRole
from app.schemas import IngestEvent

router = APIRouter(prefix="/api", tags=["ingest"])


def _check_tenant_access(user: User, tenant_id: str) -> None:
    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized for this tenant")


@router.post("/tenants/{tenant_id}/ingest")
async def ingest_event(tenant_id: str, payload: IngestEvent, user: User = Depends(get_current_user)):
    """Generic webhook shape any connector (Wazuh, a custom script, etc.)
    can POST to. Production hardening note: this currently authenticates
    with the console's own JWT; a machine-to-machine per-connector secret
    token is the right mechanism for a real SIEM forwarder and is called
    out in README.md's roadmap rather than implemented here."""
    _check_tenant_access(user, tenant_id)
    bus = await get_bus()
    await bus.publish(
        CH_RAW_EVENTS,
        {
            "tenant_id": tenant_id,
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
async def simulate_attack(tenant_id: str, user: User = Depends(get_current_user)):
    """Fires a synthetic brute-force scenario through the real pipeline so
    you can see detection -> enrichment -> classification -> response -> a
    pending approval happen end to end, without any external log source."""
    _check_tenant_access(user, tenant_id)
    bus = await get_bus()
    for event in brute_force_scenario():
        await bus.publish(
            CH_RAW_EVENTS,
            {"tenant_id": tenant_id, **event},
            actor="connector",
            tenant_id=tenant_id,
        )
    return {"status": "simulated", "events": len(brute_force_scenario())}


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
