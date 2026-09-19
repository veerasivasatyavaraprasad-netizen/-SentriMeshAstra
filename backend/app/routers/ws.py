import asyncio
import logging

from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect

from app.auth import user_from_jwt
from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import UserRole
from app.realtime import stream_tenant_events

logger = logging.getLogger("sentrimesh.ws")
router = APIRouter(tags=["realtime"])


@router.websocket("/ws/tenants/{tenant_id}")
async def tenant_events_ws(websocket: WebSocket, tenant_id: str):
    """Push channel for one tenant's dashboard. Browsers can't set custom
    headers on a WebSocket handshake, so auth travels as a query param
    (?token=<jwt>) instead of the usual Authorization header — checked
    against the same JWT and tenant-scoping rules as every REST route.
    """
    settings = get_settings()
    origin = websocket.headers.get("origin")
    if origin is not None and settings.cors_origins and origin not in settings.cors_origins:
        await websocket.close(code=4403)
        return

    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return

    async with AsyncSessionLocal() as db:
        try:
            user = await user_from_jwt(token, db)
        except Exception:
            await websocket.close(code=4401)
            return

    if user.role != UserRole.ADMIN and user.tenant_id != tenant_id:
        await websocket.close(code=4403)
        return

    await websocket.accept()

    async def watch_for_disconnect() -> None:
        try:
            while True:
                message = await websocket.receive()
                if message.get("type") == "websocket.disconnect":
                    return
        except WebSocketDisconnect:
            return

    async def forward_events() -> None:
        async for event in stream_tenant_events(tenant_id, settings.redis_url):
            await websocket.send_json(event)

    watcher = asyncio.create_task(watch_for_disconnect())
    forwarder = asyncio.create_task(forward_events())
    try:
        await asyncio.wait({watcher, forwarder}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (watcher, forwarder):
            if not task.done():
                task.cancel()
        await asyncio.gather(watcher, forwarder, return_exceptions=True)
