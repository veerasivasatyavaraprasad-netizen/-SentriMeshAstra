"""Tests the WebSocket push path with a real, bound TCP server and a real
WebSocket client (the `websockets` library — uvicorn's own dependency,
already in the environment) — not Starlette's simulated-ASGI TestClient.
This is the same thing a browser tab actually does: open a real socket,
authenticate over the query string, and receive real-time frames as the
agent pipeline reacts to real ingested events.
"""
import asyncio
import json
import os
import uuid

import pytest
import uvicorn
import websockets

WS_TEST_PORT = 8799  # fixed port for this test module only; not shared with anything else


async def _login(client, email, password):
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def live_server(client):
    """Runs the *same already-lifespan-started* app (via the `client`
    fixture) on a real bound port, so a real WebSocket client can connect
    to it — httpx's ASGITransport (used by `client`) never opens a real
    socket, so it can't be used for a genuine WS handshake test."""
    from app.main import app

    config = uvicorn.Config(app, host="127.0.0.1", port=WS_TEST_PORT, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(50):
        if server.started:
            break
        await asyncio.sleep(0.1)
    assert server.started, "test uvicorn server never started"
    try:
        yield f"ws://127.0.0.1:{WS_TEST_PORT}"
    finally:
        server.should_exit = True
        await task


async def _create_tenant_and_connector(client, admin_token):
    domain = f"{uuid.uuid4().hex[:12]}.example.com"
    r = await client.post("/api/tenants", json={"name": "WS Test Co", "domain": domain, "sector": "finance"}, headers=_auth(admin_token))
    tenant = r.json()
    r = await client.post(
        f"/api/tenants/{tenant['id']}/connectors",
        json={"connector_type": "generic", "display_name": "ws-test"},
        headers=_auth(admin_token),
    )
    return tenant, r.json()


async def test_websocket_pushes_real_events_within_the_dashboard_channel_set(client, live_server):
    admin_email = os.environ["BOOTSTRAP_ADMIN_EMAIL"]
    admin_password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    admin_token = await _login(client, admin_email, admin_password)
    tenant, connector = await _create_tenant_and_connector(client, admin_token)

    ws_url = f"{live_server}/ws/tenants/{tenant['id']}?token={admin_token}"
    async with websockets.connect(ws_url) as ws:
        headers = {"Authorization": f"Bearer {connector['token']}"}
        for _ in range(6):
            r = await client.post(
                f"/api/tenants/{tenant['id']}/ingest",
                json={"source": "test", "event_type": "login_failed", "data": {"src_ip": "203.0.113.201", "user": "root"}},
                headers=headers,
            )
            assert r.status_code == 200
        r = await client.post(
            f"/api/tenants/{tenant['id']}/ingest",
            json={"source": "test", "event_type": "login_success", "data": {"src_ip": "203.0.113.201", "user": "root"}},
            headers=headers,
        )
        assert r.status_code == 200

        received = []
        try:
            async with asyncio.timeout(8):
                while len(received) < 3:
                    msg = json.loads(await ws.recv())
                    received.append(msg)
        except TimeoutError:
            pass

    assert len(received) >= 3, f"expected several push events, got {received}"
    channels = {m["channel"] for m in received}
    assert "incidents.new" in channels
    assert all(m["payload"]["tenant_id"] == tenant["id"] for m in received)


async def test_websocket_rejects_connection_with_no_token(live_server):
    with pytest.raises(Exception):
        async with websockets.connect(f"{live_server}/ws/tenants/{uuid.uuid4()}"):
            pass


async def test_websocket_rejects_connection_with_invalid_token(live_server):
    with pytest.raises(Exception):
        async with websockets.connect(f"{live_server}/ws/tenants/{uuid.uuid4()}?token=not-a-real-jwt"):
            pass


async def test_websocket_rejects_security_holder_for_a_tenant_that_is_not_theirs(client, live_server):
    admin_email = os.environ["BOOTSTRAP_ADMIN_EMAIL"]
    admin_password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    admin_token = await _login(client, admin_email, admin_password)
    tenant_a, _ = await _create_tenant_and_connector(client, admin_token)
    tenant_b, _ = await _create_tenant_and_connector(client, admin_token)

    holder_email = f"holder-{uuid.uuid4().hex[:8]}@example.com"
    await client.post(
        "/api/auth/security-holders",
        json={"email": holder_email, "password": "HolderPass123!", "full_name": "Holder", "tenant_id": tenant_a["id"]},
        headers=_auth(admin_token),
    )
    holder_token = await _login(client, holder_email, "HolderPass123!")

    with pytest.raises(Exception):
        async with websockets.connect(f"{live_server}/ws/tenants/{tenant_b['id']}?token={holder_token}"):
            pass
