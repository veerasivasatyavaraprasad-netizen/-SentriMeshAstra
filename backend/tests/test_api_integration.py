"""End-to-end tests against the real FastAPI app (real Alembic migrations,
real Postgres, real Redis-backed agent bus, all 8 agents actually running)
via the `client` fixture in conftest.py — not mocks, not curl scripts run
by hand. This is what previously only got exercised manually during
development; codifying it here means a regression gets caught by `pytest`
instead of by someone noticing the dashboard looks wrong.
"""
import asyncio
import os
import uuid

import pytest

ADMIN_EMAIL = os.environ["BOOTSTRAP_ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]


async def _login(client, email, password):
    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


async def _admin_token(client):
    return await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)


async def _create_tenant(client, admin_token, name="Test Co"):
    domain = f"{uuid.uuid4().hex[:12]}.example.com"
    r = await client.post(
        "/api/tenants", json={"name": name, "domain": domain, "sector": "finance"}, headers=_auth(admin_token)
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _wait_until(predicate, *, timeout=6.0, interval=0.2):
    """Poll `predicate` (an async callable returning truthy/falsy) until
    it's truthy or the timeout elapses. Used instead of a flat sleep to
    wait for the async detection -> enrichment -> classification ->
    response pipeline to finish reacting to a simulated attack."""
    elapsed = 0.0
    while elapsed < timeout:
        result = await predicate()
        if result:
            return result
        await asyncio.sleep(interval)
        elapsed += interval
    raise AssertionError(f"Condition not met within {timeout}s")


async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_login_wrong_password_returns_401(client):
    r = await client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "definitely-wrong"})
    assert r.status_code == 401


async def test_admin_can_onboard_tenant_and_security_holder_is_scoped(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    holder_email = f"holder-{uuid.uuid4().hex[:8]}@example.com"
    r = await client.post(
        "/api/auth/security-holders",
        json={"email": holder_email, "password": "HolderPass123!", "full_name": "Test Holder", "tenant_id": tenant["id"]},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200, r.text

    holder_token = await _login(client, holder_email, "HolderPass123!")

    # Scoped to their own tenant...
    r = await client.get("/api/tenants", headers=_auth(holder_token))
    assert r.status_code == 200
    tenant_ids = {t["id"] for t in r.json()}
    assert tenant_ids == {tenant["id"]}

    # ...and forbidden from a different one, even if they know its ID.
    other_tenant = await _create_tenant(client, admin_token, name="Other Co")
    r = await client.get(f"/api/tenants/{other_tenant['id']}/incidents", headers=_auth(holder_token))
    assert r.status_code == 403


async def test_full_attack_pipeline_reaches_a_pending_approval(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    r = await client.post(f"/api/tenants/{tenant['id']}/demo/simulate-attack", headers=_auth(admin_token))
    assert r.status_code == 200

    async def incident_fully_classified():
        # An incident exists as soon as Detection opens it, at default
        # severity "low" — that's before ThreatIntel enrichment and
        # Orchestrator classification (both further async hops on the bus)
        # have run. Wait for the severity to actually change, not just for
        # the row to exist, or this races the pipeline and reads it half-done.
        resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
        data = resp.json()
        if data and data[0]["severity"] != "low":
            return data
        return None

    incidents = await _wait_until(incident_fully_classified)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["severity"] in ("high", "critical")
    assert any("T1110" in t for t in incident["mitre_techniques"])
    assert incident["enrichment"]["ip_reputation"]["198.51.100.23"]["verdict"] == "malicious"

    async def approval_exists():
        resp = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
        data = resp.json()
        return data if data else None

    approvals = await _wait_until(approval_exists)
    assert len(approvals) == 1
    assert approvals[0]["status"] == "pending"
    assert approvals[0]["action"]["action_type"] == "block_ip"
    assert approvals[0]["action"]["tier"] == "tier2_one_tap"


async def test_approve_action_executes_as_dry_run_and_can_be_rolled_back(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    await client.post(f"/api/tenants/{tenant['id']}/demo/simulate-attack", headers=_auth(admin_token))

    async def get_pending():
        resp = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
        data = [a for a in resp.json() if a["status"] == "pending"]
        return data if data else None

    approval = (await _wait_until(get_pending))[0]

    r = await client.post(
        f"/api/tenants/{tenant['id']}/approvals/{approval['id']}/decide",
        json={"approve": True, "note": "looks malicious"},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200, r.text
    decided = r.json()
    assert decided["status"] == "approved"
    assert decided["action"]["executed"] is True
    assert decided["action"]["execution_result"]["simulated"] is True  # ENABLE_REAL_RESPONSE_EXECUTION is off for tests

    proposal_id = decided["action"]["id"]
    r = await client.post(f"/api/tenants/{tenant['id']}/actions/{proposal_id}/rollback", headers=_auth(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["outcome"]["success"] is True
    assert r.json()["action"]["execution_result"]["rolled_back"] is True

    # Deciding an already-decided approval is rejected, not silently reprocessed.
    r = await client.post(
        f"/api/tenants/{tenant['id']}/approvals/{approval['id']}/decide",
        json={"approve": True},
        headers=_auth(admin_token),
    )
    assert r.status_code == 400


async def test_reject_action_leaves_it_unexecuted(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    await client.post(f"/api/tenants/{tenant['id']}/demo/simulate-attack", headers=_auth(admin_token))

    async def get_pending():
        resp = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
        data = [a for a in resp.json() if a["status"] == "pending"]
        return data if data else None

    approval = (await _wait_until(get_pending))[0]

    r = await client.post(
        f"/api/tenants/{tenant['id']}/approvals/{approval['id']}/decide",
        json={"approve": False, "note": "false positive"},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200
    decided = r.json()
    assert decided["status"] == "rejected"
    assert decided["action"]["executed"] is False


async def test_kill_switch_blocks_execution_even_after_approval(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    r = await client.post(
        f"/api/tenants/{tenant['id']}/kill-switch", json={"engaged": True, "reason": "test"}, headers=_auth(admin_token)
    )
    assert r.status_code == 200
    assert r.json()["kill_switch_engaged"] is True

    await client.post(f"/api/tenants/{tenant['id']}/demo/simulate-attack", headers=_auth(admin_token))

    async def get_pending():
        resp = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
        data = [a for a in resp.json() if a["status"] == "pending"]
        return data if data else None

    approval = (await _wait_until(get_pending))[0]

    r = await client.post(
        f"/api/tenants/{tenant['id']}/approvals/{approval['id']}/decide",
        json={"approve": True},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200
    # Approved, but the kill switch must still block real execution.
    assert r.json()["action"]["executed"] is False


async def test_security_holder_can_engage_but_not_disengage_kill_switch(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    holder_email = f"holder-{uuid.uuid4().hex[:8]}@example.com"
    await client.post(
        "/api/auth/security-holders",
        json={"email": holder_email, "password": "HolderPass123!", "full_name": "Holder", "tenant_id": tenant["id"]},
        headers=_auth(admin_token),
    )
    holder_token = await _login(client, holder_email, "HolderPass123!")

    r = await client.post(
        f"/api/tenants/{tenant['id']}/kill-switch", json={"engaged": True, "reason": "panic"}, headers=_auth(holder_token)
    )
    assert r.status_code == 200
    assert r.json()["kill_switch_engaged"] is True

    r = await client.post(
        f"/api/tenants/{tenant['id']}/kill-switch", json={"engaged": False}, headers=_auth(holder_token)
    )
    assert r.status_code == 403

    r = await client.post(
        f"/api/tenants/{tenant['id']}/kill-switch", json={"engaged": False}, headers=_auth(admin_token)
    )
    assert r.status_code == 200
    assert r.json()["kill_switch_engaged"] is False


async def test_generate_report_now_returns_a_summary(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    r = await client.post(f"/api/tenants/{tenant['id']}/reports/generate-now", headers=_auth(admin_token))
    assert r.status_code == 200
    report = r.json()
    assert report["report_type"] == "daily"
    assert isinstance(report["summary"], str) and len(report["summary"]) > 0


async def test_activity_log_is_scoped_per_tenant(client):
    admin_token = await _admin_token(client)
    tenant_a = await _create_tenant(client, admin_token, name="Tenant A")
    tenant_b = await _create_tenant(client, admin_token, name="Tenant B")

    await client.post(f"/api/tenants/{tenant_a['id']}/demo/simulate-attack", headers=_auth(admin_token))

    async def has_activity(tenant_id):
        resp = await client.get(f"/api/tenants/{tenant_id}/activity", headers=_auth(admin_token))
        data = resp.json()
        return data if data else None

    activity_a = await _wait_until(lambda: has_activity(tenant_a["id"]))
    assert all(entry["tenant_id"] == tenant_a["id"] for entry in activity_a)

    r = await client.get(f"/api/tenants/{tenant_b['id']}/activity", headers=_auth(admin_token))
    assert r.json() == []  # tenant B never had anything happen to it


async def test_platform_audit_is_admin_only(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    holder_email = f"holder-{uuid.uuid4().hex[:8]}@example.com"
    await client.post(
        "/api/auth/security-holders",
        json={"email": holder_email, "password": "HolderPass123!", "full_name": "Holder", "tenant_id": tenant["id"]},
        headers=_auth(admin_token),
    )
    holder_token = await _login(client, holder_email, "HolderPass123!")

    r = await client.get("/api/admin/platform-audit", headers=_auth(holder_token))
    assert r.status_code == 403

    r = await client.get("/api/admin/platform-audit", headers=_auth(admin_token))
    assert r.status_code == 200


async def test_exposure_scan_produces_a_finding_incident(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    # A domain that resolves nowhere real — the scanner should handle the
    # connection failure gracefully rather than raising, and still produce
    # a (low-severity, "unreachable") incident recording that outcome.
    unreachable_domain = f"{uuid.uuid4().hex}.invalid"
    r = await client.post(
        f"/api/tenants/{tenant['id']}/exposure-scan", params={"domain": unreachable_domain}, headers=_auth(admin_token)
    )
    assert r.status_code == 200

    async def has_incident():
        resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
        data = resp.json()
        return data if data else None

    incidents = await _wait_until(has_incident)
    assert unreachable_domain in incidents[0]["title"]


@pytest.mark.parametrize("bad_ip", ["not-an-ip", "203.0.113.1; DROP TABLE users;--"])
async def test_ingest_rejects_malformed_events_gracefully(client, bad_ip):
    """Not a security boundary test of SQL injection (SQLAlchemy's
    parameterized queries already prevent that structurally) — this
    confirms a malformed/hostile-looking payload in event data doesn't
    crash the ingestion pipeline or produce a 500."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "test", "event_type": "login_failed", "data": {"src_ip": bad_ip}},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200


async def test_connector_token_authenticates_ingest_without_a_human_jwt(client):
    """The whole point of connector tokens: a real forwarder (Wazuh, etc.)
    authenticates with its own secret, never a human's session token."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    r = await client.post(
        f"/api/tenants/{tenant['id']}/connectors",
        json={"connector_type": "wazuh", "display_name": "Prod Wazuh"},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200, r.text
    connector = r.json()
    assert connector["token"].startswith("smac_")
    assert connector["has_token"] is True

    # The token alone authenticates — no human Authorization at all otherwise.
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "wazuh", "event_type": "login_failed", "data": {"src_ip": "198.51.100.23"}},
        headers={"Authorization": f"Bearer {connector['token']}"},
    )
    assert r.status_code == 200, r.text

    # The connector's health (last_event_at) reflects that push.
    async def connector_seen():
        resp = await client.get(f"/api/tenants/{tenant['id']}/connectors", headers=_auth(admin_token))
        matching = [c for c in resp.json() if c["id"] == connector["id"]]
        return matching[0] if matching and matching[0]["last_event_at"] else None

    seen = await _wait_until(connector_seen)
    assert seen["last_event_at"] is not None

    # A garbage token is rejected outright.
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "wazuh", "event_type": "login_failed", "data": {}},
        headers={"Authorization": "Bearer smac_totally-fake"},
    )
    assert r.status_code == 401

    # Rotating the token invalidates the old one immediately.
    r = await client.post(
        f"/api/tenants/{tenant['id']}/connectors/{connector['id']}/rotate-token", headers=_auth(admin_token)
    )
    assert r.status_code == 200
    new_token = r.json()["token"]
    assert new_token != connector["token"]

    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "wazuh", "event_type": "login_failed", "data": {}},
        headers={"Authorization": f"Bearer {connector['token']}"},  # the OLD token
    )
    assert r.status_code == 401

    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "wazuh", "event_type": "login_failed", "data": {}},
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert r.status_code == 200


async def test_demo_attack_updates_the_demo_connectors_health(client):
    """Regression test for a real bug: simulate-attack and the generic
    ingest route never attached connector_id to the events they published,
    so Overview's "Coverage health" panel showed every connector as having
    no events, forever, even right after a successful simulated attack."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    r = await client.get(f"/api/tenants/{tenant['id']}/connectors", headers=_auth(admin_token))
    demo_connector = next(c for c in r.json() if c["connector_type"] == "synthetic_demo")
    assert demo_connector["last_event_at"] is None

    await client.post(f"/api/tenants/{tenant['id']}/demo/simulate-attack", headers=_auth(admin_token))

    async def demo_connector_seen():
        resp = await client.get(f"/api/tenants/{tenant['id']}/connectors", headers=_auth(admin_token))
        c = next(x for x in resp.json() if x["connector_type"] == "synthetic_demo")
        return c if c["last_event_at"] else None

    seen = await _wait_until(demo_connector_seen)
    assert seen["last_event_at"] is not None
