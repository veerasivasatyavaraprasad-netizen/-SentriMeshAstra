"""End-to-end tests against the real FastAPI app (real Alembic migrations,
real Postgres, real Redis-backed agent bus, all 8 agents actually running)
via the `client` fixture in conftest.py — not mocks, not curl scripts run
by hand. This is what previously only got exercised manually during
development; codifying it here means a regression gets caught by `pytest`
instead of by someone noticing the dashboard looks wrong.

There is no synthetic/demo data path in the app itself — every event here
goes in through a real connector token via POST .../ingest, exactly as a
real log forwarder would. The one thing tests mock is the third-party
AbuseIPDB HTTP call (app.connectors.threat_feed._abuseipdb_lookup) so the
suite doesn't depend on network access or a committed real API key —
that's a test-boundary mock of an external vendor API, not fabricated
data inside the product.
"""
import asyncio
import os
import uuid

import pytest

from app.connectors import threat_feed

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


async def _create_connector(client, admin_token, tenant_id, connector_type="generic"):
    r = await client.post(
        f"/api/tenants/{tenant_id}/connectors",
        json={"connector_type": connector_type, "display_name": connector_type},
        headers=_auth(admin_token),
    )
    assert r.status_code == 200, r.text
    return r.json()  # includes ["token"], shown once, exactly as the console would show it


async def _push_bruteforce(client, tenant_id, connector_token, ip="198.51.100.23", user="root"):
    """Pushes the same real event shape a real log forwarder would send —
    through the real connector-token-authenticated ingest endpoint — to
    drive the detection -> enrichment -> classification -> response
    pipeline. IANA reserves 198.51.100.0/24 (TEST-NET-2) for exactly this:
    documentation and testing, never a real host."""
    headers = {"Authorization": f"Bearer {connector_token}"}
    for _ in range(6):
        r = await client.post(
            f"/api/tenants/{tenant_id}/ingest",
            json={"source": "test", "event_type": "login_failed", "data": {"src_ip": ip, "user": user}},
            headers=headers,
        )
        assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/tenants/{tenant_id}/ingest",
        json={"source": "test", "event_type": "login_success", "data": {"src_ip": ip, "user": user}},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.fixture
def mock_abuseipdb_malicious(monkeypatch):
    """Stands in for the real AbuseIPDB HTTP call so tests don't depend on
    network access or a committed real API key. Everything downstream of
    this (severity scoring, the block_ip recommendation, the approval it
    creates) is the app's real, unmocked logic reacting to this one
    external-vendor response. Also fakes a configured API key — otherwise
    lookup_ip short-circuits at "no key configured" before ever reaching
    the mocked call, same as it would in a real unconfigured deployment."""

    class _FakeSettingsWithKey:
        abuseipdb_api_key = "test-fake-key-mocked-below"

    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettingsWithKey())

    async def fake_lookup(ip, api_key):
        return {"verdict": "malicious", "score": 92, "tags": ["credential-stuffing"], "source": "abuseipdb"}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", fake_lookup)


async def _wait_until(predicate, *, timeout=6.0, interval=0.2):
    """Poll `predicate` (an async callable returning truthy/falsy) until
    it's truthy or the timeout elapses. Used instead of a flat sleep to
    wait for the async detection -> enrichment -> classification ->
    response pipeline to finish reacting to a real ingested event."""
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


async def test_responses_carry_standard_security_headers(client):
    r = await client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "same-origin"


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


async def test_a_new_tenant_has_no_connectors_and_no_data(client):
    """There is no demo/synthetic feed anymore — a freshly onboarded
    company starts completely empty until a real connector is added."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    r = await client.get(f"/api/tenants/{tenant['id']}/connectors", headers=_auth(admin_token))
    assert r.json() == []

    r = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
    assert r.json() == []

    r = await client.get(f"/api/tenants/{tenant['id']}/overview", headers=_auth(admin_token))
    overview = r.json()
    assert overview["open_incidents"] == 0
    assert overview["connector_health"] == []


async def test_ingest_without_any_connector_token_is_rejected(client):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    # No Authorization header at all.
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "test", "event_type": "login_failed", "data": {"src_ip": "198.51.100.23"}},
    )
    assert r.status_code == 401

    # A human's own JWT doesn't work either — only a connector token does.
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "test", "event_type": "login_failed", "data": {}},
        headers=_auth(admin_token),
    )
    assert r.status_code == 401


async def test_full_attack_pipeline_reaches_a_pending_approval(client, mock_abuseipdb_malicious):
    # "generic" connector type: _push_bruteforce sends the flat
    # {"src_ip": ..., "user": ...} shape, which the generic normalizer
    # understands. A "wazuh"-typed connector expects real nested Wazuh
    # alert JSON instead — see test_log_formats.py and
    # test_wazuh_connector_pipeline_uses_real_alert_shape below for that.
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"])

    await _push_bruteforce(client, tenant["id"], connector["token"])

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
    assert incident["enrichment"]["ip_reputation"]["198.51.100.23"]["source"] == "abuseipdb"

    async def approval_exists():
        resp = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
        data = resp.json()
        return data if data else None

    approvals = await _wait_until(approval_exists)
    assert len(approvals) == 1
    assert approvals[0]["status"] == "pending"
    assert approvals[0]["action"]["action_type"] == "block_ip"
    assert approvals[0]["action"]["tier"] == "tier2_one_tap"


async def test_without_a_real_threat_intel_key_brute_force_only_notifies(client):
    """No AbuseIPDB key is configured for this test run (no
    mock_abuseipdb_malicious fixture here) — enrichment honestly reports
    'unknown', so the Orchestrator can't confirm malicious intent and the
    Response agent only notifies (tier-1, auto) rather than proposing a
    block. This is the real, honest behavior without a real threat-intel
    source connected — not a gap papered over by fake data."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"])

    await _push_bruteforce(client, tenant["id"], connector["token"], ip="203.0.113.44")

    async def incident_fully_classified():
        resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
        data = resp.json()
        if data and data[0]["severity"] != "low":
            return data
        return None

    incidents = await _wait_until(incident_fully_classified)
    assert incidents[0]["enrichment"]["ip_reputation"]["203.0.113.44"]["verdict"] == "unknown"

    # No block_ip proposal, and definitely nothing waiting on approval,
    # since "notify" is a tier-1 action that runs immediately.
    r = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
    assert r.json() == []


async def test_approve_action_executes_as_dry_run_and_can_be_rolled_back(client, mock_abuseipdb_malicious):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"])
    await _push_bruteforce(client, tenant["id"], connector["token"])

    async def get_pending():
        resp = await client.get(f"/api/tenants/{tenant['id']}/approvals", headers=_auth(admin_token))
        data = [a for a in resp.json() if a["status"] == "pending"]
        return data if data else None

    approval = (await _wait_until(get_pending))[0]

    r = await client.post(
        f"/api/tenants/{tenant['id']}/approvals/{approval['id']}/decide",
        json={"approve": True, "note": "confirmed malicious"},
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


async def test_reject_action_leaves_it_unexecuted(client, mock_abuseipdb_malicious):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"])
    await _push_bruteforce(client, tenant["id"], connector["token"])

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


async def test_kill_switch_blocks_execution_even_after_approval(client, mock_abuseipdb_malicious):
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    r = await client.post(
        f"/api/tenants/{tenant['id']}/kill-switch", json={"engaged": True, "reason": "test"}, headers=_auth(admin_token)
    )
    assert r.status_code == 200
    assert r.json()["kill_switch_engaged"] is True

    connector = await _create_connector(client, admin_token, tenant["id"])
    await _push_bruteforce(client, tenant["id"], connector["token"])

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


async def test_activity_log_is_scoped_per_tenant(client, mock_abuseipdb_malicious):
    admin_token = await _admin_token(client)
    tenant_a = await _create_tenant(client, admin_token, name="Tenant A")
    tenant_b = await _create_tenant(client, admin_token, name="Tenant B")
    connector_a = await _create_connector(client, admin_token, tenant_a["id"])

    await _push_bruteforce(client, tenant_a["id"], connector_a["token"])

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
    connector = await _create_connector(client, admin_token, tenant["id"])
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={"source": "test", "event_type": "login_failed", "data": {"src_ip": bad_ip}},
        headers={"Authorization": f"Bearer {connector['token']}"},
    )
    assert r.status_code == 200


async def test_connector_token_lifecycle_and_health_tracking(client):
    """The whole point of connector tokens: a real forwarder (Wazuh, etc.)
    authenticates with its own secret, never a human's session token — and
    a leaked one is remediated by rotation, not by deleting the connector."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)

    connector = await _create_connector(client, admin_token, tenant["id"], "wazuh")
    assert connector["token"].startswith("smac_")
    assert connector["has_token"] is True
    assert connector["last_event_at"] is None

    # The token alone authenticates — no human Authorization at all otherwise.
    # Real nested Wazuh alert shape, since this connector is registered as
    # connector_type "wazuh" and gets parsed by normalize_wazuh().
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json={
            "source": "wazuh",
            "data": {
                "rule": {"level": 10, "description": "Multiple authentication failures.", "id": "5710", "groups": ["authentication_failed"]},
                "data": {"srcip": "198.51.100.23", "srcuser": "root"},
            },
        },
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


async def test_wazuh_connector_pipeline_uses_real_alert_shape_and_its_own_mitre_data(client):
    """End-to-end proof that a connector registered as connector_type
    "wazuh" gets parsed by the real Wazuh alert format (nested rule/data,
    including rule.mitre) — not the generic flat-field guesser — and that
    the resulting incident carries Wazuh's OWN real MITRE ATT&CK
    classification rather than our own technique_key heuristic guess."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"], "wazuh")
    headers = {"Authorization": f"Bearer {connector['token']}"}

    def wazuh_alert(rule_id: str, level: int, description: str, groups: list[str], mitre_id=None, mitre_technique=None, srcuser="root"):
        rule = {"id": rule_id, "level": level, "description": description, "groups": groups}
        if mitre_id:
            rule["mitre"] = {"id": [mitre_id], "technique": [mitre_technique]}
        return {"source": "wazuh", "data": {"rule": rule, "data": {"srcip": "198.51.100.77", "srcuser": srcuser}}}

    for _ in range(6):
        r = await client.post(
            f"/api/tenants/{tenant['id']}/ingest",
            json=wazuh_alert("5710", 10, "Multiple authentication failures.", ["authentication_failed"], "T1110", "Brute Force"),
            headers=headers,
        )
        assert r.status_code == 200
    r = await client.post(
        f"/api/tenants/{tenant['id']}/ingest",
        json=wazuh_alert("5715", 3, "sshd authentication success.", ["authentication_success"], "T1110", "Brute Force"),
        headers=headers,
    )
    assert r.status_code == 200

    async def incident_with_real_mitre_data():
        resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
        data = resp.json()
        if data and data[0]["mitre_techniques"]:
            return data
        return None

    incidents = await _wait_until(incident_with_real_mitre_data)
    assert len(incidents) == 1
    # Wazuh's own classification, verbatim — not our MITRE_MAP guess.
    assert incidents[0]["mitre_techniques"] == ["T1110 - Brute Force"]


async def test_wazuh_malware_alert_opens_incident_with_real_rule_description(client):
    """End-to-end proof that a real Wazuh rootcheck/malware alert (not a
    login event) is classified as malware_detected and opens an incident
    whose description is Wazuh's own rule.description — through the real
    ingest -> Integration -> Detection pipeline, no mocking."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"], "wazuh")
    headers = {"Authorization": f"Bearer {connector['token']}"}

    alert = {
        "source": "wazuh",
        "data": {
            "rule": {
                "id": "510",
                "level": 7,
                "description": "Rootcheck: Trojaned version of file '/usr/bin/find' detected.",
                "groups": ["rootcheck"],
            },
            "agent": {"id": "001", "name": "db-server-01"},
            "data": {"srcip": "198.51.100.88"},
        },
    }
    r = await client.post(f"/api/tenants/{tenant['id']}/ingest", json=alert, headers=headers)
    assert r.status_code == 200

    async def malware_incident():
        resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
        matches = [i for i in resp.json() if "Malware" in i["title"] and i["severity"] != "low"]
        return matches if matches else None

    incidents = await _wait_until(malware_incident)
    assert len(incidents) == 1
    incident = incidents[0]
    assert "198.51.100.88" in incident["title"]
    assert incident["description"] == "Rootcheck: Trojaned version of file '/usr/bin/find' detected."
    assert incident["enrichment"]["context"]["technique_key"] == "malware_signature"
    # A confirmed malware signature is direct evidence of compromise on
    # its own — never silently left at "low".
    assert incident["severity"] == "medium"


def _azure_sign_in(user: str, ip: str, country: str, city: str = "City"):
    return {
        "source": "azure_ad",
        "data": {
            "userPrincipalName": user,
            "ipAddress": ip,
            "status": {"errorCode": 0},
            "location": {"city": city, "countryOrRegion": country},
            "appDisplayName": "Office 365",
        },
    }


async def test_impossible_travel_detected_from_real_azure_ad_sign_ins(client):
    """End-to-end: two real Azure-AD-shaped sign-ins for the same user,
    from countries an ocean apart, minutes apart — through the real
    ingest -> Detection -> Orchestrator pipeline, no mocking of the
    detection logic itself (only AbuseIPDB, which impossible-travel
    doesn't even use — Azure AD supplies the country directly)."""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"], "azure_ad")
    headers = {"Authorization": f"Bearer {connector['token']}"}

    user = f"alice-{uuid.uuid4().hex[:6]}@contoso.com"
    r = await client.post(f"/api/tenants/{tenant['id']}/ingest", json=_azure_sign_in(user, "203.0.113.1", "US", "Seattle"), headers=headers)
    assert r.status_code == 200

    # Give Detection's async handler chain time to actually store the
    # first sign-in as the user's location baseline (app/geo.py /
    # set_last_value) before the second sign-in arrives to compare
    # against it — polling the activity log isn't a reliable enough
    # signal for this specific step, since the raw-event audit entry
    # exists as soon as the POST returns, well before that.
    await asyncio.sleep(1.0)

    r = await client.post(f"/api/tenants/{tenant['id']}/ingest", json=_azure_sign_in(user, "203.0.113.2", "RU", "Moscow"), headers=headers)
    assert r.status_code == 200

    async def impossible_travel_incident():
        # Wait for classification (severity != "low"), not just for the
        # row to exist — Detection opens it at the default severity,
        # before Orchestrator's async classification hop has run.
        resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
        matches = [i for i in resp.json() if "Impossible travel" in i["title"] and i["severity"] != "low"]
        return matches if matches else None

    incidents = await _wait_until(impossible_travel_incident)
    assert len(incidents) == 1
    incident = incidents[0]
    assert "T1078" in incident["mitre_techniques"][0]
    assert incident["severity"] in ("high", "critical")
    assert incident["enrichment"]["context"]["from_country"] == "US"
    assert incident["enrichment"]["context"]["to_country"] == "RU"
    assert incident["enrichment"]["context"]["implied_speed_kmh"] > 1000


async def test_impossible_travel_not_flagged_for_repeat_sign_ins_from_the_same_country(client):
    """The false-positive check that's actually achievable in a fast test:
    two sign-ins from the *same* country, seconds apart (completely
    normal — someone signing in twice), must never trigger this,
    regardless of how little time separates them. (A genuinely
    plausible-vs-impossible *cross-country* comparison is a physics
    question already covered directly in tests/test_geo.py — two API
    calls in a test necessarily land seconds apart, and real intercontinental
    distances in mere seconds are correctly flagged, not a false positive.)"""
    admin_token = await _admin_token(client)
    tenant = await _create_tenant(client, admin_token)
    connector = await _create_connector(client, admin_token, tenant["id"], "azure_ad")
    headers = {"Authorization": f"Bearer {connector['token']}"}

    user = f"bob-{uuid.uuid4().hex[:6]}@contoso.com"
    r = await client.post(f"/api/tenants/{tenant['id']}/ingest", json=_azure_sign_in(user, "203.0.113.3", "US", "Seattle"), headers=headers)
    assert r.status_code == 200

    await asyncio.sleep(1.0)  # let the first sign-in's baseline actually get stored first

    r = await client.post(f"/api/tenants/{tenant['id']}/ingest", json=_azure_sign_in(user, "203.0.113.4", "US", "Portland"), headers=headers)
    assert r.status_code == 200
    await asyncio.sleep(1.5)  # give the pipeline a moment; nothing should appear

    resp = await client.get(f"/api/tenants/{tenant['id']}/incidents", headers=_auth(admin_token))
    assert all("Impossible travel" not in i["title"] for i in resp.json())
