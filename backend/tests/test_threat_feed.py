from app.connectors import threat_feed


class _FakeSettings:
    abuseipdb_api_key = "fake-key-for-test"


class _NoKeySettings:
    abuseipdb_api_key = None


async def test_lookup_ip_uses_abuseipdb_when_key_configured(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettings())

    async def fake_abuseipdb_lookup(ip, api_key):
        assert api_key == "fake-key-for-test"
        return {"verdict": "malicious", "score": 97, "tags": ["abuseipdb"], "source": "abuseipdb"}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", fake_abuseipdb_lookup)

    result = await threat_feed.lookup_ip("1.2.3.4")
    assert result["source"] == "abuseipdb"
    assert result["verdict"] == "malicious"


async def test_lookup_ip_reports_unknown_not_fabricated_when_abuseipdb_fails(monkeypatch):
    """No local blocklist to fall back to — a failed real lookup means
    'unknown', never a guessed verdict standing in for real data."""
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettings())

    async def failing_abuseipdb_lookup(ip, api_key):
        return None  # simulates a timeout/non-200/parse failure

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", failing_abuseipdb_lookup)

    result = await threat_feed.lookup_ip("203.0.113.77")
    assert result["verdict"] == "unknown"
    assert result["source"] == "none"


async def test_lookup_ip_reports_unknown_when_no_api_key_configured(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _NoKeySettings())
    result = await threat_feed.lookup_ip("203.0.113.77")
    assert result["verdict"] == "unknown"
    assert result["tags"] == ["no-abuseipdb-key-configured"]


async def test_lookup_ip_never_calls_abuseipdb_for_rfc1918_addresses(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettings())

    async def fail_if_called(ip, api_key):
        raise AssertionError("internal-network IPs must never be sent to a public reputation API")

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", fail_if_called)

    result = await threat_feed.lookup_ip("10.0.0.5")
    assert result["verdict"] == "clean"
    assert result["source"] == "rfc1918"


async def test_lookup_ip_does_treat_rfc5737_test_ranges_as_internal(monkeypatch):
    """Regression test: Python's ipaddress.is_private also flags RFC 5737
    documentation/test ranges (used throughout this codebase's own tests
    as stand-in public IPs) as private. That would silently short-circuit
    every real-looking test IP before it ever reached AbuseIPDB — this
    locks in that lookup_ip does NOT use the overly broad is_private."""
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettings())
    called = {}

    async def record_call(ip, api_key):
        called["ip"] = ip
        return {"verdict": "malicious", "score": 90, "tags": [], "source": "abuseipdb"}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", record_call)

    for test_net_ip in ("192.0.2.1", "198.51.100.23", "203.0.113.77"):
        called.clear()
        result = await threat_feed.lookup_ip(test_net_ip)
        assert called.get("ip") == test_net_ip, f"{test_net_ip} never reached AbuseIPDB"
        assert result["verdict"] == "malicious"
