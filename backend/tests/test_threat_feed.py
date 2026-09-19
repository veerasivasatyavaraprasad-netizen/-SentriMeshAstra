from app.connectors import threat_feed


class _FakeSettings:
    abuseipdb_api_key = "fake-key-for-test"


async def test_lookup_ip_uses_abuseipdb_when_key_configured(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettings())

    async def fake_abuseipdb_lookup(ip, api_key):
        assert api_key == "fake-key-for-test"
        return {"verdict": "malicious", "score": 97, "tags": ["abuseipdb"], "source": "abuseipdb"}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", fake_abuseipdb_lookup)

    result = await threat_feed.lookup_ip("1.2.3.4")
    assert result["source"] == "abuseipdb"
    assert result["verdict"] == "malicious"


async def test_lookup_ip_falls_back_to_local_list_when_abuseipdb_fails(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _FakeSettings())

    async def failing_abuseipdb_lookup(ip, api_key):
        return None  # simulates a timeout/non-200/parse failure

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", failing_abuseipdb_lookup)

    result = await threat_feed.lookup_ip("198.51.100.23")
    assert result["source"] == "local-demo"
    assert result["verdict"] == "malicious"
