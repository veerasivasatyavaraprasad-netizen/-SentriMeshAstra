from app.connectors import threat_feed


class _Settings:
    def __init__(self, **keys):
        self.abuseipdb_api_key = keys.get("abuseipdb")
        self.virustotal_api_key = keys.get("virustotal")
        self.otx_api_key = keys.get("otx")
        self.greynoise_api_key = keys.get("greynoise")
        self.shodan_api_key = keys.get("shodan")
        self.abusech_auth_key = keys.get("threatfox")


async def test_lookup_ip_uses_abuseipdb_when_only_it_is_configured(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings(abuseipdb="fake-key"))

    async def fake_abuseipdb_lookup(ip, api_key):
        assert api_key == "fake-key"
        return {"verdict": "malicious", "detail": "AbuseIPDB confidence 97/100", "raw": {"score": 97, "total_reports": 12}}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", fake_abuseipdb_lookup)

    result = await threat_feed.lookup_ip("1.2.3.4")
    assert result["verdict"] == "malicious"
    assert result["source"] == "abuseipdb"
    assert result["score"] == 97
    assert result["sources"]["abuseipdb"]["verdict"] == "malicious"


async def test_lookup_ip_reports_unknown_when_every_configured_source_fails(monkeypatch):
    """No local blocklist to fall back to — every source failing means
    'unknown', never a guessed verdict standing in for real data."""
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings(abuseipdb="fake-key", shodan="fake-key"))

    async def failing_lookup(ip, api_key):
        return None  # simulates a timeout/non-200/parse failure

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", failing_lookup)
    monkeypatch.setattr(threat_feed, "_shodan_lookup", failing_lookup)

    result = await threat_feed.lookup_ip("203.0.113.77")
    assert result["verdict"] == "unknown"
    assert result["sources"] == {}


async def test_lookup_ip_reports_unknown_when_no_source_configured(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings())
    result = await threat_feed.lookup_ip("203.0.113.77")
    assert result["verdict"] == "unknown"
    assert result["tags"] == ["no-source-configured"]


async def test_lookup_ip_never_calls_any_source_for_rfc1918_addresses(monkeypatch):
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings(abuseipdb="fake-key"))

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
    every real-looking test IP before it ever reached a real source — this
    locks in that lookup_ip does NOT use the overly broad is_private."""
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings(abuseipdb="fake-key"))
    called = {}

    async def record_call(ip, api_key):
        called["ip"] = ip
        return {"verdict": "malicious", "detail": "test", "raw": {"score": 90, "total_reports": 1}}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", record_call)

    for test_net_ip in ("192.0.2.1", "198.51.100.23", "203.0.113.77"):
        called.clear()
        result = await threat_feed.lookup_ip(test_net_ip)
        assert called.get("ip") == test_net_ip, f"{test_net_ip} never reached the source"
        assert result["verdict"] == "malicious"


async def test_lookup_ip_aggregates_multiple_sources_malicious_wins(monkeypatch):
    """A confirmed malware C2 match from one source outweighs a 'clean'
    from another — malicious is never averaged away."""
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings(abuseipdb="k1", threatfox="k2"))

    async def clean_abuseipdb(ip, api_key):
        return {"verdict": "clean", "detail": "AbuseIPDB confidence 0/100", "raw": {"score": 0, "total_reports": 0}}

    async def malicious_threatfox(ip, api_key):
        return {"verdict": "malicious", "detail": "ThreatFox: confirmed IOC match (Emotet)", "raw": {"malware": ["Emotet"], "match_count": 1}}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", clean_abuseipdb)
    monkeypatch.setattr(threat_feed, "_threatfox_lookup", malicious_threatfox)

    result = await threat_feed.lookup_ip("198.51.100.5")
    assert result["verdict"] == "malicious"
    assert "abuseipdb" in result["sources"]
    assert "threatfox" in result["sources"]
    assert result["sources"]["threatfox"]["verdict"] == "malicious"


async def test_lookup_ip_partial_source_failure_still_uses_the_reachable_one(monkeypatch):
    """One configured source timing out must not blank out a real verdict
    a different configured source did return."""
    monkeypatch.setattr(threat_feed, "get_settings", lambda: _Settings(abuseipdb="k1", virustotal="k2"))

    async def failing(ip, api_key):
        return None

    async def real_result(ip, api_key):
        return {"verdict": "suspicious", "detail": "VirusTotal 1 malicious / 0 suspicious engine(s)", "raw": {"malicious": 1, "suspicious": 0}}

    monkeypatch.setattr(threat_feed, "_abuseipdb_lookup", failing)
    monkeypatch.setattr(threat_feed, "_virustotal_lookup", real_result)

    result = await threat_feed.lookup_ip("198.51.100.6")
    assert result["verdict"] == "suspicious"
    assert "abuseipdb" not in result["sources"]
    assert "virustotal" in result["sources"]


def _patch_httpx_client(monkeypatch, handler):
    """Swaps httpx.AsyncClient for one wired to a MockTransport, so a real
    httpx client parses a real (canned) HTTP response — proving the
    connector's own parsing logic — without any real network call."""
    import httpx

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def fake_client(**kwargs):
        kwargs.pop("transport", None)
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)


async def test_virustotal_verdict_requires_at_least_two_engines_for_malicious(monkeypatch):
    """A lone flagged engine out of ~90 is noise; VirusTotal's own UI
    treats that distinction as meaningful, and so do we."""
    import httpx

    def handler(request):
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}})

    _patch_httpx_client(monkeypatch, handler)
    result = await threat_feed._virustotal_lookup("1.2.3.4", "fake-key")
    assert result["verdict"] == "suspicious"


async def test_greynoise_riot_service_reports_clean_even_if_classification_missing(monkeypatch):
    import httpx

    def handler(request):
        return httpx.Response(200, json={"riot": True, "noise": False, "name": "Google Public DNS"})

    _patch_httpx_client(monkeypatch, handler)
    result = await threat_feed._greynoise_lookup("8.8.8.8", "fake-key")
    assert result["verdict"] == "clean"
    assert "RIOT" in result["detail"]


async def test_shodan_never_reports_malicious_only_suspicious_when_vulns_present(monkeypatch):
    import httpx

    def handler(request):
        return httpx.Response(200, json={"ports": [22, 443], "vulns": ["CVE-2021-44228"]})

    _patch_httpx_client(monkeypatch, handler)
    result = await threat_feed._shodan_lookup("1.2.3.4", "fake-key")
    assert result["verdict"] == "suspicious"
    assert "CVE-2021-44228" in result["raw"]["vulns"]


async def test_threatfox_reports_malware_family_on_confirmed_match(monkeypatch):
    import httpx

    def handler(request):
        return httpx.Response(200, json={"query_status": "ok", "data": [{"malware_printable": "Emotet"}]})

    _patch_httpx_client(monkeypatch, handler)
    result = await threat_feed._threatfox_lookup("1.2.3.4", "fake-key")
    assert result["verdict"] == "malicious"
    assert "Emotet" in result["detail"]


async def test_threatfox_no_result_is_clean_not_unknown(monkeypatch):
    import httpx

    def handler(request):
        return httpx.Response(200, json={"query_status": "no_result"})

    _patch_httpx_client(monkeypatch, handler)
    result = await threat_feed._threatfox_lookup("1.2.3.4", "fake-key")
    assert result["verdict"] == "clean"


async def test_otx_pulse_count_thresholds(monkeypatch):
    import httpx

    def handler(request):
        return httpx.Response(200, json={"pulse_info": {"count": 3}})

    _patch_httpx_client(monkeypatch, handler)
    result = await threat_feed._otx_lookup("1.2.3.4", "fake-key")
    assert result["verdict"] == "malicious"
