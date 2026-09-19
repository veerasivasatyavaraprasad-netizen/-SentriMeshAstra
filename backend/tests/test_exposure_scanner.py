"""Tests app/connectors/exposure_scanner.py: the real HTTPS/header check
(scan_domain) against a real local HTTPS-shaped server response, and the
real SerpAPI OSINT step (search_public_exposure) against a response
shaped like SerpAPI's own documented JSON."""
import httpx

from app.connectors.exposure_scanner import scan_domain, search_public_exposure


def _patch_httpx_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def fake_client(**kwargs):
        kwargs.pop("transport", None)
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)


async def test_scan_domain_flags_missing_security_headers(monkeypatch):
    def handler(request):
        return httpx.Response(200, headers={"server": "nginx/1.18.0"})

    _patch_httpx_client(monkeypatch, handler)
    report = await scan_domain("example.com")
    assert report.reachable is True
    warnings = [f for f in report.findings if f.status == "warning"]
    assert any("strict-transport-security" in f.check for f in warnings)
    assert any("nginx/1.18.0" in f.detail for f in report.findings)


async def test_scan_domain_reports_all_headers_present_as_ok(monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=63072000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
            },
        )

    _patch_httpx_client(monkeypatch, handler)
    report = await scan_domain("example.com")
    assert all(f.status == "ok" for f in report.findings if f.check.startswith("header:"))


async def test_scan_domain_reports_unreachable_honestly(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")

    _patch_httpx_client(monkeypatch, handler)
    report = await scan_domain("unreachable.example.com")
    assert report.reachable is False
    assert report.findings[0].status == "warning"


async def test_search_public_exposure_flags_indexed_findings(monkeypatch):
    def handler(request):
        assert request.url.host == "serpapi.com"
        assert "site:example.com" in request.url.params.get("q")
        return httpx.Response(
            200,
            json={
                "organic_results": [
                    {"title": "Index of /backups", "link": "http://example.com/backups/", "snippet": ".env  .sql"}
                ]
            },
        )

    _patch_httpx_client(monkeypatch, handler)
    findings = await search_public_exposure("example.com", "fake-serpapi-key")
    assert len(findings) == 1
    assert findings[0].status == "warning"
    assert "example.com/backups" in findings[0].detail


async def test_search_public_exposure_reports_ok_when_nothing_indexed(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"organic_results": []})

    _patch_httpx_client(monkeypatch, handler)
    findings = await search_public_exposure("example.com", "fake-serpapi-key")
    assert len(findings) == 1
    assert findings[0].status == "ok"


async def test_search_public_exposure_degrades_to_no_findings_on_failure(monkeypatch):
    def handler(request):
        return httpx.Response(401)

    _patch_httpx_client(monkeypatch, handler)
    findings = await search_public_exposure("example.com", "bad-key")
    assert findings == []
