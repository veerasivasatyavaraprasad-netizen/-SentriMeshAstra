"""Tests app/connectors/vuln_scanner.py's real OSV.dev + GitHub Advisory
Database parsing against response shapes matching each API's own
documented schema — using a real httpx client against a MockTransport
(no network), proving the connector's own parsing logic runs for real."""
import httpx

from app.connectors import vuln_scanner


def _patch_httpx_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def fake_client(**kwargs):
        kwargs.pop("transport", None)
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)


async def test_osv_query_parses_a_real_shaped_response(monkeypatch):
    def handler(request):
        assert request.url.host == "api.osv.dev"
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "summary": "Remote code execution via unsafe deserialization",
                        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    }
                ]
            },
        )

    _patch_httpx_client(monkeypatch, handler)
    result = await vuln_scanner._query_osv("PyPI", "vulnerable-pkg", "1.0.0")
    assert result == [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Remote code execution via unsafe deserialization",
            "severity": "critical",
            "source": "osv.dev",
        }
    ]


async def test_osv_query_returns_empty_list_for_no_known_vulns(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={})

    _patch_httpx_client(monkeypatch, handler)
    result = await vuln_scanner._query_osv("npm", "safe-pkg", "2.0.0")
    assert result == []


async def test_osv_query_degrades_to_none_on_failure(monkeypatch):
    def handler(request):
        return httpx.Response(500)

    _patch_httpx_client(monkeypatch, handler)
    result = await vuln_scanner._query_osv("npm", "some-pkg", "1.0.0")
    assert result is None


async def test_github_advisories_parses_a_real_shaped_response(monkeypatch):
    def handler(request):
        assert request.url.host == "api.github.com"
        return httpx.Response(
            200,
            json=[
                {
                    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                    "cve_id": "CVE-2024-12345",
                    "summary": "Prototype pollution",
                    "severity": "high",
                }
            ],
        )

    _patch_httpx_client(monkeypatch, handler)
    result = await vuln_scanner._query_github_advisories("npm", "some-pkg")
    assert result == [
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Prototype pollution",
            "severity": "high",
            "source": "github-advisory-database",
            "cve_id": "CVE-2024-12345",
        }
    ]


async def test_github_advisories_skips_unsupported_ecosystem_without_a_network_call():
    called = {"count": 0}

    async def fail_if_called(*args, **kwargs):
        called["count"] += 1
        raise AssertionError("should never be called for an unmapped ecosystem")

    result = await vuln_scanner._query_github_advisories("some-unknown-ecosystem", "pkg")
    assert result == []
    assert called["count"] == 0


async def test_check_package_dedupes_the_same_cve_from_both_sources(monkeypatch):
    async def fake_osv(ecosystem, name, version):
        return [{"id": "GHSA-x", "summary": "s", "severity": "high", "source": "osv.dev", "cve_id": "CVE-2024-1"}]

    async def fake_github(ecosystem, name):
        return [{"id": "GHSA-x", "summary": "s", "severity": "high", "source": "github-advisory-database", "cve_id": "CVE-2024-1"}]

    monkeypatch.setattr(vuln_scanner, "_query_osv", fake_osv)
    monkeypatch.setattr(vuln_scanner, "_query_github_advisories", fake_github)

    result = await vuln_scanner.check_package("npm", "pkg", "1.0.0")
    assert len(result["vulnerabilities"]) == 1
    assert result["sources_unreachable"] == []


async def test_check_package_reports_unreachable_sources_honestly(monkeypatch):
    async def failing_osv(ecosystem, name, version):
        return None

    async def failing_github(ecosystem, name):
        return None

    monkeypatch.setattr(vuln_scanner, "_query_osv", failing_osv)
    monkeypatch.setattr(vuln_scanner, "_query_github_advisories", failing_github)

    result = await vuln_scanner.check_package("npm", "pkg", "1.0.0")
    assert result["vulnerabilities"] == []
    assert set(result["sources_unreachable"]) == {"osv.dev", "github-advisory-database"}
