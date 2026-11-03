
from urllib.parse import urlparse

import httpx
import pytest

import app.services.analysis_orchestrator as orchestrator_module


class DummyAnalyzer:
    async def analyze(self, context):
        return {
            "findings": [],
            "tls_info": {},
            "headers": {},
            "redirects": [],
            "privacy": {},
            "cookies": {},
            "threat": {},
        }


class DummyRedirectAnalyzer:
    async def analyze(self, context):
        return {
            "findings": [],
            "redirects": context.redirect_history,
        }


def fake_url_validator(url):
    """Deterministic URL validation for isolated orchestrator tests."""

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    blocked_hosts = {
        "localhost",
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "169.254.169.254",
    }

    if parsed.scheme not in {"http", "https"}:
        return False, None, "Unsupported protocol"

    if hostname in blocked_hosts:
        return False, None, "Private or restricted destination"

    return True, url, None


def install_test_dependencies(monkeypatch, handler, max_redirects=5):
    """Replace network, analyzers, scoring, and persistence dependencies."""

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def mock_async_client(*args, **kwargs):
        return real_async_client(
            *args,
            transport=transport,
            **kwargs,
        )

    monkeypatch.setattr(
        orchestrator_module.httpx,
        "AsyncClient",
        mock_async_client,
    )

    monkeypatch.setattr(
        orchestrator_module,
        "validate_target_url_security",
        fake_url_validator,
    )

    monkeypatch.setattr(
        orchestrator_module.settings,
        "MAX_REDIRECTS",
        max_redirects,
    )

    monkeypatch.setattr(
        orchestrator_module.cache_service,
        "set",
        lambda *args, **kwargs: None,
    )

    async def fake_update_status(*args, **kwargs):
        return None

    monkeypatch.setattr(
        orchestrator_module.AnalysisOrchestrator,
        "update_status",
        fake_update_status,
    )

    analyzer = orchestrator_module.analysis_orchestrator

    analyzer.tls_analyzer = DummyAnalyzer()
    analyzer.header_analyzer = DummyAnalyzer()
    analyzer.redirect_analyzer = DummyRedirectAnalyzer()
    analyzer.tracker_analyzer = DummyAnalyzer()
    analyzer.cookie_analyzer = DummyAnalyzer()
    analyzer.url_analyzer = DummyAnalyzer()
    analyzer.phishing_analyzer = DummyAnalyzer()

    monkeypatch.setattr(
        orchestrator_module.ScoreEngine,
        "calculate_scores",
        staticmethod(
            lambda **kwargs: {
                "overallScore": 90,
                "securityScore": 90,
                "privacyScore": 90,
                "threatScore": 90,
                "riskClassification": "SAFE",
            }
        ),
    )

    return analyzer


def make_response(request, status=200, headers=None, content=b"OK"):
    return httpx.Response(
        status_code=status,
        headers=headers or {},
        content=content,
        request=request,
    )


@pytest.mark.asyncio
async def test_private_ip_redirect_is_blocked(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        return make_response(
            request,
            status=302,
            headers={"Location": "http://127.0.0.1:8000/admin"},
        )

    analyzer = install_test_dependencies(monkeypatch, handler)

    report = await analyzer.run_analysis(
        analysis_id="test-private-redirect",
        raw_url="https://example.com",
    )

    assert len(requested_urls) == 1
    assert requested_urls[0] == "https://example.com"

    assert any(
        finding["id"] == "redir-target-blocked"
        for finding in report["findings"]
    )


@pytest.mark.asyncio
async def test_localhost_redirect_is_blocked(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        return make_response(
            request,
            status=302,
            headers={"Location": "http://localhost:8000"},
        )

    analyzer = install_test_dependencies(monkeypatch, handler)

    report = await analyzer.run_analysis(
        analysis_id="test-localhost-redirect",
        raw_url="https://example.com",
    )

    assert len(requested_urls) == 1

    assert any(
        finding["id"] == "redir-target-blocked"
        for finding in report["findings"]
    )


@pytest.mark.asyncio
async def test_metadata_redirect_is_blocked(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        return make_response(
            request,
            status=302,
            headers={
                "Location": (
                    "http://169.254.169.254/latest/meta-data/"
                )
            },
        )

    analyzer = install_test_dependencies(monkeypatch, handler)

    report = await analyzer.run_analysis(
        analysis_id="test-metadata-redirect",
        raw_url="https://example.com",
    )

    assert len(requested_urls) == 1

    assert any(
        finding["id"] == "redir-target-blocked"
        for finding in report["findings"]
    )


@pytest.mark.asyncio
async def test_redirect_loop_is_detected(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        if request.url.path == "/":
            return make_response(
                request,
                status=302,
                headers={"Location": "/next"},
            )

        return make_response(
            request,
            status=302,
            headers={"Location": "/"},
        )

    analyzer = install_test_dependencies(monkeypatch, handler)

    report = await analyzer.run_analysis(
        analysis_id="test-redirect-loop",
        raw_url="https://example.com",
    )

    # The repeated destination must never be requested.
    assert len(requested_urls) == 2

    assert any(
        finding["id"] == "redir-loop"
        for finding in report["findings"]
    )


@pytest.mark.asyncio
async def test_maximum_redirect_limit_is_enforced(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        next_number = len(requested_urls)

        return make_response(
            request,
            status=302,
            headers={"Location": f"/redirect-{next_number}"},
        )

    analyzer = install_test_dependencies(
        monkeypatch,
        handler,
        max_redirects=2,
    )

    report = await analyzer.run_analysis(
        analysis_id="test-redirect-limit",
        raw_url="https://example.com",
    )

    # Initial request + two permitted redirects.
    assert len(requested_urls) == 3

    assert any(
        finding["id"] == "redir-limit"
        for finding in report["findings"]
    )


@pytest.mark.asyncio
async def test_valid_public_redirect_succeeds(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        if request.url.path == "/":
            return make_response(
                request,
                status=301,
                headers={"Location": "/final"},
            )

        return make_response(
            request,
            status=200,
            headers={"Content-Type": "text/html"},
            content=b"<html><body>Safe test page</body></html>",
        )

    analyzer = install_test_dependencies(monkeypatch, handler)

    report = await analyzer.run_analysis(
        analysis_id="test-valid-redirect",
        raw_url="https://example.com",
    )

    assert len(requested_urls) == 2
    assert requested_urls[1] == "https://example.com/final"

    assert report["id"] == "test-valid-redirect"

    assert not any(
        finding["id"] == "redir-target-blocked"
        for finding in report["findings"]
    )


@pytest.mark.asyncio
async def test_unsupported_redirect_protocol_is_blocked(monkeypatch):
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))

        return make_response(
            request,
            status=302,
            headers={"Location": "file:///etc/passwd"},
        )

    analyzer = install_test_dependencies(monkeypatch, handler)

    report = await analyzer.run_analysis(
        analysis_id="test-unsupported-redirect",
        raw_url="https://example.com",
    )

    assert len(requested_urls) == 1

    assert any(
        finding["id"] == "redir-target-blocked"
        for finding in report["findings"]
    )
