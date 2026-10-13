import pytest
from app.analyzers.base import AnalysisContext
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.score_engine import ScoreEngine

@pytest.mark.asyncio
async def test_header_analyzer_missing_and_optimal():
    analyzer = HeaderAnalyzer()

    # Case 1: Missing all headers
    context = AnalysisContext(
        raw_url="https://example.com",
        normalized_url="https://example.com",
        domain="example.com",
        response_headers={}
    )
    res = await analyzer.analyze(context)
    headers = {h["headerName"]: h for h in res["headers"]}

    assert headers["Content-Security-Policy"]["present"] is False
    assert headers["Content-Security-Policy"]["status"] == "MISSING"
    assert headers["Strict-Transport-Security"]["present"] is False

    # Case 2: Optimal headers
    context_opt = AnalysisContext(
        raw_url="https://example.com",
        normalized_url="https://example.com",
        domain="example.com",
        response_headers={
            "content-security-policy": "default-src 'self'; script-src 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff"
        }
    )
    res_opt = await analyzer.analyze(context_opt)
    headers_opt = {h["headerName"]: h for h in res_opt["headers"]}

    assert headers_opt["Content-Security-Policy"]["present"] is True
    assert headers_opt["Content-Security-Policy"]["status"] == "OPTIMAL"
    assert headers_opt["Strict-Transport-Security"]["present"] is True
    assert headers_opt["X-Frame-Options"]["present"] is True

@pytest.mark.asyncio
async def test_url_analyzer():
    analyzer = URLAnalyzer()
    context = AnalysisContext(
        raw_url="https://secure-login-verify-account.update.bank.top/login",
        normalized_url="https://secure-login-verify-account.update.bank.top/login",
        domain="secure-login-verify-account.update.bank.top"
    )
    res = await analyzer.analyze(context)
    indicators = {i["name"]: i for i in res["indicators"]}

    assert indicators["suspicious_keywords"]["detected"] is True
    assert indicators["excessive_subdomains"]["detected"] is True
    assert indicators["unusual_tld"]["detected"] is True

def test_score_engine():
    scores = ScoreEngine.calculate_scores(
        url_data={"indicators": []},
        tls_data={"tls_info": {"valid": True, "issuer": "Let's Encrypt", "protocolVersion": "TLSv1.3"}},
        headers_data={"headers": [
            {"headerName": "Content-Security-Policy", "present": True, "status": "OPTIMAL"},
            {"headerName": "Strict-Transport-Security", "present": True, "status": "OPTIMAL"},
            {"headerName": "X-Frame-Options", "present": True, "status": "OPTIMAL"},
        ]},
        redirects_data={"redirects": {"hasSuspiciousRedirect": False}},
        privacy_data={"privacy": {"trackers": [], "adNetworkCount": 0, "fingerprintingDetected": False}},
        cookies_data={"cookies": {"thirdPartyCount": 0}},
        threat_data={"threat": {"probability": 0.05}}
    )

    assert scores["overallScore"] >= 90
    assert scores["riskClassification"] == "SAFE"
    assert scores["securityScore"] >= 90
    assert scores["privacyScore"] == 100
