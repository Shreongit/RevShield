
import datetime
import time
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers import (
    AnalysisContext,
    CookieAnalyzer,
    HeaderAnalyzer,
    PhishingAnalyzer,
    RedirectAnalyzer,
    ScoreEngine,
    TLSAnalyzer,
    TrackerAnalyzer,
    URLAnalyzer,
)
from app.core.config import settings
from app.core.security import (
    validate_target_url_security,
    validate_target_url_security_with_addresses,
)
from app.core.pinned_transport import (
    PinnedAddressRegistry,
    PinnedAsyncHTTPTransport,
)
from app.models.models import AnalysisReport
from app.services.cache_service import cache_service


class AnalysisOrchestrator:

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 WebShield-Scanner/1.0"
    )

    REDIRECT_STATUSES = {301, 302, 303, 307, 308}

    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.redirect_analyzer = RedirectAnalyzer()
        self.tracker_analyzer = TrackerAnalyzer()
        self.cookie_analyzer = CookieAnalyzer()
        self.phishing_analyzer = PhishingAnalyzer()

    @staticmethod
    def _redirect_loop_key(url: str) -> str:
        """Normalize equivalent URLs for redirect-loop detection."""
        parsed = urlparse(url)

        return parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=parsed.path or "/",
            fragment="",
        ).geturl()

    async def update_status(
        self,
        analysis_id: str,
        target_url: str,
        domain: str,
        stage: str,
        stage_progress: int,
        stage_message: str,
        is_complete: bool = False,
        error: Optional[str] = None,
        report: Optional[Dict[str, Any]] = None,
    ):
        payload = {
            "analysisId": analysis_id,
            "targetUrl": target_url,
            "domain": domain,
            "stage": stage,
            "stageProgress": stage_progress,
            "stageMessage": stage_message,
            "isComplete": is_complete,
            "error": error,
            "report": report,
        }

        cache_service.set(
            f"status:{analysis_id}",
            payload,
            ttl=3600,
        )

    async def run_analysis(
        self,
        analysis_id: str,
        raw_url: str,
        user_id: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:

        start_time = time.time()

        try:
            parsed_pre = urlparse(
                raw_url if "://" in raw_url else "https://" + raw_url
            )
            domain = (parsed_pre.hostname or raw_url).lower()
        except (TypeError, ValueError):
            domain = str(raw_url)[:255]

        # ==========================================
        # 1. VALIDATE INITIAL URL
        # ==========================================

        await self.update_status(
            analysis_id,
            raw_url,
            domain,
            stage="VALIDATING_URL",
            stage_progress=10,
            stage_message=(
                "Checking URL format and validating against "
                "private networks (Anti-SSRF)..."
            ),
        )

        (
            is_valid,
            normalized_url,
            initial_addresses,
            err_msg,
        ) = validate_target_url_security_with_addresses(raw_url)

        if not is_valid:
            await self.update_status(
                analysis_id,
                raw_url,
                domain,
                stage="FAILED",
                stage_progress=100,
                stage_message=f"Validation failed: {err_msg}",
                is_complete=True,
                error=err_msg,
            )

            return {"error": err_msg}

        parsed = urlparse(normalized_url)
        domain = parsed.hostname or domain

        # ==========================================
        # 2. INSPECT TLS
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="INSPECTING_TLS",
            stage_progress=25,
            stage_message=(
                "Establishing SSL handshake and parsing "
                "certificate parameters..."
            ),
        )

        context = AnalysisContext(
            raw_url=raw_url,
            normalized_url=normalized_url,
            domain=domain,
        )

        tls_res = await self.tls_analyzer.analyze(context)

        # ==========================================
        # 3. SECURE HTTP FETCH
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="ANALYZING_HEADERS",
            stage_progress=40,
            stage_message=(
                "Requesting website headers with TLS verification "
                "and redirect security checks..."
            ),
        )

        redirect_hops: List[Dict[str, Any]] = []
        cookies_list: List[Dict[str, Any]] = []

        response_status = 502
        response_headers: Dict[str, Any] = {}
        response_body = ""

        fetch_issue: Optional[str] = None
        fetch_issue_type: Optional[str] = None

        current_url = normalized_url
        visited_urls = set()
        redirect_count = 0

        max_redirects = max(
            0,
            int(settings.MAX_REDIRECTS),
        )

        max_response_bytes = max(
            1,
            int(settings.MAX_RESPONSE_BYTES),
        )

        timeout = httpx.Timeout(
            settings.REQUEST_TIMEOUT_SECONDS
        )

        registry = PinnedAddressRegistry()

        registry.register_url(
            normalized_url,
            initial_addresses,
        )

        pinned_transport = PinnedAsyncHTTPTransport(
            registry=registry,
            verify=True,
            retries=0,
        )

        # Production uses the DNS-pinned transport.
        # Existing tests may replace AsyncClient with a wrapper
        # that supplies its own MockTransport.
        client_kwargs = {
            "timeout": timeout,
            "follow_redirects": False,
            "trust_env": False,
            "headers": {"User-Agent": self.USER_AGENT},
        }

        if isinstance(httpx.AsyncClient, type):
            client_kwargs["transport"] = pinned_transport

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:

                for _ in range(max_redirects + 1):

                    (
                        is_valid,
                        safe_url,
                        validated_addresses,
                        validation_error,
                    ) = validate_target_url_security_with_addresses(
                        current_url
                    )

                    if not is_valid:
                        fetch_issue = (
                            "A redirect destination was rejected "
                            "by URL security validation."
                        )
                        fetch_issue_type = "blocked"
                        break

                    current_url = safe_url

                    registry.register_url(
                        current_url,
                        validated_addresses,
                    )

                    loop_key = self._redirect_loop_key(current_url)

                    if loop_key in visited_urls:
                        fetch_issue = (
                            "A redirect loop was detected. "
                            "The repeated destination was not requested."
                        )
                        fetch_issue_type = "loop"
                        break

                    visited_urls.add(loop_key)

                    async with client.stream(
                        "GET",
                        current_url,
                    ) as response:

                        response_status = response.status_code
                        response_headers = dict(response.headers)

                        actual_url = str(response.url)

                        redirect_hops.append({
                            "url": actual_url,
                            "status_code": response.status_code,
                        })

                        location = response.headers.get("location")

                        is_redirect = (
                            response.status_code in self.REDIRECT_STATUSES
                            and bool(location)
                        )

                        if is_redirect:

                            if redirect_count >= max_redirects:
                                fetch_issue = (
                                    "The configured maximum redirect "
                                    "count was reached."
                                )
                                fetch_issue_type = "limit"
                                break

                            next_url = urljoin(
                                actual_url,
                                location,
                            )

                            next_parsed = urlparse(next_url)

                            if next_parsed.scheme.lower() not in (
                                "http",
                                "https",
                            ):
                                fetch_issue = (
                                    "A redirect used an unsupported "
                                    "URL protocol and was blocked."
                                )
                                fetch_issue_type = "blocked"
                                break

                            (
                                next_valid,
                                safe_next_url,
                                next_addresses,
                                next_error,
                            ) = validate_target_url_security_with_addresses(
                                next_url
                            )

                            if not next_valid:
                                fetch_issue = (
                                    "A redirect destination was rejected "
                                    "by URL security validation."
                                )
                                fetch_issue_type = "blocked"
                                break

                            registry.register_url(
                                safe_next_url,
                                next_addresses,
                            )

                            redirect_count += 1
                            current_url = safe_next_url

                            continue

                        body = bytearray()

                        async for chunk in response.aiter_bytes():

                            remaining = (
                                max_response_bytes - len(body)
                            )

                            if remaining <= 0:
                                break

                            body.extend(chunk[:remaining])

                            if len(body) >= max_response_bytes:
                                break

                        encoding = response.encoding or "utf-8"

                        response_body = body.decode(
                            encoding,
                            errors="replace",
                        )

                        for name, value in response.cookies.items():

                            cookies_list.append({
                                "name": name,
                                "domain": (
                                    urlparse(actual_url).hostname
                                    or domain
                                ),
                                "path": "/",
                                "secure": (
                                    urlparse(actual_url).scheme.lower()
                                    == "https"
                                ),
                            })

                        break

        except httpx.RequestError:
            response_status = 502
            response_headers = {}
            response_body = ""

            fetch_issue = (
                "The HTTP request failed. The destination may be "
                "unreachable or its TLS certificate may not be trusted."
            )
            fetch_issue_type = "request_error"

        # ==========================================
        # 4. POPULATE ANALYSIS CONTEXT
        # ==========================================

        context.response_status = response_status
        context.response_headers = response_headers
        context.response_body = response_body
        context.redirect_history = redirect_hops
        context.response_cookies = cookies_list

        # ==========================================
        # 5. ANALYZE HEADERS
        # ==========================================

        headers_res = await self.header_analyzer.analyze(context)

        # ==========================================
        # 6. ANALYZE REDIRECTS
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="TRACING_REDIRECTS",
            stage_progress=55,
            stage_message=(
                "Auditing redirect chain for protocol downgrades "
                "and unsafe destinations..."
            ),
        )

        redirects_res = await self.redirect_analyzer.analyze(context)

        if fetch_issue:

            if fetch_issue_type == "blocked":
                redirects_res["findings"].append({
                    "id": "redir-target-blocked",
                    "category": "REDIRECTS",
                    "title": "Unsafe Redirect Destination Blocked",
                    "status": "FAIL",
                    "impact": "CRITICAL",
                    "description": fetch_issue,
                    "remediation": (
                        "Ensure redirect destinations resolve only "
                        "to permitted public network addresses and "
                        "use supported HTTP or HTTPS protocols."
                    ),
                })

            elif fetch_issue_type == "loop":
                redirects_res["findings"].append({
                    "id": "redir-loop",
                    "category": "REDIRECTS",
                    "title": "Redirect Loop Detected",
                    "status": "WARN",
                    "impact": "MEDIUM",
                    "description": fetch_issue,
                    "remediation": (
                        "Correct the redirect configuration to "
                        "prevent repeated destinations."
                    ),
                })

            elif fetch_issue_type == "limit":
                redirects_res["findings"].append({
                    "id": "redir-limit",
                    "category": "REDIRECTS",
                    "title": "Maximum Redirect Limit Reached",
                    "status": "WARN",
                    "impact": "MEDIUM",
                    "description": fetch_issue,
                    "remediation": (
                        "Reduce unnecessary redirects and configure "
                        "a valid final destination."
                    ),
                })

        # ==========================================
        # 7. DETECT TRACKERS
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="DETECTING_TRACKERS",
            stage_progress=70,
            stage_message=(
                "Inspecting page resources for trackers, "
                "analytics beacons, and advertising..."
            ),
        )

        trackers_res = await self.tracker_analyzer.analyze(context)

        # ==========================================
        # 8. ANALYZE COOKIES
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="ANALYZING_COOKIES",
            stage_progress=80,
            stage_message=(
                "Evaluating cookie security attributes, "
                "persistence, and classification..."
            ),
        )

        cookies_res = await self.cookie_analyzer.analyze(context)

        # ==========================================
        # 9. EVALUATE THREATS
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="EVALUATING_THREATS",
            stage_progress=90,
            stage_message=(
                "Executing Machine Learning threat classification "
                "and heuristic checks..."
            ),
        )

        url_res = await self.url_analyzer.analyze(context)
        phishing_res = await self.phishing_analyzer.analyze(context)

        # ==========================================
        # 10. CALCULATE SCORES
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="CALCULATING_SCORE",
            stage_progress=98,
            stage_message=(
                "Synthesizing multi-factor security "
                "and privacy score..."
            ),
        )

        scores = ScoreEngine.calculate_scores(
            url_data=url_res,
            tls_data=tls_res,
            headers_data=headers_res,
            redirects_data=redirects_res,
            privacy_data=trackers_res,
            cookies_data=cookies_res,
            threat_data=phishing_res,
        )

        # ==========================================
        # 11. AGGREGATE FINDINGS
        # ==========================================

        all_findings = (
            url_res.get("findings", [])
            + tls_res.get("findings", [])
            + headers_res.get("findings", [])
            + redirects_res.get("findings", [])
            + trackers_res.get("findings", [])
            + cookies_res.get("findings", [])
            + phishing_res.get("findings", [])
        )

        # ==========================================
        # 12. BUILD REPORT
        # ==========================================

        elapsed_ms = int(
            (time.time() - start_time) * 1000
        )

        analyzed_at_iso = (
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
        )

        report_payload = {
            "id": analysis_id,
            "domain": domain,
            "targetUrl": raw_url,
            "normalizedUrl": normalized_url,
            "analyzedAt": analyzed_at_iso,
            "executionTimeMs": elapsed_ms,
            "scores": scores,
            "tls": tls_res["tls_info"],
            "headers": headers_res["headers"],
            "redirects": redirects_res["redirects"],
            "privacy": trackers_res["privacy"],
            "cookies": cookies_res["cookies"],
            "threat": phishing_res["threat"],
            "findings": all_findings,
        }

        # ==========================================
        # 13. CACHE REPORT
        # ==========================================

        cache_service.set(
            f"report:{analysis_id}",
            report_payload,
            ttl=settings.ANALYSIS_CACHE_TTL_SECONDS,
        )

        cache_service.set(
            f"domain:{domain}",
            report_payload,
            ttl=settings.ANALYSIS_CACHE_TTL_SECONDS,
        )

        # ==========================================
        # 14. SAVE TO DATABASE
        # ==========================================

        if db_session:
            try:
                db_report = AnalysisReport(
                    id=analysis_id,
                    domain=domain,
                    target_url=raw_url,
                    normalized_url=normalized_url,
                    overall_score=scores["overallScore"],
                    security_score=scores["securityScore"],
                    privacy_score=scores["privacyScore"],
                    threat_score=scores["threatScore"],
                    risk_classification=scores["riskClassification"],
                    execution_time_ms=elapsed_ms,
                    report_json=report_payload,
                    user_id=user_id,
                )

                db_session.add(db_report)
                await db_session.commit()

            except Exception:
                await db_session.rollback()

        # ==========================================
        # 15. COMPLETE ANALYSIS
        # ==========================================

        await self.update_status(
            analysis_id,
            normalized_url,
            domain,
            stage="COMPLETED",
            stage_progress=100,
            stage_message="Analysis completed successfully.",
            is_complete=True,
            report=report_payload,
        )

        return report_payload


analysis_orchestrator = AnalysisOrchestrator()
