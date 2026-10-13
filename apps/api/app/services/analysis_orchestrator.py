import asyncio
import datetime
import time
import uuid
from urllib.parse import urlparse
from typing import Any, Callable, Dict, List, Optional
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
from app.core.security import validate_target_url_security
from app.models.models import AnalysisReport
from app.services.cache_service import cache_service

class AnalysisOrchestrator:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.redirect_analyzer = RedirectAnalyzer()
        self.tracker_analyzer = TrackerAnalyzer()
        self.cookie_analyzer = CookieAnalyzer()
        self.phishing_analyzer = PhishingAnalyzer()

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
        report: Optional[Dict[str, Any]] = None
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
            "report": report
        }
        cache_service.set(f"status:{analysis_id}", payload, ttl=3600)

    async def run_analysis(
        self,
        analysis_id: str,
        raw_url: str,
        user_id: Optional[str] = None,
        db_session: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        parsed_pre = urlparse(raw_url if "://" in raw_url else "https://" + raw_url)
        domain = (parsed_pre.hostname or raw_url).lower()

        # 1. Stage: VALIDATING_URL
        await self.update_status(
            analysis_id, raw_url, domain,
            stage="VALIDATING_URL",
            stage_progress=10,
            stage_message="Checking URL format and validating against private networks (Anti-SSRF)..."
        )

        is_valid, normalized_url, err_msg = validate_target_url_security(raw_url)
        if not is_valid:
            await self.update_status(
                analysis_id, raw_url, domain,
                stage="FAILED",
                stage_progress=100,
                stage_message=f"Validation failed: {err_msg}",
                is_complete=True,
                error=err_msg
            )
            return {"error": err_msg}

        parsed = urlparse(normalized_url)
        domain = parsed.hostname or domain

        # 2. Stage: INSPECTING_TLS
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="INSPECTING_TLS",
            stage_progress=25,
            stage_message="Establishing SSL handshake and parsing certificate parameters..."
        )

        # Context container
        context = AnalysisContext(
            raw_url=raw_url,
            normalized_url=normalized_url,
            domain=domain
        )

        tls_res = await self.tls_analyzer.analyze(context)

        # 3. Stage: ANALYZING_HEADERS & HTTP Fetch
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="ANALYZING_HEADERS",
            stage_progress=40,
            stage_message="Requesting website headers and verifying security policies..."
        )

        # Fetch HTTP response safely with limits
        redirect_hops = []
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=settings.REQUEST_TIMEOUT_SECONDS,
                follow_redirects=True,
                max_redirects=settings.MAX_REDIRECTS,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 WebShield-Scanner/1.0"}
            ) as client:
                resp = await client.get(normalized_url)

                # Record redirect history
                if resp.history:
                    for h in resp.history:
                        redirect_hops.append({
                            "url": str(h.url),
                            "status_code": h.status_code
                        })
                redirect_hops.append({
                    "url": str(resp.url),
                    "status_code": resp.status_code
                })

                context.response_status = resp.status_code
                context.response_headers = dict(resp.headers)
                context.response_body = resp.text[: settings.MAX_RESPONSE_BYTES]
                context.redirect_history = redirect_hops

                # Parse cookies from client
                cookies_list = []
                for name, value in resp.cookies.items():
                    cookies_list.append({
                        "name": name,
                        "domain": domain,
                        "path": "/",
                        "secure": normalized_url.startswith("https://")
                    })
                context.response_cookies = cookies_list

        except httpx.RequestError as e:
            # Fallback headers when domain is partially unreachable
            context.response_status = 502
            context.response_headers = {}

        headers_res = await self.header_analyzer.analyze(context)

        # 4. Stage: TRACING_REDIRECTS
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="TRACING_REDIRECTS",
            stage_progress=55,
            stage_message="Auditing redirect chain for protocol downgrades or unauthorized domains..."
        )
        redirects_res = await self.redirect_analyzer.analyze(context)

        # 5. Stage: DETECTING_TRACKERS
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="DETECTING_TRACKERS",
            stage_progress=70,
            stage_message="Inspecting page resources for trackers, analytics beacons, and advertising..."
        )
        trackers_res = await self.tracker_analyzer.analyze(context)

        # 6. Stage: ANALYZING_COOKIES
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="ANALYZING_COOKIES",
            stage_progress=80,
            stage_message="Evaluating cookie security attributes, persistence, and classification..."
        )
        cookies_res = await self.cookie_analyzer.analyze(context)

        # 7. Stage: EVALUATING_THREATS
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="EVALUATING_THREATS",
            stage_progress=90,
            stage_message="Executing Machine Learning threat classification & heuristic checks..."
        )
        url_res = await self.url_analyzer.analyze(context)
        phishing_res = await self.phishing_analyzer.analyze(context)

        # 8. Stage: CALCULATING_SCORE
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="CALCULATING_SCORE",
            stage_progress=98,
            stage_message="Synthesizing multi-factor security and privacy score..."
        )

        scores = ScoreEngine.calculate_scores(
            url_data=url_res,
            tls_data=tls_res,
            headers_data=headers_res,
            redirects_data=redirects_res,
            privacy_data=trackers_res,
            cookies_data=cookies_res,
            threat_data=phishing_res
        )

        # Aggregate findings
        all_findings = (
            url_res.get("findings", []) +
            tls_res.get("findings", []) +
            headers_res.get("findings", []) +
            redirects_res.get("findings", []) +
            trackers_res.get("findings", []) +
            cookies_res.get("findings", []) +
            phishing_res.get("findings", [])
        )

        elapsed_ms = int((time.time() - start_time) * 1000)
        analyzed_at_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

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
            "findings": all_findings
        }

        # Cache final report by ID and domain
        cache_service.set(f"report:{analysis_id}", report_payload, ttl=settings.ANALYSIS_CACHE_TTL_SECONDS)
        cache_service.set(f"domain:{domain}", report_payload, ttl=settings.ANALYSIS_CACHE_TTL_SECONDS)

        # Save to database if session provided
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
                    user_id=user_id
                )
                db_session.add(db_report)
                await db_session.commit()
            except Exception:
                await db_session.rollback()

        # Mark COMPLETED
        await self.update_status(
            analysis_id, normalized_url, domain,
            stage="COMPLETED",
            stage_progress=100,
            stage_message="Analysis completed successfully.",
            is_complete=True,
            report=report_payload
        )

        return report_payload

analysis_orchestrator = AnalysisOrchestrator()
