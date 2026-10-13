import asyncio
import uuid
from urllib.parse import urlparse
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.security import validate_target_url_security
from app.models.models import AnalysisReport
from app.schemas.schemas import AnalysisStatusResponse, AnalyzeRequest, FullReportSchema
from app.services.analysis_orchestrator import analysis_orchestrator
from app.services.cache_service import cache_service

router = APIRouter(prefix="", tags=["Analysis"])

@router.post("/analyze", response_model=AnalysisStatusResponse)
async def submit_analysis(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a target URL for security, privacy, and threat analysis.
    Checks cache first unless force_refresh is enabled.
    """
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    # Preliminary security validation
    is_valid, normalized_url, err_msg = validate_target_url_security(raw_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    parsed = urlparse(normalized_url)
    domain = parsed.hostname or raw_url.lower()

    # Check cache unless force refresh
    if not req.force_refresh:
        cached_report = cache_service.get(f"domain:{domain}")
        if cached_report:
            return AnalysisStatusResponse(
                analysisId=cached_report["id"],
                targetUrl=raw_url,
                domain=domain,
                stage="COMPLETED",
                stageProgress=100,
                stageMessage="Cached report retrieved.",
                isComplete=True,
                report=cached_report
            )

    analysis_id = str(uuid.uuid4())

    # Initial status in cache
    await analysis_orchestrator.update_status(
        analysis_id=analysis_id,
        target_url=raw_url,
        domain=domain,
        stage="INITIALIZING",
        stage_progress=5,
        stage_message="Queuing website intelligence inspection..."
    )

    # Spawn async analysis task
    background_tasks.add_task(
        analysis_orchestrator.run_analysis,
        analysis_id=analysis_id,
        raw_url=normalized_url,
        user_id=None,
        db_session=None  # will save directly in orchestrator
    )

    return AnalysisStatusResponse(
        analysisId=analysis_id,
        targetUrl=raw_url,
        domain=domain,
        stage="INITIALIZING",
        stageProgress=5,
        stageMessage="Analysis queued and initiated.",
        isComplete=False
    )

@router.get("/analysis/{analysis_id}/status", response_model=AnalysisStatusResponse)
async def get_analysis_status(analysis_id: str):
    """
    Poll live analysis progress by analysis ID.
    """
    status_data = cache_service.get(f"status:{analysis_id}")
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis job not found or expired."
        )
    return status_data

@router.get("/analysis/{analysis_id}", response_model=FullReportSchema)
async def get_analysis_report_by_id(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """
    Retrieve full security intelligence report by analysis ID.
    """
    report_data = cache_service.get(f"report:{analysis_id}")
    if report_data:
        return report_data

    # Check database
    res = await db.execute(select(AnalysisReport).where(AnalysisReport.id == analysis_id))
    db_report = res.scalars().first()
    if db_report and db_report.report_json:
        return db_report.report_json

    raise HTTPException(status_code=404, detail="Analysis report not found.")

@router.get("/report/{domain}", response_model=FullReportSchema)
async def get_report_by_domain(domain: str, db: AsyncSession = Depends(get_db)):
    """
    Retrieve latest analysis report by domain name.
    """
    clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").split("/")[0]
    cached_report = cache_service.get(f"domain:{clean_domain}")
    if cached_report:
        return cached_report

    # Check database for most recent
    res = await db.execute(
        select(AnalysisReport)
        .where(AnalysisReport.domain == clean_domain)
        .order_by(AnalysisReport.created_at.desc())
    )
    db_report = res.scalars().first()
    if db_report and db_report.report_json:
        return db_report.report_json

    raise HTTPException(
        status_code=404,
        detail=f"No previous security report found for domain '{clean_domain}'. Run a new scan to generate report."
    )
