import asyncio
from app.tasks.celery_app import celery_app
from app.services.analysis_orchestrator import analysis_orchestrator

@celery_app.task(name="tasks.execute_url_analysis")
def execute_url_analysis_task(analysis_id: str, raw_url: str, user_id: str = None):
    """
    Celery background worker task for full website security & privacy analysis.
    """
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(
        analysis_orchestrator.run_analysis(
            analysis_id=analysis_id,
            raw_url=raw_url,
            user_id=user_id
        )
    )
