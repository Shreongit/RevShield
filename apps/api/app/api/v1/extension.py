from typing import Any, Dict, List
from fastapi import APIRouter
from app.analyzers.tracker_analyzer import TRACKER_SIGNATURES
from app.schemas.schemas import ExtensionConfigResponse

router = APIRouter(prefix="/extension", tags=["Extension Integration"])

@router.get("/config", response_model=ExtensionConfigResponse)
async def get_extension_configuration():
    """
    Returns latest tracker signature metrics, default ruleset config, and recommended settings.
    """
    return ExtensionConfigResponse(
        version="1.0.0",
        whitelistedDomains=[],
        ruleSignaturesCount=len(TRACKER_SIGNATURES),
        recommendedSettings={
            "blockTrackers": True,
            "blockAds": True,
            "blockFingerprinting": True,
            "badgeCounter": True
        }
    )
