from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserLogin(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Analysis Request / Status Schemas
class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect (e.g. example.com or https://example.com)")
    force_refresh: bool = False

class FindingSchema(BaseModel):
    id: str
    category: str
    title: str
    status: str  # PASS, WARN, FAIL, INFO
    impact: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    remediation: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class SecurityHeaderSchema(BaseModel):
    headerName: str
    present: bool
    value: Optional[str] = None
    status: str  # OPTIMAL, SUBOPTIMAL, MISSING, DEPRECATED
    impact: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    explanation: str
    recommendation: Optional[str] = None

class TLSCertificateSchema(BaseModel):
    valid: bool
    issuer: str
    subject: str
    validFrom: str
    validTo: str
    daysRemaining: int
    protocolVersion: str
    cipherSuite: Optional[str] = None
    hasMixedContent: bool = False
    enforcesHttps: bool = True
    hstsPreloaded: Optional[bool] = False

class RedirectHopSchema(BaseModel):
    step: int
    url: str
    statusCode: int
    domain: str
    isHttps: bool
    isExternal: bool

class RedirectsSummarySchema(BaseModel):
    initialUrl: str
    finalUrl: str
    totalHops: int
    hasSuspiciousRedirect: bool
    chain: List[RedirectHopSchema]

class DetectedTrackerSchema(BaseModel):
    domain: str
    owner: Optional[str] = None
    category: str
    requestCount: int
    impact: str
    description: str
    sampleUrls: Optional[List[str]] = None

class PrivacySummarySchema(BaseModel):
    totalThirdPartyRequests: int
    trackerCount: int
    adNetworkCount: int
    fingerprintingDetected: bool
    trackers: List[DetectedTrackerSchema]
    categoriesEncountered: List[str]

class DetectedCookieSchema(BaseModel):
    name: str
    domain: str
    path: str
    isSecure: bool
    isHttpOnly: bool
    sameSite: str
    isThirdParty: bool
    isPersistent: bool
    expires: Optional[str] = None
    estimatedPurpose: str

class CookiesSummarySchema(BaseModel):
    totalCookies: int
    firstPartyCount: int
    thirdPartyCount: int
    sessionCount: int
    persistentCount: int
    insecureCount: int
    items: List[DetectedCookieSchema]

class PhishingIndicatorSchema(BaseModel):
    name: str
    detected: bool
    description: str
    weight: float
    value: Optional[Any] = None

class ThreatAnalysisSchema(BaseModel):
    probability: float
    classification: str
    confidenceScore: float
    indicators: List[PhishingIndicatorSchema]
    modelType: str
    featureImportance: List[Dict[str, Any]]
    notice: str

class ScoreFactorSchema(BaseModel):
    name: str
    impactPoints: int
    reason: str
    type: str  # POSITIVE | NEGATIVE

class ScoreBreakdownSchema(BaseModel):
    overallScore: int
    securityScore: int
    privacyScore: int
    threatScore: int
    riskClassification: str
    factors: List[ScoreFactorSchema]

class FullReportSchema(BaseModel):
    id: str
    domain: str
    targetUrl: str
    normalizedUrl: str
    analyzedAt: str
    executionTimeMs: int
    scores: ScoreBreakdownSchema
    tls: TLSCertificateSchema
    headers: List[SecurityHeaderSchema]
    redirects: RedirectsSummarySchema
    privacy: PrivacySummarySchema
    cookies: CookiesSummarySchema
    threat: ThreatAnalysisSchema
    findings: List[FindingSchema]

class AnalysisStatusResponse(BaseModel):
    analysisId: str
    targetUrl: str
    domain: str
    stage: str
    stageProgress: int
    stageMessage: str
    isComplete: bool
    error: Optional[str] = None
    report: Optional[FullReportSchema] = None

class WhitelistItemCreate(BaseModel):
    domain: str
    reason: Optional[str] = "User added"

class WhitelistItemResponse(BaseModel):
    id: str
    domain: str
    reason: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ExtensionSyncRequest(BaseModel):
    device_name: Optional[str] = "Chrome Extension"
    browser: Optional[str] = "Chrome"
    extension_version: Optional[str] = "1.0.0"
    total_ads_blocked: int = 0
    total_trackers_blocked: int = 0
    local_whitelist: List[str] = []

class ExtensionConfigResponse(BaseModel):
    version: str = "1.0.0"
    whitelistedDomains: List[str]
    ruleSignaturesCount: int
    recommendedSettings: Dict[str, Any]
