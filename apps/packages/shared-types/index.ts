export type RiskLevel = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK';

export type ImpactLevel = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type TrackerCategory =
  | 'ANALYTICS'
  | 'ADVERTISING'
  | 'SOCIAL'
  | 'SESSION_REPLAY'
  | 'FINGERPRINTING'
  | 'TELEMETRY'
  | 'CRYPTOMINING'
  | 'CONTENT_DELIVERY'
  | 'UNKNOWN';

export interface AnalysisFinding {
  id: string;
  category: 'SECURITY' | 'PRIVACY' | 'THREAT' | 'COOKIES' | 'REDIRECTS';
  title: string;
  status: 'PASS' | 'WARN' | 'FAIL' | 'INFO';
  impact: ImpactLevel;
  description: string;
  remediation?: string;
  details?: Record<string, any>;
}

export interface SecurityHeaderResult {
  headerName: string;
  present: boolean;
  value?: string;
  status: 'OPTIMAL' | 'SUBOPTIMAL' | 'MISSING' | 'DEPRECATED';
  impact: ImpactLevel;
  explanation: string;
  recommendation?: string;
}

export interface TLSCertificateInfo {
  valid: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocolVersion: string;
  cipherSuite?: string;
  hasMixedContent: boolean;
  enforcesHttps: boolean;
  hstsPreloaded?: boolean;
}

export interface RedirectHop {
  step: number;
  url: string;
  statusCode: number;
  domain: string;
  isHttps: boolean;
  isExternal: boolean;
}

export interface DetectedTracker {
  domain: string;
  owner?: string;
  category: TrackerCategory;
  requestCount: number;
  impact: ImpactLevel;
  description: string;
  sampleUrls?: string[];
}

export interface DetectedCookie {
  name: string;
  domain: string;
  path: string;
  isSecure: boolean;
  isHttpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | 'Unset';
  isThirdParty: boolean;
  isPersistent: boolean;
  expires?: string;
  estimatedPurpose: string;
}

export interface PhishingIndicator {
  name: string;
  detected: boolean;
  description: string;
  weight: number;
  value?: string | number | boolean;
}

export interface ThreatAnalysisResult {
  probability: number;
  classification: RiskLevel;
  confidenceScore: number;
  indicators: PhishingIndicator[];
  modelType: string;
  featureImportance: { feature: string; impact: number; explanation: string }[];
  notice: string;
}

export interface ScoreFactor {
  name: string;
  impactPoints: number;
  reason: string;
  type: 'POSITIVE' | 'NEGATIVE';
}

export interface ScoreBreakdown {
  overallScore: number;
  securityScore: number;
  privacyScore: number;
  threatScore: number;
  riskClassification: RiskLevel;
  factors: ScoreFactor[];
}

export interface FullAnalysisReport {
  id: string;
  domain: string;
  targetUrl: string;
  normalizedUrl: string;
  analyzedAt: string;
  executionTimeMs: number;
  scores: ScoreBreakdown;
  tls: TLSCertificateInfo;
  headers: SecurityHeaderResult[];
  redirects: {
    initialUrl: string;
    finalUrl: string;
    totalHops: number;
    hasSuspiciousRedirect: boolean;
    chain: RedirectHop[];
  };
  privacy: {
    totalThirdPartyRequests: number;
    trackerCount: number;
    adNetworkCount: number;
    fingerprintingDetected: boolean;
    trackers: DetectedTracker[];
    categoriesEncountered: TrackerCategory[];
  };
  cookies: {
    totalCookies: number;
    firstPartyCount: number;
    thirdPartyCount: number;
    sessionCount: number;
    persistentCount: number;
    insecureCount: number;
    items: DetectedCookie[];
  };
  threat: ThreatAnalysisResult;
  findings: AnalysisFinding[];
}

export type AnalysisStage =
  | 'INITIALIZING'
  | 'VALIDATING_URL'
  | 'INSPECTING_TLS'
  | 'ANALYZING_HEADERS'
  | 'TRACING_REDIRECTS'
  | 'DETECTING_TRACKERS'
  | 'ANALYZING_COOKIES'
  | 'EVALUATING_THREATS'
  | 'CALCULATING_SCORE'
  | 'COMPLETED'
  | 'FAILED';

export interface AnalysisStatusResponse {
  analysisId: string;
  targetUrl: string;
  domain: string;
  stage: AnalysisStage;
  stageProgress: number; // 0 - 100
  stageMessage: string;
  isComplete: boolean;
  error?: string;
  report?: FullAnalysisReport;
}

export interface ExtensionSyncState {
  version: string;
  lastSyncedAt: string;
  whitelistDomains: string[];
  customRules: { id: string; pattern: string; action: 'BLOCK' | 'ALLOW' }[];
  totalAdsBlocked: number;
  totalTrackersBlocked: number;
}
