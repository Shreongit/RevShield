import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Lock,
  Eye,
  Cookie,
  CornerDownRight,
  Cpu,
  RefreshCw,
  Share2,
  Download,
  AlertCircle,
  CheckCircle,
  ExternalLink,
  ArrowLeft
} from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';
import { getReportByDomain, submitAnalysis, getAnalysisStatus } from '../services/api';
import { OverviewSection } from '../components/analysis/OverviewSection';
import { SecuritySection } from '../components/analysis/SecuritySection';
import { PrivacySection } from '../components/analysis/PrivacySection';
import { CookiesSection } from '../components/analysis/CookiesSection';
import { RedirectsSection } from '../components/analysis/RedirectsSection';
import { ThreatSection } from '../components/analysis/ThreatSection';
import { ExtensionCTA } from '../components/analysis/ExtensionCTA';
import { LiveProgressStepper } from '../components/analysis/LiveProgressStepper';

type TabType = 'overview' | 'security' | 'privacy' | 'cookies' | 'redirects' | 'threat';

export const ReportPage: React.FC = () => {
  const { domain } = useParams<{ domain: string }>();
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [report, setReport] = useState<FullAnalysisReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [refreshProgress, setRefreshProgress] = useState<any>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const navigate = useNavigate();

  const fetchReport = async (domainName: string) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const data = await getReportByDomain(domainName);
      setReport(data);
    } catch (err: any) {
      // If not found in cache, trigger a fresh scan
      handleRefresh(domainName);
      return;
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (domain) {
      fetchReport(domain);
    }
  }, [domain]);

  const handleRefresh = async (targetDomain?: string) => {
    const d = targetDomain || domain;
    if (!d) return;

    setIsRefreshing(true);
    setErrorMessage(null);

    try {
      const initial = await submitAnalysis(d, true);
      setRefreshProgress(initial);

      const pollInterval = setInterval(async () => {
        try {
          const status = await getAnalysisStatus(initial.analysisId);
          setRefreshProgress(status);

          if (status.isComplete) {
            clearInterval(pollInterval);
            setIsRefreshing(false);
            if (status.report) {
              setReport(status.report);
            } else if (status.error) {
              setErrorMessage(status.error);
            }
          }
        } catch {
          clearInterval(pollInterval);
          setIsRefreshing(false);
          setErrorMessage('Failed to refresh report.');
        }
      }, 800);
    } catch (err: any) {
      setIsRefreshing(false);
      setErrorMessage(err.message || 'Scan failed.');
    }
  };

  const handleShare = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `revshield-report-${report.domain}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isRefreshing && refreshProgress) {
    return (
      <div className="max-w-5xl mx-auto px-4 py-16 w-full">
        <LiveProgressStepper
          currentStage={refreshProgress.stage}
          progress={refreshProgress.stageProgress}
          stageMessage={refreshProgress.stageMessage}
          error={errorMessage || undefined}
        />
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <div className="h-8 w-8 rounded-full border-2 border-accent border-t-transparent animate-spin" />
        <span className="text-xs font-mono text-text-muted">Loading Intelligence Report for {domain}...</span>
      </div>
    );
  }

  if (!report) {
    const isSecurityRestricted =
      errorMessage?.includes('restricted for security') ||
      errorMessage?.includes('localhost') ||
      errorMessage?.includes('private');

    return (
      <div className="max-w-lg mx-auto px-4 py-20 text-center space-y-5">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-amber-500/10 text-amber-400 mx-auto border border-amber-500/20">
          <AlertCircle className="h-7 w-7" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-bold text-text-primary">
            {isSecurityRestricted ? 'Private Network Protection' : 'Report Not Available'}
          </h2>
          <p className="text-xs sm:text-sm text-text-secondary leading-relaxed max-w-md mx-auto">
            {isSecurityRestricted
              ? `RevShield's Anti-SSRF engine restricts analysis of localhost, loopback addresses, and private subnets to prevent internal network scanning.`
              : errorMessage || `Unable to locate or generate a security report for ${domain}.`}
          </p>
        </div>

        {isSecurityRestricted ? (
          <div className="pt-2 space-y-3">
            <Link
              to="/"
              className="inline-flex items-center space-x-2 rounded-xl bg-accent hover:bg-accent-hover px-5 py-2.5 text-xs font-semibold text-white shadow-sm transition-all"
            >
              <Shield className="h-4 w-4" />
              <span>Scan a Public Website</span>
            </Link>
            <div className="flex items-center justify-center gap-2 text-xs text-text-muted">
              <span>Try:</span>
              <Link to="/report/github.com" className="text-accent hover:underline">github.com</Link>
              <span>&bull;</span>
              <Link to="/report/wikipedia.org" className="text-accent hover:underline">wikipedia.org</Link>
              <span>&bull;</span>
              <Link to="/report/cloudflare.com" className="text-accent hover:underline">cloudflare.com</Link>
            </div>
          </div>
        ) : (
          <button
            onClick={() => handleRefresh()}
            className="inline-flex items-center space-x-2 rounded-xl bg-accent hover:bg-accent-hover px-5 py-2.5 text-xs font-semibold text-white shadow-sm transition-all"
          >
            <RefreshCw className="h-4 w-4" />
            <span>Retry Analysis</span>
          </button>
        )}
      </div>
    );
  }

  const tabs: { id: TabType; label: string; icon: any; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'security', label: 'Security & TLS', icon: Lock },
    { id: 'privacy', label: 'Privacy & Trackers', icon: Eye, count: report.privacy.trackerCount },
    { id: 'cookies', label: 'Cookies & Storage', icon: Cookie, count: report.cookies.totalCookies },
    { id: 'redirects', label: 'Redirects', icon: CornerDownRight, count: report.redirects.totalHops },
    { id: 'threat', label: 'Threat ML', icon: Cpu },
  ];

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-8">
      {/* Back link & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <Link
            to="/"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-text-secondary hover:text-text-primary transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl sm:text-2xl font-bold font-mono text-text-primary tracking-tight">
                {report.domain}
              </h1>
              <a
                href={report.normalizedUrl}
                target="_blank"
                rel="noreferrer"
                className="text-text-muted hover:text-accent transition-colors"
              >
                <ExternalLink className="h-4 w-4" />
              </a>
            </div>
            <p className="text-[11px] font-mono text-text-muted">
              Scanned at {new Date(report.analyzedAt).toLocaleString()} &bull; {report.executionTimeMs}ms execution
            </p>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => handleRefresh()}
            className="flex items-center space-x-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-mono font-medium text-text-secondary hover:text-text-primary hover:border-border-focus transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Re-Scan</span>
          </button>
          <button
            onClick={handleShare}
            className="flex items-center space-x-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-mono font-medium text-text-secondary hover:text-text-primary hover:border-border-focus transition-colors"
          >
            <Share2 className="h-3.5 w-3.5" />
            <span>{copied ? 'Copied URL!' : 'Share'}</span>
          </button>
          <button
            onClick={handleDownloadJSON}
            className="flex items-center space-x-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-mono font-medium text-text-secondary hover:text-text-primary hover:border-border-focus transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Segmented Navigation Tabs */}
      <div className="border-b border-border">
        <nav className="flex space-x-2 overflow-x-auto pb-px" aria-label="Tabs">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isSelected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 py-2.5 px-3.5 text-xs font-medium rounded-t-lg border-b-2 whitespace-nowrap transition-colors ${
                  isSelected
                    ? 'border-accent text-accent font-semibold bg-accent-subtle/40'
                    : 'border-transparent text-text-secondary hover:text-text-primary hover:border-border'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span
                    className={`rounded-full px-1.5 py-0.2 text-[10px] font-mono ${
                      isSelected ? 'bg-accent text-white' : 'bg-surface-elevated text-text-muted'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Active Tab Panel Content */}
      <div className="min-h-[400px]">
        {activeTab === 'overview' && <OverviewSection report={report} />}
        {activeTab === 'security' && <SecuritySection report={report} />}
        {activeTab === 'privacy' && <PrivacySection report={report} />}
        {activeTab === 'cookies' && <CookiesSection report={report} />}
        {activeTab === 'redirects' && <RedirectsSection report={report} />}
        {activeTab === 'threat' && <ThreatSection report={report} />}
      </div>

      {/* Contextual Extension CTA */}
      <div className="pt-6">
        <ExtensionCTA />
      </div>
    </div>
  );
};
