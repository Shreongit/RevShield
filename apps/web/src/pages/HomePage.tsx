import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, ArrowRight, ShieldCheck, Eye, Zap, AlertTriangle, Lock, Layers, Terminal } from 'lucide-react';
import { submitAnalysis, getAnalysisStatus } from '../services/api';
import { LiveProgressStepper } from '../components/analysis/LiveProgressStepper';
import { ExtensionCTA } from '../components/analysis/ExtensionCTA';
import { AnalysisStatusResponse } from '@webshield/shared-types';

const SAMPLE_DOMAINS = ['github.com', 'wikipedia.org', 'cloudflare.com', 'mozilla.org'];

export const HomePage: React.FC = () => {
  const [urlInput, setUrlInput] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [analysisStatus, setAnalysisStatus] = useState<AnalysisStatusResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleAnalyze = async (targetUrl?: string) => {
    const raw = (targetUrl || urlInput).trim();
    if (!raw) return;

    setErrorMessage(null);
    setIsSubmitting(true);

    try {
      const initialStatus = await submitAnalysis(raw);
      setAnalysisStatus(initialStatus);

      // If already cached and complete, navigate directly
      if (initialStatus.isComplete && initialStatus.domain) {
        navigate(`/report/${initialStatus.domain}`);
        return;
      }

      // Start polling
      const pollInterval = setInterval(async () => {
        try {
          const status = await getAnalysisStatus(initialStatus.analysisId);
          setAnalysisStatus(status);

          if (status.isComplete) {
            clearInterval(pollInterval);
            setIsSubmitting(false);
            if (status.error) {
              setErrorMessage(status.error);
            } else if (status.domain) {
              navigate(`/report/${status.domain}`);
            }
          }
        } catch {
          clearInterval(pollInterval);
          setIsSubmitting(false);
          setErrorMessage('Lost connection to analysis worker.');
        }
      }, 800);
    } catch (err: any) {
      setIsSubmitting(false);
      setErrorMessage(err.message || 'Failed to submit analysis');
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      {/* Hero Section */}
      <section className="relative px-4 pt-16 pb-20 sm:px-6 lg:px-8 max-w-5xl mx-auto w-full text-center">
        {/* Small product mark */}
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full border border-border bg-surface text-xs font-medium text-text-secondary mb-6 shadow-sm">
          <Shield className="h-3.5 w-3.5 text-accent" />
          <span className="font-semibold text-text-primary">RevShield 1.0</span>
          <span>&bull;</span>
          <span>Open-Source Intelligence</span>
        </div>

        {/* Large Headline */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-text-primary max-w-4xl mx-auto leading-[1.15]">
          Understand what happens <br className="hidden sm:inline" />
          <span className="text-accent">behind every website.</span>
        </h1>

        {/* Supporting text */}
        <p className="mt-5 text-base sm:text-lg text-text-secondary max-w-2xl mx-auto leading-relaxed">
          Analyze any website for security, privacy, trackers, advertising networks, cookies, and suspicious behavior.
        </p>

        {/* Large URL Input Hero */}
        <div className="mt-10 max-w-2xl mx-auto">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAnalyze();
            }}
            className="relative flex flex-col sm:flex-row items-center gap-2 p-2 rounded-2xl border border-border bg-surface shadow-md focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/20 transition-all"
          >
            <div className="flex items-center pl-3 w-full">
              <Search className="h-5 w-5 text-text-muted shrink-0 mr-2.5" />
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com"
                disabled={isSubmitting}
                className="w-full bg-transparent font-mono text-sm sm:text-base text-text-primary placeholder:text-text-muted focus:outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={isSubmitting || !urlInput.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 rounded-xl bg-accent hover:bg-accent-hover disabled:opacity-50 text-white px-6 py-3 text-sm font-semibold tracking-tight shadow-sm shrink-0 transition-all"
            >
              <span>{isSubmitting ? 'Analyzing...' : 'Analyze website'}</span>
              <ArrowRight className="h-4 w-4" />
            </button>
          </form>

          {/* Sample quick presets */}
          <div className="mt-3 flex items-center justify-center flex-wrap gap-2 text-xs font-mono text-text-muted">
            <span>Try sample:</span>
            {SAMPLE_DOMAINS.map((domain) => (
              <button
                key={domain}
                onClick={() => {
                  setUrlInput(domain);
                  handleAnalyze(domain);
                }}
                disabled={isSubmitting}
                className="hover:text-accent hover:underline focus:outline-none transition-colors"
              >
                {domain}
              </button>
            ))}
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-600 dark:text-rose-400 flex items-center justify-center space-x-2 text-left">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        {/* Live Stepper when submitting */}
        {isSubmitting && analysisStatus && (
          <div className="mt-10">
            <LiveProgressStepper
              currentStage={analysisStatus.stage}
              progress={analysisStatus.stageProgress}
              stageMessage={analysisStatus.stageMessage}
              error={errorMessage || undefined}
            />
          </div>
        )}

        {/* Capability Indicators Grid (Subtle, non-card inline badges) */}
        {!isSubmitting && (
          <div className="mt-14 pt-8 border-t border-border/60 max-w-4xl mx-auto">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 text-center">
              <div className="flex flex-col items-center space-y-1">
                <Lock className="h-4 w-4 text-accent" />
                <span className="text-xs font-medium text-text-primary">Security Audit</span>
                <span className="text-[11px] text-text-muted">HTTPS, TLS & Headers</span>
              </div>
              <div className="flex flex-col items-center space-y-1">
                <Eye className="h-4 w-4 text-shield-low" />
                <span className="text-xs font-medium text-text-primary">Privacy Analysis</span>
                <span className="text-[11px] text-text-muted">3rd-Party Resources</span>
              </div>
              <div className="flex flex-col items-center space-y-1">
                <Layers className="h-4 w-4 text-shield-warning" />
                <span className="text-xs font-medium text-text-primary">Tracker Detection</span>
                <span className="text-[11px] text-text-muted">Telemetry & Pixels</span>
              </div>
              <div className="flex flex-col items-center space-y-1">
                <Zap className="h-4 w-4 text-shield-danger" />
                <span className="text-xs font-medium text-text-primary">Ad Network Audit</span>
                <span className="text-[11px] text-text-muted">Monetization Calls</span>
              </div>
              <div className="flex flex-col items-center space-y-1 col-span-2 sm:col-span-1">
                <AlertTriangle className="h-4 w-4 text-shield-warning" />
                <span className="text-xs font-medium text-text-primary">Phishing Heuristics</span>
                <span className="text-[11px] text-text-muted">ML Threat Model</span>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* How it Works Section */}
      <section className="py-16 border-t border-border bg-surface/30 px-4 sm:px-6 lg:px-8">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="text-xs font-mono uppercase tracking-widest text-accent font-semibold">Methodology</span>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-text-primary mt-1">
              Transparent, Multi-Vector Intelligence
            </h2>
            <p className="text-xs sm:text-sm text-text-secondary mt-2">
              Every submitted URL is analyzed across isolated execution stages to inspect structural integrity and data leakage.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="rounded-2xl border border-border bg-surface p-6 space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-subtle text-accent font-mono font-bold text-sm">
                01
              </div>
              <h3 className="text-base font-semibold text-text-primary">Network & Transport Audit</h3>
              <p className="text-xs text-text-secondary leading-relaxed">
                Verifies cryptographic TLS certificates, cipher suite robustness, HSTS enforcement, and hop-by-hop HTTP redirect behavior.
              </p>
            </div>

            <div className="rounded-2xl border border-border bg-surface p-6 space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-subtle text-accent font-mono font-bold text-sm">
                02
              </div>
              <h3 className="text-base font-semibold text-text-primary">Tracker & Privacy Taxonomy</h3>
              <p className="text-xs text-text-secondary leading-relaxed">
                Categorizes all third-party scripts, advertising pixels, session replay beacons, and canvas fingerprinting vectors against curated databases.
              </p>
            </div>

            <div className="rounded-2xl border border-border bg-surface p-6 space-y-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-subtle text-accent font-mono font-bold text-sm">
                03
              </div>
              <h3 className="text-base font-semibold text-text-primary">Interpretable Threat ML</h3>
              <p className="text-xs text-text-secondary leading-relaxed">
                Extracts 25+ lexical and structural features to compute calibrated phishing probability with transparent factor attribution.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Extension CTA Container */}
      <section className="py-16 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto w-full">
        <ExtensionCTA />
      </section>
    </div>
  );
};
