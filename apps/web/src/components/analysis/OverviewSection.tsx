import React from 'react';
import { Shield, Lock, Eye, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';
import { ScoreGauge } from '../ui/ScoreGauge';

export const OverviewSection: React.FC<{ report: FullAnalysisReport }> = ({ report }) => {
  const { scores } = report;

  return (
    <div className="space-y-6">
      {/* Top Banner Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 rounded-2xl border border-border bg-surface p-6 sm:p-8 shadow-sm">
        {/* Score Gauge */}
        <div className="flex items-center justify-center border-b lg:border-b-0 lg:border-r border-border pb-6 lg:pb-0 lg:pr-8">
          <ScoreGauge score={scores.overallScore} risk={scores.riskClassification} size="lg" />
        </div>

        {/* Sub-Scores Grid */}
        <div className="lg:col-span-2 flex flex-col justify-center space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Security Subscore */}
            <div className="rounded-xl border border-border bg-surface-elevated p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-text-muted uppercase">Security</span>
                <Lock className="h-4 w-4 text-accent" />
              </div>
              <div className="flex items-baseline space-x-1.5">
                <span className="text-2xl font-mono font-semibold text-text-primary">{scores.securityScore}</span>
                <span className="text-xs text-text-muted font-mono">/ 100</span>
              </div>
              <p className="text-[11px] text-text-secondary mt-1">HTTPS, TLS & Headers</p>
            </div>

            {/* Privacy Subscore */}
            <div className="rounded-xl border border-border bg-surface-elevated p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-text-muted uppercase">Privacy</span>
                <Eye className="h-4 w-4 text-shield-low" />
              </div>
              <div className="flex items-baseline space-x-1.5">
                <span className="text-2xl font-mono font-semibold text-text-primary">{scores.privacyScore}</span>
                <span className="text-xs text-text-muted font-mono">/ 100</span>
              </div>
              <p className="text-[11px] text-text-secondary mt-1">Trackers, Ads & Cookies</p>
            </div>

            {/* Threat Subscore */}
            <div className="rounded-xl border border-border bg-surface-elevated p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-text-muted uppercase">Threat Defense</span>
                <AlertTriangle className="h-4 w-4 text-shield-warning" />
              </div>
              <div className="flex items-baseline space-x-1.5">
                <span className="text-2xl font-mono font-semibold text-text-primary">{scores.threatScore}</span>
                <span className="text-xs text-text-muted font-mono">/ 100</span>
              </div>
              <p className="text-[11px] text-text-secondary mt-1">Phishing & Homographs</p>
            </div>
          </div>

          {/* Quick Metrics Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 border-t border-border pt-4 text-xs font-mono">
            <div>
              <span className="text-text-muted block text-[10px] uppercase">Trackers</span>
              <span className="font-semibold text-text-primary">{report.privacy.trackerCount} detected</span>
            </div>
            <div>
              <span className="text-text-muted block text-[10px] uppercase">Ad Networks</span>
              <span className="font-semibold text-text-primary">{report.privacy.adNetworkCount} active</span>
            </div>
            <div>
              <span className="text-text-muted block text-[10px] uppercase">Cookies</span>
              <span className="font-semibold text-text-primary">{report.cookies.totalCookies} stored</span>
            </div>
            <div>
              <span className="text-text-muted block text-[10px] uppercase">TLS Protocol</span>
              <span className="font-semibold text-text-primary">{report.tls.protocolVersion || 'None'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Transparent Score Breakdown Factors */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <h3 className="text-sm font-semibold text-text-primary uppercase font-mono tracking-wider mb-4 flex items-center space-x-2">
          <span>Score Attribution & Factors</span>
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {scores.factors.map((factor, idx) => (
            <div
              key={idx}
              className="flex items-start space-x-3 rounded-lg border border-border bg-surface-elevated p-3 text-xs"
            >
              {factor.type === 'POSITIVE' ? (
                <CheckCircle className="h-4 w-4 text-shield-safe shrink-0 mt-0.5" />
              ) : (
                <XCircle className="h-4 w-4 text-shield-danger shrink-0 mt-0.5" />
              )}
              <div className="flex flex-col">
                <div className="flex items-center space-x-2">
                  <span className="font-medium text-text-primary">{factor.name}</span>
                  <span
                    className={`font-mono text-[10px] font-bold ${
                      factor.impactPoints > 0 ? 'text-shield-safe' : 'text-shield-danger'
                    }`}
                  >
                    {factor.impactPoints > 0 ? `+${factor.impactPoints}` : factor.impactPoints} pts
                  </span>
                </div>
                <p className="text-text-secondary text-[11px] mt-0.5 leading-relaxed">{factor.reason}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
