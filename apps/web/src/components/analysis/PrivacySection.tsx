import React from 'react';
import { Eye, ShieldBan, Fingerprint, Layers, Activity } from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';
import { ImpactBadge } from '../ui/ImpactBadge';

export const PrivacySection: React.FC<{ report: FullAnalysisReport }> = ({ report }) => {
  const { privacy } = report;

  const getCategoryBadge = (category: string) => {
    switch (category) {
      case 'ANALYTICS':
        return 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20';
      case 'ADVERTISING':
        return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20';
      case 'SOCIAL':
        return 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20';
      case 'SESSION_REPLAY':
        return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20';
      case 'FINGERPRINTING':
        return 'bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30';
      default:
        return 'bg-surface-elevated text-text-secondary border-border';
    }
  };

  return (
    <div className="space-y-6">
      {/* Privacy Stats Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-2xl border border-border bg-surface p-5 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-text-muted uppercase">Third-Party Requests</span>
            <Layers className="h-4 w-4 text-accent" />
          </div>
          <span className="text-3xl font-mono font-bold text-text-primary">
            {privacy.totalThirdPartyRequests}
          </span>
          <p className="text-xs text-text-secondary mt-1">External resource network calls</p>
        </div>

        <div className="rounded-2xl border border-border bg-surface p-5 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-text-muted uppercase">Known Trackers</span>
            <Eye className="h-4 w-4 text-shield-warning" />
          </div>
          <span className="text-3xl font-mono font-bold text-text-primary">
            {privacy.trackerCount}
          </span>
          <p className="text-xs text-text-secondary mt-1">Identified profiling services</p>
        </div>

        <div className="rounded-2xl border border-border bg-surface p-5 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-text-muted uppercase">Device Fingerprinting</span>
            <Fingerprint className="h-4 w-4 text-shield-danger" />
          </div>
          <span className={`text-xl font-mono font-bold ${privacy.fingerprintingDetected ? 'text-shield-danger' : 'text-shield-safe'}`}>
            {privacy.fingerprintingDetected ? 'DETECTED' : 'NOT DETECTED'}
          </span>
          <p className="text-xs text-text-secondary mt-1">Hardware / canvas signature vectors</p>
        </div>
      </div>

      {/* Trackers Detailed List */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4 border-b border-border pb-3">
          <div className="flex items-center space-x-2.5">
            <ShieldBan className="h-5 w-5 text-accent" />
            <h3 className="text-base font-semibold text-text-primary">Detected Trackers & Analytics Networks</h3>
          </div>
          <span className="text-xs font-mono text-text-muted">
            {privacy.trackers.length} entities categorized
          </span>
        </div>

        {privacy.trackers.length === 0 ? (
          <div className="rounded-xl border border-border bg-surface-elevated p-8 text-center">
            <Eye className="h-8 w-8 text-shield-safe mx-auto mb-2 opacity-80" />
            <h4 className="text-sm font-semibold text-text-primary">Zero Trackers Detected</h4>
            <p className="text-xs text-text-secondary mt-1 max-w-sm mx-auto">
              This website did not load any known commercial tracking pixels, behavioral telemetry scripts, or session recorders.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {privacy.trackers.map((t, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-border bg-surface-elevated p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <span className="font-mono text-sm font-semibold text-text-primary">{t.domain}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border uppercase ${getCategoryBadge(t.category)}`}>
                      {t.category}
                    </span>
                  </div>
                  <p className="text-xs text-text-secondary leading-normal">{t.description}</p>
                  {t.owner && (
                    <span className="text-[11px] text-text-muted font-mono block">Operated by: {t.owner}</span>
                  )}
                </div>

                <div className="flex sm:flex-col items-center sm:items-end justify-between sm:justify-center shrink-0 border-t sm:border-t-0 border-border pt-2 sm:pt-0">
                  <span className="text-xs font-mono font-semibold text-text-primary">
                    {t.requestCount} {t.requestCount === 1 ? 'request' : 'requests'}
                  </span>
                  <ImpactBadge impact={t.impact} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
