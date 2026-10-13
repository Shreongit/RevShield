import React from 'react';
import { ArrowRight, CornerDownRight, CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';

export const RedirectsSection: React.FC<{ report: FullAnalysisReport }> = ({ report }) => {
  const { redirects } = report;

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6 border-b border-border pb-3">
          <div className="flex items-center space-x-2.5">
            <CornerDownRight className="h-5 w-5 text-accent" />
            <h3 className="text-base font-semibold text-text-primary">HTTP Redirect Chain Audit</h3>
          </div>
          <span className="text-xs font-mono text-text-muted">
            {redirects.totalHops} {redirects.totalHops === 1 ? 'hop' : 'sequential hops'}
          </span>
        </div>

        {redirects.hasSuspiciousRedirect && (
          <div className="mb-6 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 flex items-start space-x-3 text-xs text-rose-600 dark:text-rose-400">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold block">Protocol Downgrade Detected</span>
              <p className="mt-0.5 leading-relaxed">
                Traffic transitioned from secure HTTPS to unencrypted HTTP during the redirect sequence, exposing communication to interception.
              </p>
            </div>
          </div>
        )}

        {/* Visual Timeline */}
        <div className="space-y-4">
          {redirects.chain.map((hop, idx) => (
            <div key={idx} className="relative flex items-start space-x-4 group">
              {/* Step indicator */}
              <div className="flex h-8 w-8 items-center justify-center rounded-full border border-border bg-surface-elevated font-mono text-xs font-semibold text-text-primary shrink-0 z-10">
                {hop.step}
              </div>

              {/* Card */}
              <div className="flex-1 rounded-xl border border-border bg-surface-elevated p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-semibold text-text-primary">{hop.domain}</span>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                        hop.isHttps ? 'text-shield-safe bg-emerald-500/10' : 'text-shield-danger bg-rose-500/10'
                      }`}
                    >
                      {hop.isHttps ? 'HTTPS' : 'HTTP'}
                    </span>
                    {hop.isExternal && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono text-shield-warning bg-amber-500/10">
                        EXTERNAL
                      </span>
                    )}
                  </div>
                  <span className="font-mono text-[11px] text-text-secondary truncate block max-w-xl">
                    {hop.url}
                  </span>
                </div>

                <div className="shrink-0">
                  <span className="rounded bg-surface px-2 py-1 font-mono text-xs font-semibold text-text-primary border border-border">
                    HTTP {hop.statusCode}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
