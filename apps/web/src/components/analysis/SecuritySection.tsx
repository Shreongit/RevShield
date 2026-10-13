import React from 'react';
import { Lock, ShieldCheck, ShieldAlert, CheckCircle2, XCircle, AlertCircle, HelpCircle } from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';
import { ImpactBadge, StatusBadge } from '../ui/ImpactBadge';

export const SecuritySection: React.FC<{ report: FullAnalysisReport }> = ({ report }) => {
  const { tls, headers } = report;

  return (
    <div className="space-y-6">
      {/* TLS Certificate Summary */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4 border-b border-border pb-3">
          <div className="flex items-center space-x-2.5">
            <Lock className="h-5 w-5 text-accent" />
            <h3 className="text-base font-semibold text-text-primary">Transport Layer Security (TLS/SSL)</h3>
          </div>
          <StatusBadge status={tls.valid ? 'PASS' : 'FAIL'} />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="rounded-lg bg-surface-elevated border border-border p-3">
            <span className="text-text-muted block text-[10px] uppercase">Certificate Issuer</span>
            <span className="font-semibold text-text-primary truncate block mt-0.5" title={tls.issuer}>
              {tls.issuer || 'N/A'}
            </span>
          </div>

          <div className="rounded-lg bg-surface-elevated border border-border p-3">
            <span className="text-text-muted block text-[10px] uppercase">Protocol Version</span>
            <span className="font-semibold text-text-primary block mt-0.5">
              {tls.protocolVersion || 'N/A'}
            </span>
          </div>

          <div className="rounded-lg bg-surface-elevated border border-border p-3">
            <span className="text-text-muted block text-[10px] uppercase">Days Until Expiry</span>
            <span className={`font-semibold block mt-0.5 ${tls.daysRemaining < 15 ? 'text-shield-warning' : 'text-shield-safe'}`}>
              {tls.daysRemaining} days remaining
            </span>
          </div>

          <div className="rounded-lg bg-surface-elevated border border-border p-3">
            <span className="text-text-muted block text-[10px] uppercase">Cipher Suite</span>
            <span className="font-semibold text-text-primary truncate block mt-0.5" title={tls.cipherSuite || 'Default'}>
              {tls.cipherSuite || 'Standard TLS Cipher'}
            </span>
          </div>
        </div>
      </div>

      {/* Security Headers Table */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4 border-b border-border pb-3">
          <div className="flex items-center space-x-2.5">
            <ShieldCheck className="h-5 w-5 text-shield-safe" />
            <h3 className="text-base font-semibold text-text-primary">HTTP Security Response Headers</h3>
          </div>
          <span className="text-xs font-mono text-text-muted">
            {headers.filter((h) => h.present).length} of {headers.length} configured
          </span>
        </div>

        <div className="space-y-4">
          {headers.map((header) => (
            <div
              key={header.headerName}
              className="rounded-xl border border-border bg-surface-elevated p-4 transition-colors hover:border-border-focus"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                <div className="flex items-center space-x-2.5">
                  {header.present ? (
                    <CheckCircle2 className="h-4 w-4 text-shield-safe shrink-0" />
                  ) : (
                    <XCircle className="h-4 w-4 text-shield-danger shrink-0" />
                  )}
                  <span className="font-mono text-sm font-semibold text-text-primary">
                    {header.headerName}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <StatusBadge status={header.present ? (header.status === 'OPTIMAL' ? 'PASS' : 'WARN') : 'FAIL'} />
                  <ImpactBadge impact={header.impact} />
                </div>
              </div>

              <p className="text-xs text-text-secondary leading-relaxed mb-2">
                {header.explanation}
              </p>

              {header.value && (
                <div className="rounded bg-surface p-2 font-mono text-[11px] text-text-primary overflow-x-auto border border-border mb-2">
                  <span className="text-text-muted">Value: </span>
                  {header.value}
                </div>
              )}

              {header.recommendation && (
                <div className="rounded bg-accent-subtle/50 p-2.5 text-xs text-text-secondary border border-accent/20">
                  <span className="font-semibold text-accent block text-[11px] mb-0.5">Recommended Configuration:</span>
                  <code className="font-mono text-[11px] text-text-primary">{header.recommendation}</code>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
