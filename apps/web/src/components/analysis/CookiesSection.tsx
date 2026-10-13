import React from 'react';
import { Cookie, ShieldCheck, ShieldAlert, Clock, Globe } from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';

export const CookiesSection: React.FC<{ report: FullAnalysisReport }> = ({ report }) => {
  const { cookies } = report;

  return (
    <div className="space-y-6">
      {/* Cookie Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-border bg-surface p-4 shadow-sm">
          <span className="text-xs font-mono text-text-muted uppercase block">Total Cookies</span>
          <span className="text-2xl font-mono font-bold text-text-primary mt-1 block">{cookies.totalCookies}</span>
        </div>
        <div className="rounded-2xl border border-border bg-surface p-4 shadow-sm">
          <span className="text-xs font-mono text-text-muted uppercase block">First-Party</span>
          <span className="text-2xl font-mono font-bold text-text-primary mt-1 block">{cookies.firstPartyCount}</span>
        </div>
        <div className="rounded-2xl border border-border bg-surface p-4 shadow-sm">
          <span className="text-xs font-mono text-text-muted uppercase block">Third-Party</span>
          <span className={`text-2xl font-mono font-bold mt-1 block ${cookies.thirdPartyCount > 0 ? 'text-shield-warning' : 'text-text-primary'}`}>
            {cookies.thirdPartyCount}
          </span>
        </div>
        <div className="rounded-2xl border border-border bg-surface p-4 shadow-sm">
          <span className="text-xs font-mono text-text-muted uppercase block">Missing Secure</span>
          <span className={`text-2xl font-mono font-bold mt-1 block ${cookies.insecureCount > 0 ? 'text-shield-danger' : 'text-shield-safe'}`}>
            {cookies.insecureCount}
          </span>
        </div>
      </div>

      {/* Cookies Table */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4 border-b border-border pb-3">
          <div className="flex items-center space-x-2.5">
            <Cookie className="h-5 w-5 text-accent" />
            <h3 className="text-base font-semibold text-text-primary">Detected Cookie Storage</h3>
          </div>
          <span className="text-xs font-mono text-text-muted">
            Sensitive values redacted
          </span>
        </div>

        {cookies.items.length === 0 ? (
          <div className="rounded-xl border border-border bg-surface-elevated p-8 text-center">
            <Cookie className="h-8 w-8 text-shield-safe mx-auto mb-2 opacity-80" />
            <h4 className="text-sm font-semibold text-text-primary">No Cookies Set</h4>
            <p className="text-xs text-text-secondary mt-1 max-w-sm mx-auto">
              This webpage does not issue any HTTP Set-Cookie headers on initial load.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-surface-elevated text-text-muted border-b border-border">
                <tr>
                  <th className="py-2.5 px-3 font-semibold">Name</th>
                  <th className="py-2.5 px-3 font-semibold">Domain</th>
                  <th className="py-2.5 px-3 font-semibold">Secure</th>
                  <th className="py-2.5 px-3 font-semibold">HttpOnly</th>
                  <th className="py-2.5 px-3 font-semibold">SameSite</th>
                  <th className="py-2.5 px-3 font-semibold">Purpose</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {cookies.items.map((c, idx) => (
                  <tr key={idx} className="hover:bg-surface-elevated/50 transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-text-primary">{c.name}</td>
                    <td className="py-2.5 px-3 text-text-secondary">{c.domain}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${c.isSecure ? 'text-shield-safe bg-emerald-500/10' : 'text-shield-danger bg-rose-500/10'}`}>
                        {c.isSecure ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${c.isHttpOnly ? 'text-shield-safe bg-emerald-500/10' : 'text-text-muted bg-surface-subtle'}`}>
                        {c.isHttpOnly ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-text-secondary">{c.sameSite}</td>
                    <td className="py-2.5 px-3 font-sans text-text-secondary">{c.estimatedPurpose}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
