import React from 'react';
import { Cpu, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { FullAnalysisReport } from '@webshield/shared-types';

export const ThreatSection: React.FC<{ report: FullAnalysisReport }> = ({ report }) => {
  const { threat } = report;
  const probPercent = Math.round(threat.probability * 100);

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4 border-b border-border pb-3">
          <div className="flex items-center space-x-2.5">
            <Cpu className="h-5 w-5 text-accent" />
            <h3 className="text-base font-semibold text-text-primary">Machine Learning Threat Intelligence</h3>
          </div>
          <span className="text-xs font-mono text-text-muted">
            Model: {threat.modelType}
          </span>
        </div>

        {/* Probability & Risk Meter */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="rounded-xl border border-border bg-surface-elevated p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-text-muted uppercase">Threat Probability</span>
              <span className="text-xl font-mono font-bold text-text-primary">{probPercent}%</span>
            </div>
            <div className="h-2 w-full bg-surface rounded-full overflow-hidden border border-border">
              <div
                className={`h-full transition-all duration-500 ${
                  probPercent > 50 ? 'bg-shield-danger' : probPercent > 25 ? 'bg-shield-warning' : 'bg-shield-safe'
                }`}
                style={{ width: `${Math.max(5, probPercent)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] font-mono text-text-muted">
              <span>0% (Safe)</span>
              <span>50%</span>
              <span>100% (High Risk)</span>
            </div>
          </div>

          <div className="rounded-xl border border-border bg-surface-elevated p-5 flex flex-col justify-center">
            <span className="text-xs font-mono text-text-muted uppercase mb-1">Model Classification</span>
            <span
              className={`text-xl font-mono font-bold ${
                threat.classification === 'HIGH_RISK'
                  ? 'text-shield-danger'
                  : threat.classification === 'SUSPICIOUS'
                  ? 'text-shield-warning'
                  : 'text-shield-safe'
              }`}
            >
              {threat.classification}
            </span>
            <p className="text-xs text-text-secondary mt-1">
              Confidence score: {(threat.confidenceScore * 100).toFixed(0)}%
            </p>
          </div>
        </div>

        {/* Feature Importance Breakdown */}
        {threat.featureImportance && threat.featureImportance.length > 0 && (
          <div className="space-y-3 mb-6">
            <h4 className="text-xs font-mono uppercase tracking-wider text-text-muted">
              Key Structural Factors Influencing Classification
            </h4>
            <div className="space-y-2">
              {threat.featureImportance.map((f, idx) => (
                <div key={idx} className="rounded-lg border border-border bg-surface-elevated p-3 text-xs">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-semibold text-text-primary">{f.feature}</span>
                    <span className="font-mono text-text-muted text-[11px]">Weight: {(f.impact * 100).toFixed(1)}%</span>
                  </div>
                  <p className="text-text-secondary text-[11px]">{f.explanation}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Transparency Notice */}
        <div className="rounded-xl border border-border bg-surface-elevated/50 p-3.5 flex items-start space-x-2.5 text-xs text-text-secondary">
          <Info className="h-4 w-4 text-text-muted shrink-0 mt-0.5" />
          <p className="leading-relaxed text-[11px]">{threat.notice}</p>
        </div>
      </div>
    </div>
  );
};
