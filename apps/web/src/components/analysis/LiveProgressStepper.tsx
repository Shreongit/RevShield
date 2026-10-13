import React from 'react';
import { CheckCircle2, Circle, Loader2, AlertCircle } from 'lucide-react';
import { AnalysisStage } from '@webshield/shared-types';

interface LiveProgressStepperProps {
  currentStage: AnalysisStage;
  progress: number;
  stageMessage: string;
  error?: string;
}

const STAGES: { key: AnalysisStage; label: string }[] = [
  { key: 'VALIDATING_URL', label: 'Validating URL & Network Safety' },
  { key: 'INSPECTING_TLS', label: 'Inspecting TLS / SSL Handshake' },
  { key: 'ANALYZING_HEADERS', label: 'Auditing HTTP Security Headers' },
  { key: 'TRACING_REDIRECTS', label: 'Tracing Redirect Chain' },
  { key: 'DETECTING_TRACKERS', label: 'Detecting Trackers & Advertising' },
  { key: 'ANALYZING_COOKIES', label: 'Auditing Cookie & Storage Vectors' },
  { key: 'EVALUATING_THREATS', label: 'Evaluating Machine Learning Threats' },
  { key: 'CALCULATING_SCORE', label: 'Synthesizing Intelligence Report' }
];

export const LiveProgressStepper: React.FC<LiveProgressStepperProps> = ({
  currentStage,
  progress,
  stageMessage,
  error
}) => {
  const currentStageIndex = STAGES.findIndex((s) => s.key === currentStage);

  return (
    <div className="w-full max-w-xl mx-auto rounded-2xl border border-border bg-surface p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-xs uppercase font-mono tracking-widest text-accent font-semibold">Live Inspection</span>
          <h3 className="text-lg font-semibold text-text-primary tracking-tight">Analyzing Target Website</h3>
        </div>
        <span className="text-sm font-mono font-bold text-accent">{progress}%</span>
      </div>

      {/* Progress Track */}
      <div className="h-1.5 w-full bg-surface-subtle rounded-full overflow-hidden mb-6">
        <div
          className="h-full bg-accent transition-all duration-500 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Current Stage Message */}
      <div className="rounded-lg bg-surface-elevated border border-border p-3 mb-6 flex items-start space-x-3">
        {error ? (
          <AlertCircle className="h-5 w-5 text-shield-danger shrink-0 mt-0.5" />
        ) : (
          <Loader2 className="h-5 w-5 text-accent animate-spin shrink-0 mt-0.5" />
        )}
        <div className="flex flex-col">
          <span className="text-xs font-mono text-text-muted uppercase">Current Stage</span>
          <span className={`text-sm ${error ? 'text-shield-danger font-medium' : 'text-text-primary'}`}>
            {error || stageMessage}
          </span>
        </div>
      </div>

      {/* Checklist items */}
      <div className="space-y-2.5">
        {STAGES.map((s, idx) => {
          const isDone = currentStage === 'COMPLETED' || (currentStageIndex > idx && currentStageIndex !== -1);
          const isCurrent = s.key === currentStage;

          return (
            <div key={s.key} className="flex items-center space-x-3 text-xs">
              {isDone ? (
                <CheckCircle2 className="h-4 w-4 text-shield-safe shrink-0" />
              ) : isCurrent ? (
                <Loader2 className="h-4 w-4 text-accent animate-spin shrink-0" />
              ) : (
                <Circle className="h-4 w-4 text-text-muted shrink-0 opacity-40" />
              )}
              <span
                className={`font-medium ${
                  isDone
                    ? 'text-text-secondary'
                    : isCurrent
                    ? 'text-text-primary font-semibold'
                    : 'text-text-muted'
                }`}
              >
                {s.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
