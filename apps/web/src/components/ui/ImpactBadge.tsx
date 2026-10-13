import React from 'react';
import { ImpactLevel } from '@webshield/shared-types';

export const ImpactBadge: React.FC<{ impact: ImpactLevel }> = ({ impact }) => {
  const getStyles = () => {
    switch (impact) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20';
      case 'INFO':
      default:
        return 'bg-surface-elevated text-text-secondary border-border';
    }
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium border uppercase tracking-wider ${getStyles()}`}>
      Impact: {impact}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: 'PASS' | 'WARN' | 'FAIL' | 'INFO' }> = ({ status }) => {
  const getStyles = () => {
    switch (status) {
      case 'PASS':
        return 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
      case 'WARN':
        return 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30';
      case 'FAIL':
        return 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30';
      case 'INFO':
      default:
        return 'bg-surface-elevated text-text-secondary border-border';
    }
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold border uppercase tracking-wider ${getStyles()}`}>
      {status}
    </span>
  );
};
