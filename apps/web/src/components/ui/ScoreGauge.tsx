import React from 'react';
import { RiskLevel } from '@webshield/shared-types';

interface ScoreGaugeProps {
  score: number;
  risk: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
  label?: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, risk, size = 'lg', label = 'Overall Score' }) => {
  // Score color calculation
  const getColor = (s: number) => {
    if (s >= 80) return '#10b981'; // Emerald
    if (s >= 60) return '#3b82f6'; // Blue
    if (s >= 40) return '#f59e0b'; // Amber
    return '#f43f5e'; // Coral
  };

  const color = getColor(score);

  // SVG parameters
  const radius = size === 'lg' ? 68 : size === 'md' ? 48 : 34;
  const strokeWidth = size === 'lg' ? 8 : size === 'md' ? 6 : 4;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getRiskBadge = (r: RiskLevel) => {
    switch (r) {
      case 'SAFE':
        return { text: 'SAFE & RESILIENT', bg: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20' };
      case 'LOW_RISK':
        return { text: 'LOW RISK', bg: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20' };
      case 'SUSPICIOUS':
        return { text: 'MODERATE RISK', bg: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' };
      case 'HIGH_RISK':
        return { text: 'HIGH RISK', bg: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' };
    }
  };

  const badge = getRiskBadge(risk);

  return (
    <div className="flex flex-col items-center justify-center text-center">
      <div className="relative flex items-center justify-center">
        <svg
          className="transform -rotate-90"
          width={radius * 2 + strokeWidth * 2}
          height={radius * 2 + strokeWidth * 2}
        >
          {/* Background track */}
          <circle
            cx={radius + strokeWidth}
            cy={radius + strokeWidth}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            fill="transparent"
            className="text-surface-subtle"
          />
          {/* Active progress arc */}
          <circle
            cx={radius + strokeWidth}
            cy={radius + strokeWidth}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Typography */}
        <div className="absolute flex flex-col items-center justify-center">
          <span
            className={`font-semibold font-mono tracking-tight text-text-primary ${
              size === 'lg' ? 'text-4xl' : size === 'md' ? 'text-2xl' : 'text-lg'
            }`}
          >
            {score}
          </span>
          {size === 'lg' && (
            <span className="text-[11px] uppercase tracking-wider text-text-muted font-medium -mt-1">
              out of 100
            </span>
          )}
        </div>
      </div>

      {size === 'lg' && (
        <div className="mt-4 flex flex-col items-center space-y-1.5">
          <span className="text-xs uppercase font-mono tracking-widest text-text-muted">{label}</span>
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold border ${badge.bg}`}>
            {badge.text}
          </span>
        </div>
      )}
    </div>
  );
};
