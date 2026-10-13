import React from 'react';
import { Link } from 'react-router-dom';
import { Chrome, Shield, CheckCircle, ArrowRight } from 'lucide-react';

export const ExtensionCTA: React.FC = () => {
  return (
    <div className="rounded-2xl border border-accent/30 bg-gradient-to-br from-surface to-surface-elevated p-6 sm:p-8 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-2 max-w-xl">
          <div className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-accent-subtle text-accent border border-accent/20">
            <Chrome className="h-3.5 w-3.5" />
            <span>Continuous Protection</span>
          </div>
          <h3 className="text-xl font-semibold text-text-primary tracking-tight">
            Protect your browsing automatically with the RevShield Extension.
          </h3>
          <p className="text-xs sm:text-sm text-text-secondary leading-relaxed">
            Analyze every visited website in real time and automatically block intrusive trackers, telemetry beacons, and advertising networks locally on your device.
          </p>
          <div className="flex items-center space-x-4 pt-1 text-xs text-text-muted">
            <span className="flex items-center space-x-1">
              <CheckCircle className="h-3.5 w-3.5 text-shield-safe" />
              <span>100% Local Blocking</span>
            </span>
            <span className="flex items-center space-x-1">
              <CheckCircle className="h-3.5 w-3.5 text-shield-safe" />
              <span>Free & Open Source</span>
            </span>
          </div>
        </div>

        <div className="shrink-0 flex flex-col sm:flex-row md:flex-col gap-2.5">
          <Link
            to="/extension"
            className="inline-flex items-center justify-center space-x-2 rounded-xl bg-accent hover:bg-accent-hover text-white px-5 py-2.5 text-sm font-medium shadow-sm transition-all"
          >
            <Chrome className="h-4 w-4" />
            <span>Get the Extension</span>
            <ArrowRight className="h-4 w-4" />
          </Link>
          <span className="text-[11px] text-center text-text-muted">Available for Chromium browsers</span>
        </div>
      </div>
    </div>
  );
};
