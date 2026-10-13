import React, { useState } from 'react';
import { Chrome, Shield, ShieldCheck, EyeOff, Zap, Download, ToggleLeft, ToggleRight, CheckCircle2, ChevronRight, Lock, Layers } from 'lucide-react';

export const ExtensionPage: React.FC = () => {
  const [demoProtectionOn, setDemoProtectionOn] = useState(true);

  return (
    <div className="flex flex-col min-h-screen py-12 px-4 sm:px-6 lg:px-8 max-w-6xl mx-auto w-full space-y-16">
      {/* Hero Section */}
      <section className="text-center max-w-3xl mx-auto space-y-4">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full border border-border bg-surface text-xs font-mono font-medium text-text-secondary">
          <Chrome className="h-3.5 w-3.5 text-accent" />
          <span>Manifest V3 Extension</span>
          <span>&bull;</span>
          <span>Zero-Latency Blocking</span>
        </div>

        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-text-primary">
          Continuous Real-Time Protection <br />
          <span className="text-accent">Right Inside Your Browser.</span>
        </h1>

        <p className="text-sm sm:text-base text-text-secondary leading-relaxed">
          The RevShield extension blocks ads, trackers, and fingerprinting vectors locally using native DeclarativeNetRequest rules without slowing down page rendering or transmitting your browsing history.
        </p>

        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <a
            href="#install-guide"
            className="inline-flex items-center space-x-2 rounded-xl bg-accent hover:bg-accent-hover text-white px-6 py-3 text-sm font-semibold shadow-sm transition-all"
          >
            <Download className="h-4 w-4" />
            <span>Install RevShield Extension</span>
          </a>
          <a
            href="https://github.com/ifshreyas/RevShield/tree/main/apps/extension"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center space-x-2 rounded-xl border border-border bg-surface hover:bg-surface-elevated px-5 py-3 text-sm font-semibold text-text-primary transition-all"
          >
            <span>View Extension Source</span>
          </a>
        </div>
      </section>

      {/* Interactive Extension Interface Preview & Architecture Feature Grid */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Architecture details */}
        <div className="lg:col-span-7 space-y-6">
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-widest text-accent font-semibold">Core Architecture</span>
            <h2 className="text-2xl font-bold text-text-primary tracking-tight">
              Engineered for absolute privacy & speed
            </h2>
          </div>

          <div className="space-y-4">
            <div className="rounded-xl border border-border bg-surface p-4 flex items-start space-x-3.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 text-shield-safe shrink-0 mt-0.5">
                <Lock className="h-4 w-4" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-text-primary">100% Local Rule Execution</h3>
                <p className="text-xs text-text-secondary leading-relaxed">
                  Blocking happens inside Chromium's network engine via DeclarativeNetRequest. Your browsing data never leaves your device.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-surface p-4 flex items-start space-x-3.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10 text-accent shrink-0 mt-0.5">
                <Zap className="h-4 w-4" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-text-primary">Zero Performance Overhead</h3>
                <p className="text-xs text-text-secondary leading-relaxed">
                  No heavy DOM observers or synchronous JavaScript hooks. Pages load up to 40% faster by aborting tracking scripts before execution.
                </p>
              </div>
            </div>

            <div className="rounded-xl border border-border bg-surface p-4 flex items-start space-x-3.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/10 text-shield-low shrink-0 mt-0.5">
                <Layers className="h-4 w-4" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-text-primary">Granular Per-Site Whitelist</h3>
                <p className="text-xs text-text-secondary leading-relaxed">
                  Easily toggle protection on or off for specific domains with one click directly from the browser popup.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* High-Fidelity Interactive Mockup of Extension Popup */}
        <div className="lg:col-span-5 flex justify-center">
          <div className="w-full max-w-[340px] rounded-2xl border-2 border-border bg-surface shadow-2xl p-5 space-y-4 font-sans">
            {/* Extension Header */}
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-accent" />
                <span className="text-sm font-bold tracking-tight text-text-primary">RevShield</span>
              </div>
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-accent-subtle text-accent border border-accent/20">
                ACTIVE
              </span>
            </div>

            {/* Current Site Status */}
            <div className="rounded-xl bg-surface-elevated border border-border p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-semibold text-text-primary">example.com</span>
                <span className="text-[10px] font-mono text-text-muted">HTTPS Valid</span>
              </div>
              <div className="flex items-center justify-between pt-1">
                <span className="text-xs text-text-secondary">Protection Status</span>
                <button
                  onClick={() => setDemoProtectionOn(!demoProtectionOn)}
                  className="text-accent hover:text-accent-hover transition-colors"
                >
                  {demoProtectionOn ? (
                    <ToggleRight className="h-6 w-6 text-shield-safe" />
                  ) : (
                    <ToggleLeft className="h-6 w-6 text-text-muted" />
                  )}
                </button>
              </div>
            </div>

            {/* Stats Breakdown */}
            <div className="grid grid-cols-2 gap-2 text-center">
              <div className="rounded-lg bg-surface-elevated border border-border p-2.5">
                <span className="text-[10px] font-mono text-text-muted uppercase block">Trackers Blocked</span>
                <span className="text-xl font-mono font-bold text-text-primary mt-0.5 block">
                  {demoProtectionOn ? 7 : 0}
                </span>
              </div>
              <div className="rounded-lg bg-surface-elevated border border-border p-2.5">
                <span className="text-[10px] font-mono text-text-muted uppercase block">Ads Blocked</span>
                <span className="text-xl font-mono font-bold text-text-primary mt-0.5 block">
                  {demoProtectionOn ? 14 : 0}
                </span>
              </div>
            </div>

            {/* Deep link CTA inside popup */}
            <button
              onClick={() => alert('This opens the detailed RevShield intelligence report in a new tab.')}
              className="w-full rounded-xl bg-accent hover:bg-accent-hover text-white py-2 text-xs font-semibold shadow-sm transition-colors flex items-center justify-center space-x-1.5"
            >
              <span>View Detailed Analysis</span>
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </section>

      {/* Installation Guide */}
      <section id="install-guide" className="rounded-2xl border border-border bg-surface p-8 space-y-6">
        <div className="border-b border-border pb-4">
          <span className="text-xs font-mono uppercase tracking-widest text-accent font-semibold">Quick Setup</span>
          <h2 className="text-xl font-bold text-text-primary mt-1">
            Loading the Extension Locally (Developer Mode)
          </h2>
        </div>

        <ol className="space-y-4 text-xs sm:text-sm text-text-secondary list-decimal list-inside leading-relaxed">
          <li>
            <strong className="text-text-primary">Build the extension:</strong> Run{' '}
            <code className="font-mono bg-surface-elevated px-2 py-0.5 rounded text-accent">npm run build:extension</code> from the root folder.
          </li>
          <li>
            <strong className="text-text-primary">Open Browser Extensions:</strong> Navigate to{' '}
            <code className="font-mono bg-surface-elevated px-2 py-0.5 rounded text-text-primary">chrome://extensions</code> in Chrome, Brave, Edge, or Arc.
          </li>
          <li>
            <strong className="text-text-primary">Enable Developer Mode:</strong> Toggle the "Developer mode" switch in the top-right corner.
          </li>
          <li>
            <strong className="text-text-primary">Load Unpacked:</strong> Click <strong className="text-text-primary">"Load unpacked"</strong> and select the <code className="font-mono">apps/extension/dist</code> folder.
          </li>
        </ol>
      </section>
    </div>
  );
};
