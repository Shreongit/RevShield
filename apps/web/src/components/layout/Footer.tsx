import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Github, EyeOff } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-border bg-surface/50 mt-auto">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand Col */}
          <div className="space-y-3 md:col-span-1">
            <div className="flex items-center space-x-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-accent text-white">
                <Shield className="h-4 w-4" />
              </div>
              <span className="font-semibold text-text-primary tracking-tight">RevShield</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed">
              Open-source web privacy & security intelligence engine. Auditing trackers, TLS certificates, headers, cookies, and phishing risks.
            </p>
          </div>

          {/* Product Links */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-text-muted">Product</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <Link to="/" className="text-text-secondary hover:text-text-primary transition-colors">
                  Website Analyzer
                </Link>
              </li>
              <li>
                <Link to="/extension" className="text-text-secondary hover:text-text-primary transition-colors">
                  Browser Extension
                </Link>
              </li>
            </ul>
          </div>

          {/* Transparency / Docs */}
          <div className="space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-text-muted">Transparency</h4>
            <ul className="space-y-2 text-xs">
              <li>
                <a
                  href="https://github.com/ifshreyas/RevShield"
                  target="_blank"
                  rel="noreferrer"
                  className="text-text-secondary hover:text-text-primary transition-colors"
                >
                  Open Source Code
                </a>
              </li>
              <li>
                <span className="text-text-muted">Transparent Scoring Methodology</span>
              </li>
              <li>
                <span className="text-text-muted">Anti-SSRF Architecture</span>
              </li>
            </ul>
          </div>

          {/* Core Philosophy Box */}
          <div className="space-y-2 rounded-xl border border-border p-4 bg-surface">
            <div className="flex items-center space-x-2 text-xs font-medium text-text-primary">
              <EyeOff className="h-4 w-4 text-accent" />
              <span>Zero-Tracking Guarantee</span>
            </div>
            <p className="text-[11px] text-text-secondary leading-normal">
              RevShield never stores sensitive request payloads, personal browsing histories, or authentication tokens.
            </p>
          </div>
        </div>

        <div className="border-t border-border pt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-text-muted">
            &copy; {new Date().getFullYear()} RevShield. Released under MIT Open Source License.
          </p>
          <div className="flex items-center space-x-6 text-xs text-text-muted">
            <span>No Account Required</span>
            <span>&bull;</span>
            <span>No Ads</span>
            <span>&bull;</span>
            <span>Client-Side Local Blocking</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
