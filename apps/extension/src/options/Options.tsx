import React, { useState, useEffect } from 'react';
import { Shield, Plus, Trash2, CheckCircle2, RotateCcw, Power, Eye, Zap } from 'lucide-react';
import { ExtensionSettings, GlobalStats } from '../types/messages';

export const Options: React.FC = () => {
  const [settings, setSettings] = useState<ExtensionSettings>({
    protectionEnabled: true,
    blockAds: true,
    blockTrackers: true,
    blockFingerprinting: true,
    badgeCounter: true,
    whitelistedDomains: [],
  });
  const [globalStats, setGlobalStats] = useState<GlobalStats>({
    adsBlocked: 0,
    trackersBlocked: 0,
    totalBlocked: 0,
  });
  const [newDomain, setNewDomain] = useState('');
  const [saveMessage, setSaveMessage] = useState('');

  const loadData = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (res) => {
        if (res && res.settings) {
          setSettings(res.settings);
        }
      });
      chrome.runtime.sendMessage({ type: 'GET_POPUP_DATA' }, (res) => {
        if (res && res.globalStats) {
          setGlobalStats(res.globalStats);
        }
      });
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const updateSettings = (partial: Partial<ExtensionSettings>) => {
    const updated = { ...settings, ...partial };
    setSettings(updated);

    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', settings: partial }, () => {
        setSaveMessage('Settings saved');
        setTimeout(() => setSaveMessage(''), 2000);
      });
    }
  };

  const handleAddDomain = (e: React.FormEvent) => {
    e.preventDefault();
    const d = newDomain.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!d || settings.whitelistedDomains.includes(d)) return;

    const list = [...settings.whitelistedDomains, d];
    updateSettings({ whitelistedDomains: list });
    setNewDomain('');
  };

  const handleRemoveDomain = (domain: string) => {
    const list = settings.whitelistedDomains.filter((item) => item !== domain);
    updateSettings({ whitelistedDomains: list });
  };

  const handleResetStats = () => {
    if (confirm('Are you sure you want to reset all blocked statistics to zero?')) {
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.sendMessage({ type: 'RESET_STATS' }, () => {
          setGlobalStats({ adsBlocked: 0, trackersBlocked: 0, totalBlocked: 0 });
          setSaveMessage('Statistics reset');
          setTimeout(() => setSaveMessage(''), 2000);
        });
      }
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 py-12 space-y-8 font-sans">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div className="flex items-center space-x-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-subtle text-accent">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">RevShield Extension Settings</h1>
            <p className="text-xs text-text-secondary">Continuous local background protection & domain management.</p>
          </div>
        </div>
        {saveMessage && (
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full flex items-center space-x-1">
            <CheckCircle2 className="h-3 w-3" />
            <span>{saveMessage}</span>
          </span>
        )}
      </div>

      {/* Global Protection & Toggles */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm space-y-4">
        <h2 className="text-sm font-semibold text-text-primary uppercase font-mono tracking-wider">
          Protection Configuration
        </h2>

        <div className="divide-y divide-border/60">
          {/* Master Toggle */}
          <div className="flex items-center justify-between py-3">
            <div>
              <div className="text-sm font-medium text-text-primary">Master Background Protection</div>
              <div className="text-xs text-text-secondary">Enable or pause continuous DeclarativeNetRequest blocking across all websites.</div>
            </div>
            <button
              onClick={() => updateSettings({ protectionEnabled: !settings.protectionEnabled })}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                settings.protectionEnabled ? 'bg-accent' : 'bg-surface-elevated'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  settings.protectionEnabled ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Ad Blocking */}
          <div className="flex items-center justify-between py-3">
            <div>
              <div className="text-sm font-medium text-text-primary">Block Advertising Networks</div>
              <div className="text-xs text-text-secondary">Block display ads, programmatic banner networks, and monetization scripts.</div>
            </div>
            <button
              onClick={() => updateSettings({ blockAds: !settings.blockAds })}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                settings.blockAds ? 'bg-accent' : 'bg-surface-elevated'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  settings.blockAds ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Tracker Blocking */}
          <div className="flex items-center justify-between py-3">
            <div>
              <div className="text-sm font-medium text-text-primary">Block Web Trackers & Telemetry</div>
              <div className="text-xs text-text-secondary">Block session recorders, fingerprinting scripts, social pixels, and telemetry beacons.</div>
            </div>
            <button
              onClick={() => updateSettings({ blockTrackers: !settings.blockTrackers })}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                settings.blockTrackers ? 'bg-accent' : 'bg-surface-elevated'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  settings.blockTrackers ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Badge Counter */}
          <div className="flex items-center justify-between py-3">
            <div>
              <div className="text-sm font-medium text-text-primary">Show Block Badge on Toolbar</div>
              <div className="text-xs text-text-secondary">Display live counter badge over the extension icon in Chrome's toolbar.</div>
            </div>
            <button
              onClick={() => updateSettings({ badgeCounter: !settings.badgeCounter })}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                settings.badgeCounter ? 'bg-accent' : 'bg-surface-elevated'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  settings.badgeCounter ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Lifetime Blocked Statistics */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary uppercase font-mono tracking-wider">
            Lifetime Protection Statistics
          </h2>
          <button
            onClick={handleResetStats}
            className="inline-flex items-center space-x-1 text-xs text-text-muted hover:text-shield-danger transition-colors"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset Counters</span>
          </button>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-xl border border-border bg-surface-elevated p-4 text-center">
            <div className="text-xs text-text-muted font-mono uppercase">Total Threats</div>
            <div className="text-2xl font-bold font-mono text-text-primary mt-1">
              {globalStats.totalBlocked.toLocaleString()}
            </div>
          </div>
          <div className="rounded-xl border border-border bg-surface-elevated p-4 text-center">
            <div className="text-xs text-text-muted font-mono uppercase">Trackers Blocked</div>
            <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
              {globalStats.trackersBlocked.toLocaleString()}
            </div>
          </div>
          <div className="rounded-xl border border-border bg-surface-elevated p-4 text-center">
            <div className="text-xs text-text-muted font-mono uppercase">Ads Blocked</div>
            <div className="text-2xl font-bold font-mono text-accent mt-1">
              {globalStats.adsBlocked.toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Whitelist Management */}
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-sm space-y-4">
        <h2 className="text-sm font-semibold text-text-primary uppercase font-mono tracking-wider">
          Domain Whitelist ({settings.whitelistedDomains.length})
        </h2>
        <p className="text-xs text-text-secondary leading-relaxed">
          Whitelisted websites will bypass local DeclarativeNetRequest blocking rules.
        </p>

        <form onSubmit={handleAddDomain} className="flex gap-2">
          <input
            type="text"
            placeholder="example.com"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            className="flex-1 rounded-lg border border-border bg-surface-elevated px-3 py-2 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
          <button
            type="submit"
            disabled={!newDomain.trim()}
            className="rounded-lg bg-accent hover:bg-accent-hover disabled:opacity-50 text-white px-4 py-2 text-xs font-semibold shadow-sm transition-colors flex items-center space-x-1"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Add Domain</span>
          </button>
        </form>

        {settings.whitelistedDomains.length === 0 ? (
          <div className="text-center py-6 text-xs text-text-muted font-mono">
            No domains whitelisted. Protection is active on all websites.
          </div>
        ) : (
          <div className="space-y-2 max-h-60 overflow-y-auto pt-2">
            {settings.whitelistedDomains.map((domain) => (
              <div
                key={domain}
                className="flex items-center justify-between rounded-lg border border-border bg-surface-elevated p-2.5 text-xs font-mono"
              >
                <span className="text-text-primary">{domain}</span>
                <button
                  onClick={() => handleRemoveDomain(domain)}
                  className="text-text-muted hover:text-shield-danger transition-colors p-1"
                  title="Remove from whitelist"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
