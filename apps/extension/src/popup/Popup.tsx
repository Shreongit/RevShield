import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Settings, ExternalLink, Eye, Zap, Info, Power } from 'lucide-react';
import { normalizeDomain, isInternalOrBrowserUrl, isPrivateOrLocalHost } from '@webshield/shared-utils';
import { PopupDataResponse } from '../types/messages';

export const Popup: React.FC = () => {
  const [data, setData] = useState<PopupDataResponse | null>(null);
  const [currentDomain, setCurrentDomain] = useState<string>('Detecting...');
  const [isInternal, setIsInternal] = useState<boolean>(false);
  const [currentTabId, setCurrentTabId] = useState<number | undefined>(undefined);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchPopupData = useCallback((tabId?: number, domain?: string) => {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage(
        { type: 'GET_POPUP_DATA', tabId, domain },
        (response: PopupDataResponse) => {
          if (response && !('error' in response)) {
            setData(response);
          }
          setIsLoading(false);
        }
      );
    }
  }, []);

  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (tab && tab.url) {
          const tabId = tab.id;
          setCurrentTabId(tabId);

          if (isInternalOrBrowserUrl(tab.url)) {
            setIsInternal(true);
            setCurrentDomain('Browser Internal Page');
            fetchPopupData(tabId, '');
            return;
          }

          const domain = normalizeDomain(tab.url);
          if (!domain) {
            setIsInternal(true);
            setCurrentDomain('New Tab');
            fetchPopupData(tabId, '');
            return;
          }

          if (isPrivateOrLocalHost(domain)) {
            setIsInternal(true);
            setCurrentDomain(`${domain} (Local)`);
            fetchPopupData(tabId, domain);
            return;
          }

          setCurrentDomain(domain);
          setIsInternal(false);
          fetchPopupData(tabId, domain);
        }
      });

      // Real-time updates when storage changes while popup is open
      const storageListener = (changes: Record<string, chrome.storage.StorageChange>, areaName: string) => {
        if (areaName === 'local') {
          fetchPopupData(currentTabId, currentDomain);
        }
      };

      chrome.storage.onChanged.addListener(storageListener);
      return () => {
        chrome.storage.onChanged.removeListener(storageListener);
      };
    }
  }, [fetchPopupData, currentTabId, currentDomain]);

  const handleToggleSiteProtection = () => {
    if (isInternal || !data || !currentDomain) return;
    const willWhitelist = data.isProtected; // If protected, we are adding to whitelist (disabling protection)

    chrome.runtime.sendMessage(
      { type: 'TOGGLE_SITE_PROTECTION', domain: currentDomain, whitelisted: willWhitelist },
      () => {
        fetchPopupData(currentTabId, currentDomain);
      }
    );
  };

  const handleOpenReport = () => {
    let targetUrl = 'http://localhost:5173';
    if (!isInternal && currentDomain && currentDomain !== 'Detecting...') {
      targetUrl = `http://localhost:5173/report/${encodeURIComponent(currentDomain)}`;
    }
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  };

  const handleOpenOptions = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open('/options.html', '_blank');
    }
  };

  const isProtected = data?.isProtected ?? true;
  const isGlobalEnabled = data?.protectionEnabled ?? true;
  const trackersCount = data?.tabStats.trackersBlocked ?? 0;
  const adsCount = data?.tabStats.adsBlocked ?? 0;
  const totalGlobal = data?.globalStats.totalBlocked ?? 0;
  const siteLifetimeTotal = data?.siteStats.totalBlocked ?? 0;

  return (
    <div className="w-[360px] bg-background text-text-primary p-4 space-y-4 font-sans select-none">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-3">
        <div className="flex items-center space-x-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-surface border border-border">
            <Shield className="h-4 w-4 text-accent" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-semibold tracking-tight">RevShield</span>
            <span className="text-[9px] uppercase font-mono tracking-widest text-text-muted -mt-1">Continuous Protection</span>
          </div>
        </div>
        <button
          onClick={handleOpenOptions}
          title="Open settings"
          className="text-text-muted hover:text-text-primary transition-colors p-1"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>

      {/* Current Site Card */}
      <div className="rounded-xl border border-border bg-surface p-3.5 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-semibold text-text-primary truncate max-w-[200px]" title={currentDomain}>
            {currentDomain}
          </span>
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
              !isGlobalEnabled
                ? 'bg-red-500/10 text-red-400 border-red-500/20'
                : isInternal
                ? 'bg-surface-elevated text-text-muted border-border'
                : isProtected
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
            }`}
          >
            {!isGlobalEnabled
              ? 'PAUSED'
              : isInternal
              ? 'INTERNAL'
              : isProtected
              ? 'PROTECTED'
              : 'WHITELISTED'}
          </span>
        </div>

        {isInternal ? (
          <div className="flex items-center space-x-2 py-1 text-xs text-text-muted">
            <Info className="h-3.5 w-3.5 shrink-0 text-accent" />
            <span>Local and browser pages are not scanned for SSRF safety.</span>
          </div>
        ) : (
          <div className="flex items-center justify-between pt-1 border-t border-border/50">
            <span className="text-xs text-text-secondary">Protection for this site</span>
            <button
              onClick={handleToggleSiteProtection}
              className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                isProtected ? 'bg-accent' : 'bg-surface-elevated'
              }`}
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  isProtected ? 'translate-x-4' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        )}
      </div>

      {/* Block Counters for Active Tab */}
      <div className="grid grid-cols-2 gap-2.5">
        <div className="rounded-xl border border-border bg-surface p-3 text-center space-y-1">
          <div className="flex items-center justify-center space-x-1 text-text-muted">
            <Eye className="h-3.5 w-3.5" />
            <span className="text-[10px] uppercase font-mono tracking-wider">Trackers</span>
          </div>
          <div className="text-xl font-bold font-mono text-text-primary">
            {isLoading ? '-' : trackersCount}
          </div>
          <div className="text-[10px] text-text-muted">blocked this tab</div>
        </div>

        <div className="rounded-xl border border-border bg-surface p-3 text-center space-y-1">
          <div className="flex items-center justify-center space-x-1 text-text-muted">
            <Zap className="h-3.5 w-3.5" />
            <span className="text-[10px] uppercase font-mono tracking-wider">Ads</span>
          </div>
          <div className="text-xl font-bold font-mono text-text-primary">
            {isLoading ? '-' : adsCount}
          </div>
          <div className="text-[10px] text-text-muted">blocked this tab</div>
        </div>
      </div>

      {/* Per-site lifetime stats if available */}
      {!isInternal && siteLifetimeTotal > 0 && (
        <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated text-xs font-mono text-text-muted">
          <span>Site History:</span>
          <span className="text-text-primary font-semibold">{siteLifetimeTotal} blocked on this domain</span>
        </div>
      )}

      {/* Deep Link to RevShield Intelligence Report */}
      <button
        onClick={handleOpenReport}
        className="w-full flex items-center justify-center space-x-2 rounded-xl bg-accent hover:bg-accent-hover text-white py-2.5 text-xs font-semibold shadow-sm transition-all"
      >
        <span>{isInternal ? 'Open RevShield Scanner' : 'View Full Intelligence Report'}</span>
        <ExternalLink className="h-3.5 w-3.5" />
      </button>

      {/* Global Lifetime Stats Footer */}
      <div className="text-center text-[10px] font-mono text-text-muted pt-1">
        {totalGlobal.toLocaleString()} total threats intercepted locally
      </div>
    </div>
  );
};
