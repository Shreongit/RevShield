import {
  compileDeclarativeNetRequestRules,
  getRuleCategoryById,
  KNOWN_TRACKER_SIGNATURES,
} from '@webshield/rule-engine';
import { normalizeDomain, isInternalOrBrowserUrl, isPrivateOrLocalHost } from '@webshield/shared-utils';
import { storageService } from '../utils/storage';
import { ExtensionMessage, PopupDataResponse, TabStats } from '../types/messages';

interface MemoryTabState {
  tabId: number;
  url: string;
  domain: string;
  adsBlocked: number;
  trackersBlocked: number;
  totalBlocked: number;
  isInternal: boolean;
}

const tabMemory = new Map<number, MemoryTabState>();

// Synchronize Chromium DeclarativeNetRequest rules with current settings and whitelist
async function syncDNRRules(): Promise<void> {
  try {
    const settings = await storageService.getSettings();

    // If global protection is disabled, remove all blocking rules
    if (!settings.protectionEnabled) {
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = existing.map((r) => r.id);
      if (removeRuleIds.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds,
          addRules: [],
        });
      }
      return;
    }

    // Filter signatures based on settings
    let signatures = [...KNOWN_TRACKER_SIGNATURES];
    if (!settings.blockAds) {
      signatures = signatures.filter((s) => s.category !== 'ADVERTISING');
    }
    if (!settings.blockTrackers) {
      signatures = signatures.filter((s) => s.category === 'ADVERTISING');
    }

    const compiledRules = compileDeclarativeNetRequestRules(signatures, settings.whitelistedDomains);
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existingRules.map((r) => r.id);

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules: compiledRules as any,
    });
  } catch (err) {
    console.error('[RevShield] DNR Rule Sync Failed:', err);
  }
}

// Update the extension badge on the browser toolbar
async function updateTabBadge(tabId: number, count: number): Promise<void> {
  try {
    const settings = await storageService.getSettings();
    if (!settings.badgeCounter || count <= 0) {
      await chrome.action.setBadgeText({ tabId, text: '' });
      return;
    }

    await chrome.action.setBadgeText({ tabId, text: count.toString() });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#6366f1' }); // Indigo
  } catch {
    // Tab may have been closed
  }
}

// Service worker startup & installation handlers
chrome.runtime.onInstalled.addListener(async () => {
  await storageService.init();
  await syncDNRRules();
});

chrome.runtime.onStartup.addListener(async () => {
  await storageService.init();
  await syncDNRRules();
});

// Initialize on execution
storageService.init().then(() => syncDNRRules());

// Tab navigation lifecycle
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'loading') {
    const url = changeInfo.url || tab.url || '';
    const isInternal = isInternalOrBrowserUrl(url);
    const domain = isInternal ? '' : normalizeDomain(url);

    tabMemory.set(tabId, {
      tabId,
      url,
      domain,
      adsBlocked: 0,
      trackersBlocked: 0,
      totalBlocked: 0,
      isInternal,
    });

    updateTabBadge(tabId, 0);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabMemory.delete(tabId);
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const state = tabMemory.get(activeInfo.tabId);
  if (state) {
    await updateTabBadge(activeInfo.tabId, state.totalBlocked);
  } else {
    await updateTabBadge(activeInfo.tabId, 0);
  }
});

// Continuous Rule Matching & Counter Updates
if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(async (info) => {
    try {
      const tabId = info.request.tabId;
      if (!tabId || tabId < 0) return;

      const ruleId = info.rule.ruleId;
      const blockType = getRuleCategoryById(ruleId);

      // Determine domain from tab state or initiator
      let domain = '';
      const tabState = tabMemory.get(tabId);
      if (tabState && tabState.domain) {
        domain = tabState.domain;
      } else if (info.request.initiator) {
        domain = normalizeDomain(info.request.initiator);
      }

      // Check if domain is whitelisted
      const settings = await storageService.getSettings();
      if (!settings.protectionEnabled || settings.whitelistedDomains.includes(domain)) {
        return;
      }

      // Update in-memory tab state
      const currentTab = tabMemory.get(tabId) || {
        tabId,
        url: '',
        domain,
        adsBlocked: 0,
        trackersBlocked: 0,
        totalBlocked: 0,
        isInternal: false,
      };

      if (blockType === 'AD') {
        currentTab.adsBlocked += 1;
      } else {
        currentTab.trackersBlocked += 1;
      }
      currentTab.totalBlocked += 1;
      tabMemory.set(tabId, currentTab);

      // Update badge
      await updateTabBadge(tabId, currentTab.totalBlocked);

      // Persist to storage
      storageService.recordBlock(blockType, domain);
    } catch (err) {
      console.error('[RevShield] Rule match processing error:', err);
    }
  });
}

// Centralized message dispatcher for Popup and Options pages
chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.type) {
        case 'GET_POPUP_DATA': {
          const settings = await storageService.getSettings();
          const globalStats = await storageService.getGlobalStats();

          let domain = message.domain || '';
          let tabId = message.tabId;

          // If domain not provided, inspect active tab state
          if (!domain && tabId && tabMemory.has(tabId)) {
            domain = tabMemory.get(tabId)!.domain;
          }

          const isInternal = isInternalOrBrowserUrl(domain) || isPrivateOrLocalHost(domain);
          const isWhitelisted = domain ? settings.whitelistedDomains.includes(domain) : false;
          const isProtected = settings.protectionEnabled && !isWhitelisted && !isInternal;

          const siteStats = domain ? await storageService.getDomainStats(domain) : {
            adsBlocked: 0,
            trackersBlocked: 0,
            totalBlocked: 0,
            lastUpdated: Date.now(),
          };

          const memTab = (tabId && tabMemory.get(tabId)) || {
            tabId: tabId || 0,
            url: '',
            domain,
            adsBlocked: 0,
            trackersBlocked: 0,
            totalBlocked: 0,
            isInternal,
          };

          const tabStats: TabStats = {
            domain,
            adsBlocked: memTab.adsBlocked,
            trackersBlocked: memTab.trackersBlocked,
            totalBlocked: memTab.totalBlocked,
            isWhitelisted,
            isProtected,
            isInternal,
          };

          const response: PopupDataResponse = {
            globalStats,
            siteStats,
            tabStats,
            protectionEnabled: settings.protectionEnabled,
            whitelistedDomains: settings.whitelistedDomains,
            isWhitelisted,
            isProtected,
          };

          sendResponse(response);
          break;
        }

        case 'TOGGLE_SITE_PROTECTION': {
          const { domain, whitelisted } = message;
          const updatedWhitelist = await storageService.toggleDomainWhitelist(domain, whitelisted);
          await syncDNRRules();

          // Update tab memory
          for (const [id, state] of tabMemory.entries()) {
            if (state.domain === domain) {
              if (whitelisted) {
                updateTabBadge(id, 0);
              }
            }
          }

          sendResponse({ success: true, whitelistedDomains: updatedWhitelist });
          break;
        }

        case 'TOGGLE_GLOBAL_PROTECTION': {
          const updated = await storageService.updateSettings({ protectionEnabled: message.enabled });
          await syncDNRRules();
          sendResponse({ success: true, settings: updated });
          break;
        }

        case 'GET_SETTINGS': {
          const currentSettings = await storageService.getSettings();
          sendResponse({ settings: currentSettings });
          break;
        }

        case 'UPDATE_SETTINGS': {
          const newSettings = await storageService.updateSettings(message.settings);
          await syncDNRRules();
          sendResponse({ success: true, settings: newSettings });
          break;
        }

        case 'RESET_STATS': {
          await storageService.resetStats();
          for (const [id] of tabMemory.entries()) {
            updateTabBadge(id, 0);
          }
          sendResponse({ success: true });
          break;
        }

        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (err: any) {
      console.error('[RevShield] Message handling error:', err);
      sendResponse({ error: err.message || 'Internal error' });
    }
  })();

  return true; // Asynchronous sendResponse
});
