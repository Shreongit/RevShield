import { GlobalStats, DomainStats, ExtensionSettings } from '../types/messages';
import { BlockType } from '@webshield/rule-engine';

export const DEFAULT_SETTINGS: ExtensionSettings = {
  protectionEnabled: true,
  blockAds: true,
  blockTrackers: true,
  blockFingerprinting: true,
  badgeCounter: true,
  whitelistedDomains: [],
};

export const DEFAULT_GLOBAL_STATS: GlobalStats = {
  adsBlocked: 0,
  trackersBlocked: 0,
  totalBlocked: 0,
};

class StorageService {
  private globalStatsCache: GlobalStats = { ...DEFAULT_GLOBAL_STATS };
  private domainStatsCache: Record<string, DomainStats> = {};
  private settingsCache: ExtensionSettings = { ...DEFAULT_SETTINGS };
  private isInitialized = false;
  private pendingFlushTimeout: ReturnType<typeof setTimeout> | null = null;

  async init(): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return;
    }

    const data = await chrome.storage.local.get([
      'globalStats',
      'domainStats',
      'settings',
      'whitelistedDomains',
      'protectionEnabled',
      'totalAdsBlocked',
      'totalTrackersBlocked',
    ]);

    // Backward compatibility & migration
    const legacyAds = data.totalAdsBlocked || 0;
    const legacyTrackers = data.totalTrackersBlocked || 0;

    this.globalStatsCache = data.globalStats || {
      adsBlocked: legacyAds,
      trackersBlocked: legacyTrackers,
      totalBlocked: legacyAds + legacyTrackers,
    };

    this.domainStatsCache = data.domainStats || {};

    const legacyWhitelist = data.whitelistedDomains || [];
    const legacyProtection = data.protectionEnabled !== undefined ? data.protectionEnabled : true;

    this.settingsCache = {
      ...DEFAULT_SETTINGS,
      ...(data.settings || {}),
      whitelistedDomains: data.settings?.whitelistedDomains || legacyWhitelist,
      protectionEnabled: data.settings?.protectionEnabled !== undefined ? data.settings.protectionEnabled : legacyProtection,
    };

    this.isInitialized = true;
  }

  async ensureInitialized(): Promise<void> {
    if (!this.isInitialized) {
      await this.init();
    }
  }

  async getGlobalStats(): Promise<GlobalStats> {
    await this.ensureInitialized();
    return { ...this.globalStatsCache };
  }

  async getDomainStats(domain: string): Promise<DomainStats> {
    await this.ensureInitialized();
    if (!domain) {
      return { adsBlocked: 0, trackersBlocked: 0, totalBlocked: 0, lastUpdated: Date.now() };
    }
    const cleanDomain = domain.toLowerCase().trim();
    return (
      this.domainStatsCache[cleanDomain] || {
        adsBlocked: 0,
        trackersBlocked: 0,
        totalBlocked: 0,
        lastUpdated: Date.now(),
      }
    );
  }

  async getSettings(): Promise<ExtensionSettings> {
    await this.ensureInitialized();
    return { ...this.settingsCache };
  }

  async updateSettings(partial: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
    await this.ensureInitialized();
    this.settingsCache = {
      ...this.settingsCache,
      ...partial,
    };

    await chrome.storage.local.set({
      settings: this.settingsCache,
      whitelistedDomains: this.settingsCache.whitelistedDomains,
      protectionEnabled: this.settingsCache.protectionEnabled,
    });

    return { ...this.settingsCache };
  }

  async toggleDomainWhitelist(domain: string, isWhitelisted: boolean): Promise<string[]> {
    await this.ensureInitialized();
    const cleanDomain = domain.toLowerCase().trim();
    let list = [...this.settingsCache.whitelistedDomains];

    if (isWhitelisted) {
      if (!list.includes(cleanDomain)) {
        list.push(cleanDomain);
      }
    } else {
      list = list.filter((d) => d !== cleanDomain);
    }

    this.settingsCache.whitelistedDomains = list;

    await chrome.storage.local.set({
      settings: this.settingsCache,
      whitelistedDomains: list,
    });

    return list;
  }

  recordBlock(blockType: BlockType, domain?: string): void {
    // 1. Update Global Stats
    if (blockType === 'AD') {
      this.globalStatsCache.adsBlocked += 1;
    } else {
      this.globalStatsCache.trackersBlocked += 1;
    }
    this.globalStatsCache.totalBlocked += 1;

    // 2. Update Domain Stats
    if (domain) {
      const cleanDomain = domain.toLowerCase().trim();
      const existing = this.domainStatsCache[cleanDomain] || {
        adsBlocked: 0,
        trackersBlocked: 0,
        totalBlocked: 0,
        lastUpdated: Date.now(),
      };

      if (blockType === 'AD') {
        existing.adsBlocked += 1;
      } else {
        existing.trackersBlocked += 1;
      }
      existing.totalBlocked += 1;
      existing.lastUpdated = Date.now();

      this.domainStatsCache[cleanDomain] = existing;
    }

    // 3. Debounced Batch Save (every 400ms) to avoid excessive disk I/O
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.pendingFlushTimeout) return;

    this.pendingFlushTimeout = setTimeout(async () => {
      this.pendingFlushTimeout = null;
      try {
        await chrome.storage.local.set({
          globalStats: this.globalStatsCache,
          domainStats: this.domainStatsCache,
          totalAdsBlocked: this.globalStatsCache.adsBlocked,
          totalTrackersBlocked: this.globalStatsCache.trackersBlocked,
        });
      } catch (err) {
        console.error('[RevShield] Storage flush failed:', err);
      }
    }, 400);
  }

  async resetStats(): Promise<void> {
    this.globalStatsCache = { adsBlocked: 0, trackersBlocked: 0, totalBlocked: 0 };
    this.domainStatsCache = {};

    await chrome.storage.local.set({
      globalStats: this.globalStatsCache,
      domainStats: this.domainStatsCache,
      totalAdsBlocked: 0,
      totalTrackersBlocked: 0,
    });
  }
}

export const storageService = new StorageService();
