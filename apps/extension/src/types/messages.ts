export interface GlobalStats {
  adsBlocked: number;
  trackersBlocked: number;
  totalBlocked: number;
}

export interface DomainStats {
  adsBlocked: number;
  trackersBlocked: number;
  totalBlocked: number;
  lastUpdated: number;
}

export interface TabStats {
  domain: string;
  adsBlocked: number;
  trackersBlocked: number;
  totalBlocked: number;
  isWhitelisted: boolean;
  isProtected: boolean;
  isInternal: boolean;
}

export interface ExtensionSettings {
  protectionEnabled: boolean;
  blockAds: boolean;
  blockTrackers: boolean;
  blockFingerprinting: boolean;
  badgeCounter: boolean;
  whitelistedDomains: string[];
}

export interface PopupDataResponse {
  globalStats: GlobalStats;
  siteStats: DomainStats;
  tabStats: TabStats;
  protectionEnabled: boolean;
  whitelistedDomains: string[];
  isWhitelisted: boolean;
  isProtected: boolean;
}

export type ExtensionMessage =
  | { type: 'GET_POPUP_DATA'; tabId?: number; domain?: string }
  | { type: 'TOGGLE_SITE_PROTECTION'; domain: string; whitelisted: boolean }
  | { type: 'TOGGLE_GLOBAL_PROTECTION'; enabled: boolean }
  | { type: 'GET_SETTINGS' }
  | { type: 'UPDATE_SETTINGS'; settings: Partial<ExtensionSettings> }
  | { type: 'RESET_STATS' };
