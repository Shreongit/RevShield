import { TrackerCategory } from '@webshield/shared-types';

export interface TrackerSignature {
  pattern: string;
  category: TrackerCategory;
  owner: string;
  description: string;
}

export const KNOWN_TRACKER_SIGNATURES: TrackerSignature[] = [
  // Analytics
  { pattern: 'google-analytics.com', category: 'ANALYTICS', owner: 'Google LLC', description: 'Web traffic measurement & visitor behavior telemetry.' },
  { pattern: 'googletagmanager.com', category: 'ANALYTICS', owner: 'Google LLC', description: 'Tag management container system.' },
  { pattern: 'hotjar.com', category: 'SESSION_REPLAY', owner: 'Hotjar Ltd', description: 'Session recording, click maps, and user behavior heatmaps.' },
  { pattern: 'clarity.ms', category: 'SESSION_REPLAY', owner: 'Microsoft', description: 'Session replay and behavioral click telemetry.' },
  { pattern: 'mixpanel.com', category: 'ANALYTICS', owner: 'Mixpanel Inc', description: 'Product analytics and user action tracking.' },
  { pattern: 'segment.io', category: 'TELEMETRY', owner: 'Twilio Segment', description: 'Customer data platform and event aggregation.' },
  { pattern: 'amplitude.com', category: 'ANALYTICS', owner: 'Amplitude Inc', description: 'Product behavioral analytics engine.' },
  { pattern: 'matomo.org', category: 'ANALYTICS', owner: 'InnoCraft', description: 'Open-source web analytics platform.' },
  { pattern: 'plausible.io', category: 'ANALYTICS', owner: 'Plausible Insights', description: 'Lightweight privacy-friendly analytics.' },
  { pattern: 'sentry.io', category: 'TELEMETRY', owner: 'Functional Software', description: 'Application performance and error telemetry.' },
  { pattern: 'datadoghq.com', category: 'TELEMETRY', owner: 'Datadog Inc', description: 'Real user monitoring and synthetic traces.' },

  // Advertising
  { pattern: 'doubleclick.net', category: 'ADVERTISING', owner: 'Google LLC', description: 'Programmatic display advertising network.' },
  { pattern: 'googlesyndication.com', category: 'ADVERTISING', owner: 'Google LLC', description: 'AdSense ad distribution and monetization.' },
  { pattern: 'adnxs.com', category: 'ADVERTISING', owner: 'AppNexus / Xandr', description: 'Digital ad exchange and real-time bidding.' },
  { pattern: 'criteo.com', category: 'ADVERTISING', owner: 'Criteo SA', description: 'Behavioral retargeting and commercial tracking.' },
  { pattern: 'taboola.com', category: 'ADVERTISING', owner: 'Taboola Inc', description: 'Content recommendation and sponsored advertising.' },
  { pattern: 'outbrain.com', category: 'ADVERTISING', owner: 'Outbrain Inc', description: 'Native sponsored content distribution network.' },
  { pattern: 'rubiconproject.com', category: 'ADVERTISING', owner: 'Magnite Inc', description: 'Supply-side automated ad platform.' },
  { pattern: 'pubmatic.com', category: 'ADVERTISING', owner: 'PubMatic Inc', description: 'Digital advertising yield and targeting engine.' },
  { pattern: 'openx.net', category: 'ADVERTISING', owner: 'OpenX Software', description: 'Programmatic ad marketplace.' },
  { pattern: 'amazon-adsystem.com', category: 'ADVERTISING', owner: 'Amazon.com Inc', description: 'Amazon Sponsored Products and display ad network.' },
  { pattern: 'advertising.com', category: 'ADVERTISING', owner: 'Yahoo Inc', description: 'Display and video advertising network.' },

  // Social
  { pattern: 'facebook.net', category: 'SOCIAL', owner: 'Meta Platforms Inc', description: 'Facebook Pixel, SDK, and cross-site social tracking.' },
  { pattern: 'connect.facebook.net', category: 'SOCIAL', owner: 'Meta Platforms Inc', description: 'Meta social tracking and graph connectors.' },
  { pattern: 'tiktok.com', category: 'SOCIAL', owner: 'ByteDance Ltd', description: 'TikTok analytics pixel and conversion tracking.' },
  { pattern: 'linkedin.com/px', category: 'SOCIAL', owner: 'Microsoft LinkedIn', description: 'LinkedIn Insight conversion tracking tag.' },
  { pattern: 'licdn.com', category: 'SOCIAL', owner: 'Microsoft LinkedIn', description: 'LinkedIn asset and tracking delivery.' },
  { pattern: 'twitter.com/uwt.js', category: 'SOCIAL', owner: 'X Corp', description: 'Twitter universal website conversion tag.' },
  { pattern: 'pinterest.com/ct.html', category: 'SOCIAL', owner: 'Pinterest Inc', description: 'Pinterest conversion and audience tag.' },

  // Fingerprinting & Telemetry
  { pattern: 'fingerprintjs.com', category: 'FINGERPRINTING', owner: 'FingerprintJS Inc', description: 'Device & browser canvas/audio fingerprinting engine.' },
  { pattern: 'fpnpmcdn.net', category: 'FINGERPRINTING', owner: 'FingerprintJS Inc', description: 'Fingerprint CDN payload host.' },
  { pattern: 'iovation.com', category: 'FINGERPRINTING', owner: 'TransUnion', description: 'Device reputation and hardware identification.' },
  { pattern: 'threatmetrix.com', category: 'FINGERPRINTING', owner: 'LexisNexis', description: 'Browser profiling and behavioral biometric engine.' },

  // Cryptomining
  { pattern: 'coinhive.com', category: 'CRYPTOMINING', owner: 'Coinhive', description: 'Browser-based Monero cryptocurrency miner.' },
  { pattern: 'coin-hive.com', category: 'CRYPTOMINING', owner: 'Coinhive', description: 'Cryptocurrency in-browser miner.' },
  { pattern: 'cryptoloot.pro', category: 'CRYPTOMINING', owner: 'Crypto-Loot', description: 'Web client CPU hashing script.' }
];

export interface DeclarativeRule {
  id: number;
  priority: number;
  action: { type: 'block' | 'allow' };
  condition: {
    urlFilter: string;
    resourceTypes: string[];
    excludedInitiatorDomains?: string[];
  };
}

export function compileDeclarativeNetRequestRules(
  signatures: TrackerSignature[] = KNOWN_TRACKER_SIGNATURES,
  whitelistedDomains: string[] = []
): DeclarativeRule[] {
  return signatures.map((sig, index) => {
    return {
      id: index + 1001,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: `||${sig.pattern}^`,
        resourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame', 'ping', 'other'],
        ...(whitelistedDomains.length > 0 ? { excludedInitiatorDomains: whitelistedDomains } : {})
      }
    };
  });
}

export function matchTrackerDomain(hostnameOrUrl: string): TrackerSignature | null {
  const target = hostnameOrUrl.toLowerCase();
  for (const sig of KNOWN_TRACKER_SIGNATURES) {
    if (target.includes(sig.pattern)) {
      return sig;
    }
  }
  return null;
}
