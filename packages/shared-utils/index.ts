import { RiskLevel } from '@webshield/shared-types';

export function isInternalOrBrowserUrl(url: string): boolean {
  if (!url) return true;
  const lower = url.trim().toLowerCase();
  return (
    lower.startsWith('chrome://') ||
    lower.startsWith('chrome-extension://') ||
    lower.startsWith('edge://') ||
    lower.startsWith('brave://') ||
    lower.startsWith('about:') ||
    lower.startsWith('file://') ||
    lower.startsWith('view-source:')
  );
}

export function isPrivateOrLocalHost(domain: string): boolean {
  if (!domain) return false;
  const d = domain.toLowerCase().trim();
  return (
    d === 'localhost' ||
    d.endsWith('.localhost') ||
    d === '127.0.0.1' ||
    d === '::1' ||
    d.startsWith('192.168.') ||
    d.startsWith('10.') ||
    d.startsWith('172.16.') ||
    d.endsWith('.local') ||
    d.endsWith('.internal')
  );
}

export function normalizeDomain(input: string): string {
  if (!input) return '';
  let cleaned = input.trim().toLowerCase();

  // If internal browser URL, return empty
  if (isInternalOrBrowserUrl(cleaned)) {
    return '';
  }

  // Strip scheme
  cleaned = cleaned.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  cleaned = cleaned.replace(/^www\./, '');
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split('?')[0];
  cleaned = cleaned.split('#')[0];
  cleaned = cleaned.split(':')[0];
  return cleaned;
}

export function normalizeUrl(input: string): string {
  if (!input) return '';
  let cleaned = input.trim();
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'https://' + cleaned;
  }
  return cleaned;
}

export function getRiskLevelFromScore(score: number): RiskLevel {
  if (score >= 80) return 'SAFE';
  if (score >= 60) return 'LOW_RISK';
  if (score >= 40) return 'SUSPICIOUS';
  return 'HIGH_RISK';
}

export function getRiskLabel(risk: RiskLevel): string {
  switch (risk) {
    case 'SAFE':
      return 'Safe & Resilient';
    case 'LOW_RISK':
      return 'Low Risk';
    case 'SUSPICIOUS':
      return 'Moderate / Suspicious';
    case 'HIGH_RISK':
      return 'High Risk';
  }
}

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
