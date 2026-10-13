import { AnalysisStatusResponse, FullAnalysisReport } from '@webshield/shared-types';

const API_BASE = '/api/v1';

export async function submitAnalysis(url: string, forceRefresh = false): Promise<AnalysisStatusResponse> {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url, force_refresh: forceRefresh }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to submit analysis' }));
    throw new Error(err.detail || 'Analysis request failed');
  }

  return res.json();
}

export async function getAnalysisStatus(analysisId: string): Promise<AnalysisStatusResponse> {
  const res = await fetch(`${API_BASE}/analysis/${analysisId}/status`);
  if (!res.ok) {
    throw new Error('Could not retrieve analysis status');
  }
  return res.json();
}

export async function getReportByDomain(domain: string): Promise<FullAnalysisReport> {
  const res = await fetch(`${API_BASE}/report/${encodeURIComponent(domain)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Report not found' }));
    throw new Error(err.detail || 'Report not found');
  }
  return res.json();
}

export async function getReportById(id: string): Promise<FullAnalysisReport> {
  const res = await fetch(`${API_BASE}/analysis/${id}`);
  if (!res.ok) {
    throw new Error('Report not found');
  }
  return res.json();
}
