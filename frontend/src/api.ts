export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const DEFAULT_TENANT_ID = 'default';

export interface CaseSummary {
  case_id: string;
  tenant_id: string;
  total_findings: number;
  review_status_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  layer_breakdown: Record<string, number>;
  source_artifact_count: number;
  latest_timestamp?: string;
}

export interface FindingItem {
  finding_id: string;
  finding_fingerprint: string;
  fact: string;
  sanitized_fact: string;
  severity: string;
  confidence: number;
  mitre_mapping?: string;
  layer: string;
  source_artifact_id: string;
  contributing_correlation_ids?: string[];
  timestamp: string;
  review_status: string;
  reviewed_by?: string;
  injection_flagged: boolean;
  injection_score?: number;
  sanitization_actions?: string[];
}

export interface ReportJson {
  case_id: string;
  tenant_id: string;
  summary: Record<string, any>;
  findings: FindingItem[];
  timeline: any[];
}

export async function fetchCaseSummary(caseId: string, tenantId = DEFAULT_TENANT_ID): Promise<CaseSummary> {
  const res = await fetch(`${API_BASE_URL}/cases/${caseId}`, {
    headers: { 'X-Tenant-ID': tenantId, 'Accept': 'application/json' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function fetchReportJson(caseId: string, allowUnreviewed = true, tenantId = DEFAULT_TENANT_ID): Promise<ReportJson> {
  const res = await fetch(`${API_BASE_URL}/reports/${caseId}/report?format=json&allow_unreviewed=${allowUnreviewed}`, {
    headers: { 'X-Tenant-ID': tenantId, 'Accept': 'application/json' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function fetchReportHtml(caseId: string, allowUnreviewed = true, tenantId = DEFAULT_TENANT_ID): Promise<string> {
  const res = await fetch(`${API_BASE_URL}/reports/${caseId}/report?format=html&allow_unreviewed=${allowUnreviewed}`, {
    headers: { 'X-Tenant-ID': tenantId, 'Accept': 'text/html' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.text();
}

export async function uploadEvidenceFile(file: File, caseId: string, tenantId = DEFAULT_TENANT_ID): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('case_id', caseId);

  const res = await fetch(`${API_BASE_URL}/evidence/upload`, {
    method: 'POST',
    headers: { 'X-Tenant-ID': tenantId },
    body: formData,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function queryCaseAi(caseId: string, query: string, tenantId = DEFAULT_TENANT_ID): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/cases/${caseId}/query`, {
    method: 'POST',
    headers: { 'X-Tenant-ID': tenantId, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}
