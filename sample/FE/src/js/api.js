import { logout, isTokenExpired, getAuthToken, getAuthTenantId } from './authSession.js';
import { isCaseReportGenerated } from './caseUtils.js';

export { isCaseReportGenerated };

export const API_BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://127.0.0.1:8000';
export const DEFAULT_TENANT_ID = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_TENANT_ID) || 'default';

export function getActiveTenantId() {
  return getAuthTenantId() || DEFAULT_TENANT_ID;
}

// Coalesce simultaneous identical in-flight GET requests (e.g., StrictMode double-mounts & sibling widgets)
const _inflightGets = new Map();

// Helper for authenticated requests
export async function fetchWithAuth(url, options = {}) {
  const token = getAuthToken();

  // Proactive check: if token is missing or expired, fail closed
  if (!token || isTokenExpired(token)) {
    if (token) logout('session_expired');
    throw new Error('Authentication required or session expired. Please log in.');
  }

  const tenantId = getActiveTenantId();
  const method = (options.method || 'GET').toUpperCase();
  const canDedupGet = method === 'GET' && !options.noDedup && !options.signal;
  const dedupKey = canDedupGet ? `${API_BASE_URL}${url}|${tenantId}|${token.slice(-16)}` : null;

  if (dedupKey && _inflightGets.has(dedupKey)) {
    return _inflightGets.get(dedupKey);
  }

  const headers = {
    'Accept': 'application/json',
    'X-Tenant-ID': tenantId,
    'Authorization': `Bearer ${token}`,
    ...options.headers,
  };

  // Only set Content-Type to application/json if it's not a FormData upload
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const execRequest = async () => {
    let response;
    try {
      response = await fetch(`${API_BASE_URL}${url}`, {
        ...options,
        headers,
      });
    } catch (netErr) {
      throw new Error(`Network failure connecting to ARGUS backend: ${netErr.message || netErr}`);
    }

    if (!response.ok) {
      let errorMsg = `HTTP Error ${response.status}`;
      try {
        const errData = await response.json();
        errorMsg = errData.detail || errorMsg;
      } catch(e) {
        try {
          const text = await response.text();
          if (text) errorMsg = text.slice(0, 200);
        } catch(_) {}
      }

      // Global 401 Unauthorized interceptor: automatically wipe session and redirect to login
      if (response.status === 401) {
        logout('session_expired');
      }

      const err = new Error(errorMsg);
      err.status = response.status;
      throw err;
    }

    // Handle empty responses (e.g. 204 No Content)
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      return response.json();
    }
    return response.text();
  };

  if (!dedupKey) {
    return execRequest();
  }

  const promise = execRequest().finally(() => {
    _inflightGets.delete(dedupKey);
  });
  _inflightGets.set(dedupKey, promise);
  return promise;
}

export async function login(userid, password) {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ userid, password }),
  });

  if (!response.ok) {
    let errorMsg = 'Login failed';
    try {
      const errData = await response.json();
      errorMsg = errData.detail || errorMsg;
    } catch(e) {}
    throw new Error(errorMsg);
  }
  
  return response.json();
}

export async function fetchCases() {
  const res = await fetchWithAuth('/cases/');
  if (res && Array.isArray(res.data) && typeof localStorage !== 'undefined') {
    try {
      res.data.forEach((c) => {
        if (c?.case_id && !c.has_report && !c.submitted_to_senior && !c.submitted_to_auditor && c.status !== 'closed') {
          localStorage.removeItem(`argus_case_${c.case_id}_report_completed`);
        }
      });
    } catch (_) {}
  }
  return res;
}

export async function fetchCaseSummary(caseId) {
  return fetchWithAuth(`/cases/${caseId}`);
}

export async function fetchFindings(caseId) {
  return fetchWithAuth(`/cases/${caseId}/findings`);
}

export async function fetchEvidenceForCase(caseId) {
  return fetchWithAuth(`/evidence/case/${caseId}`);
}

export async function uploadEvidenceFile(file, caseId, options = {}) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('case_id', caseId);
  if (options.hostId) {
    formData.append('host_id', options.hostId);
  }
  if (options.uploadedBy) {
    formData.append('uploaded_by', options.uploadedBy);
  }
  if (options.relativePath) {
    formData.append('relative_path', options.relativePath);
  }

  const asyncQuery = options.asyncMode !== false ? '&async_mode=true' : '';
  return fetchWithAuth(`/evidence/upload?case_id=${encodeURIComponent(caseId)}${asyncQuery}`, {
    method: 'POST',
    body: formData,
  });
}

export async function deleteEvidence(evidenceId, caseId) {
  const query = caseId ? `?case_id=${encodeURIComponent(caseId)}` : '';
  return fetchWithAuth(`/evidence/${encodeURIComponent(evidenceId)}${query}`, {
    method: 'DELETE',
  });
}

export async function updatePassword(currentPassword, newPassword) {
  return fetchWithAuth('/auth/update-password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

export async function fetchCurrentUserProfile() {
  return fetchWithAuth('/auth/me');
}

export async function updateCurrentUserProfile(profileData) {
  return fetchWithAuth('/auth/me', {
    method: 'PUT',
    body: JSON.stringify(profileData),
  });
}

export async function requestPasswordResetOtp(userid) {
  const response = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userid: userid.trim() }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to send OTP code');
  }
  return response.json();
}

export async function verifyOtpAndResetPassword(userid, otp, newPassword) {
  const response = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userid: userid.trim(), otp: otp.trim(), new_password: newPassword }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Failed to verify OTP');
  }
  return response.json();
}

export async function fetchActivity(caseId = null) {
  const query = caseId ? `?case_id=${encodeURIComponent(caseId)}&limit=200` : '?limit=200';
  return fetchWithAuth(`/cases/activity${query}`);
}

export async function fetchEmployees() {
  return fetchWithAuth('/auth/employees');
}

export async function fetchAuditorStats(limit = 50) {
  return fetchWithAuth(`/cases/auditor-stats?limit=${limit}`);
}

export async function fetchCaseNotes(caseId) {
  return fetchWithAuth(`/cases/${caseId}/notes`);
}

export async function createCaseNote(caseId, noteData) {
  return fetchWithAuth(`/cases/${caseId}/notes`, {
    method: 'POST',
    body: JSON.stringify(noteData),
  });
}

export async function fetchReviewNotes(caseId) {
  return fetchWithAuth(`/cases/${caseId}/review-notes`);
}

export async function createReviewNote(caseId, noteData) {
  return fetchWithAuth(`/cases/${caseId}/review-notes`, {
    method: 'POST',
    body: JSON.stringify(noteData),
  });
}

export async function updateReviewNote(caseId, noteId, noteData) {
  return fetchWithAuth(`/cases/${caseId}/review-notes/${noteId}`, {
    method: 'PUT',
    body: JSON.stringify(noteData),
  });
}

export async function deleteReviewNote(caseId, noteId) {
  return fetchWithAuth(`/cases/${caseId}/review-notes/${noteId}`, {
    method: 'DELETE',
  });
}

export async function queryCase(caseId, queryText, history = []) {
  return fetchWithAuth(`/cases/${caseId}/query`, {
    method: 'POST',
    body: JSON.stringify({ query: queryText, history }),
  });
}

export async function fetchReport(caseId, format = 'html', allowUnreviewed = false) {
  const cleanFormat = encodeURIComponent(format || 'html');
  const allowFlag = Boolean(allowUnreviewed);
  return fetchWithAuth(`/reports/${encodeURIComponent(caseId)}/report?format=${cleanFormat}&allow_unreviewed=${allowFlag}`);
}

export async function submitCaseReportStage(caseId, stage = 'submitted_to_senior', payload = {}) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/report-submission`, {
    method: 'POST',
    body: JSON.stringify({ stage, ...payload }),
  });
}




export async function closeCase(caseId, reason = null) {
  const options = {
    method: 'PUT',
  };
  if (reason) {
    options.headers = { 'Content-Type': 'application/json' };
    options.body = JSON.stringify({ reason });
  }
  return fetchWithAuth(`/cases/${caseId}/close`, options);
}

export async function fetchAgentResults(caseId) {
  return fetchWithAuth(`/cases/${caseId}/agents`);
}

export async function triggerAgentAnalysis(caseId) {
  return fetchWithAuth(`/cases/${caseId}/run-agents`, {
    method: 'POST',
  });
}

export async function stopWorkload(caseId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/stop-workload`, {
    method: 'POST',
  });
}

export async function restartWorkload(caseId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/restart-workload`, {
    method: 'POST',
  });
}

export async function assignAnalyst(caseId, analystId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/assign-analyst`, {
    method: 'PUT',
    body: JSON.stringify({ analyst_id: analystId }),
  });
}

export async function assignSeniorAnalyst(caseId, seniorAnalystId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/assign-senior`, {
    method: 'PUT',
    body: JSON.stringify({ senior_analyst_id: seniorAnalystId }),
  });
}

export async function acquireCaseLock(caseId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/lock`, {
    method: 'POST',
  });
}

export async function fetchCaseLock(caseId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/lock`);
}

export async function releaseCaseLock(caseId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/lock`, {
    method: 'DELETE',
  });
}

export async function sendCaseLockHeartbeat(caseId) {
  return fetchWithAuth(`/cases/${encodeURIComponent(caseId)}/heartbeat`, {
    method: 'POST',
  });
}

export async function fetchAllActiveLocks() {
  return fetchWithAuth('/cases/locks/active');
}

