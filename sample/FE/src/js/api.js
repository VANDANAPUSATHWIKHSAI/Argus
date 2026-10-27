import { logout, isTokenExpired, getAuthToken, getAuthTenantId } from './authSession.js';

export const API_BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://127.0.0.1:8000';
export const DEFAULT_TENANT_ID = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_TENANT_ID) || 'default';

export function getActiveTenantId() {
  return getAuthTenantId() || DEFAULT_TENANT_ID;
}

// Helper for authenticated requests
export async function fetchWithAuth(url, options = {}) {
  const token = getAuthToken();

  // Proactive check: if token is missing or expired, fail closed
  if (!token || isTokenExpired(token)) {
    if (token) logout('session_expired');
    throw new Error('Authentication required or session expired. Please log in.');
  }

  const tenantId = getActiveTenantId();
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
  return fetchWithAuth('/cases/');
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

export async function uploadEvidenceFile(file, caseId) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('case_id', caseId);

  return fetchWithAuth(`/evidence/upload?case_id=${encodeURIComponent(caseId)}`, {
    method: 'POST',
    body: formData,
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

export async function fetchActivity() {
  return fetchWithAuth('/cases/activity');
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

export async function queryCase(caseId, queryText) {
  return fetchWithAuth(`/cases/${caseId}/query`, {
    method: 'POST',
    body: JSON.stringify({ query: queryText }),
  });
}

export async function fetchReport(caseId, format = 'html', allowUnreviewed = false) {
  const cleanFormat = encodeURIComponent(format || 'html');
  const allowFlag = Boolean(allowUnreviewed);
  return fetchWithAuth(`/reports/${encodeURIComponent(caseId)}/report?format=${cleanFormat}&allow_unreviewed=${allowFlag}`);
}

export async function closeCase(caseId) {
  return fetchWithAuth(`/cases/${caseId}/close`, {
    method: 'PUT',
  });
}

export async function fetchAgentResults(caseId) {
  return fetchWithAuth(`/cases/${caseId}/agents`);
}

export async function triggerAgentAnalysis(caseId) {
  return fetchWithAuth(`/cases/${caseId}/run-agents`, {
    method: 'POST',
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

