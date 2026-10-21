import { logout, isTokenExpired, getAuthToken } from './authSession';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
export const DEFAULT_TENANT_ID = import.meta.env.VITE_TENANT_ID || 'default';

// Helper for authenticated requests
export async function fetchWithAuth(url, options = {}) {
  const token = getAuthToken();

  // Proactive check: if token is expired before making request, log out immediately
  if (token && isTokenExpired(token)) {
    logout('session_expired');
    throw new Error('Session expired. Please log in again.');
  }

  const headers = {
    'Accept': 'application/json',
    'X-Tenant-ID': DEFAULT_TENANT_ID,
    ...options.headers,
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Only set Content-Type to application/json if it's not a FormData upload
  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${API_BASE_URL}${url}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const errData = await response.json();
      errorMsg = errData.detail || errorMsg;
    } catch(e) {}

    // Global 401 Unauthorized interceptor: automatically wipe session and redirect to login
    if (response.status === 401) {
      logout('session_expired');
    }

    throw new Error(errorMsg);
  }

  return response.json();
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

export async function fetchAuditorStats(limit = 50) {
  const token = getAuthToken();
  const headers = {
    'Accept': 'application/json',
    'X-Tenant-ID': DEFAULT_TENANT_ID,
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const response = await fetch(`${API_BASE_URL}/cases/auditor-stats?limit=${limit}`, { headers });
  if (!response.ok) {
    const fallbackRes = await fetch(`${API_BASE_URL}/cases/auditor-stats?limit=${limit}`, {
      headers: { 'Accept': 'application/json', 'X-Tenant-ID': DEFAULT_TENANT_ID }
    });
    if (fallbackRes.ok) return fallbackRes.json();
  }
  return response.json();
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

export async function fetchReport(caseId, format = 'html', allowUnreviewed = true) {
  const token = getAuthToken();
  const url = `${API_BASE_URL}/reports/${caseId}/report?format=${format}&allow_unreviewed=${allowUnreviewed}`;
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Tenant-ID': DEFAULT_TENANT_ID,
    }
  });
  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const errData = await response.json();
      errorMsg = errData.detail || errorMsg;
    } catch(e) {}
    throw new Error(errorMsg);
  }
  if (format === 'json') {
    return response.json();
  }
  return response.text();
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

