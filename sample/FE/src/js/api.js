export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const DEFAULT_TENANT_ID = import.meta.env.VITE_TENANT_ID || 'dev-team';

// Helper for authenticated requests
async function fetchWithAuth(url, options = {}) {
  const token = localStorage.getItem('argus_token');
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

  return fetchWithAuth('/evidence/upload', {
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

export async function fetchActivity() {
  return fetchWithAuth('/cases/activity');
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

