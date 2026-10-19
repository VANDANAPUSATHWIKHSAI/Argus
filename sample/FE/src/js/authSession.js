// ARGUS Session & Auth Lifecycle Management

export const IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes of inactivity
export const TOKEN_BUFFER_MS = 5 * 1000; // 5 seconds buffer before strict exp

/**
 * Safely parse JWT payload (supporting base64url and UTF-8)
 */
export function parseJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null; // Dev fallback or mock token
  try {
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

/**
 * Check if the given token is expired
 */
export function isTokenExpired(token) {
  if (!token) return true;
  const payload = parseJwt(token);
  // Non-JWT tokens (e.g. dev mock tokens) are treated as non-expired
  if (!payload || !payload.exp) return false;
  return Date.now() >= payload.exp * 1000 - TOKEN_BUFFER_MS;
}

/**
 * Get remaining milliseconds until token expires
 */
export function getTokenRemainingMs(token) {
  if (!token) return 0;
  const payload = parseJwt(token);
  if (!payload || !payload.exp) return 60 * 60 * 1000; // Default 1 hr if dev token
  const remaining = payload.exp * 1000 - Date.now();
  return remaining > 0 ? remaining : 0;
}

/**
 * Clear all authentication and session data from localStorage
 */
export function clearSession() {
  try {
    localStorage.removeItem('argus_token');
    localStorage.removeItem('argus_user');
    localStorage.removeItem('active_case_id');
    localStorage.removeItem('active_case_name');
    localStorage.removeItem('argus_last_active');
    window.dispatchEvent(new Event('argus_logout'));
  } catch (e) {
    console.error('Error clearing session:', e);
  }
}

/**
 * Perform clean logout and redirect to login page
 * @param {string|null} reason - Optional reason code: 'session_expired' | 'idle_timeout' | null
 */
export function logout(reason = null) {
  clearSession();
  const currentPath = window.location.pathname;
  if (currentPath === '/login') return;

  const search = reason ? `?reason=${encodeURIComponent(reason)}` : '';
  window.location.href = `/login${search}`;
}
