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
 * Check if the given token is expired.
 * Fails closed: any non-string, malformed, non-JWT token or missing expiration is treated as expired.
 */
export function isTokenExpired(token) {
  if (!token || typeof token !== 'string') return true;
  const payload = parseJwt(token);
  // Fail closed: require valid JWT payload with numeric exp claim
  if (!payload || typeof payload.exp !== 'number') return true;
  return Date.now() >= payload.exp * 1000 - TOKEN_BUFFER_MS;
}

/**
 * Get remaining milliseconds until token expires.
 * Fails closed: returns 0 if token is missing or not a valid JWT.
 */
export function getTokenRemainingMs(token) {
  if (!token || typeof token !== 'string') return 0;
  const payload = parseJwt(token);
  if (!payload || typeof payload.exp !== 'number') return 0;
  const remaining = payload.exp * 1000 - Date.now();
  return remaining > 0 ? remaining : 0;
}

/**
 * Get active user's tenant ID if authoritative from user object or stored tenant
 */
export function getAuthTenantId() {
  try {
    const user = getAuthUser();
    return user?.tenant_id || user?.tenantId || (typeof localStorage !== 'undefined' ? localStorage.getItem('argus_tenant') : null) || null;
  } catch (e) {
    return null;
  }
}

/**
 * Get active auth token from localStorage (persistent) or sessionStorage (temporary)
 */
export function getAuthToken() {
  try {
    return localStorage.getItem('argus_token') || sessionStorage.getItem('argus_token') || null;
  } catch (e) {
    return null;
  }
}

/**
 * Get active user object from localStorage or sessionStorage
 */
export function getAuthUser() {
  try {
    const raw = localStorage.getItem('argus_user') || sessionStorage.getItem('argus_user');
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

/**
 * Store auth session.
 * @param {string} token
 * @param {object} user
 * @param {boolean} keepActive - If true, persist in localStorage across browser restarts.
 *                                If false, store strictly in sessionStorage (expires on browser/tab close).
 */
export function setAuthSession(token, user, keepActive = true) {
  try {
    const userStr = JSON.stringify(user);
    if (keepActive) {
      localStorage.setItem('argus_token', token);
      localStorage.setItem('argus_user', userStr);
      localStorage.setItem('argus_keep_active', 'true');
      sessionStorage.setItem('argus_token', token);
      sessionStorage.setItem('argus_user', userStr);
    } else {
      // Ephemeral tab session: active while tab is open, cleared when tab/browser closes
      sessionStorage.setItem('argus_token', token);
      sessionStorage.setItem('argus_user', userStr);
      localStorage.setItem('argus_token', token);
      localStorage.setItem('argus_user', userStr);
      localStorage.setItem('argus_keep_active', 'false');
    }
    localStorage.setItem('argus_last_active', String(Date.now()));
  } catch (e) {
    console.error('Error saving auth session:', e);
  }
}

// Clean up temporary session tokens when tab/browser is closed if keepActive was false
if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
  window.addEventListener('beforeunload', () => {
    try {
      if (localStorage.getItem('argus_keep_active') === 'false') {
        localStorage.removeItem('argus_token');
        localStorage.removeItem('argus_user');
      }
    } catch (e) {}
  });
}

/**
 * Clear all authentication and session data from both localStorage and sessionStorage
 */
export function clearSession() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('argus_token');
      localStorage.removeItem('argus_user');
      localStorage.removeItem('argus_tenant');
      localStorage.removeItem('active_case_id');
      localStorage.removeItem('active_case_name');
      localStorage.removeItem('argus_last_active');
    }
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem('argus_token');
      sessionStorage.removeItem('argus_user');
      sessionStorage.removeItem('argus_tenant');
    }
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
      try {
        const ev = typeof CustomEvent === 'function' ? new CustomEvent('argus_logout') : { type: 'argus_logout' };
        window.dispatchEvent(ev);
      } catch (_) {}
    }
  } catch (e) {
    console.error('Error clearing session:', e);
  }
}

export const clearAuthSession = clearSession;

/**
 * Perform clean logout and redirect to login page
 * @param {string|null} reason - Optional reason code: 'session_expired' | 'idle_timeout' | null
 */
export function logout(reason = null) {
  clearSession();
  if (typeof window !== 'undefined' && window.location) {
    const currentPath = window.location.pathname || '';
    if (currentPath === '/login') return;

    const search = reason ? `?reason=${encodeURIComponent(reason)}` : '';
    window.location.href = `/login${search}`;
  }
}
