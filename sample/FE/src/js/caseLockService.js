/**
 * ARGUS Case Lock Service
 * =======================
 * Client-side management of case locking, heartbeats, read-only status,
 * and cross-component lock notifications.
 */

import { acquireCaseLock, fetchCaseLock, releaseCaseLock, sendCaseLockHeartbeat } from './api.js';

export const ARGUS_CASE_LOCK_CHANGED_EVENT = 'argus:caseLockChanged';

let _activeHeartbeatTimer = null;
let _activeLockedCaseId = null;
let _currentLockState = null;

export function getCachedLockState() {
  return _currentLockState;
}

export function dispatchCaseLockEvent(lockData) {
  _currentLockState = lockData;
  if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
    const detail = lockData || null;
    const event = typeof CustomEvent === 'function'
      ? new CustomEvent(ARGUS_CASE_LOCK_CHANGED_EVENT, { detail })
      : { type: ARGUS_CASE_LOCK_CHANGED_EVENT, detail };
    window.dispatchEvent(event);
  }
}

/**
 * Attempt to acquire or refresh lock for a case.
 * Returns lock status dictionary: { isLocked, isOwner, readOnly, lockedBy, message }
 */
export async function syncCaseLock(caseId) {
  if (!caseId) {
    if (_activeLockedCaseId) {
      const prevId = _activeLockedCaseId;
      _activeLockedCaseId = null;
      releaseActiveCaseLock(prevId).catch(() => {});
    }
    stopCaseLockHeartbeat();
    dispatchCaseLockEvent(null);
    return null;
  }

  // If switching cases and we previously held a lock on another case, release the old one safely
  if (_activeLockedCaseId && _activeLockedCaseId !== caseId) {
    const prevId = _activeLockedCaseId;
    _activeLockedCaseId = null;
    releaseActiveCaseLock(prevId).catch(() => {});
  }

  try {
    const res = await acquireCaseLock(caseId);
    const lockData = {
      caseId,
      isLocked: Boolean(res.is_locked),
      isOwner: Boolean(res.is_owner),
      readOnly: Boolean(res.read_only),
      lockStatus: res.lock_status,
      lockedBy: res.lock?.locked_by || { name: 'Another Analyst' },
      lockedAt: res.lock?.locked_at,
      expiresAt: res.lock?.expires_at,
      message: res.message || ''
    };

    // If we acquired/own the lock, maintain heartbeat
    if (lockData.isOwner) {
      startCaseLockHeartbeat(caseId);
    } else {
      stopCaseLockHeartbeat();
    }

    dispatchCaseLockEvent(lockData);
    return lockData;
  } catch (err) {
    // If backend reports 423 Locked or fails, attempt read-only fetch
    console.warn(`[CASE LOCK] Could not acquire lock for ${caseId}:`, err.message);
    try {
      const statusRes = await fetchCaseLock(caseId);
      const fallbackData = {
        caseId,
        isLocked: Boolean(statusRes.is_locked),
        isOwner: Boolean(statusRes.is_owner),
        readOnly: Boolean(statusRes.read_only ?? true),
        lockStatus: statusRes.status,
        lockedBy: statusRes.lock?.locked_by || { name: 'Another Analyst' },
        lockedAt: statusRes.lock?.locked_at,
        expiresAt: statusRes.lock?.expires_at,
        message: statusRes.message || 'Case is locked in read-only mode.'
      };
      stopCaseLockHeartbeat();
      dispatchCaseLockEvent(fallbackData);
      return fallbackData;
    } catch (_fallbackErr) {
      const errLock = {
        caseId,
        isLocked: false,
        isOwner: true,
        readOnly: false,
        message: 'Could not connect to lock manager.'
      };
      dispatchCaseLockEvent(errLock);
      return errLock;
    }
  }
}

/**
 * Heartbeat management
 */
export function startCaseLockHeartbeat(caseId) {
  stopCaseLockHeartbeat();
  _activeLockedCaseId = caseId;

  // Ping heartbeat every 45 seconds to keep 10-minute TTL fresh
  _activeHeartbeatTimer = setInterval(async () => {
    if (!_activeLockedCaseId) return;
    try {
      const res = await sendCaseLockHeartbeat(_activeLockedCaseId);
      if (res && res.read_only) {
        // Lost ownership
        stopCaseLockHeartbeat();
        dispatchCaseLockEvent({
          caseId: _activeLockedCaseId,
          isLocked: true,
          isOwner: false,
          readOnly: true,
          lockedBy: res.lock?.locked_by || { name: 'Another Analyst' },
          message: 'Case lock was transferred or expired. Switched to Read-Only mode.'
        });
      }
    } catch (e) {
      console.warn('[CASE LOCK] Heartbeat ping failed:', e.message);
    }
  }, 45000);
}

export function stopCaseLockHeartbeat() {
  if (_activeHeartbeatTimer) {
    clearInterval(_activeHeartbeatTimer);
    _activeHeartbeatTimer = null;
  }
  _activeLockedCaseId = null;
}

/**
 * Release lock explicitly (e.g., when switching cases or logging out)
 */
export async function releaseActiveCaseLock(caseId) {
  const targetId = caseId || _activeLockedCaseId;
  stopCaseLockHeartbeat();
  if (!targetId) return;

  try {
    await releaseCaseLock(targetId);
  } catch (e) {
    console.debug('[CASE LOCK] Release notice:', e.message);
  } finally {
    dispatchCaseLockEvent(null);
  }
}

/**
 * Subscribe to lock changes across components
 */
export function subscribeToCaseLock(callback) {
  if (typeof window === 'undefined' || typeof callback !== 'function') {
    return () => {};
  }

  const handler = (event) => {
    callback(event.detail || null);
  };

  window.addEventListener(ARGUS_CASE_LOCK_CHANGED_EVENT, handler);
  return () => {
    window.removeEventListener(ARGUS_CASE_LOCK_CHANGED_EVENT, handler);
  };
}

// Automatically release active case lock when window is unloaded or page hides
if (typeof window !== 'undefined') {
  const onUnload = () => {
    if (_activeLockedCaseId) {
      try {
        const token = localStorage.getItem('argus_token');
        if (token && typeof navigator !== 'undefined' && navigator.sendBeacon) {
          const blob = new Blob([JSON.stringify({})], { type: 'application/json' });
          navigator.sendBeacon(`/api/v1/cases/${_activeLockedCaseId}/unlock`, blob);
        }
      } catch (_e) {}
    }
  };
  window.addEventListener('pagehide', onUnload);
  window.addEventListener('beforeunload', onUnload);
}

