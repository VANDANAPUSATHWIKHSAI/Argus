/**
 * ARGUS Canonical Active-Case Event and State Management
 * Standardized across the entire frontend application:
 * - Canonical event name: 'argus:caseChanged'
 * - Single source of truth for localStorage read/write with event dispatch
 * - Unified subscriber supporting both same-tab CustomEvents and cross-tab storage events
 */

export const ARGUS_CASE_CHANGED_EVENT = 'argus:caseChanged';

export function getActiveCaseId() {
  try {
    return (typeof localStorage !== 'undefined' ? localStorage.getItem('active_case_id') : null) || '';
  } catch (_e) {
    return '';
  }
}

export function getActiveCaseName() {
  try {
    return (typeof localStorage !== 'undefined' ? localStorage.getItem('active_case_name') : null) || 'Current Case';
  } catch (_e) {
    return 'Current Case';
  }
}

export function setActiveCase(caseId, caseName = '') {
  try {
    if (typeof localStorage !== 'undefined') {
      if (caseId) {
        localStorage.setItem('active_case_id', String(caseId));
        if (caseName) {
          localStorage.setItem('active_case_name', String(caseName));
        }
      } else {
        localStorage.removeItem('active_case_id');
        localStorage.removeItem('active_case_name');
      }
    }

    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
      const detail = {
        caseId: caseId ? String(caseId) : '',
        caseName: caseName ? String(caseName) : '',
      };
      const event = typeof CustomEvent === 'function'
        ? new CustomEvent(ARGUS_CASE_CHANGED_EVENT, { detail })
        : { type: ARGUS_CASE_CHANGED_EVENT, detail };
      window.dispatchEvent(event);
    }
  } catch (e) {
    console.error('Error updating active case:', e);
  }
}

/**
 * Subscribe to active-case changes across both same-window and cross-tab (storage) updates.
 * Returns an unsubscribe cleanup function.
 * @param {Function} callback - Function receiving { caseId, caseName }
 * @returns {Function} unsubscribe
 */
export function subscribeToActiveCase(callback) {
  if (typeof window === 'undefined' || typeof callback !== 'function') {
    return () => {};
  }

  const handleUpdate = (e) => {
    // If it's a cross-tab storage event, only trigger if relevant keys changed
    if (e && e.type === 'storage') {
      if (e.key !== 'active_case_id' && e.key !== 'active_case_name' && e.key !== null) {
        return;
      }
    }

    const caseId = getActiveCaseId();
    const caseName = getActiveCaseName();
    callback({ caseId, caseName });
  };

  window.addEventListener('storage', handleUpdate);
  window.addEventListener(ARGUS_CASE_CHANGED_EVENT, handleUpdate);

  return () => {
    window.removeEventListener('storage', handleUpdate);
    window.removeEventListener(ARGUS_CASE_CHANGED_EVENT, handleUpdate);
  };
}
