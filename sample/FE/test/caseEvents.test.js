import test from 'node:test';
import assert from 'node:assert/strict';

// Set up mock window and storage
const storage = new Map();
const listeners = new Map();

globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
  clear: () => storage.clear(),
};

globalThis.window = {
  addEventListener: (event, handler) => {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event).add(handler);
  },
  removeEventListener: (event, handler) => {
    if (listeners.has(event)) {
      listeners.get(event).delete(handler);
    }
  },
  dispatchEvent: (event) => {
    const handlers = listeners.get(event.type);
    if (handlers) {
      for (const h of handlers) {
        h(event);
      }
    }
  }
};

globalThis.CustomEvent = class CustomEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.detail = init.detail || {};
  }
};

const {
  ARGUS_CASE_CHANGED_EVENT,
  getActiveCaseId,
  getActiveCaseName,
  setActiveCase,
  subscribeToActiveCase
} = await import('../src/js/caseEvents.js');

test('caseEvents: canonical event name is argus:caseChanged', () => {
  assert.equal(ARGUS_CASE_CHANGED_EVENT, 'argus:caseChanged');
});

test('caseEvents: setActiveCase updates storage and dispatches canonical event', () => {
  storage.clear();
  let receivedDetail = null;

  const handleCase = (e) => {
    receivedDetail = e.detail;
  };
  window.addEventListener(ARGUS_CASE_CHANGED_EVENT, handleCase);

  try {
    setActiveCase('CASE-2026-X1', 'Operation Ironclad');
    assert.equal(getActiveCaseId(), 'CASE-2026-X1');
    assert.equal(getActiveCaseName(), 'Operation Ironclad');
    assert.ok(receivedDetail);
    assert.equal(receivedDetail.caseId, 'CASE-2026-X1');
    assert.equal(receivedDetail.caseName, 'Operation Ironclad');
  } finally {
    window.removeEventListener(ARGUS_CASE_CHANGED_EVENT, handleCase);
  }
});

test('caseEvents: subscribeToActiveCase handles same-window events', () => {
  storage.clear();
  let notifiedState = null;

  const unsubscribe = subscribeToActiveCase((state) => {
    notifiedState = state;
  });

  try {
    setActiveCase('CASE-888', 'Solaris Breach');
    assert.ok(notifiedState);
    assert.equal(notifiedState.caseId, 'CASE-888');
    assert.equal(notifiedState.caseName, 'Solaris Breach');
  } finally {
    unsubscribe();
  }
});

test('caseEvents: subscribeToActiveCase synchronizes cross-tab storage changes', () => {
  storage.clear();
  let notifiedState = null;

  const unsubscribe = subscribeToActiveCase((state) => {
    notifiedState = state;
  });

  try {
    // Simulate another browser tab writing to localStorage
    storage.set('active_case_id', 'CASE-CROSS-TAB');
    storage.set('active_case_name', 'Cross Tab Case');

    // Simulate browser firing 'storage' event in this window
    window.dispatchEvent({ type: 'storage', key: 'active_case_id' });

    assert.ok(notifiedState);
    assert.equal(notifiedState.caseId, 'CASE-CROSS-TAB');
    assert.equal(notifiedState.caseName, 'Cross Tab Case');
  } finally {
    unsubscribe();
  }
});

test('caseEvents: subscribeToActiveCase ignores unrelated storage keys', () => {
  storage.clear();
  let callCount = 0;

  const unsubscribe = subscribeToActiveCase(() => {
    callCount += 1;
  });

  try {
    window.dispatchEvent({ type: 'storage', key: 'argus_theme' });
    window.dispatchEvent({ type: 'storage', key: 'unrelated_data' });
    assert.equal(callCount, 0);
  } finally {
    unsubscribe();
  }
});

test('caseEvents: setActiveCase with empty arguments clears active case and notifies subscribers', () => {
  storage.set('active_case_id', 'OLD-CASE');
  storage.set('active_case_name', 'Old Case');

  let notifiedState = null;
  const unsubscribe = subscribeToActiveCase((state) => {
    notifiedState = state;
  });

  try {
    setActiveCase('', '');
    assert.equal(getActiveCaseId(), '');
    assert.equal(getActiveCaseName(), 'Current Case');
    assert.ok(notifiedState);
    assert.equal(notifiedState.caseId, '');
  } finally {
    unsubscribe();
  }
});

test('caseEvents: unsubscribe cleanly removes both event listeners preventing memory leaks', () => {
  let callCount = 0;
  const unsubscribe = subscribeToActiveCase(() => {
    callCount += 1;
  });

  unsubscribe();

  setActiveCase('CASE-999', 'Ghost Case');
  window.dispatchEvent({ type: 'storage', key: 'active_case_id' });

  assert.equal(callCount, 0);
});
