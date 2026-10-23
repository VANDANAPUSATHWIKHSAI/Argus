import test from 'node:test';
import assert from 'node:assert/strict';

// Set up mock window and localStorage
const storage = new Map();
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
  clear: () => storage.clear(),
};
globalThis.window = {
  location: { pathname: '/dashboard', href: '' },
  dispatchEvent: () => {},
};

// Create a valid non-expired JWT for authenticated tests
const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
const futureSec = Math.floor(Date.now() / 1000) + 7200;
const validPayload = Buffer.from(JSON.stringify({ sub: 'auditor1', role: 'auditor', exp: futureSec })).toString('base64');
const validJwt = `${header}.${validPayload}.signature`;

const {
  fetchWithAuth,
  fetchAuditorStats,
  fetchReport,
  getActiveTenantId
} = await import('../src/js/api.js');

test('apiSecurity: fetchWithAuth attaches Authorization and authoritative tenant headers', async () => {
  localStorage.setItem('argus_token', validJwt);
  localStorage.setItem('argus_tenant', 'secops-tenant-101');

  let interceptedUrl = '';
  let interceptedHeaders = {};

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    interceptedUrl = url;
    interceptedHeaders = options.headers || {};
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ status: 'success', data: [] })
    };
  };

  try {
    const res = await fetchWithAuth('/cases/');
    assert.ok(interceptedUrl.endsWith('/cases/'));
    assert.equal(interceptedHeaders['Authorization'], `Bearer ${validJwt}`);
    assert.equal(interceptedHeaders['X-Tenant-ID'], 'secops-tenant-101');
    assert.deepEqual(res, { status: 'success', data: [] });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiSecurity: fetchWithAuth throws and fails closed on 401 Unauthorized', async () => {
  localStorage.setItem('argus_token', validJwt);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    headers: { get: () => 'application/json' },
    json: async () => ({ detail: 'Token has expired or is invalid' })
  });

  try {
    await assert.rejects(
      async () => {
        await fetchWithAuth('/cases/secret-123');
      },
      (err) => {
        assert.equal(err.status, 401);
        assert.ok(err.message.includes('Token has expired'));
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiSecurity: fetchAuditorStats does NOT retry without authentication', async () => {
  localStorage.setItem('argus_token', validJwt);

  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, options) => {
    fetchCalls += 1;
    // Verify that every single call sends the Authorization header
    assert.ok(options.headers['Authorization'], 'Every call must include Authorization header');
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ totalCases: 5, pendingAudits: 2 })
    };
  };

  try {
    const stats = await fetchAuditorStats();
    assert.equal(fetchCalls, 1);
    assert.equal(stats.totalCases, 5);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiSecurity: fetchReport defaults to allowUnreviewed=false', async () => {
  localStorage.setItem('argus_token', validJwt);

  let capturedUrl = '';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    capturedUrl = url;
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'text/html' },
      text: async () => '<html><body>Forensic Report</body></html>'
    };
  };

  try {
    await fetchReport('CASE-2026-001');
    assert.ok(capturedUrl.includes('allow_unreviewed=false'), `Expected allow_unreviewed=false in ${capturedUrl}`);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiSecurity: getActiveTenantId does not trust arbitrary client keys', () => {
  localStorage.clear();
  assert.equal(getActiveTenantId(), 'default');

  localStorage.setItem('argus_tenant', 'enterprise-org-9');
  assert.equal(getActiveTenantId(), 'enterprise-org-9');
});
