import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
const validPayload = Buffer.from(JSON.stringify({ sub: 'analyst1', role: 'analyst', exp: futureSec })).toString('base64');
const validJwt = `${header}.${validPayload}.signature`;

const {
  fetchCurrentUserProfile,
  updateCurrentUserProfile
} = await import('../src/js/api.js');

test('profileApi: fetchCurrentUserProfile calls /auth/me with auth token and tenant header', async () => {
  localStorage.setItem('argus_token', validJwt);
  localStorage.setItem('argus_tenant', 'argus-core');

  let interceptedUrl = '';
  let interceptedMethod = 'GET';
  let interceptedHeaders = {};

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    interceptedUrl = url;
    interceptedMethod = options.method || 'GET';
    interceptedHeaders = options.headers || {};
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({
        id: 'analyst1',
        name: 'Junior Analyst',
        email: 'analyst@argus.local',
        role: 'analyst',
        phone: '+1-555-0101',
        doj: '2025-01-15'
      })
    };
  };

  try {
    const profile = await fetchCurrentUserProfile();
    assert.ok(interceptedUrl.endsWith('/auth/me'));
    assert.equal(interceptedMethod, 'GET');
    assert.equal(interceptedHeaders['Authorization'], `Bearer ${validJwt}`);
    assert.equal(interceptedHeaders['X-Tenant-ID'], 'argus-core');
    assert.equal(profile.id, 'analyst1');
    assert.equal(profile.name, 'Junior Analyst');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('profileApi: updateCurrentUserProfile issues PUT /auth/me with updated fields', async () => {
  localStorage.setItem('argus_token', validJwt);

  let interceptedUrl = '';
  let interceptedMethod = '';
  let interceptedBody = null;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    interceptedUrl = url;
    interceptedMethod = options.method || 'GET';
    interceptedBody = options.body ? JSON.parse(options.body) : null;
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({
        id: 'analyst1',
        name: 'Analyst Jane',
        email: 'jane@argus.local',
        phone: '+1-555-9988'
      })
    };
  };

  try {
    const updated = await updateCurrentUserProfile({
      name: 'Analyst Jane',
      email: 'jane@argus.local',
      phone: '+1-555-9988'
    });

    assert.ok(interceptedUrl.endsWith('/auth/me'));
    assert.equal(interceptedMethod, 'PUT');
    assert.deepEqual(interceptedBody, {
      name: 'Analyst Jane',
      email: 'jane@argus.local',
      phone: '+1-555-9988'
    });
    assert.equal(updated.name, 'Analyst Jane');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('profileRoute: App.jsx registers /profile for all operational roles', () => {
  const appSrc = fs.readFileSync(path.resolve(__dirname, '../src/App.jsx'), 'utf8');
  assert.ok(appSrc.includes('path="/profile"'), 'App.jsx must register /profile path');
  assert.ok(appSrc.includes("allowedRoles={['admin', 'analyst', 'senior_analyst', 'auditor']}"), 'Profile must be accessible to all authenticated roles');
});

test('profileSecurity: Profile.jsx displays actual user fields and never reveals passwords or secrets', () => {
  const profileSrc = fs.readFileSync(path.resolve(__dirname, '../src/pages/Profile.jsx'), 'utf8');
  assert.ok(profileSrc.includes('fetchCurrentUserProfile'), 'Profile page must fetch live authenticated user details');
  assert.ok(profileSrc.includes('updateCurrentUserProfile'), 'Profile page must support updating user profile');
  assert.ok(!profileSrc.includes('password_hash'), 'Profile component must never expose or display password hashes');
  assert.ok(!profileSrc.includes('analyst@agency.gov'), 'Profile component must not use hardcoded dummy agency emails');
});
