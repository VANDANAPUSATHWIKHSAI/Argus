import test from 'node:test';
import assert from 'node:assert/strict';

// Set up mock window and localStorage for Node test runner
const storage = new Map();
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
  clear: () => storage.clear(),
};
globalThis.window = {
  dispatchEvent: () => {},
};

const {
  isTokenExpired,
  getTokenRemainingMs,
  getAuthTenantId,
  clearAuthSession,
} = await import('../src/js/authSession.js');

test('authSession: isTokenExpired fails closed when token is missing', () => {
  assert.equal(isTokenExpired(null), true);
  assert.equal(isTokenExpired(undefined), true);
  assert.equal(isTokenExpired(''), true);
});

test('authSession: isTokenExpired fails closed on non-JWT or malformed tokens', () => {
  // Developer role switcher tokens or plaintext fake tokens
  assert.equal(isTokenExpired('dev_role_token_admin_12345'), true);
  assert.equal(isTokenExpired('not.a.valid.jwt.with.too.many.parts'), true);
  assert.equal(isTokenExpired('invalid-two-parts.token'), true);
});

test('authSession: isTokenExpired fails closed when JWT exp is missing or non-numeric', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const payloadNoExp = Buffer.from(JSON.stringify({ sub: 'admin', role: 'admin' })).toString('base64');
  const tokenNoExp = `${header}.${payloadNoExp}.signature`;

  assert.equal(isTokenExpired(tokenNoExp), true);

  const payloadStringExp = Buffer.from(JSON.stringify({ sub: 'admin', exp: 'tomorrow' })).toString('base64');
  const tokenStringExp = `${header}.${payloadStringExp}.signature`;
  assert.equal(isTokenExpired(tokenStringExp), true);
});

test('authSession: isTokenExpired correctly validates future vs expired tokens', () => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');

  // Expired token (1 hour in the past)
  const pastSec = Math.floor(Date.now() / 1000) - 3600;
  const expiredPayload = Buffer.from(JSON.stringify({ sub: 'user1', exp: pastSec })).toString('base64');
  const expiredToken = `${header}.${expiredPayload}.sig`;
  assert.equal(isTokenExpired(expiredToken), true);
  assert.equal(getTokenRemainingMs(expiredToken), 0);

  // Active token (1 hour in the future)
  const futureSec = Math.floor(Date.now() / 1000) + 3600;
  const activePayload = Buffer.from(JSON.stringify({ sub: 'user2', exp: futureSec })).toString('base64');
  const activeToken = `${header}.${activePayload}.sig`;
  assert.equal(isTokenExpired(activeToken), false);
  assert.ok(getTokenRemainingMs(activeToken) > 3000 * 1000);
});

test('authSession: getAuthTenantId retrieves stored tenant or falls back safely', () => {
  localStorage.clear();
  assert.equal(getAuthTenantId(), null);

  localStorage.setItem('argus_tenant', 'tenant-forensics-42');
  assert.equal(getAuthTenantId(), 'tenant-forensics-42');
});

test('authSession: clearAuthSession purges all sensitive forensic session keys', () => {
  localStorage.setItem('argus_token', 'sample-token');
  localStorage.setItem('argus_user', JSON.stringify({ userid: 'analyst1', role: 'analyst' }));
  localStorage.setItem('argus_tenant', 'tenant-a');
  localStorage.setItem('active_case_id', 'CASE-999');
  localStorage.setItem('active_case_name', 'Incident Alpha');

  clearAuthSession();

  assert.equal(localStorage.getItem('argus_token'), null);
  assert.equal(localStorage.getItem('argus_user'), null);
  assert.equal(localStorage.getItem('argus_tenant'), null);
  assert.equal(localStorage.getItem('active_case_id'), null);
  assert.equal(localStorage.getItem('active_case_name'), null);
});
