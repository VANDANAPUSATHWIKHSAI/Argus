import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '../src');

// Set up mock window and authenticated localStorage
const storage = new Map();
globalThis.localStorage = {
  getItem: (k) => (storage.has(k) ? storage.get(k) : null),
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
  clear: () => storage.clear(),
};
globalThis.window = {
  location: { pathname: '/report', href: '' },
  dispatchEvent: () => {},
};

const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
const futureSec = Math.floor(Date.now() / 1000) + 7200;
const validPayload = Buffer.from(JSON.stringify({ sub: 'auditor1', role: 'auditor', exp: futureSec })).toString('base64');
const validJwt = `${header}.${validPayload}.signature`;

test('reportGating: fetchReport enforces review gating with allowUnreviewed=false by default', async () => {
  localStorage.setItem('argus_token', validJwt);
  const { fetchReport } = await import('../src/js/api.js');

  let requestedUrl = '';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    requestedUrl = url;
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'text/html' },
      text: async () => '<html><body>Report Content</body></html>'
    };
  };

  try {
    await fetchReport('CASE-TEST-101');
    assert.ok(requestedUrl.includes('allow_unreviewed=false'), 'Must pass allow_unreviewed=false by default');

    await fetchReport('CASE-TEST-102', 'pdf', false);
    assert.ok(requestedUrl.includes('allow_unreviewed=false'), 'Must pass allow_unreviewed=false when false');

    await fetchReport('CASE-TEST-103', 'html', true);
    assert.ok(requestedUrl.includes('allow_unreviewed=true'), 'Allows unreviewed only with explicit true');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('reportGating: AuditorReportWorkspace does not contain hardcoded ARGUS_956 fallback', () => {
  const workspacePath = path.join(feSrcDir, 'pages', 'AuditorReportWorkspace.jsx');
  const source = fs.readFileSync(workspacePath, 'utf8');

  // Verify ARGUS_956 fallback is eliminated
  assert.ok(!source.includes("|| 'ARGUS_956'"), 'Must not fallback to hardcoded ARGUS_956 in state initialization');
  assert.ok(!source.includes("=== 'ARGUS_956'"), 'Must not search for hardcoded ARGUS_956 in backend case list');
});

test('reportGating: AuditorReportWorkspace validates stored case against authorized backend cases', () => {
  const workspacePath = path.join(feSrcDir, 'pages', 'AuditorReportWorkspace.jsx');
  const source = fs.readFileSync(workspacePath, 'utf8');

  assert.ok(source.includes('validCases.find(c => c.case_id === stored)'), 'Must validate stored case against backend cases');
  assert.ok(source.includes("setActiveCase(presentCase.case_id,"), 'Must set active case from backend case');
});

test('reportGating: MITRE ATT&CK mappings are explicitly labeled as local display labels', () => {
  const workspacePath = path.join(feSrcDir, 'pages', 'AuditorReportWorkspace.jsx');
  const source = fs.readFileSync(workspacePath, 'utf8');

  assert.ok(
    source.includes('Note: MITRE ATT&CK technique names are local UI display labels for reference only, not certified forensic conclusions.'),
    'Must present MITRE mappings as local display labels only, not authoritative conclusions'
  );
});

test('reportGating: Evidence SHA-256 displays explicit unverified integrity status', () => {
  const workspacePath = path.join(feSrcDir, 'pages', 'AuditorReportWorkspace.jsx');
  const source = fs.readFileSync(workspacePath, 'utf8');

  assert.ok(
    source.includes('Integrity unverified by server'),
    'Must explicitly state evidence integrity is unverified by server'
  );
});
