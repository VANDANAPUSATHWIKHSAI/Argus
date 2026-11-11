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

test('reportGating: fetchReport never sets report_completed flag prematurely on read', async () => {
  localStorage.clear();
  localStorage.setItem('argus_token', validJwt);
  const { fetchReport } = await import('../src/js/api.js');

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => ({ case_id: 'CASE-UNFINISHED', findings: [] }),
  });

  try {
    await fetchReport('CASE-UNFINISHED', 'json', true);
    assert.equal(
      localStorage.getItem('argus_case_CASE-UNFINISHED_report_completed'),
      null,
      'Reading draft report must not mark argus_case_*_report_completed as true'
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('reportGating: getCaseSubmissionState and isAgentSwarmComplete keep incomplete cases locked', async () => {
  localStorage.clear();
  const { getCaseSubmissionState, isAgentSwarmComplete } = await import('../src/js/caseUtils.js');

  const openUnfinished = getCaseSubmissionState({ case_id: 'CASE-NEW', status: 'open', has_report: false }, 'CASE-NEW');
  assert.equal(openUnfinished.isReportReady, false);
  assert.equal(openUnfinished.submittedToSenior, false);
  assert.equal(openUnfinished.submittedToAuditor, false);

  const partialAgents = isAgentSwarmComplete({
    stage_statuses: { agent1: 'COMPLETED', agent2: 'RUNNING', agent7: 'PENDING' },
    findings_count: 2,
  }, 2);
  assert.equal(partialAgents, false);

  const fullAgents = isAgentSwarmComplete({
    stage_statuses: {
      agent1: 'COMPLETED',
      agent2: 'COMPLETED',
      agent3: 'COMPLETED',
      agent4: 'COMPLETED',
      agent5a: 'COMPLETED',
      agent5b: 'COMPLETED',
      agent6: 'COMPLETED',
      agent7: 'COMPLETED',
    },
    findings_count: 2,
  }, 2);
  assert.equal(fullAgents, true);

  const submittedCase = getCaseSubmissionState({ case_id: 'CASE-DONE', status: 'open', submitted_to_senior: true }, 'CASE-DONE');
  assert.equal(submittedCase.isReportReady, true);
  assert.equal(submittedCase.submittedToSenior, true);
});

test('reportGating: SeniorDashboard, AuditorDashboard, AuditorReportWorkspace, and Chatbot gate reports until completion', () => {
  const seniorSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'SeniorDashboard.jsx'), 'utf8');
  const audDashSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'AuditorDashboard.jsx'), 'utf8');
  const audWsSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'AuditorReportWorkspace.jsx'), 'utf8');
  const chatSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'Chatbot.jsx'), 'utf8');
  const modalSrc = fs.readFileSync(path.join(feSrcDir, 'components', 'AnalystSubmitReportModal.jsx'), 'utf8');

  assert.ok(seniorSrc.includes('if (subState.isReportReady)'), 'SeniorDashboard must only fetch report when ready');
  assert.ok(audDashSrc.includes('if (!subState.isReportReady)'), 'AuditorDashboard must not fetch report before completion');
  assert.ok(audDashSrc.includes('isReportUnlocked ? ('), 'AuditorDashboard must lock GeneratedReportCard until report unlocks');
  assert.ok(audWsSrc.includes('!isReportReady'), 'AuditorReportWorkspace must gate all roles when report is not ready');
  assert.ok(chatSrc.includes('isAgentSwarmComplete'), 'Chatbot must verify swarm completion before generating report');
  assert.ok(modalSrc.includes('isAgentComplete'), 'AnalystSubmitReportModal must accept and enforce isAgentComplete');
});

test('reportGating: isAgentSwarmComplete unlocks finished NEEDS_REVIEW / PARTIAL_SUCCESS / claims-only swarms while blocking failed runs', async () => {
  localStorage.clear();
  const { isAgentSwarmComplete, isAgentStageFinished } = await import('../src/js/caseUtils.js');

  assert.equal(isAgentStageFinished('NEEDS_REVIEW'), true);
  assert.equal(isAgentStageFinished('PARTIAL_SUCCESS'), true);
  assert.equal(isAgentStageFinished('FAILED'), false);
  assert.equal(isAgentStageFinished('RUNNING'), false);

  const reviewAndPartialClaimsOnly = isAgentSwarmComplete({
    status: 'PARTIAL_SUCCESS',
    findings_count: 0,
    stage_statuses: {
      agent1: 'SUCCESS',
      agent2: 'SUCCESS',
      agent3: 'COMPLETED_WITH_FINDINGS',
      agent4: 'COMPLETED',
      agent5a: 'PARTIAL_SUCCESS',
      agent5b: 'SUCCESS',
      agent6: 'COMPLETED',
      agent7: 'NEEDS_REVIEW',
    },
    claims: [{ agent_id: 'agent1', claim: 'Verified binary metadata' }],
  }, 0);
  assert.equal(reviewAndPartialClaimsOnly, true);

  const cleanNoFindingsRun = isAgentSwarmComplete({
    status: 'COMPLETED',
    evidence_count: 1,
    findings_count: 0,
    stage_statuses: {
      agent1: 'SUCCESS',
      agent2: 'SUCCESS',
      agent3: 'COMPLETED_WITH_NO_FINDINGS',
      agent4: 'COMPLETED',
      agent5a: 'SUCCESS',
      agent5b: 'SUCCESS',
      agent6: 'COMPLETED',
      agent7: 'NO_CLAIMS',
    },
  }, 0);
  assert.equal(cleanNoFindingsRun, true);

  const failedAgent7 = isAgentSwarmComplete({
    status: 'PARTIAL_SUCCESS',
    findings_count: 3,
    stage_statuses: {
      agent1: 'SUCCESS',
      agent2: 'SUCCESS',
      agent3: 'COMPLETED',
      agent4: 'COMPLETED',
      agent5a: 'SUCCESS',
      agent5b: 'SUCCESS',
      agent6: 'COMPLETED',
      agent7: 'FAILED',
    },
  }, 3);
  assert.equal(failedAgent7, false);

  const agentsSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'Agents.jsx'), 'utf8');
  assert.ok(agentsSrc.includes('isAgentStageFinished'), 'Agents.jsx must reuse shared isAgentStageFinished helper');
  assert.ok(agentsSrc.includes('isAgentSwarmComplete'), 'Agents.jsx must reuse shared isAgentSwarmComplete helper');

  const chatSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'Chatbot.jsx'), 'utf8');
  assert.ok(chatSrc.includes('isChatbotReportUnlocked'), 'Chatbot sidebar must gate report readiness pill behind completed swarm');

  const adminSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'AdminDashboard.jsx'), 'utf8');
  assert.ok(adminSrc.includes("Closed Early"), 'AdminDashboard must not show completed report on early-closed cases without report');

  const audDashSrc = fs.readFileSync(path.join(feSrcDir, 'pages', 'AuditorDashboard.jsx'), 'utf8');
  assert.ok(audDashSrc.includes('disabled={!isReportUnlocked}'), 'AuditorDashboard header button must stay disabled before report unlock');
});

