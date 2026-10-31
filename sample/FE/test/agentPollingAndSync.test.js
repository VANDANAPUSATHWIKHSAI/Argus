import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '../src');

test('agentPollingAndSync: Agents.jsx prevents overlapping polling cycles', () => {
  const agentsPath = path.join(feSrcDir, 'pages', 'Agents.jsx');
  const source = fs.readFileSync(agentsPath, 'utf8');

  // Verify isPolling lock is used to prevent overlapping async requests inside interval
  assert.ok(source.includes('let isPolling = false;'), 'Must initialize polling lock');
  assert.ok(source.includes('if (isPolling) return;'), 'Must skip cycle when previous polling cycle is in-flight');
  assert.ok(source.includes('isPolling = true;'), 'Must set lock before async fetch');
  assert.ok(source.includes('isPolling = false;'), 'Must release lock in finally block');
});

test('agentPollingAndSync: in-flight responses for an old case cannot overwrite newly selected case', () => {
  const agentsPath = path.join(feSrcDir, 'pages', 'Agents.jsx');
  const source = fs.readFileSync(agentsPath, 'utf8');

  // Verify race condition guards in loadAgentResults
  assert.ok(
    source.includes('if (getActiveCaseId() !== caseId) return;'),
    'Must discard response if active case changed while request was in flight'
  );

  // Verify race condition guards in polling interval
  assert.ok(
    source.includes('if (getActiveCaseId() !== activeCaseId) return;'),
    'Polling must discard telemetry if active case changed'
  );
});

test('agentPollingAndSync: duplicate agent execution is prevented when running or loading', () => {
  const agentsPath = path.join(feSrcDir, 'pages', 'Agents.jsx');
  const source = fs.readFileSync(agentsPath, 'utf8');

  // Verify handleRunAnalysis guard
  assert.ok(
    source.includes('if (runningAgents || loading) return;'),
    'Must prevent duplicate triggers when running or loading'
  );

  // Verify button is disabled
  assert.ok(
    source.includes('disabled={runningAgents || loading || !activeCaseId'),
    'Run button must be disabled when running, loading, or no active case'
  );
});

test('agentPollingAndSync: bounded error threshold terminates polling on repeated failures', () => {
  const agentsPath = path.join(feSrcDir, 'pages', 'Agents.jsx');
  const source = fs.readFileSync(agentsPath, 'utf8');

  assert.ok(source.includes('const MAX_CONSECUTIVE_ERRORS = 5;'), 'Must define bounded error threshold');
  assert.ok(source.includes('if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS)'), 'Must check consecutive error limit');
  assert.ok(source.includes("title: '📡 Backend Polling Paused'"), 'Must produce truthful warning when polling stops');
});

test('agentPollingAndSync: tabs and tabpanels have accessible ARIA roles and keyboard interaction', () => {
  const agentsPath = path.join(feSrcDir, 'pages', 'Agents.jsx');
  const source = fs.readFileSync(agentsPath, 'utf8');

  assert.ok(source.includes('role="tablist"'), 'Must have tablist container');
  assert.ok(source.includes('role="tab"'), 'Must have tab role for agent selection');
  assert.ok(source.includes('aria-selected={isSelected}'), 'Must indicate selected tab state');
  assert.ok(source.includes('aria-controls={`agent-panel-${agent.id}`}'), 'Tab must declare aria-controls');
  assert.ok(source.includes('role="tabpanel"'), 'Deep dive card must have tabpanel role');
  assert.ok(source.includes('aria-labelledby={`agent-tab-${selectedAgentTab}`}'), 'Tabpanel must declare aria-labelledby');
  assert.ok(source.includes("if (e.key === 'Enter' || e.key === ' ')"), 'Must support keyboard selection');
});
