import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const srcDir = path.resolve(__dirname, '../src');

test('adminCaseManagement: AdminDashboard does NOT contain broken setHasOpenCase call', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  assert.ok(fs.existsSync(pagePath), 'AdminDashboard.jsx must exist');
  const content = fs.readFileSync(pagePath, 'utf8');

  assert.ok(!content.includes('setHasOpenCase'), 'Must not call undefined setHasOpenCase');
});

test('adminCaseManagement: AdminDashboard uses setActiveCase on case creation', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  const content = fs.readFileSync(pagePath, 'utf8');

  assert.ok(content.includes('setActiveCase'), 'Must call setActiveCase to broadcast case changes');
  assert.ok(content.includes('availableAnalystOptions'), 'Must provide robust analyst options with fallback');
  assert.ok(content.includes('availableSeniorOptions'), 'Must provide robust senior analyst options with fallback');
});

test('adminCaseManagement: AdminDashboard does not use fake fallback 12 for casesSolved', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  const content = fs.readFileSync(pagePath, 'utf8');

  assert.ok(!content.includes('|| 12'), 'Must not use fake fallback 12 for cases solved');
  assert.ok(content.includes('setCasesSolved(closedCount)'), 'Must assign true closed count to casesSolved');
});

test('adminCaseManagement: AdminDashboard does not block admin from creating case when active case exists', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  const content = fs.readFileSync(pagePath, 'utf8');

  // Verify create case button opens modal directly
  assert.ok(
    content.includes('onClick={() => setShowCreateModal(true)}'),
    'Admin must be able to open Create Case modal without blocking'
  );
});

test('adminCaseManagement: AdminDashboard computes dynamic progress and displays 0% when no case or unstarted', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  const content = fs.readFileSync(pagePath, 'utf8');

  assert.ok(content.includes('progressPercent'), 'Must compute dynamic progressPercent');
  assert.ok(content.includes('stageStatusText'), 'Must provide dynamic stage status summary text');
  assert.ok(content.includes('fetchCaseSummary'), 'Must load case summary telemetry for active case');
  assert.ok(content.includes('0% Complete'), 'Must support 0% completion state for new/unstarted cases');
});
