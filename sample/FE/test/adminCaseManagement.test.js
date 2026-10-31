import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const srcDir = path.resolve(__dirname, '../src');

test('adminCaseManagement: AdminDashboard imports and uses canonical setActiveCase and subscribeToActiveCase', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  assert.ok(fs.existsSync(pagePath), 'AdminDashboard.jsx must exist');
  const content = fs.readFileSync(pagePath, 'utf8');

  // Must import canonical setActiveCase and subscribeToActiveCase
  assert.ok(
    content.includes('setActiveCase') && content.includes('../js/caseEvents'),
    'AdminDashboard must import canonical setActiveCase from caseEvents'
  );
  assert.ok(
    content.includes('subscribeToActiveCase'),
    'AdminDashboard must subscribe to active case changes'
  );

  // Must call setActiveCase on case creation
  assert.ok(
    content.includes('setActiveCase(createdId, newCaseName)'),
    'AdminDashboard must invoke setActiveCase on case creation'
  );

  // Must NOT reference undefined setHasOpenCase
  assert.ok(
    !content.includes('setHasOpenCase'),
    'AdminDashboard must not have undefined setHasOpenCase calls'
  );
});

test('adminCaseManagement: AdminDashboard dynamically computes case stage without falsely labeling new cases as Under Review', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  const content = fs.readFileSync(pagePath, 'utf8');

  // Must have getCaseStageInfo
  assert.ok(
    content.includes('getCaseStageInfo'),
    'AdminDashboard must compute case stage info based on actual lifecycle progress'
  );

  // Must distinguish between investigation, review, audit, and closed
  assert.ok(
    content.includes("stage: 'investigation'"),
    'Must support active investigation stage for newly created cases'
  );
  assert.ok(
    content.includes("stage: 'review'"),
    'Must support review stage when report submitted to senior'
  );
  assert.ok(
    content.includes("stage: 'audit'"),
    'Must support audit stage when escalated to auditor'
  );
  assert.ok(
    content.includes("stage: 'closed'"),
    'Must support closed stage'
  );

  // Must support clean pending states when no case is active
  assert.ok(
    content.includes("investigationStatus: 'pending'"),
    'All pipeline nodes must remain pending when no case is active'
  );
});

test('adminCaseManagement: SearchableSelect for analyst assignment has resilient fallback options', () => {
  const pagePath = path.join(srcDir, 'pages', 'AdminDashboard.jsx');
  const content = fs.readFileSync(pagePath, 'utf8');

  assert.ok(
    content.includes('analystSelectOptions'),
    'AdminDashboard must define resilient analystSelectOptions'
  );
  assert.ok(
    content.includes('seniorSelectOptions'),
    'AdminDashboard must define resilient seniorSelectOptions'
  );
});
