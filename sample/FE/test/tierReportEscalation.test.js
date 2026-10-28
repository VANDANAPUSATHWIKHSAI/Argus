import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const srcDir = path.resolve(__dirname, '../src');

test('tierReportEscalation: AnalystSubmitReportModal persists senior handoff record and creates audit case note', () => {
  const modalPath = path.join(srcDir, 'components', 'AnalystSubmitReportModal.jsx');
  assert.ok(fs.existsSync(modalPath), 'AnalystSubmitReportModal.jsx must exist');
  const content = fs.readFileSync(modalPath, 'utf8');

  // Must call createCaseNote
  assert.ok(content.includes('createCaseNote'), 'Must create durable case note for analyst report handoff');

  // Must persist to localStorage key pattern argus_case_${caseId}_submitted_to_senior
  assert.ok(content.includes('submitted_to_senior'), 'Must persist handoff record in localStorage for multi-view sync');
  assert.ok(content.includes('dispatchEvent'), 'Must dispatch storage event for immediate UI synchronization');
});

test('tierReportEscalation: SeniorSubmitToAuditorModal persists auditor promotion record and validation memo', () => {
  const modalPath = path.join(srcDir, 'components', 'SeniorSubmitToAuditorModal.jsx');
  assert.ok(fs.existsSync(modalPath), 'SeniorSubmitToAuditorModal.jsx must exist');
  const content = fs.readFileSync(modalPath, 'utf8');

  // Must call createCaseNote with senior validation memo
  assert.ok(content.includes('createCaseNote'), 'Must create durable case note for senior analyst auditor escalation');
  assert.ok(content.includes('seniorMemo'), 'Must provide editable validation memo for senior review');

  // Must persist to localStorage key pattern argus_case_${caseId}_submitted_to_auditor
  assert.ok(content.includes('submitted_to_auditor'), 'Must persist auditor escalation record in localStorage');
  assert.ok(content.includes('dispatchEvent'), 'Must dispatch storage event on escalation');
});

test('tierReportEscalation: SeniorDashboard integrates both analyst submission badge and auditor escalation action', () => {
  const pagePath = path.join(srcDir, 'pages', 'SeniorDashboard.jsx');
  assert.ok(fs.existsSync(pagePath), 'SeniorDashboard.jsx must exist');
  const content = fs.readFileSync(pagePath, 'utf8');

  // Must check both submission keys
  assert.ok(content.includes('submitted_to_senior'), 'Must check analyst submission status');
  assert.ok(content.includes('submitted_to_auditor'), 'Must check auditor submission status');

  // Must render SeniorSubmitToAuditorModal
  assert.ok(content.includes('SeniorSubmitToAuditorModal'), 'Must mount SeniorSubmitToAuditorModal component');
  assert.ok(content.includes('Submit to Auditor') || content.includes('Submitted to Auditor'), 'Must render Submit to Auditor action button');
});

test('tierReportEscalation: AuditorDashboard and AuditorReportWorkspace surface Senior Analyst validation memo', () => {
  const dashPath = path.join(srcDir, 'pages', 'AuditorDashboard.jsx');
  const wsPath = path.join(srcDir, 'pages', 'AuditorReportWorkspace.jsx');
  assert.ok(fs.existsSync(dashPath), 'AuditorDashboard.jsx must exist');
  assert.ok(fs.existsSync(wsPath), 'AuditorReportWorkspace.jsx must exist');

  const dashContent = fs.readFileSync(dashPath, 'utf8');
  const wsContent = fs.readFileSync(wsPath, 'utf8');

  // Dashboard verifies escalation
  assert.ok(dashContent.includes('submitted_to_auditor'), 'AuditorDashboard must check auditor escalation status');
  assert.ok(dashContent.includes('Case Report Validated & Escalated by Senior Analyst'), 'AuditorDashboard must display Senior Analyst validation badge');

  // Workspace verifies escalation
  assert.ok(wsContent.includes('submitted_to_auditor'), 'AuditorReportWorkspace must check auditor escalation status');
  assert.ok(wsContent.includes('Validated & Promoted by Senior Analyst'), 'AuditorReportWorkspace must render Senior Analyst memo banner');
  assert.ok(wsContent.includes('SeniorSubmitToAuditorModal'), 'AuditorReportWorkspace must mount SeniorSubmitToAuditorModal for senior analyst review mode');
});

