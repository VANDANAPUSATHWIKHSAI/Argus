import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '..', 'src');
const backendRoutesDir = path.resolve(__dirname, '..', '..', '..', 'api', 'routes');

test('caseUtils: isCaseReportGenerated identifies cases with and without generated reports', async () => {
  const { isCaseReportGenerated } = await import('../src/js/caseUtils.js');

  // Case with report flags
  assert.equal(isCaseReportGenerated({ case_id: 'C1', has_report: true }), true);
  assert.equal(isCaseReportGenerated({ case_id: 'C2', submitted_to_senior: true }), true);
  assert.equal(isCaseReportGenerated({ case_id: 'C3', submitted_to_auditor: true }), true);
  assert.equal(isCaseReportGenerated({ case_id: 'C4', audit_certified: true }), true);
  assert.equal(isCaseReportGenerated({ case_id: 'C5', audit_status: 'certified' }), true);

  // Case without report
  assert.equal(isCaseReportGenerated({ case_id: 'C_OPEN', status: 'open' }), false);
  assert.equal(isCaseReportGenerated(null), false);
  assert.equal(isCaseReportGenerated(''), false);
});

test('CloseCaseReasonModal.jsx: renders reason modal with validation, accessibility and presets', () => {
  const modalPath = path.join(feSrcDir, 'components', 'CloseCaseReasonModal.jsx');
  assert.ok(fs.existsSync(modalPath), 'CloseCaseReasonModal.jsx must exist in components directory');

  const source = fs.readFileSync(modalPath, 'utf8');
  assert.ok(source.includes('role="dialog"'), 'Must have role=dialog for accessibility');
  assert.ok(source.includes('aria-modal="true"'), 'Must have aria-modal attribute');
  assert.ok(source.includes('textarea'), 'Must have textarea for entering reason');
  assert.ok(source.includes('trimmed'), 'Must validate trimmed reason');
  assert.ok(source.includes('PRESET_REASONS'), 'Must provide preset quick closure rationale chips');
  assert.ok(source.includes('Confirm & Close Case') || source.includes('Confirm &amp; Close Case'), 'Must have confirmation action button');
  assert.ok(source.includes('onClose'), 'Must handle close/cancel');
});

test('Cases.jsx: guards case closing and asks for reason if closed before report generation', () => {
  const casesPath = path.join(feSrcDir, 'pages', 'Cases.jsx');
  const source = fs.readFileSync(casesPath, 'utf8');

  assert.ok(source.includes('CloseCaseReasonModal'), 'Cases.jsx must import and mount CloseCaseReasonModal');
  assert.ok(source.includes('isCaseReportGenerated'), 'Cases.jsx must check isCaseReportGenerated before closing');
  assert.ok(source.includes('executeCloseCase'), 'Cases.jsx must execute closure with supplied reason');
  assert.ok(source.includes('closeReasonModal'), 'Cases.jsx must manage closeReasonModal state');
});

test('AdminDashboard.jsx: prompts for reason when closing a case before report generation', () => {
  const adminPath = path.join(feSrcDir, 'pages', 'AdminDashboard.jsx');
  const source = fs.readFileSync(adminPath, 'utf8');

  assert.ok(source.includes('CloseCaseReasonModal'), 'AdminDashboard.jsx must import and mount CloseCaseReasonModal');
  assert.ok(source.includes('isCaseReportGenerated'), 'AdminDashboard.jsx must verify if case report is generated');
  assert.ok(source.includes('initiateCloseCase'), 'AdminDashboard.jsx must gate close button through initiateCloseCase');
});

test('Evidence, Upload, and Sanitized pages: enforce closure reason when closing before report generation', () => {
  const evidenceSource = fs.readFileSync(path.join(feSrcDir, 'pages', 'Evidence.jsx'), 'utf8');
  const uploadSource = fs.readFileSync(path.join(feSrcDir, 'pages', 'Upload.jsx'), 'utf8');
  const sanitizedSource = fs.readFileSync(path.join(feSrcDir, 'pages', 'Sanitized.jsx'), 'utf8');

  assert.ok(evidenceSource.includes('CloseCaseReasonModal'), 'Evidence.jsx must mount CloseCaseReasonModal');
  assert.ok(evidenceSource.includes('isCaseReportGenerated'), 'Evidence.jsx must check isCaseReportGenerated');

  assert.ok(uploadSource.includes('CloseCaseReasonModal'), 'Upload.jsx must mount CloseCaseReasonModal');
  assert.ok(uploadSource.includes('isCaseReportGenerated'), 'Upload.jsx must check isCaseReportGenerated');

  assert.ok(sanitizedSource.includes('CloseCaseReasonModal'), 'Sanitized.jsx must mount CloseCaseReasonModal');
  assert.ok(sanitizedSource.includes('isCaseReportGenerated'), 'Sanitized.jsx must check isCaseReportGenerated');
});

test('Backend api/routes/cases.py: rejects closing case without report when reason is absent', () => {
  const casesRoutePath = path.join(backendRoutesDir, 'cases.py');
  const source = fs.readFileSync(casesRoutePath, 'utf8');

  assert.ok(source.includes('has_report'), 'Backend cases.py must check case report status');
  assert.ok(source.includes('A reason is required to close a case before report generation'), 'Backend must reject close if no report and no reason');
  assert.ok(source.includes('closed_reason'), 'Backend must record closed_reason');
});
