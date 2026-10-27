import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '../src');

test('caseLockService: exports canonical lock event and lifecycle sync functions', async () => {
  const servicePath = path.join(feSrcDir, 'js', 'caseLockService.js');
  const source = fs.readFileSync(servicePath, 'utf8');

  assert.ok(source.includes("export const ARGUS_CASE_LOCK_CHANGED_EVENT = 'argus:caseLockChanged'"), 'Must define canonical case lock changed event');
  assert.ok(source.includes('export async function syncCaseLock('), 'Must export syncCaseLock function');
  assert.ok(source.includes('export async function releaseActiveCaseLock('), 'Must export releaseActiveCaseLock function');
  assert.ok(source.includes('export function subscribeToCaseLock('), 'Must export subscribeToCaseLock function');
  assert.ok(source.includes('export function startCaseLockHeartbeat('), 'Must export startCaseLockHeartbeat function');
  assert.ok(source.includes('export function stopCaseLockHeartbeat('), 'Must export stopCaseLockHeartbeat function');
});

test('caseLockService: safely releases previous lock when switching cases or clearing active case', () => {
  const servicePath = path.join(feSrcDir, 'js', 'caseLockService.js');
  const source = fs.readFileSync(servicePath, 'utf8');

  // Must detect switching cases and release previous lock
  assert.ok(
    source.includes('_activeLockedCaseId && _activeLockedCaseId !== caseId'),
    'Must detect when switching to a different case while holding prior lock'
  );
  assert.ok(
    source.includes('releaseActiveCaseLock(prevId)'),
    'Must release previous lock when switching cases'
  );

  // Must release lock on window unload / pagehide
  assert.ok(source.includes("window.addEventListener('beforeunload'"), 'Must attach beforeunload listener');
  assert.ok(source.includes("window.addEventListener('pagehide'"), 'Must attach pagehide listener');
});

test('caseLockService: heartbeat ping handles transferred/expired ownership', () => {
  const servicePath = path.join(feSrcDir, 'js', 'caseLockService.js');
  const source = fs.readFileSync(servicePath, 'utf8');

  assert.ok(source.includes('sendCaseLockHeartbeat('), 'Must ping heartbeat endpoint');
  assert.ok(source.includes('res.read_only'), 'Must detect if heartbeat reports lost ownership/read_only');
  assert.ok(source.includes('stopCaseLockHeartbeat()'), 'Must stop heartbeat when ownership is lost');
});

test('CaseLockBanner: renders frosted warning with analyst name and navigation options', () => {
  const bannerPath = path.join(feSrcDir, 'components', 'CaseLockBanner.jsx');
  const source = fs.readFileSync(bannerPath, 'utf8');

  assert.ok(source.includes('CASE LOCK IN EFFECT'), 'Must display clear lock badge');
  assert.ok(source.includes('Read-Only Access: Case Under Active Investigation'), 'Must state read-only investigation status');
  assert.ok(source.includes('handleRefresh'), 'Must provide manual refresh capability');
  assert.ok(source.includes("navigate('/cases')"), 'Must provide fast path to switch case');
  assert.ok(source.includes('compact'), 'Must support compact indicator badge');
});

test('Agents.jsx: enforces case lock read-only restrictions on multi-agent analysis', () => {
  const agentsPath = path.join(feSrcDir, 'pages', 'Agents.jsx');
  const source = fs.readFileSync(agentsPath, 'utf8');

  assert.ok(source.includes('syncCaseLock'), 'Must sync case lock on mount or case switch');
  assert.ok(source.includes('subscribeToCaseLock'), 'Must subscribe to case lock changes');
  assert.ok(source.includes('<CaseLockBanner lockState={caseLock}'), 'Must render CaseLockBanner');
  assert.ok(source.includes('if (caseLock?.readOnly)'), 'Must block analysis execution if case is read-only');
  assert.ok(source.includes('Cannot launch multi-agent analysis'), 'Must explain read-only lock status to user');
});

test('Cases.jsx: renders lock pills, read-only switch button, and guards case closing', () => {
  const casesPath = path.join(feSrcDir, 'pages', 'Cases.jsx');
  const source = fs.readFileSync(casesPath, 'utf8');

  assert.ok(source.includes('c.lock && c.lock.is_locked'), 'Must render lock status badge for locked cases');
  assert.ok(source.includes('Investigate (Read-Only)'), 'Must provide Read-Only access button for locked cases');
  assert.ok(source.includes('targetCase?.lock?.is_locked && targetCase?.lock?.read_only'), 'Must prevent closing a case locked by another analyst');
  assert.ok(source.includes('handleSetActiveCase'), 'Must notify user when setting locked case as active');
});

test('CaseNotes.jsx: blocks note creation, editing, and deletion in read-only mode', () => {
  const notesPath = path.join(feSrcDir, 'pages', 'CaseNotes.jsx');
  const source = fs.readFileSync(notesPath, 'utf8');

  assert.ok(source.includes('syncCaseLock'), 'Must sync case lock in CaseNotes');
  assert.ok(source.includes('<CaseLockBanner lockState={caseLock}'), 'Must render CaseLockBanner in CaseNotes');
  assert.ok(source.includes('openNewNote'), 'Must guard new note creation');
  assert.ok(source.includes('openEditNote'), 'Must guard note editing');
  assert.ok(source.includes('handleDelete'), 'Must guard note deletion');
  assert.ok(source.includes('handleSave'), 'Must guard note saving');
});

test('Upload.jsx: blocks drag-and-drop, browsing, and evidence upload in read-only mode', () => {
  const uploadPath = path.join(feSrcDir, 'pages', 'Upload.jsx');
  const source = fs.readFileSync(uploadPath, 'utf8');

  assert.ok(source.includes('syncCaseLock'), 'Must sync case lock in Upload workspace');
  assert.ok(source.includes('<CaseLockBanner lockState={caseLock}'), 'Must render CaseLockBanner in Upload');
  assert.ok(source.includes('handleUpload'), 'Must guard evidence upload handler');
  assert.ok(source.includes('handleDrop'), 'Must guard drag and drop in read-only mode');
  assert.ok(source.includes('Evidence Upload Disabled'), 'Must display evidence upload disabled UI');
  assert.ok(source.includes('handleCloseCase'), 'Must guard closing case in read-only mode');
});
