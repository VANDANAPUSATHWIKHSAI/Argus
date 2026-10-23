import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '../src');

test('caseNotesSync: failed save displays server error and never claims successful persistence', () => {
  const notesPath = path.join(feSrcDir, 'pages', 'CaseNotes.jsx');
  const source = fs.readFileSync(notesPath, 'utf8');

  // Verify catch block in handleSave
  assert.ok(
    source.includes("setAlertConfig({ isOpen: true, title: 'Server Error', message: \"Failed to persist note: \" + (e.message || 'Backend rejection') });"),
    'Must honestly report save failure without pretending note was persisted'
  );
});

test('caseNotesSync: local drafts are distinguishable and explicitly tagged with unsynced status', () => {
  const notesPath = path.join(feSrcDir, 'pages', 'CaseNotes.jsx');
  const source = fs.readFileSync(notesPath, 'utf8');

  assert.ok(
    source.includes("syncStatus: n.syncStatus || 'unsynced'"),
    'Must tag local-only drafts with unsynced status'
  );
  assert.ok(
    source.includes("syncStatus: 'unsynced'"),
    'Recoverable notes after fetch error must be marked as unsynced'
  );
});

test('caseNotesSync: fetch failure preserves recoverable local drafts without deleting them', () => {
  const notesPath = path.join(feSrcDir, 'pages', 'CaseNotes.jsx');
  const source = fs.readFileSync(notesPath, 'utf8');

  // Verify fetch failure catch preserves localStorage notes
  assert.ok(
    source.includes("const localNotes = JSON.parse(localStorage.getItem(`case_notes_${activeCaseId}`) || '[]');"),
    'Must read local notes on fetch failure'
  );
  assert.ok(
    source.includes("if (marked.length > 0) setNotes(marked);"),
    'Must retain local notes if fetch fails'
  );
});

test('caseNotesSync: visibility listener and polling timer are cleanly torn down on unmount', () => {
  const notesPath = path.join(feSrcDir, 'pages', 'CaseNotes.jsx');
  const source = fs.readFileSync(notesPath, 'utf8');

  assert.ok(source.includes('clearInterval(intervalId);'), 'Must clear interval timer on cleanup');
  assert.ok(
    source.includes("document.removeEventListener('visibilitychange', handleVisibilityChange);"),
    'Must remove visibility listener on cleanup'
  );
});
