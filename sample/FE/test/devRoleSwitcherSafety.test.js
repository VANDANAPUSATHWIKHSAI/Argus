import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '../src');

test('devRoleSwitcherSafety: App.jsx does not mount or render DevRoleSwitcher', () => {
  const appPath = path.join(feSrcDir, 'App.jsx');
  const appSource = fs.readFileSync(appPath, 'utf8');

  // Assert DevRoleSwitcher is neither imported nor rendered in App.jsx
  assert.ok(!appSource.includes('<DevRoleSwitcher'), 'App.jsx must not mount DevRoleSwitcher component');
  assert.ok(!appSource.includes('import DevRoleSwitcher'), 'App.jsx must not import DevRoleSwitcher');
});

test('devRoleSwitcherSafety: DevRoleSwitcher source does not contain guessed passwords or fake JWTs', () => {
  const switcherPath = path.join(feSrcDir, 'components', 'DevRoleSwitcher.jsx');
  const source = fs.readFileSync(switcherPath, 'utf8');

  // Verify no candidate password strings (e.g. password: '123' or pass: '123')
  assert.ok(!source.includes("password: '123'"), 'Must not contain hardcoded candidate passwords');
  assert.ok(!source.includes("password: \"123\""), 'Must not contain hardcoded candidate passwords');
  assert.ok(!source.includes("pass: '123'"), 'Must not contain candidate passwords');

  // Verify no fake JWT generation
  assert.ok(!source.includes('fakeJwt'), 'Must not fabricate synthetic JWTs');
  assert.ok(!source.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), 'Must not contain hardcoded JWT headers');

  // Verify safe redirect to /login
  assert.ok(source.includes("navigate(`/login?role="), 'Must redirect to real login page for authentication');
});

test('devRoleSwitcherSafety: DevRoleSwitcher requires both DEV environment and explicit opt-in flag', () => {
  const switcherPath = path.join(feSrcDir, 'components', 'DevRoleSwitcher.jsx');
  const source = fs.readFileSync(switcherPath, 'utf8');

  // Must check DEV mode and VITE_ENABLE_DEV_SWITCHER === 'true'
  assert.ok(source.includes('import.meta.env.DEV'), 'Must check import.meta.env.DEV');
  assert.ok(source.includes("import.meta.env.VITE_ENABLE_DEV_SWITCHER === 'true'"), 'Must require explicit opt-in flag');
  assert.ok(source.includes('if (!isDevSwitcherEnabled)'), 'Must check isDevSwitcherEnabled');
  assert.ok(source.includes('return null;'), 'Must fail closed and return null if not enabled');
});

test('devRoleSwitcherSafety: React hook rules obeyed at top of DevRoleSwitcher component', () => {
  const switcherPath = path.join(feSrcDir, 'components', 'DevRoleSwitcher.jsx');
  const source = fs.readFileSync(switcherPath, 'utf8');

  const hookDeclarations = [
    'useNavigate()',
    'useLocation()',
    'useState(false)',
    'useState(null)',
  ];

  for (const hook of hookDeclarations) {
    assert.ok(source.includes(hook), `Expected hook ${hook} to be declared`);
  }

  // Ensure hooks are called before the isDevSwitcherEnabled early return
  const returnIndex = source.indexOf('if (!isDevSwitcherEnabled)');
  for (const hook of hookDeclarations) {
    const hookIndex = source.indexOf(hook);
    assert.ok(hookIndex < returnIndex, `Hook ${hook} must be called unconditionally before early return`);
  }
});
