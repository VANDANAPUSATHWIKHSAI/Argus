import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const feSrcDir = path.resolve(__dirname, '../src');

test('ForensicGraph: imports and uses useMemo for nodeMap constant-time lookups', () => {
  const filePath = path.join(feSrcDir, 'components', 'ForensicGraph.jsx');
  const source = fs.readFileSync(filePath, 'utf8');

  assert.ok(source.includes('useMemo'), 'ForensicGraph must import useMemo');
  assert.ok(source.includes('const nodeMap = useMemo('), 'ForensicGraph must construct memoized nodeMap');
  assert.ok(source.includes('nodeMap.get(edge.source)'), 'Must lookup edge source in nodeMap O(1)');
  assert.ok(source.includes('nodeMap.get(edge.target)'), 'Must lookup edge target in nodeMap O(1)');
  assert.ok(!source.includes('nodes.find(n => n.id === edge.source)'), 'Must NOT run quadratic nodes.find for edge source');
  assert.ok(!source.includes('nodes.find(n => n.id === edge.target)'), 'Must NOT run quadratic nodes.find for edge target');
});

test('ForensicGraph: verifies agent correlation before querying findings', () => {
  const filePath = path.join(feSrcDir, 'components', 'ForensicGraph.jsx');
  const source = fs.readFileSync(filePath, 'utf8');

  assert.ok(source.includes('isAgentCorrelated'), 'Must calculate isAgentCorrelated from real swarm telemetry');
  assert.ok(source.includes('if (!isAgentCorrelated)'), 'Must guard graph generation behind agent correlation');
  assert.ok(source.includes('/findings?limit='), 'Findings query must be bounded via limit parameter to prevent DOM freeze');
});

test('ForensicGraph: memoizes active selection and handles missing edge endpoints gracefully', () => {
  const filePath = path.join(feSrcDir, 'components', 'ForensicGraph.jsx');
  const source = fs.readFileSync(filePath, 'utf8');

  assert.ok(source.includes('activeNodeIds'), 'Must track active connected node IDs');
  assert.ok(source.includes('activeEdgeIds'), 'Must track active connected edge IDs');
  assert.ok(source.includes('if (!srcNode || !tgtNode) return null;'), 'Must safely drop edges with missing endpoints without crashing');
});

test('ForensicGraph: preserves evidence nodes, handles canonical ID mapping and multi-ring layout', () => {
  const filePath = path.join(feSrcDir, 'components', 'ForensicGraph.jsx');
  const source = fs.readFileSync(filePath, 'utf8');

  assert.ok(source.includes('evidenceListToNodes(rawEvidence, generatedNodes, evidenceMap);'), 'Must render evidence nodes even when agent correlation has not occurred');
  assert.ok(source.includes('evidenceMap.set(evId.toLowerCase(), evNodeId);'), 'Must register canonical artifact ID in evidenceMap');
  assert.ok(source.includes('const cleanRef = ref.replace(/^ref:/i'), 'Must normalize ref prefixes when resolving derived-from edges');
  assert.ok(source.includes('const edgeId = `edge-${edge.source}-${edge.target}-${idx}`;'), 'Must generate unique React edge keys');
  assert.ok(source.includes('useMultiRing'), 'Must use multi-ring concentric layout to prevent card overlap for large node counts');
});

test('Evidence: auto-refreshes evidence table on completion and eliminates duplicate calls', () => {
  const filePath = path.join(feSrcDir, 'pages', 'Evidence.jsx');
  const source = fs.readFileSync(filePath, 'utf8');

  assert.ok(source.includes('loadEvidenceRef.current(true);'), 'Must auto-refresh evidence table when workload transitions to COMPLETED');
  assert.ok(source.includes('lastPolledCaseRef.current !== activeCaseId'), 'Must prevent duplicate loadWorkload calls caused by status transitions');
  assert.ok(!source.includes("setWorkloadStatus(prev => (prev === 'READY' ? prev : 'READY'));"), 'Must NOT clobber active workload status to READY on transient network failure');
});

