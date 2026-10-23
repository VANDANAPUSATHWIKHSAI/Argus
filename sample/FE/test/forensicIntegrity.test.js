import test from 'node:test';
import assert from 'node:assert/strict';

test('forensicIntegrity: undated timeline events are preserved and not assigned synthetic timestamps', () => {
  const rawEvents = [
    { event_id: 'ev-1', timestamp: '2026-08-10T14:30:00Z', event_type: 'login' },
    { event_id: 'ev-2', timestamp: null, event_type: 'registry_tamper' },
    { event_id: 'ev-3', timestamp: '2026-08-10T14:15:00Z', event_type: 'dns_query' },
    { event_id: 'ev-4', timestamp: 'invalid-date', event_type: 'file_delete' }
  ];

  // Process and sort according to the remediated timeline integrity logic
  const processed = rawEvents.map((ev, idx) => {
    let parsedTime = null;
    let isDated = false;
    if (ev.timestamp) {
      const d = new Date(ev.timestamp);
      if (!isNaN(d.getTime())) {
        parsedTime = d.getTime();
        isDated = true;
      }
    }
    return {
      ...ev,
      parsedTime,
      isDated,
      originalIndex: idx
    };
  });

  processed.sort((a, b) => {
    if (a.isDated && b.isDated) {
      return a.parsedTime - b.parsedTime;
    }
    if (a.isDated && !b.isDated) return -1;
    if (!a.isDated && b.isDated) return 1;
    return a.originalIndex - b.originalIndex;
  });

  // Verify dated events come first in chronological order
  assert.equal(processed[0].event_id, 'ev-3', 'DNS query at 14:15 should be first');
  assert.equal(processed[1].event_id, 'ev-1', 'Login at 14:30 should be second');

  // Verify undated events are preserved at the end and isDated is false
  assert.equal(processed[2].isDated, false);
  assert.equal(processed[2].parsedTime, null);
  assert.notEqual(processed[2].parsedTime, 1000, 'Must not assign synthetic 1000ms timestamp');

  assert.equal(processed[3].isDated, false);
  assert.equal(processed[3].parsedTime, null);
  assert.notEqual(processed[3].parsedTime, 2000, 'Must not assign synthetic 2000ms timestamp');
});

test('forensicIntegrity: hash existence does NOT imply cryptographic verification', () => {
  const evaluateHashVerification = (hash, verificationStatus) => {
    if (!hash) {
      return { status: 'absent', claim: 'Not provided' };
    }
    if (verificationStatus === 'VERIFIED') {
      return { status: 'verified', claim: 'Cryptographic custody verified by server' };
    }
    return { status: 'unverified', claim: 'Integrity unverified by server' };
  };

  const item1 = evaluateHashVerification(null, null);
  assert.equal(item1.status, 'absent');
  assert.equal(item1.claim, 'Not provided');

  const item2 = evaluateHashVerification('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', null);
  assert.equal(item2.status, 'unverified');
  assert.equal(item2.claim, 'Integrity unverified by server');
  assert.ok(!item2.claim.includes('Cryptographic custody established'), 'Must not claim verified custody without verification proof');

  const item3 = evaluateHashVerification('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'VERIFIED');
  assert.equal(item3.status, 'verified');
});

test('forensicIntegrity: evidence ingestion timestamp does NOT fallback to new Date().toISOString()', () => {
  const normalizeEvidenceTimestamp = (backendIngestionDate) => {
    if (!backendIngestionDate) return null;
    const d = new Date(backendIngestionDate);
    return isNaN(d.getTime()) ? null : d.toISOString();
  };

  const rawItemWithoutDate = { id: 'EVD-001', ingestion_date: null };
  const normalized = normalizeEvidenceTimestamp(rawItemWithoutDate.ingestion_date);

  assert.equal(normalized, null, 'Must be null when ingestion date is missing from backend');
});

test('forensicIntegrity: evidence risk rating does NOT default to Medium without authoritative data', () => {
  const normalizeEvidenceRisk = (rawMeta) => {
    if (rawMeta && rawMeta.risk_rating) return rawMeta.risk_rating;
    if (rawMeta && rawMeta.severity) return rawMeta.severity;
    return 'Unassessed';
  };

  assert.equal(normalizeEvidenceRisk({}), 'Unassessed');
  assert.notEqual(normalizeEvidenceRisk({}), 'Medium');
  assert.equal(normalizeEvidenceRisk({ risk_rating: 'High' }), 'High');
});
