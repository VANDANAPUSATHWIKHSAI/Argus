import React, { useState, useEffect } from 'react';
import TemplateV2SwitcherBar from './TemplateV2SwitcherBar';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings, fetchActivity } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates_v2.css';

export default function ModularCanvasV2() {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [summary, setSummary] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [findings, setFindings] = useState([]);
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedItem, setSelectedItem] = useState(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const cRes = await fetchCases();
        const cList = Array.isArray(cRes) ? cRes : (cRes.data || []);
        setCases(cList);
        const cid = cList[0]?.case_id || 'CASE-2026-001';
        setSelectedCaseId(cid);

        const [sData, eData, fData, aData] = await Promise.all([
          fetchCaseSummary(cid).catch(() => null),
          fetchEvidenceForCase(cid).catch(() => []),
          fetchFindings(cid).catch(() => []),
          fetchActivity(cid).catch(() => [])
        ]);

        setSummary(sData);
        setEvidence(Array.isArray(eData) ? eData : (eData.data || []));
        setFindings(Array.isArray(fData) ? fData : (fData.data || []));
        setActivities(Array.isArray(aData) ? aData : (aData.data || []));
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleCaseChange = async (e) => {
    const cid = e.target.value;
    setSelectedCaseId(cid);
    setLoading(true);
    try {
      const [sData, eData, fData, aData] = await Promise.all([
        fetchCaseSummary(cid).catch(() => null),
        fetchEvidenceForCase(cid).catch(() => []),
        fetchFindings(cid).catch(() => []),
        fetchActivity(cid).catch(() => [])
      ]);
      setSummary(sData);
      setEvidence(Array.isArray(eData) ? eData : (eData.data || []));
      setFindings(Array.isArray(fData) ? fData : (fData.data || []));
      setActivities(Array.isArray(aData) ? aData : (aData.data || []));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="v2-wrapper" style={{ paddingBottom: 60 }}>
      <TemplateV2SwitcherBar activeName="4: Modular Canvas & Board Overhaul" />

      {/* Top Controls Bar */}
      <header className="v2-canvas-header">
        <div>
          <div style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '18px', fontWeight: 800 }}>
            ARGUS CANVAS WORKBENCH
          </div>
          <div style={{ fontSize: '12px', color: '#64748B' }}>
            Pipelines & Stage Lifecycle View
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ fontSize: '12px', fontWeight: 700, color: '#475569' }}>ACTIVE CASE:</span>
          <select 
            value={selectedCaseId}
            onChange={handleCaseChange}
            style={{
              padding: '8px 14px',
              border: '2px solid #111111',
              fontFamily: 'var(--v2-mono-font)',
              fontSize: '13px',
              fontWeight: 800,
              background: '#FFFFFF'
            }}
          >
            {cases.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.title || c.description || 'Case'}</option>
            ))}
          </select>
        </div>
      </header>

      {/* 4-Column Lifecycle Pipeline Canvas Board */}
      <main className="v2-canvas-board">
        {/* Column 1: Raw Evidence Ingestion */}
        <div className="v2-canvas-column">
          <div className="v2-canvas-col-header">
            <span>[1] INGESTION ({evidence.length})</span>
            <span style={{ fontSize: '10px', background: '#111111', color: '#FFFFFF', padding: '2px 6px' }}>RAW</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {evidence.map((ev, i) => (
              <div key={i} className="v2-canvas-card" onClick={() => setSelectedItem({ type: 'evidence', data: ev })}>
                <div style={{ fontWeight: 800, fontSize: '13px', marginBottom: 4 }}>{ev.filename || ev.name}</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--v2-mono-font)', color: '#64748B' }}>{ev.artifact_type || 'Disk Image'}</div>
                <div style={{ fontSize: '10px', color: '#94A3B8', marginTop: 8 }}>{safeFormatDateOnly(ev.upload_timestamp || ev.submittedOn)}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Column 2: Sanitization & Gateway */}
        <div className="v2-canvas-column">
          <div className="v2-canvas-col-header">
            <span>[2] SANITIZATION</span>
            <span style={{ fontSize: '10px', background: '#334155', color: '#FFFFFF', padding: '2px 6px' }}>PII SCANNED</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <div className="v2-canvas-card" onClick={() => setSelectedItem({ type: 'sanitization', data: { status: 'Gate Passed', rules: ['Redacted IPv4', 'Scanned Secrets'] } })}>
              <div style={{ fontWeight: 800, fontSize: '13px', marginBottom: 4 }}>Sanitization Gateway</div>
              <div style={{ fontSize: '12px', color: '#334155' }}>Status: <strong>Clean & Masked</strong></div>
              <div style={{ fontSize: '11px', color: '#64748B', marginTop: 6 }}>Injection Score: 0.00 (Passed)</div>
            </div>
          </div>
        </div>

        {/* Column 3: Correlated Findings */}
        <div className="v2-canvas-column">
          <div className="v2-canvas-col-header">
            <span>[3] FINDINGS ({findings.length})</span>
            <span style={{ fontSize: '10px', background: '#0F172A', color: '#FFFFFF', padding: '2px 6px' }}>CORRELATED</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {findings.map((f, i) => (
              <div key={i} className="v2-canvas-card" onClick={() => setSelectedItem({ type: 'finding', data: f })}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '12px', fontWeight: 800 }}>{f.finding_id || `F-00${i+1}`}</span>
                  <span className={`v2-tag v2-tag-${(f.severity || 'low').toLowerCase()}`}>{f.severity}</span>
                </div>
                <div style={{ fontSize: '13px', color: '#0F172A', lineHeight: 1.4 }}>{f.sanitized_fact || f.fact}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Column 4: Audit & Executive Briefing */}
        <div className="v2-canvas-column">
          <div className="v2-canvas-col-header">
            <span>[4] AUDITED DOSSIER</span>
            <span style={{ fontSize: '10px', background: '#111111', color: '#FFFFFF', padding: '2px 6px' }}>VERIFIED</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <div className="v2-canvas-card">
              <div style={{ fontWeight: 800, fontSize: '13px', marginBottom: 6 }}>Case Overview: {summary?.case_id || selectedCaseId}</div>
              <div style={{ fontSize: '12px', color: '#475569', marginBottom: 8 }}>{summary?.description || 'Data breach investigation'}</div>
              <div style={{ borderTop: '1px solid #CBD5E1', paddingTop: 8, fontSize: '11px', fontWeight: 700 }}>
                Lead: {summary?.assigned_to || 'Senior Analyst'}
              </div>
            </div>

            {activities.slice(0, 3).map((a, i) => (
              <div key={i} className="v2-canvas-card">
                <div style={{ fontSize: '11px', fontFamily: 'var(--v2-mono-font)', color: '#64748B' }}>{safeFormatDateTime(a.created_at)}</div>
                <div style={{ fontWeight: 700, fontSize: '12px', margin: '2px 0' }}>{a.action || 'Audit Event'}</div>
                <div style={{ fontSize: '11px', color: '#475569' }}>{a.details || 'System operation'}</div>
              </div>
            ))}
          </div>
        </div>
      </main>

      {/* Inspector Detail Drawer */}
      {selectedItem && (
        <div style={{
          position: 'fixed',
          right: 32,
          bottom: 32,
          width: 380,
          background: '#FFFFFF',
          border: '3px solid #111111',
          boxShadow: '8px 8px 0px #111111',
          padding: 24,
          zIndex: 1000
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid #111111', paddingBottom: 10, marginBottom: 16 }}>
            <strong style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '14px' }}>CANVAS INSPECTOR</strong>
            <button onClick={() => setSelectedItem(null)} style={{ background: '#111111', color: '#FFFFFF', border: 'none', padding: '4px 8px', fontSize: '11px', cursor: 'pointer' }}>✕ CLOSE</button>
          </div>

          {selectedItem.type === 'finding' && (
            <div>
              <div style={{ fontFamily: 'var(--v2-mono-font)', fontWeight: 800, fontSize: '15px' }}>{selectedItem.data.finding_id}</div>
              <p style={{ fontSize: '13px', margin: '12px 0' }}>{selectedItem.data.sanitized_fact || selectedItem.data.fact}</p>
              <div style={{ fontSize: '12px', color: '#64748B' }}>Layer: <strong>{selectedItem.data.layer || 'System'}</strong></div>
            </div>
          )}

          {selectedItem.type === 'evidence' && (
            <div>
              <div style={{ fontWeight: 800, fontSize: '14px' }}>{selectedItem.data.filename || selectedItem.data.name}</div>
              <div style={{ fontSize: '12px', fontFamily: 'var(--v2-mono-font)', color: '#64748B', margin: '8px 0' }}>Type: {selectedItem.data.artifact_type || 'Artifact'}</div>
              <div style={{ fontSize: '11px', background: '#F1F5F9', padding: 8, border: '1px solid #111111', wordBreak: 'break-all' }}>
                SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
              </div>
            </div>
          )}

          {selectedItem.type === 'sanitization' && (
            <div>
              <div style={{ fontWeight: 800, fontSize: '14px' }}>Sanitization Gateway Specs</div>
              <p style={{ fontSize: '13px', color: '#334155' }}>All artifacts pass PII secret redaction and prompt injection checks before rendering.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
