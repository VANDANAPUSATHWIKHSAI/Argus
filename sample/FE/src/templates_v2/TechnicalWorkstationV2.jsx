import React, { useState, useEffect } from 'react';
import TemplateV2SwitcherBar from './TemplateV2SwitcherBar';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates_v2.css';

export default function TechnicalWorkstationV2() {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [evidence, setEvidence] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const cRes = await fetchCases();
        const cList = Array.isArray(cRes) ? cRes : (cRes.data || []);
        setCases(cList);
        const cid = cList[0]?.case_id || 'CASE-2026-001';
        setSelectedCaseId(cid);

        const [eData, fData] = await Promise.all([
          fetchEvidenceForCase(cid).catch(() => []),
          fetchFindings(cid).catch(() => [])
        ]);

        const eList = Array.isArray(eData) ? eData : (eData.data || []);
        const fList = Array.isArray(fData) ? fData : (fData.data || []);
        setEvidence(eList);
        setFindings(fList);
        if (fList.length > 0) setSelectedFinding(fList[0]);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleSelectCase = async (cid) => {
    setSelectedCaseId(cid);
    try {
      const [eData, fData] = await Promise.all([
        fetchEvidenceForCase(cid).catch(() => []),
        fetchFindings(cid).catch(() => [])
      ]);
      const eList = Array.isArray(eData) ? eData : (eData.data || []);
      const fList = Array.isArray(fData) ? fData : (fData.data || []);
      setEvidence(eList);
      setFindings(fList);
      if (fList.length > 0) setSelectedFinding(fList[0]);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="v2-wrapper" style={{ height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <TemplateV2SwitcherBar activeName="2: Technical & Investigative Workstation" />

      {/* Top Workstation Command Bar */}
      <div className="v2-tech-commandbar">
        <div>
          <span>FORENSIC CONSOLE [BUILD 2.4.0]</span>
          <span style={{ margin: '0 12px', color: '#475569' }}>|</span>
          <span>ACTIVE CASE: <strong style={{ color: '#38BDF8' }}>{selectedCaseId}</strong></span>
        </div>
        <div>
          <span>CRYPTO HASH: SHA-256 ENFORCED</span>
          <span style={{ margin: '0 12px', color: '#475569' }}>|</span>
          <span>PARSER: ONLINE</span>
        </div>
      </div>

      {/* 3-Panel Workstation Grid */}
      <div className="v2-tech-grid">
        {/* Panel 1: Case & Artifact Tree Navigation */}
        <div className="v2-tech-panel">
          <div className="v2-tech-panel-header">
            <span>[1] CASE & ARTIFACT TREE</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--v2-mono-font)', fontWeight: 800, color: '#64748B', marginBottom: 8 }}>
              SELECT CASE FILE:
            </div>
            {cases.map(c => (
              <div 
                key={c.case_id}
                onClick={() => handleSelectCase(c.case_id)}
                style={{
                  padding: '8px 10px',
                  marginBottom: 6,
                  border: '1px solid #111111',
                  background: selectedCaseId === c.case_id ? '#111111' : '#F8FAFC',
                  color: selectedCaseId === c.case_id ? '#FFFFFF' : '#0F172A',
                  cursor: 'pointer',
                  fontFamily: 'var(--v2-mono-font)',
                  fontSize: '12px',
                  fontWeight: 700
                }}
              >
                ▸ {c.case_id}
              </div>
            ))}

            <div style={{ fontSize: '11px', fontFamily: 'var(--v2-mono-font)', fontWeight: 800, color: '#64748B', margin: '20px 0 8px 0' }}>
              INGESTED ARTIFACTS ({evidence.length}):
            </div>
            {evidence.map((ev, i) => (
              <div key={i} style={{ padding: '6px 8px', borderBottom: '1px solid #E2E8F0', fontSize: '12px' }}>
                <div style={{ fontWeight: 600 }}>{ev.filename || ev.name}</div>
                <div style={{ fontSize: '10px', fontFamily: 'var(--v2-mono-font)', color: '#64748B' }}>{ev.artifact_type || 'Disk Image'}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Panel 2: Findings Data Grid */}
        <div className="v2-tech-panel">
          <div className="v2-tech-panel-header">
            <span>[2] CORRELATED FINDINGS MATRIX ({findings.length})</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading ? (
              <div style={{ padding: 24, fontSize: '13px', color: '#64748B' }}>Loading matrix...</div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: '#F8FAFC', borderBottom: '2px solid #111111', fontSize: '11px', fontFamily: 'var(--v2-mono-font)', uppercase: 'true' }}>
                    <th style={{ padding: '8px 12px' }}>ID</th>
                    <th style={{ padding: '8px 12px' }}>SEV</th>
                    <th style={{ padding: '8px 12px' }}>INDICATOR / FACT</th>
                    <th style={{ padding: '8px 12px' }}>LAYER</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr 
                      key={i}
                      onClick={() => setSelectedFinding(f)}
                      style={{
                        borderBottom: '1px solid #E2E8F0',
                        background: selectedFinding?.finding_id === f.finding_id ? '#F1F5F9' : 'transparent',
                        cursor: 'pointer',
                        fontSize: '12px'
                      }}
                    >
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--v2-mono-font)', fontWeight: 800 }}>
                        {f.finding_id || `F-00${i+1}`}
                      </td>
                      <td style={{ padding: '8px 12px' }}>
                        <span className={`v2-tag v2-tag-${(f.severity || 'low').toLowerCase()}`}>
                          {f.severity || 'LOW'}
                        </span>
                      </td>
                      <td style={{ padding: '8px 12px', lineHeight: 1.4 }}>
                        {f.sanitized_fact || f.fact}
                      </td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--v2-mono-font)', fontSize: '11px', color: '#64748B' }}>
                        {f.layer || 'SYS'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Panel 3: Monospaced Forensic Inspector */}
        <div className="v2-tech-panel">
          <div className="v2-tech-panel-header">
            <span>[3] FORENSIC INSPECTOR & HASH VERIFIER</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
            {selectedFinding ? (
              <div>
                <div style={{ borderBottom: '2px solid #111111', paddingBottom: 12, marginBottom: 16 }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--v2-mono-font)', color: '#64748B' }}>RECORD IDENTIFIER</div>
                  <div style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '16px', fontWeight: 800, margin: '4px 0' }}>
                    {selectedFinding.finding_id || 'F-SELECTED'}
                  </div>
                  <span className={`v2-tag v2-tag-${(selectedFinding.severity || 'low').toLowerCase()}`}>
                    {selectedFinding.severity || 'LOW'} SEVERITY
                  </span>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)', marginBottom: 4 }}>
                    SANITIZED FACT / INDICATOR:
                  </div>
                  <div style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '12px', background: '#F8FAFC', border: '1px solid #111111', padding: 10, lineHeight: 1.5 }}>
                    {selectedFinding.sanitized_fact || selectedFinding.fact}
                  </div>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)', marginBottom: 4 }}>
                    SHA-256 CRYPTOGRAPHIC PROVENANCE:
                  </div>
                  <div style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '11px', background: '#0F172A', color: '#38BDF8', padding: 10, border: '1px solid #111111', wordBreak: 'break-all' }}>
                    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                  </div>
                </div>

                <button style={{ width: '100%', background: '#111111', color: '#FFFFFF', border: 'none', padding: '10px', fontFamily: 'var(--v2-mono-font)', fontSize: '12px', fontWeight: 800, cursor: 'pointer' }}>
                  [EXECUTE FORENSIC AUDIT PASS]
                </button>
              </div>
            ) : (
              <div style={{ color: '#64748B', fontSize: '12px' }}>Select a finding row in Column 2 to inspect.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
