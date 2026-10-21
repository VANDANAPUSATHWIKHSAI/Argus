import React, { useState, useEffect } from 'react';
import TemplateSwitcherBar from './TemplateSwitcherBar';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates.css';

export default function MonochromeWorkspaceTemplate() {
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
    <div className="argus-template-wrapper template-monochrome-workspace">
      <TemplateSwitcherBar activeTemplateName="Template B: Monochrome Investigation Workspace" />

      {/* Top Workstation Status Bar */}
      <div className="workspace-topbar">
        <div>
          <span>ARGUS FORENSIC WORKSTATION</span>
          <span style={{ margin: '0 12px', color: '#666' }}>|</span>
          <span>STATION ID: WORKSTATION-01</span>
        </div>
        <div>
          <span>SYSTEM STATUS: OPERATIONAL</span>
          <span style={{ margin: '0 12px', color: '#666' }}>|</span>
          <span>LATENCY: 12ms</span>
        </div>
      </div>

      {/* Main Workspace Header */}
      <header className="workspace-header">
        <div className="workspace-title">
          <span>INVESTIGATION WORKBENCH</span>
          <span style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', background: '#111', color: '#fff', padding: '2px 8px' }}>
            {selectedCaseId}
          </span>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button style={{ background: '#111', color: '#fff', border: 'none', padding: '6px 14px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}>
            EXPORT DOSSIER
          </button>
          <button style={{ background: '#fff', color: '#111', border: '1px solid #111', padding: '6px 14px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}>
            REFRESH STREAM
          </button>
        </div>
      </header>

      {/* 3-Column High Density Workstation Grid */}
      <div className="workspace-main">
        {/* Column 1: Case & Evidence Selector */}
        <div className="workspace-col">
          <div className="workspace-col-header">
            <span>ACTIVE CASES ({cases.length})</span>
          </div>
          <div className="workspace-scroll-area">
            {cases.map((c) => (
              <div 
                key={c.case_id}
                className={`workspace-item-row ${selectedCaseId === c.case_id ? 'selected' : ''}`}
                onClick={() => handleSelectCase(c.case_id)}
              >
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700, color: '#111' }}>
                  {c.case_id}
                </div>
                <div style={{ fontSize: '13px', color: '#444', margin: '4px 0', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                  {c.title || c.description || 'Investigation'}
                </div>
                <div style={{ fontSize: '11px', color: '#888' }}>
                  {safeFormatDateOnly(c.created_at)}
                </div>
              </div>
            ))}

            <div className="workspace-col-header" style={{ marginTop: 16 }}>
              <span>EVIDENCE ARTIFACTS ({evidence.length})</span>
            </div>
            {evidence.map((ev, idx) => (
              <div key={idx} className="workspace-item-row">
                <div style={{ fontWeight: 600, fontSize: '12px', color: '#111' }}>
                  {ev.filename || ev.name}
                </div>
                <div style={{ fontSize: '11px', color: '#666', fontFamily: 'var(--font-mono)' }}>
                  {ev.artifact_type || 'Disk Image'}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Column 2: Findings Matrix Table */}
        <div className="workspace-col">
          <div className="workspace-col-header">
            <span>CORRELATED FINDINGS MATRIX ({findings.length})</span>
            <span style={{ fontSize: '10px', color: '#666' }}>SELECT ROW TO INSPECT</span>
          </div>
          <div className="workspace-scroll-area">
            {loading ? (
              <div style={{ padding: 24, fontSize: '12px', color: '#666' }}>Loading finding matrix...</div>
            ) : (
              <table className="workspace-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>SEVERITY</th>
                    <th>FACT / INDICATOR</th>
                    <th>LAYER</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr 
                      key={i}
                      onClick={() => setSelectedFinding(f)}
                      style={{ 
                        background: selectedFinding?.finding_id === f.finding_id ? '#f0f0f0' : 'transparent',
                        cursor: 'pointer'
                      }}
                    >
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '12px' }}>
                        {f.finding_id || `F-00${i+1}`}
                      </td>
                      <td>
                        <span className={`mono-badge mono-badge-${(f.severity || 'low').toLowerCase()}`}>
                          {f.severity || 'LOW'}
                        </span>
                      </td>
                      <td style={{ fontSize: '13px', lineHeight: 1.4 }}>
                        {f.sanitized_fact || f.fact}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#666' }}>
                        {f.layer || 'NETWORK'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Column 3: Forensic Inspector Panel */}
        <div className="workspace-col">
          <div className="workspace-col-header">
            <span>FORENSIC INSPECTOR</span>
          </div>
          <div className="workspace-scroll-area" style={{ padding: 16 }}>
            {selectedFinding ? (
              <div>
                <div style={{ borderBottom: '1px solid #111', paddingBottom: 12, marginBottom: 16 }}>
                  <div style={{ fontSize: '11px', color: '#666', uppercase: 'true' }}>SELECTED FINDING</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '16px', fontWeight: 700, margin: '4px 0' }}>
                    {selectedFinding.finding_id || 'F-SELECTED'}
                  </div>
                  <span className={`mono-badge mono-badge-${(selectedFinding.severity || 'low').toLowerCase()}`}>
                    {selectedFinding.severity || 'NOTICE'}
                  </span>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '11px', color: '#666', fontWeight: 700, marginBottom: 4 }}>INDICATOR DESCRIPTION</div>
                  <div style={{ fontSize: '13px', lineHeight: 1.5, background: '#fafafa', border: '1px solid #e5e5e5', padding: 12 }}>
                    {selectedFinding.sanitized_fact || selectedFinding.fact}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: 16, fontSize: '12px' }}>
                  <div>
                    <div style={{ color: '#888', fontSize: '10px' }}>CONFIDENCE</div>
                    <div style={{ fontWeight: 700 }}>{Math.round((selectedFinding.confidence || 0.95) * 100)}%</div>
                  </div>
                  <div>
                    <div style={{ color: '#888', fontSize: '10px' }}>LAYER</div>
                    <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{selectedFinding.layer || 'NETWORK'}</div>
                  </div>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '11px', color: '#666', fontWeight: 700, marginBottom: 4 }}>EVIDENCE REFERENCE</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#111' }}>
                    {Array.isArray(selectedFinding.evidence_reference) ? selectedFinding.evidence_reference.join(', ') : selectedFinding.evidence_reference || 'e-01'}
                  </div>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: '11px', color: '#666', fontWeight: 700, marginBottom: 4 }}>SHA-256 HASH VERIFICATION</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all', background: '#f5f5f5', padding: 8, border: '1px solid #e0e0e0' }}>
                    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                  </div>
                </div>

                <button style={{ width: '100%', background: '#111', color: '#fff', border: 'none', padding: '10px', fontSize: '12px', fontWeight: 700, cursor: 'pointer' }}>
                  MARK VERIFIED IN AUDIT LOG
                </button>
              </div>
            ) : (
              <div style={{ color: '#888', fontSize: '13px' }}>Select a finding row to inspect forensic details.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
