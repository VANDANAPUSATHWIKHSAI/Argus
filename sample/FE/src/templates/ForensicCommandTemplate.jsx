import React, { useState } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import { 
  PREVIEW_MOCK_CASES, 
  PREVIEW_MOCK_EVIDENCE, 
  PREVIEW_MOCK_FINDINGS,
  PREVIEW_MOCK_AUDIT_LOGS 
} from './previewMockData';
import './templates.css';

export default function ForensicCommandTemplate() {
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [filterText, setFilterText] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(PREVIEW_MOCK_FINDINGS[0]);

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];
  const filteredFindings = PREVIEW_MOCK_FINDINGS.filter(f => 
    f.sanitized_fact.toLowerCase().includes(filterText.toLowerCase()) ||
    f.finding_id.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="argus-preview-page" style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
      <TemplatePreviewBar activeName="3: Forensic Command Center" />

      {/* Top Command Status Bar */}
      <div style={{ background: 'var(--argus-dark-steel)', color: '#FFFFFF', padding: '8px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', fontFamily: 'var(--argus-mono)', borderBottom: '2px solid var(--argus-steel-blue)' }}>
        <div style={{ display: 'flex', gap: 16 }}>
          <span>FORENSIC COMMAND CENTER [v3.4]</span>
          <span style={{ color: '#94A3B8' }}>|</span>
          <span>ACTIVE DOSSIER: <strong style={{ color: '#38BDF8' }}>{selectedCase.case_id}</strong></span>
        </div>
        <div style={{ display: 'flex', gap: 16 }}>
          <span>CRYPTO VERIFIER: SHA-256 ACTIVE</span>
          <span style={{ color: '#94A3B8' }}>|</span>
          <span>GATEWAY: VERIFIED</span>
        </div>
      </div>

      {/* 3-Column Split Workstation Grid */}
      <div style={{ display: 'flex', flex: 1, minHeight: 'calc(100vh - 86px)', overflow: 'auto' }}>
        {/* Narrow Left Icon Rail */}
        <div style={{ width: 60, background: '#FFFFFF', borderRight: '2px solid var(--argus-border-strong)', display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '16px 0', gap: 20, flexShrink: 0 }}>
          <div style={{ width: 36, height: 36, background: 'var(--argus-steel-blue)', color: '#FFFFFF', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 900, fontFamily: 'var(--argus-mono)', fontSize: '14px' }}>
            A
          </div>
          <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)', uppercase: 'true' }}>
            RAIL
          </div>
        </div>

        {/* 3-Column Workspace */}
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr 360px', flex: 1, background: '#FFFFFF', minHeight: 'calc(100vh - 86px)' }}>
          {/* Column A: Case Dossier Selector & Status */}
          <div style={{ borderRight: '1px solid var(--argus-border-strong)', display: 'flex', flexDirection: 'column', background: 'var(--argus-bg-light)' }}>
            <div style={{ background: 'var(--argus-graphite)', color: '#FFFFFF', padding: '8px 12px', fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>
              [A] CASE DOSSIER SELECTOR
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 12, maxHeight: 'calc(100vh - 120px)' }}>
              {PREVIEW_MOCK_CASES.map(c => (
                <div 
                  key={c.case_id}
                  onClick={() => setSelectedCaseId(c.case_id)}
                  style={{
                    padding: '8px 10px',
                    marginBottom: 6,
                    border: '1px solid var(--argus-border-strong)',
                    background: selectedCaseId === c.case_id ? 'var(--argus-graphite)' : '#FFFFFF',
                    color: selectedCaseId === c.case_id ? '#FFFFFF' : 'var(--argus-graphite)',
                    cursor: 'pointer',
                    fontFamily: 'var(--argus-mono)',
                    fontSize: '12px',
                    fontWeight: 700
                  }}
                >
                  ▸ {c.case_id}
                </div>
              ))}

              <div style={{ borderTop: '2px solid var(--argus-border-strong)', paddingTop: 12, marginTop: 16 }}>
                <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>TENANT SCOPE:</div>
                <div style={{ fontSize: '13px', fontWeight: 800, fontFamily: 'var(--argus-mono)' }}>{selectedCase.tenant_id}</div>
              </div>
            </div>
          </div>

          {/* Column B: Correlated Findings Matrix Table */}
          <div style={{ borderRight: '1px solid var(--argus-border-strong)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ background: 'var(--argus-graphite)', color: '#FFFFFF', padding: '8px 12px', fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>[B] CORRELATED FINDINGS ({filteredFindings.length})</span>
              <input 
                type="text" 
                placeholder="Filter findings..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                style={{
                  background: '#FFFFFF',
                  color: 'var(--argus-graphite)',
                  border: 'none',
                  padding: '2px 8px',
                  fontSize: '11px',
                  borderRadius: 2,
                  fontFamily: 'var(--argus-mono)'
                }}
              />
            </div>
            <div style={{ flex: 1, overflowY: 'auto', maxHeight: 'calc(100vh - 120px)' }}>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>SEVERITY</th>
                    <th>INDICATOR FACT</th>
                    <th>LAYER</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f, i) => (
                    <tr 
                      key={i} 
                      onClick={() => setSelectedFinding(f)}
                      style={{
                        background: selectedFinding?.finding_id === f.finding_id ? '#E9EDF1' : 'transparent',
                        cursor: 'pointer'
                      }}
                    >
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{f.finding_id}</td>
                      <td><span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'}>{f.severity}</span></td>
                      <td style={{ fontSize: '12px', fontWeight: 600 }}>{f.sanitized_fact}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-text-subtle)' }}>{f.layer}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Column C: Forensic Inspector & SHA-256 Vault */}
          <div style={{ display: 'flex', flexDirection: 'column', background: 'var(--argus-bg-light)' }}>
            <div style={{ background: 'var(--argus-graphite)', color: '#FFFFFF', padding: '8px 12px', fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>
              [C] FORENSIC INSPECTOR & HASH VAULT
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 14, maxHeight: 'calc(100vh - 120px)' }}>
              {selectedFinding && (
                <div>
                  <div style={{ borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 10, marginBottom: 12 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>RECORD ID</div>
                    <div style={{ fontFamily: 'var(--argus-mono)', fontSize: '15px', fontWeight: 900 }}>{selectedFinding.finding_id}</div>
                  </div>

                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>INDICATOR FACT:</div>
                    <div style={{ fontSize: '12px', background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 10, marginTop: 4 }}>
                      {selectedFinding.sanitized_fact}
                    </div>
                  </div>

                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>SHA-256 HASH VERIFICATION:</div>
                    <div style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', background: 'var(--argus-graphite)', color: '#38BDF8', padding: 8, border: '1px solid var(--argus-graphite)', wordBreak: 'break-all', marginTop: 4 }}>
                      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                    </div>
                  </div>

                  <div style={{ borderTop: '2px solid var(--argus-border-strong)', paddingTop: 12 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)', marginBottom: 6 }}>
                      EVIDENCE FILES ({PREVIEW_MOCK_EVIDENCE.length}):
                    </div>
                    {PREVIEW_MOCK_EVIDENCE.map((ev, i) => (
                      <div key={i} style={{ fontSize: '11px', padding: '4px 0', borderBottom: '1px solid var(--argus-border-light)' }}>
                        <strong>{ev.filename}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
