import React, { useState } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import TemplateSidebarReplica from './TemplateSidebarReplica';
import { 
  PREVIEW_MOCK_CASES, 
  PREVIEW_MOCK_EVIDENCE, 
  PREVIEW_MOCK_FINDINGS, 
  PREVIEW_MOCK_AUDIT_LOGS,
  PREVIEW_MOCK_GRAPH_NODES,
  PREVIEW_MOCK_CASE_NOTES,
  PREVIEW_MOCK_SANITIZED_DATA,
  PREVIEW_MOCK_SETTINGS
} from './previewMockData';
import './templates.css';

export default function TechnicalMinimalAdvancedTemplate() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [selectedFinding, setSelectedFinding] = useState(PREVIEW_MOCK_FINDINGS[0]);

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page">
      <TemplatePreviewBar activeName="4: Technical Minimal Advanced" />

      {/* Sidebar Foundation Layout */}
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 48px)' }}>
        <TemplateSidebarReplica 
          themeName="technical-minimal"
          activeTab={activeTab}
          onTabChange={setActiveTab}
        />

        {/* Multi-Panel Advanced Content Area */}
        <main style={{ flex: 1, padding: '24px 32px', background: 'var(--argus-bg-light)', overflowY: 'auto' }}>
          {/* Header Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, borderBottom: '2px solid var(--argus-border-strong)', paddingBottom: 14 }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-steel-blue)', uppercase: 'true' }}>
                ARGUS TECHNICAL MINIMAL ADVANCED &bull; MULTI-PANEL INSPECTOR
              </div>
              <h1 style={{ fontSize: '22px', fontWeight: 900, margin: '2px 0 0 0', color: 'var(--argus-graphite)', fontFamily: 'var(--argus-mono)' }}>
                {selectedCase.case_id} — {selectedCase.name}
              </h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <select 
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                style={{
                  padding: '6px 12px',
                  border: '2px solid var(--argus-graphite)',
                  borderRadius: '4px',
                  fontFamily: 'var(--argus-mono)',
                  fontSize: '12px',
                  fontWeight: 800,
                  background: '#FFFFFF',
                  color: 'var(--argus-graphite)',
                  cursor: 'pointer'
                }}
              >
                {PREVIEW_MOCK_CASES.map(c => (
                  <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.name}</option>
                ))}
              </select>
              <span className="argus-badge-steel">{selectedCase.risk_level} RISK</span>
            </div>
          </div>

          {activeTab === 'dashboard' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 24 }}>
              {/* Primary Column: Summary + Findings Matrix */}
              <div>
                {/* Advanced Metrics Cards */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 20 }}>
                  <div className="argus-card argus-card-accent" style={{ padding: 16 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>CORRELATED FINDINGS</div>
                    <div style={{ fontSize: '26px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 4 }}>{selectedCase.total_findings}</div>
                  </div>
                  <div className="argus-card argus-card-accent" style={{ padding: 16 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>EVIDENCE ARTIFACTS</div>
                    <div style={{ fontSize: '26px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 4 }}>{selectedCase.total_evidence}</div>
                  </div>
                  <div className="argus-card argus-card-accent" style={{ padding: 16 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>CRITICAL THREATS</div>
                    <div style={{ fontSize: '26px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-steel-blue)', marginTop: 4 }}>{selectedCase.critical_findings}</div>
                  </div>
                </div>

                {/* Correlated Findings Stream */}
                <div className="argus-card">
                  <h2 style={{ fontSize: '14px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>
                    [CORRELATED FINDINGS STREAM — SELECT TO INSPECT]
                  </h2>
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
                      {PREVIEW_MOCK_FINDINGS.map((f, i) => (
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

              {/* Right Column: Advanced Evidence & Hash Inspector */}
              <div>
                <div className="argus-card">
                  <h2 style={{ fontSize: '14px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>
                    [FINDING DETAIL & HASH VAULT]
                  </h2>
                  {selectedFinding ? (
                    <div>
                      <div style={{ borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 10, marginBottom: 12 }}>
                        <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>RECORD ID</div>
                        <div style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)' }}>{selectedFinding.finding_id}</div>
                      </div>

                      <div style={{ marginBottom: 12 }}>
                        <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>MITRE ATT&CK TACTIC</div>
                        <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--argus-steel-blue)', fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedFinding.mitre_mapping}</div>
                      </div>

                      <div style={{ marginBottom: 14 }}>
                        <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>INDICATOR FACT</div>
                        <div style={{ fontSize: '12px', background: 'var(--argus-bg-light)', border: '1px solid var(--argus-border-strong)', padding: 8, borderRadius: 4, marginTop: 4 }}>
                          {selectedFinding.sanitized_fact}
                        </div>
                      </div>

                      <div style={{ borderTop: '1px solid var(--argus-border-strong)', paddingTop: 12 }}>
                        <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)', marginBottom: 6 }}>SHA-256 PROVENANCE CHECKSUM</div>
                        <div style={{ fontFamily: 'var(--argus-mono)', fontSize: '10px', background: 'var(--argus-graphite)', color: '#38BDF8', padding: 8, wordBreak: 'break-all', borderRadius: 4 }}>
                          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ fontSize: '12px', color: 'var(--argus-text-subtle)' }}>Select a finding record to inspect details.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'cases' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[ADVANCED CASE DOSSIERS]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>CASE ID</th>
                    <th>NAME</th>
                    <th>RISK LEVEL</th>
                    <th>ASSIGNED LEAD</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_CASES.map((c, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{c.case_id}</td>
                      <td style={{ fontWeight: 700 }}>{c.name}</td>
                      <td><span className="argus-badge-steel">{c.risk_level}</span></td>
                      <td>{c.assigned_to}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[EVIDENCE VAULT]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FILENAME</th>
                    <th>TYPE</th>
                    <th>SIZE</th>
                    <th>HASH</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_EVIDENCE.map((e, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 700 }}>{e.filename}</td>
                      <td>{e.artifact_type}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)' }}>{e.size_mb}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-steel-blue)' }}>{e.hash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'findings' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[FINDINGS STREAM]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FINDING ID</th>
                    <th>SEVERITY</th>
                    <th>TACTIC</th>
                    <th>FACT</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_FINDINGS.map((f, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{f.finding_id}</td>
                      <td><span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'}>{f.severity}</span></td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-steel-blue)' }}>{f.mitre_mapping}</td>
                      <td style={{ fontSize: '13px' }}>{f.sanitized_fact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'graph' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[FORENSIC GRAPH NODES]</h2>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {PREVIEW_MOCK_GRAPH_NODES.map((n, i) => (
                  <div key={i} style={{ padding: '8px 14px', background: 'var(--argus-bg-light)', border: `2px solid ${n.color}`, borderRadius: 4, fontFamily: 'var(--argus-mono)', fontSize: '12px', fontWeight: 800, color: n.color }}>
                    ● {n.label} ({n.type})
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'notes' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[CASE BRIEFINGS & CHRONOLOGICAL NOTES]</h2>
              {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
                <div key={i} style={{ padding: 12, border: '1px solid var(--argus-border-strong)', marginBottom: 10, background: 'var(--argus-bg-light)', borderRadius: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: 6 }}>
                    <strong>{n.author}</strong>
                    <span style={{ fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>{n.timestamp}</span>
                  </div>
                  <div style={{ fontSize: '13px' }}>{n.content}</div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'sanitized' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[PII SANITIZED OUTPUT]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>RECORD</th>
                    <th>REDACTED SNIPPET</th>
                    <th>RULE APPLIED</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_SANITIZED_DATA.map((s, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{s.record_id}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px' }}>{s.sanitized_snippet}</td>
                      <td style={{ color: 'var(--argus-steel-blue)' }}>{s.rule_applied}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[AUDIT TRAIL]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>LOG ID</th>
                    <th>TIMESTAMP</th>
                    <th>ACTION</th>
                    <th>DETAILS</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_AUDIT_LOGS.map((a, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{a.id}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px' }}>{a.created_at}</td>
                      <td><span className="argus-badge-steel">{a.action}</span></td>
                      <td style={{ fontSize: '12px' }}>{a.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 14px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>[SETTINGS]</h2>
              <div style={{ fontSize: '13px' }}>
                <div>Tenant: <strong>{PREVIEW_MOCK_SETTINGS.tenant_name}</strong></div>
                <div>Environment: <strong>{PREVIEW_MOCK_SETTINGS.environment}</strong></div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
