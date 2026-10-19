import React, { useState } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
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

export default function ModernWorkspaceDetailedTemplate() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page" style={{ background: '#FFFFFF', minHeight: '100vh', paddingBottom: 60, overflowY: 'auto' }}>
      <TemplatePreviewBar activeName="5: Modern Workspace Detailed" />

      {/* Top Header Workspace Navigation */}
      <header style={{ background: 'var(--argus-bg-light)', borderBottom: '2px solid var(--argus-border-strong)', padding: '16px 40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <div style={{ fontWeight: 900, fontSize: '18px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)' }}>
            ARGUS DETAILED WORKSPACE
          </div>
          
          <nav style={{ display: 'flex', gap: 6, background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 4, borderRadius: 6, flexWrap: 'wrap' }}>
            {[
              { id: 'overview', label: 'Detailed Overview' },
              { id: 'findings', label: `Correlated Findings (${PREVIEW_MOCK_FINDINGS.length})` },
              { id: 'evidence', label: `Evidence Vault (${PREVIEW_MOCK_EVIDENCE.length})` },
              { id: 'graph', label: 'Graph Topology' },
              { id: 'cases', label: 'Cases' },
              { id: 'notes', label: 'Briefings' },
              { id: 'sanitized', label: 'Sanitized' },
              { id: 'audit', label: 'Audit Log' },
              { id: 'settings', label: 'Governance' }
            ].map(tab => (
              <button 
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: '6px 14px',
                  borderRadius: 4,
                  fontSize: '12px',
                  fontWeight: 700,
                  fontFamily: 'var(--argus-mono)',
                  border: 'none',
                  background: activeTab === tab.id ? 'var(--argus-graphite)' : 'transparent',
                  color: activeTab === tab.id ? '#FFFFFF' : 'var(--argus-graphite)',
                  cursor: 'pointer'
                }}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <select 
          value={selectedCaseId} 
          onChange={(e) => setSelectedCaseId(e.target.value)}
          style={{
            padding: '6px 12px',
            border: '2px solid var(--argus-graphite)',
            borderRadius: 4,
            fontSize: '12px',
            fontFamily: 'var(--argus-mono)',
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
      </header>

      {/* Main Workspace Body */}
      <div style={{ maxWidth: 1440, margin: '0 auto', padding: '32px 40px', display: 'grid', gridTemplateColumns: '1fr 360px', gap: 32 }}>
        {/* Main Content Pane */}
        <div>
          {activeTab === 'overview' && (
            <>
              {/* Detailed Case Header */}
              <div className="argus-card argus-card-accent" style={{ background: '#FFFFFF' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                  <div>
                    <span className="argus-badge-steel" style={{ marginBottom: 6, display: 'inline-block' }}>CASE DOSSIER DETAILS</span>
                    <h1 style={{ fontSize: '24px', fontWeight: 900, margin: '4px 0 0 0', color: 'var(--argus-graphite)' }}>
                      {selectedCase.name}
                    </h1>
                  </div>
                  <span className="argus-badge-critical">{selectedCase.risk_level} RISK</span>
                </div>
                <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--argus-text-subtle)', margin: '0 0 16px 0' }}>
                  {selectedCase.description}
                </p>

                {/* 4 Multi-Metric Badges */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, background: 'var(--argus-bg-light)', padding: 14, borderRadius: 4, border: '1px solid var(--argus-border-strong)' }}>
                  <div>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>CRITICAL FINDINGS</div>
                    <div style={{ fontSize: '20px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedCase.critical_findings}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>HIGH SEVERITY</div>
                    <div style={{ fontSize: '20px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedCase.high_severity}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>MEDIUM SEVERITY</div>
                    <div style={{ fontSize: '20px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedCase.medium_severity}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>EVIDENCE ARTIFACTS</div>
                    <div style={{ fontSize: '20px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedCase.total_evidence}</div>
                  </div>
                </div>
              </div>

              {/* Correlated Findings Stream */}
              <div className="argus-card">
                <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, fontFamily: 'var(--argus-mono)' }}>
                  [CORRELATED FINDINGS STREAM & MITRE TACTICS]
                </h2>
                <table className="argus-table">
                  <thead>
                    <tr>
                      <th>FINDING ID</th>
                      <th>SEVERITY</th>
                      <th>INDICATOR FACT</th>
                      <th>LAYER</th>
                      <th>MITRE TACTIC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {PREVIEW_MOCK_FINDINGS.map((f, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{f.finding_id}</td>
                        <td><span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'}>{f.severity}</span></td>
                        <td style={{ fontSize: '13px', fontWeight: 600 }}>{f.sanitized_fact}</td>
                        <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-text-subtle)' }}>{f.layer}</td>
                        <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-steel-blue)', fontWeight: 700 }}>{f.mitre_mapping}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'findings' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[FINDINGS STREAM]</h2>
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
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{f.finding_id}</td>
                      <td><span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'}>{f.severity}</span></td>
                      <td style={{ fontSize: '13px' }}>{f.sanitized_fact}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px' }}>{f.layer}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[EVIDENCE CHECKSUM MANIFEST]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FILENAME</th>
                    <th>TYPE</th>
                    <th>SIZE</th>
                    <th>SHA-256 HASH</th>
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

          {activeTab === 'graph' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[GRAPH RELATIONSHIP TOPOLOGY]</h2>
              <div style={{ height: 320, background: 'var(--argus-bg-light)', border: '1px solid var(--argus-border-strong)', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
                {PREVIEW_MOCK_GRAPH_NODES.map((node, i) => (
                  <div key={i} style={{ padding: '10px 18px', background: '#FFFFFF', border: `2px solid ${node.color}`, borderRadius: 4, fontFamily: 'var(--argus-mono)', fontSize: '12px', fontWeight: 800, color: node.color }}>
                    ● {node.label}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'cases' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[ALL CASES]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>CASE ID</th>
                    <th>NAME</th>
                    <th>RISK LEVEL</th>
                    <th>LEAD</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_CASES.map((c, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{c.case_id}</td>
                      <td>{c.name}</td>
                      <td><span className="argus-badge-steel">{c.risk_level}</span></td>
                      <td>{c.assigned_to}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'notes' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[INVESTIGATOR BRIEFINGS]</h2>
              {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
                <div key={i} style={{ padding: 12, border: '1px solid var(--argus-border-strong)', borderRadius: 4, marginBottom: 10, background: 'var(--argus-bg-light)' }}>
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
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[SANITIZED OUTPUT]</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>ID</th>
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
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[SYSTEM AUDIT LOGS]</h2>
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
              <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 14, fontFamily: 'var(--argus-mono)' }}>[GOVERNANCE CONFIGURATION]</h2>
              <div style={{ fontSize: '13px' }}>
                <div>Tenant: <strong>{PREVIEW_MOCK_SETTINGS.tenant_name}</strong></div>
                <div>Environment: <strong>{PREVIEW_MOCK_SETTINGS.environment}</strong></div>
              </div>
            </div>
          )}
        </div>

        {/* Multi-Tab Context Drawer */}
        <div>
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h3 style={{ fontSize: '13px', fontWeight: 800, fontFamily: 'var(--argus-mono)', margin: '0 0 12px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6 }}>
              [DETAILED CONTEXT DRAWER]
            </h3>

            <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div>
                <span style={{ color: 'var(--argus-text-subtle)' }}>Dossier ID:</span><br />
                <strong style={{ fontFamily: 'var(--argus-mono)', fontSize: '14px' }}>{selectedCase.case_id}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--argus-text-subtle)' }}>Lead Investigator:</span><br />
                <strong>{selectedCase.assigned_to}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--argus-text-subtle)' }}>Tenant Scope:</span><br />
                <strong style={{ fontFamily: 'var(--argus-mono)' }}>{selectedCase.tenant_id}</strong>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--argus-border-strong)', paddingTop: 14, marginTop: 14 }}>
              <div style={{ fontSize: '11px', fontWeight: 800, fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)', marginBottom: 8 }}>EVIDENCE MANIFEST:</div>
              {PREVIEW_MOCK_EVIDENCE.map((ev, i) => (
                <div key={i} style={{ fontSize: '11px', padding: '4px 0', borderBottom: '1px solid var(--argus-border-light)' }}>
                  <strong>{ev.filename}</strong> ({ev.artifact_type})
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
