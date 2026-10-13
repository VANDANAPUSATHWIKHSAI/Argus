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

export default function ModernWorkspaceTemplate() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page" style={{ background: '#FFFFFF', minHeight: '100vh', paddingBottom: 60, overflowY: 'auto' }}>
      <TemplatePreviewBar activeName="2: Modern Workspace+" />

      {/* Top Horizontal Navigation Header Bar */}
      <header style={{ background: '#FFFFFF', borderBottom: '2px solid var(--argus-border-strong)', padding: '16px 40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <div style={{ fontWeight: 900, fontSize: '20px', letterSpacing: '-0.02em', color: 'var(--argus-graphite)' }}>
            ARGUS WORKSPACE
          </div>
          
          <nav style={{ display: 'flex', gap: 6, background: 'var(--argus-surface)', padding: 4, borderRadius: 6, flexWrap: 'wrap' }}>
            {[
              { id: 'overview', label: 'Overview' },
              { id: 'findings', label: `Findings (${PREVIEW_MOCK_FINDINGS.length})` },
              { id: 'evidence', label: `Evidence (${PREVIEW_MOCK_EVIDENCE.length})` },
              { id: 'graph', label: 'Graph Topology' },
              { id: 'cases', label: 'All Cases' },
              { id: 'notes', label: 'Notes' },
              { id: 'sanitized', label: 'Sanitized' },
              { id: 'audit', label: 'Audit Trail' },
              { id: 'settings', label: 'Settings' }
            ].map(tab => (
              <button 
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: '6px 14px',
                  borderRadius: 4,
                  fontSize: '12px',
                  fontWeight: 700,
                  border: 'none',
                  background: activeTab === tab.id ? '#FFFFFF' : 'transparent',
                  color: activeTab === tab.id ? 'var(--argus-steel-blue)' : 'var(--argus-text-subtle)',
                  cursor: 'pointer',
                  boxShadow: activeTab === tab.id ? '0 1px 3px rgba(0,0,0,0.08)' : 'none'
                }}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--argus-text-subtle)' }}>ACTIVE CASE:</span>
          <select 
            value={selectedCaseId} 
            onChange={(e) => setSelectedCaseId(e.target.value)}
            style={{
              padding: '6px 12px',
              border: '1px solid var(--argus-border-strong)',
              borderRadius: 4,
              fontSize: '13px',
              fontWeight: 700,
              background: 'var(--argus-bg-light)',
              color: 'var(--argus-graphite)',
              cursor: 'pointer'
            }}
          >
            {PREVIEW_MOCK_CASES.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.name}</option>
            ))}
          </select>
        </div>
      </header>

      {/* Main Spacious Layout */}
      <div style={{ maxWidth: 1440, margin: '0 auto', padding: '32px 40px', display: 'grid', gridTemplateColumns: '1fr 340px', gap: 32 }}>
        {/* Main Content Area */}
        <div>
          {activeTab === 'overview' && (
            <>
              {/* Prominent Case Banner */}
              <div className="argus-card argus-card-accent">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                  <div>
                    <span className="argus-badge-steel" style={{ marginBottom: 8, display: 'inline-block' }}>DOSSIER SUMMARY</span>
                    <h1 style={{ fontSize: '26px', fontWeight: 900, margin: 0, color: 'var(--argus-graphite)' }}>
                      {selectedCase.name}
                    </h1>
                  </div>
                  <span className="argus-badge-critical">{selectedCase.risk_level} RISK</span>
                </div>
                <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--argus-text-subtle)', margin: '0 0 16px 0' }}>
                  {selectedCase.description}
                </p>
                <div style={{ display: 'flex', gap: 24, fontSize: '13px', color: 'var(--argus-graphite)', borderTop: '1px solid var(--argus-border-light)', paddingTop: 12 }}>
                  <div>Assigned: <strong>{selectedCase.assigned_to}</strong></div>
                  <div>Tenant Scope: <strong>{selectedCase.tenant_id}</strong></div>
                  <div>Created: <strong>{selectedCase.created_at}</strong></div>
                </div>
              </div>

              {/* Correlated Findings Preview Table */}
              <div className="argus-card">
                <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0', color: 'var(--argus-graphite)' }}>
                  Correlated Findings Stream ({PREVIEW_MOCK_FINDINGS.length})
                </h2>
                <table className="argus-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>SEVERITY</th>
                      <th>FACT</th>
                      <th>LAYER</th>
                      <th>MITRE ATT&CK</th>
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
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>Correlated Findings Stream</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FINDING ID</th>
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
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>Evidence Manifest Vault</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FILENAME</th>
                    <th>ARTIFACT TYPE</th>
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

          {activeTab === 'graph' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>Forensic Relationship Topology</h2>
              <div style={{ height: 320, background: 'var(--argus-bg-light)', border: '1px solid var(--argus-border-strong)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
                {PREVIEW_MOCK_GRAPH_NODES.map((node, i) => (
                  <div key={i} style={{ padding: '10px 18px', background: '#FFFFFF', border: `2px solid ${node.color}`, borderRadius: 6, fontFamily: 'var(--argus-mono)', fontSize: '12px', fontWeight: 800, color: node.color }}>
                    ● {node.label}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'cases' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>All Active Cases</h2>
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
                      <td style={{ fontWeight: 700 }}>{c.name}</td>
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
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>Investigator Briefings</h2>
              {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
                <div key={i} style={{ padding: 14, border: '1px solid var(--argus-border-strong)', borderRadius: 4, marginBottom: 10, background: 'var(--argus-bg-light)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: '12px' }}>
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
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>Sanitized Output Stream</h2>
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
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>System Audit Trail</h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>ID</th>
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
              <h2 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>System Settings</h2>
              <div style={{ fontSize: '13px' }}>
                <div>Tenant: <strong>{PREVIEW_MOCK_SETTINGS.tenant_name}</strong></div>
                <div>Environment: <strong>{PREVIEW_MOCK_SETTINGS.environment}</strong></div>
              </div>
            </div>
          )}
        </div>

        {/* Right Context Drawer */}
        <div>
          <div className="argus-card">
            <h3 style={{ fontSize: '13px', fontWeight: 800, fontFamily: 'var(--argus-mono)', margin: '0 0 12px 0', borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 6 }}>
              [CASE CONTEXT DRAWER]
            </h3>
            <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div>
                <span style={{ color: 'var(--argus-text-subtle)' }}>Dossier ID:</span><br />
                <strong style={{ fontFamily: 'var(--argus-mono)' }}>{selectedCase.case_id}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--argus-text-subtle)' }}>Total Findings:</span><br />
                <strong>{selectedCase.total_findings} Records</strong>
              </div>
              <div>
                <span style={{ color: 'var(--argus-text-subtle)' }}>Evidence Files:</span><br />
                <strong>{selectedCase.total_evidence} Ingested</strong>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--argus-border-light)', paddingTop: 12, marginTop: 14 }}>
              <div style={{ fontSize: '11px', fontWeight: 800, fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)', marginBottom: 6 }}>EVIDENCE FILES:</div>
              {PREVIEW_MOCK_EVIDENCE.slice(0, 3).map((e, i) => (
                <div key={i} style={{ fontSize: '11px', padding: '4px 0', borderBottom: '1px solid var(--argus-border-light)' }}>
                  <strong>{e.filename}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
