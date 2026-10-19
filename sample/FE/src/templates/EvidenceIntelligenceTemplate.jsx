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
  PREVIEW_MOCK_SETTINGS,
  PREVIEW_MOCK_EMPLOYEES
} from './previewMockData';
import './templates.css';

export default function EvidenceIntelligenceTemplate() {
  const [activeTab, setActiveTab] = useState('graph');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [selectedNode, setSelectedNode] = useState(PREVIEW_MOCK_GRAPH_NODES[0]);

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page" style={{ background: '#FFFFFF', minHeight: '100vh', paddingBottom: 60, overflowY: 'auto' }}>
      <TemplatePreviewBar activeName="5: Evidence Intelligence Workspace" />

      {/* Hero Header */}
      <header style={{ background: 'var(--argus-graphite)', color: '#FFFFFF', padding: '24px 40px', borderBottom: '3px solid var(--argus-steel-blue)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: '#94A3B8', uppercase: 'true', fontWeight: 800 }}>
            EVIDENCE INTELLIGENCE & GRAPH PROVENANCE ENGINE
          </div>
          <h1 style={{ fontSize: '24px', fontWeight: 900, margin: '4px 0 0 0', fontFamily: 'var(--argus-mono)' }}>
            {selectedCase.case_id} — Correlation Topology
          </h1>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <select 
            value={selectedCaseId} 
            onChange={(e) => setSelectedCaseId(e.target.value)}
            style={{
              padding: '6px 14px',
              border: '2px solid #FFFFFF',
              borderRadius: '4px',
              background: '#FFFFFF',
              color: 'var(--argus-graphite)',
              fontFamily: 'var(--argus-mono)',
              fontSize: '12px',
              fontWeight: 800,
              cursor: 'pointer'
            }}
          >
            {PREVIEW_MOCK_CASES.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.name}</option>
            ))}
          </select>
          <span className="argus-badge-steel">{selectedCase.risk_level} SEVERITY</span>
        </div>
      </header>

      {/* View Switcher Sub-Header */}
      <div style={{ background: 'var(--argus-bg-light)', borderBottom: '1px solid var(--argus-border-strong)', padding: '12px 40px', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {[
          { id: 'graph', label: 'Relationship Graph' },
          { id: 'evidence', label: `Evidence Vault (${PREVIEW_MOCK_EVIDENCE.length})` },
          { id: 'findings', label: `Correlated Findings (${PREVIEW_MOCK_FINDINGS.length})` },
          { id: 'cases', label: 'Cases Listing' },
          { id: 'notes', label: 'Case Notes' },
          { id: 'sanitized', label: 'Sanitized Stream' },
          { id: 'audit', label: 'Audit Trail' },
          { id: 'settings', label: 'System Config' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '6px 16px',
              borderRadius: 4,
              fontSize: '12px',
              fontWeight: 800,
              fontFamily: 'var(--argus-mono)',
              border: activeTab === tab.id ? '1px solid var(--argus-graphite)' : '1px solid var(--argus-border-light)',
              background: activeTab === tab.id ? 'var(--argus-graphite)' : '#FFFFFF',
              color: activeTab === tab.id ? '#FFFFFF' : 'var(--argus-graphite)',
              cursor: 'pointer'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main Workspace Body */}
      <main style={{ maxWidth: 1440, margin: '0 auto', padding: '32px 40px' }}>
        {activeTab === 'graph' && (
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 32 }}>
            {/* Visual Node Topology Canvas */}
            <div className="argus-card argus-card-accent">
              <h2 style={{ fontSize: '14px', fontWeight: 900, fontFamily: 'var(--argus-mono)', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, marginBottom: 16 }}>
                [GRAPH TOPOLOGY VISUALIZER]
              </h2>
              <div style={{ height: 380, background: 'var(--argus-bg-light)', border: '2px dashed var(--argus-border-strong)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 20, justifyContent: 'center', alignItems: 'center', padding: 20 }}>
                  {PREVIEW_MOCK_GRAPH_NODES.map(node => (
                    <div 
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      style={{
                        padding: '12px 18px',
                        background: selectedNode?.id === node.id ? node.color : '#FFFFFF',
                        color: selectedNode?.id === node.id ? '#FFFFFF' : node.color,
                        border: `2px solid ${node.color}`,
                        borderRadius: 6,
                        fontFamily: 'var(--argus-mono)',
                        fontSize: '13px',
                        fontWeight: 800,
                        cursor: 'pointer',
                        boxShadow: '0 4px 10px rgba(0,0,0,0.06)'
                      }}
                    >
                      ● {node.label} ({node.type})
                    </div>
                  ))}
                </div>
              </div>

              {/* Related Evidence Matrices */}
              <div style={{ marginTop: 24 }}>
                <h3 style={{ fontSize: '13px', fontWeight: 800, fontFamily: 'var(--argus-mono)', marginBottom: 12 }}>
                  CORRELATED ARTIFACT PROVENANCE MATRIX
                </h3>
                <table className="argus-table">
                  <thead>
                    <tr>
                      <th>ARTIFACT NAME</th>
                      <th>TYPE</th>
                      <th>INGEST TIMESTAMP</th>
                      <th>CRYPTO HASH (SHA-256)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {PREVIEW_MOCK_EVIDENCE.map((e, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 700 }}>{e.filename}</td>
                        <td><span className="argus-badge-steel">{e.artifact_type}</span></td>
                        <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px' }}>{e.upload_timestamp}</td>
                        <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '10px', color: 'var(--argus-text-subtle)' }}>{e.hash.slice(0, 24)}...</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Entity Node Inspector Drawer */}
            <div>
              <div className="argus-card">
                <h2 style={{ fontSize: '14px', fontWeight: 900, fontFamily: 'var(--argus-mono)', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, marginBottom: 16 }}>
                  [ENTITY INSPECTOR]
                </h2>
                {selectedNode ? (
                  <div>
                    <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>SELECTED NODE ID</div>
                    <div style={{ fontSize: '18px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)', marginBottom: 16 }}>{selectedNode.id}</div>
                    
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>NODE TYPE</div>
                      <div style={{ fontWeight: 800, fontSize: '13px', color: selectedNode.color }}>{selectedNode.type.toUpperCase()}</div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>LABEL / IDENTIFIER</div>
                      <div style={{ fontFamily: 'var(--argus-mono)', fontSize: '13px', background: 'var(--argus-bg-light)', padding: 8, border: '1px solid var(--argus-border-strong)', borderRadius: 4, marginTop: 4 }}>
                        {selectedNode.label}
                      </div>
                    </div>

                    <div style={{ borderTop: '2px solid var(--argus-border-strong)', paddingTop: 16 }}>
                      <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)', marginBottom: 8 }}>
                        CONNECTED FINDINGS ({PREVIEW_MOCK_FINDINGS.length})
                      </div>
                      {PREVIEW_MOCK_FINDINGS.slice(0, 3).map((f, i) => (
                        <div key={i} style={{ fontSize: '11px', padding: '6px 0', borderBottom: '1px solid var(--argus-border-light)' }}>
                          <strong>{f.finding_id}</strong>: {f.sanitized_fact}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div style={{ color: 'var(--argus-text-subtle)', fontSize: '13px' }}>Select a graph node to inspect relationships.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'evidence' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [EVIDENCE VAULT & ARTIFACT INVENTORY]
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>EVIDENCE ID</th>
                  <th>FILENAME</th>
                  <th>TYPE</th>
                  <th>FILE SIZE</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_EVIDENCE.map((e, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{e.id}</td>
                    <td style={{ fontWeight: 700 }}>{e.filename}</td>
                    <td><span className="argus-badge-steel">{e.artifact_type}</span></td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px' }}>{e.size_mb}</td>
                    <td><span className="argus-badge-dark">{e.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [CORRELATED FINDINGS STREAM]
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>FINDING ID</th>
                  <th>SEVERITY</th>
                  <th>LAYER</th>
                  <th>FACT</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_FINDINGS.map((f, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{f.finding_id}</td>
                    <td><span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'}>{f.severity}</span></td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px' }}>{f.layer}</td>
                    <td style={{ fontSize: '13px' }}>{f.sanitized_fact}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'cases' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [ALL CASES INVENTORY]
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>CASE ID</th>
                  <th>CASE NAME</th>
                  <th>RISK LEVEL</th>
                  <th>ASSIGNED LEAD</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_CASES.map((c, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{c.case_id}</td>
                    <td style={{ fontWeight: 700 }}>{c.name}</td>
                    <td><span className={c.risk_level === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'}>{c.risk_level}</span></td>
                    <td>{c.assigned_to}</td>
                    <td><span className="argus-badge-dark">{c.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'notes' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [CASE NOTES & BRIEFINGS]
            </h2>
            {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
              <div key={i} style={{ padding: 16, border: '1px solid var(--argus-border-strong)', marginBottom: 12, borderRadius: 4, background: 'var(--argus-bg-light)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: '12px' }}>
                  <strong>{n.author} ({n.category})</strong>
                  <span style={{ fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>{n.timestamp}</span>
                </div>
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.5 }}>{n.content}</p>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'sanitized' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [SANITIZED PII STREAM]
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>RECORD ID</th>
                  <th>SANITIZED SNIPPET</th>
                  <th>RULE APPLIED</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_SANITIZED_DATA.map((s, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{s.record_id}</td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px' }}>{s.sanitized_snippet}</td>
                    <td style={{ fontSize: '12px', color: 'var(--argus-steel-blue)' }}>{s.rule_applied}</td>
                    <td><span className="argus-badge-dark">{s.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [AUDIT TRAIL & SYSTEM EVENTS]
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>EVENT ID</th>
                  <th>TIMESTAMP</th>
                  <th>ACTION</th>
                  <th>DETAILS</th>
                  <th>ACTOR</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_AUDIT_LOGS.map((a, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{a.id}</td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px' }}>{a.created_at}</td>
                    <td><span className="argus-badge-steel">{a.action}</span></td>
                    <td style={{ fontSize: '12px' }}>{a.details}</td>
                    <td style={{ fontWeight: 700 }}>{a.created_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '16px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 16 }}>
              [SYSTEM CONFIGURATION & TENANT PARAMETERS]
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
              <div style={{ background: 'var(--argus-bg-light)', padding: 16, border: '1px solid var(--argus-border-strong)' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>TENANT NAME</div>
                <div style={{ fontSize: '16px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.tenant_name}</div>
              </div>
              <div style={{ background: 'var(--argus-bg-light)', padding: 16, border: '1px solid var(--argus-border-strong)' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>ENVIRONMENT</div>
                <div style={{ fontSize: '16px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.environment}</div>
              </div>
              <div style={{ background: 'var(--argus-bg-light)', padding: 16, border: '1px solid var(--argus-border-strong)' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>MITRE ATT&CK FRAMEWORK</div>
                <div style={{ fontSize: '16px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.mitre_attck_mapping_version}</div>
              </div>
              <div style={{ background: 'var(--argus-bg-light)', padding: 16, border: '1px solid var(--argus-border-strong)' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>AUTOMATED PII REDACTION</div>
                <div style={{ fontSize: '16px', fontWeight: 800, marginTop: 4, color: 'var(--argus-steel-blue)' }}>ENABLED</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
