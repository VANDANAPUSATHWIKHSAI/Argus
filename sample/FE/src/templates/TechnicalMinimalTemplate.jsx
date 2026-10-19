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

export default function TechnicalMinimalTemplate() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page">
      <TemplatePreviewBar activeName="1: Technical Minimal Refined+" />

      {/* Sidebar Foundation Layout */}
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 48px)' }}>
        <TemplateSidebarReplica 
          themeName="technical-minimal"
          activeTab={activeTab}
          onTabChange={setActiveTab}
        />

        {/* Main Content Workspace */}
        <main style={{ flex: 1, padding: '32px 40px', background: 'var(--argus-bg-light)', overflowY: 'auto' }}>
          {/* Case Dossier Header Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, borderBottom: '2px solid var(--argus-border-strong)', paddingBottom: 16 }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-steel-blue)', uppercase: 'true' }}>
                ARGUS TECHNICAL MINIMAL REFINED+ &bull; DOSSIER VIEW
              </div>
              <h1 style={{ fontSize: '24px', fontWeight: 900, margin: '2px 0 0 0', color: 'var(--argus-graphite)', fontFamily: 'var(--argus-mono)' }}>
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
            <>
              {/* Summary Metric Cards with Steel-Blue Top Accents */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
                <div className="argus-card argus-card-accent">
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>CORRELATED FINDINGS</div>
                  <div style={{ fontSize: '32px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)', marginTop: 4 }}>{selectedCase.total_findings}</div>
                </div>
                <div className="argus-card argus-card-accent">
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>INGESTED ARTIFACTS</div>
                  <div style={{ fontSize: '32px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)', marginTop: 4 }}>{selectedCase.total_evidence}</div>
                </div>
                <div className="argus-card argus-card-accent">
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>TENANT ISOLATION</div>
                  <div style={{ fontSize: '14px', fontWeight: 800, fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)', marginTop: 12 }}>{selectedCase.tenant_id}</div>
                </div>
                <div className="argus-card argus-card-accent">
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>ASSIGNED LEAD</div>
                  <div style={{ fontSize: '14px', fontWeight: 800, color: 'var(--argus-graphite)', marginTop: 12 }}>{selectedCase.assigned_to}</div>
                </div>
              </div>

              {/* Correlated Findings Matrix Table */}
              <div className="argus-card">
                <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                  [CORRELATED FINDINGS MATRIX]
                </h2>
                <table className="argus-table">
                  <thead>
                    <tr>
                      <th>RECORD ID</th>
                      <th>SEVERITY</th>
                      <th>INDICATOR / FACT</th>
                      <th>LAYER</th>
                      <th>MITRE MAPPING</th>
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

          {activeTab === 'cases' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [ACTIVE CASE DOSSIER INVENTORY]
              </h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>CASE ID</th>
                    <th>DOSSIER NAME</th>
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

          {activeTab === 'evidence' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [EVIDENCE MANIFEST & CHECKSUM VAULT]
              </h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FILENAME</th>
                    <th>TYPE</th>
                    <th>SIZE</th>
                    <th>STATUS</th>
                    <th>SHA-256 CHECKSUM HASH</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_EVIDENCE.map((ev, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 700 }}>{ev.filename}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-text-subtle)' }}>{ev.artifact_type}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-text-subtle)' }}>{ev.size_mb}</td>
                      <td><span className="argus-badge-steel">{ev.status}</span></td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px', color: 'var(--argus-steel-blue)' }}>{ev.hash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'findings' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [CORRELATED FINDINGS STREAM]
              </h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FINDING ID</th>
                    <th>SEVERITY</th>
                    <th>LAYER</th>
                    <th>SANITIZED FACT</th>
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

          {activeTab === 'graph' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [FORENSIC GRAPH TOPOLOGY]
              </h2>
              <div style={{ height: 320, background: 'var(--argus-bg-light)', border: '2px dashed var(--argus-border-strong)', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
                {PREVIEW_MOCK_GRAPH_NODES.map((node, i) => (
                  <div key={i} style={{ padding: '10px 16px', background: '#FFFFFF', border: `2px solid ${node.color}`, borderRadius: 4, fontFamily: 'var(--argus-mono)', fontSize: '12px', fontWeight: 800, color: node.color }}>
                    ● {node.label}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'notes' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [CASE BRIEFINGS & CHRONOLOGICAL NOTES]
              </h2>
              {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
                <div key={i} style={{ padding: 14, border: '1px solid var(--argus-border-strong)', marginBottom: 10, background: 'var(--argus-bg-light)', borderRadius: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: 6 }}>
                    <strong>{n.author} ({n.category})</strong>
                    <span style={{ fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>{n.timestamp}</span>
                  </div>
                  <div style={{ fontSize: '13px', lineHeight: 1.5 }}>{n.content}</div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'sanitized' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [PII SANITIZED LOG STREAM]
              </h2>
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
                      <td style={{ color: 'var(--argus-steel-blue)', fontSize: '12px' }}>{s.rule_applied}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [IMMUTABLE SYSTEM AUDIT LOGS]
              </h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>LOG ID</th>
                    <th>TIMESTAMP</th>
                    <th>ACTION</th>
                    <th>DETAILS</th>
                    <th>ACTOR</th>
                  </tr>
                </thead>
                <tbody>
                  {PREVIEW_MOCK_AUDIT_LOGS.map((log, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{log.id}</td>
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '11px' }}>{log.created_at}</td>
                      <td><span className="argus-badge-steel">{log.action}</span></td>
                      <td style={{ fontSize: '12px' }}>{log.details}</td>
                      <td style={{ fontWeight: 700 }}>{log.created_by}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="argus-card">
              <h2 style={{ fontSize: '15px', fontWeight: 900, margin: '0 0 16px 0', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, fontFamily: 'var(--argus-mono)' }}>
                [TENANT CONFIGURATION]
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
                <div style={{ background: 'var(--argus-bg-light)', padding: 14, border: '1px solid var(--argus-border-strong)' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>TENANT NAME</div>
                  <div style={{ fontSize: '15px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.tenant_name}</div>
                </div>
                <div style={{ background: 'var(--argus-bg-light)', padding: 14, border: '1px solid var(--argus-border-strong)' }}>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>ENVIRONMENT</div>
                  <div style={{ fontSize: '15px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.environment}</div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
