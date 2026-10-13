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

export default function TechnicalMinimalCompactTemplate() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [filterText, setFilterText] = useState('');

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];
  const filteredFindings = PREVIEW_MOCK_FINDINGS.filter(f => 
    f.sanitized_fact.toLowerCase().includes(filterText.toLowerCase()) ||
    f.finding_id.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="argus-preview-page">
      <TemplatePreviewBar activeName="3: Technical Minimal Compact" />

      {/* Sidebar Foundation Layout */}
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 48px)' }}>
        <TemplateSidebarReplica 
          themeName="technical-minimal"
          activeTab={activeTab}
          onTabChange={setActiveTab}
        />

        {/* Compact Workspace */}
        <main style={{ flex: 1, padding: '16px 24px', background: 'var(--argus-bg-light)', overflowY: 'auto' }}>
          {/* Dense Toolbar Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, borderBottom: '2px solid var(--argus-border-strong)', paddingBottom: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, background: 'var(--argus-dark-steel)', color: '#FFFFFF', padding: '2px 8px', borderRadius: 2 }}>
                COMPACT WORKSTATION
              </span>
              <h1 style={{ fontSize: '18px', fontWeight: 900, margin: 0, color: 'var(--argus-graphite)', fontFamily: 'var(--argus-mono)' }}>
                {selectedCase.case_id} — {selectedCase.name}
              </h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <input 
                type="text" 
                placeholder="Filter dataset..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                style={{
                  padding: '4px 10px',
                  fontSize: '11px',
                  fontFamily: 'var(--argus-mono)',
                  border: '1px solid var(--argus-border-strong)',
                  borderRadius: 3,
                  width: 180
                }}
              />
              <select 
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                style={{
                  padding: '4px 8px',
                  border: '1px solid var(--argus-graphite)',
                  borderRadius: '3px',
                  fontFamily: 'var(--argus-mono)',
                  fontSize: '11px',
                  fontWeight: 800,
                  background: '#FFFFFF',
                  color: 'var(--argus-graphite)',
                  cursor: 'pointer'
                }}
              >
                {PREVIEW_MOCK_CASES.map(c => (
                  <option key={c.case_id} value={c.case_id}>{c.case_id}</option>
                ))}
              </select>
              <span className="argus-badge-steel" style={{ fontSize: '10px' }}>{selectedCase.risk_level}</span>
            </div>
          </div>

          {activeTab === 'dashboard' && (
            <>
              {/* Compact Metrics Bar */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 14 }}>
                <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', borderTop: '3px solid var(--argus-steel-blue)', padding: '10px 14px' }}>
                  <div style={{ fontSize: '9px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>FINDINGS COUNT</div>
                  <div style={{ fontSize: '20px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)' }}>{selectedCase.total_findings}</div>
                </div>
                <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', borderTop: '3px solid var(--argus-steel-blue)', padding: '10px 14px' }}>
                  <div style={{ fontSize: '9px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>EVIDENCE FILES</div>
                  <div style={{ fontSize: '20px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)' }}>{selectedCase.total_evidence}</div>
                </div>
                <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', borderTop: '3px solid var(--argus-steel-blue)', padding: '10px 14px' }}>
                  <div style={{ fontSize: '9px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>TENANT SCOPE</div>
                  <div style={{ fontSize: '12px', fontWeight: 800, fontFamily: 'var(--argus-mono)', marginTop: 4 }}>{selectedCase.tenant_id}</div>
                </div>
                <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', borderTop: '3px solid var(--argus-steel-blue)', padding: '10px 14px' }}>
                  <div style={{ fontSize: '9px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)' }}>ASSIGNED LEAD</div>
                  <div style={{ fontSize: '12px', fontWeight: 800, marginTop: 4 }}>{selectedCase.assigned_to}</div>
                </div>
              </div>

              {/* High-Density Findings Table */}
              <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
                <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10, borderBottom: '1px solid var(--argus-graphite)', paddingBottom: 4 }}>
                  [COMPACT FINDINGS MATRIX ({filteredFindings.length})]
                </div>
                <table className="argus-table">
                  <thead>
                    <tr>
                      <th style={{ padding: '6px 8px', fontSize: '10px' }}>ID</th>
                      <th style={{ padding: '6px 8px', fontSize: '10px' }}>SEVERITY</th>
                      <th style={{ padding: '6px 8px', fontSize: '10px' }}>INDICATOR FACT</th>
                      <th style={{ padding: '6px 8px', fontSize: '10px' }}>LAYER</th>
                      <th style={{ padding: '6px 8px', fontSize: '10px' }}>MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((f, i) => (
                      <tr key={i}>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--argus-mono)', fontWeight: 800, fontSize: '11px' }}>{f.finding_id}</td>
                        <td style={{ padding: '6px 8px' }}><span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'} style={{ fontSize: '9px', padding: '1px 5px' }}>{f.severity}</span></td>
                        <td style={{ padding: '6px 8px', fontSize: '12px', fontWeight: 600 }}>{f.sanitized_fact}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--argus-mono)', fontSize: '10px', color: 'var(--argus-text-subtle)' }}>{f.layer}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--argus-mono)', fontSize: '10px', color: 'var(--argus-steel-blue)', fontWeight: 700 }}>{f.mitre_mapping}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeTab === 'cases' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[CASES COMPACT INVENTORY]</div>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>CASE ID</th>
                    <th>NAME</th>
                    <th>RISK</th>
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

          {activeTab === 'evidence' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[EVIDENCE CHECKSUM MANIFEST]</div>
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
                      <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '10px', color: 'var(--argus-steel-blue)' }}>{e.hash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'findings' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[FINDINGS COMPACT STREAM]</div>
              {PREVIEW_MOCK_FINDINGS.map((f, i) => (
                <div key={i} style={{ padding: '8px 10px', borderBottom: '1px solid var(--argus-border-light)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                  <span style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{f.finding_id}</span>
                  <span className={f.severity === 'CRITICAL' ? 'argus-badge-critical' : 'argus-badge-steel'} style={{ fontSize: '9px' }}>{f.severity}</span>
                  <span style={{ flex: 1, margin: '0 12px' }}>{f.sanitized_fact}</span>
                  <span style={{ fontFamily: 'var(--argus-mono)', fontSize: '10px', color: 'var(--argus-text-subtle)' }}>{f.layer}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'graph' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[GRAPH COMPACT NODES]</div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {PREVIEW_MOCK_GRAPH_NODES.map((n, i) => (
                  <div key={i} style={{ padding: '6px 12px', background: 'var(--argus-bg-light)', border: '1px solid var(--argus-border-strong)', fontFamily: 'var(--argus-mono)', fontSize: '11px', fontWeight: 700 }}>
                    ● {n.label} ({n.type})
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'notes' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[CASE NOTES]</div>
              {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
                <div key={i} style={{ fontSize: '12px', padding: '6px 0', borderBottom: '1px solid var(--argus-border-light)' }}>
                  <strong>{n.author}</strong> ({n.timestamp}): {n.content}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'sanitized' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[SANITIZED REDACTIONS]</div>
              {PREVIEW_MOCK_SANITIZED_DATA.map((s, i) => (
                <div key={i} style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', padding: '6px 0', borderBottom: '1px solid var(--argus-border-light)' }}>
                  <strong>{s.record_id}</strong>: {s.sanitized_snippet}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'audit' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[SYSTEM AUDIT LOGS]</div>
              {PREVIEW_MOCK_AUDIT_LOGS.map((a, i) => (
                <div key={i} style={{ fontSize: '11px', padding: '4px 0', borderBottom: '1px solid var(--argus-border-light)', display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontFamily: 'var(--argus-mono)' }}>{a.created_at}</span>
                  <strong>{a.action}</strong>
                  <span>{a.details}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'settings' && (
            <div style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 14 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>[SETTINGS]</div>
              <div style={{ fontSize: '12px' }}>
                <div>Tenant: <strong>{PREVIEW_MOCK_SETTINGS.tenant_name}</strong></div>
                <div>Env: <strong>{PREVIEW_MOCK_SETTINGS.environment}</strong></div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
