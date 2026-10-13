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

export default function ModernWorkspaceSplitTemplate() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [selectedFinding, setSelectedFinding] = useState(PREVIEW_MOCK_FINDINGS[0]);

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page" style={{ background: '#FFFFFF', minHeight: '100vh', paddingBottom: 60, overflowY: 'auto' }}>
      <TemplatePreviewBar activeName="6: Modern Workspace Split View" />

      {/* Top Header Workspace Bar */}
      <header style={{ background: '#FFFFFF', borderBottom: '2px solid var(--argus-border-strong)', padding: '14px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontWeight: 900, fontSize: '18px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-graphite)' }}>
            ARGUS SPLIT WORKSPACE
          </div>
          
          <nav style={{ display: 'flex', gap: 4, background: 'var(--argus-surface)', padding: 3, borderRadius: 4, flexWrap: 'wrap' }}>
            {[
              { id: 'overview', label: 'Split Workspace' },
              { id: 'findings', label: `Findings (${PREVIEW_MOCK_FINDINGS.length})` },
              { id: 'evidence', label: `Evidence (${PREVIEW_MOCK_EVIDENCE.length})` },
              { id: 'graph', label: 'Graph Topology' },
              { id: 'cases', label: 'Cases' },
              { id: 'notes', label: 'Notes' },
              { id: 'sanitized', label: 'Sanitized' },
              { id: 'audit', label: 'Audit Trail' },
              { id: 'settings', label: 'Settings' }
            ].map(tab => (
              <button 
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: '5px 12px',
                  borderRadius: 3,
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: 'var(--argus-mono)',
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

        <select 
          value={selectedCaseId} 
          onChange={(e) => setSelectedCaseId(e.target.value)}
          style={{
            padding: '4px 10px',
            border: '1px solid var(--argus-border-strong)',
            borderRadius: 3,
            fontSize: '12px',
            fontFamily: 'var(--argus-mono)',
            fontWeight: 800,
            background: 'var(--argus-bg-light)',
            color: 'var(--argus-graphite)',
            cursor: 'pointer'
          }}
        >
          {PREVIEW_MOCK_CASES.map(c => (
            <option key={c.case_id} value={c.case_id}>{c.case_id}</option>
          ))}
        </select>
      </header>

      {/* Main Content Area */}
      <div style={{ maxWidth: 1440, margin: '0 auto', padding: '24px 32px' }}>
        {activeTab === 'overview' && (
          <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr 340px', gap: 20 }}>
            {/* Column 1: Left Navigation Rail & Dossier Selector */}
            <div className="argus-card" style={{ padding: 16, background: 'var(--argus-bg-light)' }}>
              <div style={{ fontSize: '11px', fontWeight: 900, fontFamily: 'var(--argus-mono)', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, marginBottom: 12 }}>
                [DOSSIERS ({PREVIEW_MOCK_CASES.length})]
              </div>
              {PREVIEW_MOCK_CASES.map(c => (
                <div 
                  key={c.case_id}
                  onClick={() => setSelectedCaseId(c.case_id)}
                  style={{
                    padding: '8px 10px',
                    marginBottom: 6,
                    borderRadius: 4,
                    border: '1px solid var(--argus-border-strong)',
                    background: selectedCaseId === c.case_id ? 'var(--argus-graphite)' : '#FFFFFF',
                    color: selectedCaseId === c.case_id ? '#FFFFFF' : 'var(--argus-graphite)',
                    cursor: 'pointer',
                    fontFamily: 'var(--argus-mono)',
                    fontSize: '11px',
                    fontWeight: 700
                  }}
                >
                  ▸ {c.case_id}
                  <div style={{ fontSize: '10px', opacity: 0.8, marginTop: 2 }}>{c.risk_level} RISK</div>
                </div>
              ))}
            </div>

            {/* Column 2: Center Findings & Inspector Table */}
            <div className="argus-card" style={{ padding: 16 }}>
              <div style={{ fontSize: '12px', fontWeight: 900, fontFamily: 'var(--argus-mono)', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, marginBottom: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>[CORRELATED FINDINGS — CLICK TO INSPECT]</span>
                <span className="argus-badge-steel">{selectedCase.risk_level}</span>
              </div>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>SEVERITY</th>
                    <th>FACT</th>
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

            {/* Column 3: Right Finding Detail & SHA-256 Vault */}
            <div className="argus-card" style={{ padding: 16, background: 'var(--argus-bg-light)' }}>
              <div style={{ fontSize: '11px', fontWeight: 900, fontFamily: 'var(--argus-mono)', borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 6, marginBottom: 12 }}>
                [INSPECTOR & HASH VAULT]
              </div>
              {selectedFinding ? (
                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>RECORD ID</div>
                  <div style={{ fontSize: '15px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>{selectedFinding.finding_id}</div>

                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>MITRE MAPPING</div>
                  <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--argus-steel-blue)', fontFamily: 'var(--argus-mono)', marginBottom: 10 }}>{selectedFinding.mitre_mapping}</div>

                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>INDICATOR FACT</div>
                  <div style={{ fontSize: '12px', background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', padding: 8, borderRadius: 3, marginBottom: 12 }}>
                    {selectedFinding.sanitized_fact}
                  </div>

                  <div style={{ borderTop: '1px solid var(--argus-border-strong)', paddingTop: 10 }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)', marginBottom: 4 }}>SHA-256 CHECKSUM</div>
                    <div style={{ fontFamily: 'var(--argus-mono)', fontSize: '10px', background: 'var(--argus-graphite)', color: '#38BDF8', padding: 6, wordBreak: 'break-all', borderRadius: 3 }}>
                      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: '12px', color: 'var(--argus-text-subtle)' }}>Select a finding to inspect record details.</div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[CORRELATED FINDINGS STREAM]</h2>
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
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[EVIDENCE VAULT]</h2>
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

        {activeTab === 'graph' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[FORENSIC GRAPH TOPOLOGY]</h2>
            <div style={{ height: 320, background: 'var(--argus-bg-light)', border: '1px solid var(--argus-border-strong)', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 14 }}>
              {PREVIEW_MOCK_GRAPH_NODES.map((node, i) => (
                <div key={i} style={{ padding: '8px 14px', background: '#FFFFFF', border: `2px solid ${node.color}`, borderRadius: 4, fontFamily: 'var(--argus-mono)', fontSize: '12px', fontWeight: 800, color: node.color }}>
                  ● {node.label}
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'cases' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[ALL CASES]</h2>
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

        {activeTab === 'notes' && (
          <div className="argus-card">
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[BRIEFINGS & NOTES]</h2>
            {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
              <div key={i} style={{ padding: 12, border: '1px solid var(--argus-border-strong)', borderRadius: 4, marginBottom: 8, background: 'var(--argus-bg-light)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: 4 }}>
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
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[SANITIZED LOGS]</h2>
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
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[AUDIT LOGS]</h2>
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
            <h2 style={{ fontSize: '15px', fontWeight: 900, marginBottom: 12, fontFamily: 'var(--argus-mono)' }}>[SETTINGS]</h2>
            <div style={{ fontSize: '13px' }}>
              <div>Tenant: <strong>{PREVIEW_MOCK_SETTINGS.tenant_name}</strong></div>
              <div>Env: <strong>{PREVIEW_MOCK_SETTINGS.environment}</strong></div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
