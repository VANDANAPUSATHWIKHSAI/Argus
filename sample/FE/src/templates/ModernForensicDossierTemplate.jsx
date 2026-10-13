import React, { useState } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import { 
  PREVIEW_MOCK_CASES, 
  PREVIEW_MOCK_EVIDENCE, 
  PREVIEW_MOCK_FINDINGS, 
  PREVIEW_MOCK_AUDIT_LOGS,
  PREVIEW_MOCK_CASE_NOTES,
  PREVIEW_MOCK_SANITIZED_DATA,
  PREVIEW_MOCK_SETTINGS
} from './previewMockData';
import './templates.css';

export default function ModernForensicDossierTemplate() {
  const [activeView, setActiveView] = useState('dossier');
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page" style={{ background: '#FAF8F5', minHeight: '100vh', paddingBottom: 80, overflowY: 'auto' }}>
      <TemplatePreviewBar activeName="6: Modern Forensic Dossier" />

      {/* Official Intelligence Dossier Header */}
      <div style={{ background: '#FFFFFF', borderBottom: '3px solid var(--argus-graphite)', padding: '40px 56px' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-steel-blue)', uppercase: 'true', letterSpacing: '0.12em' }}>
                ARGUS FORENSIC INTELLIGENCE DOSSIER &bull; CLASSIFIED INTERNAL USE
              </div>
              <h1 style={{ fontFamily: 'var(--argus-serif)', fontSize: '32px', fontWeight: 400, margin: '6px 0 0 0', color: 'var(--argus-graphite)' }}>
                Investigation Dossier: {selectedCase.name}
              </h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <select 
                value={selectedCaseId} 
                onChange={(e) => setSelectedCaseId(e.target.value)}
                style={{
                  padding: '8px 14px',
                  border: '2px solid var(--argus-graphite)',
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
              <span className="argus-badge-critical">SEALED DOSSIER</span>
            </div>
          </div>

          {/* Key Parameters Row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, paddingTop: 20, borderTop: '1px solid var(--argus-border-strong)' }}>
            <div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>DOSSIER ID</div>
              <div style={{ fontSize: '14px', fontWeight: 900, fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedCase.case_id}</div>
            </div>
            <div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>LEAD INVESTIGATOR</div>
              <div style={{ fontSize: '14px', fontWeight: 700, marginTop: 2 }}>{selectedCase.assigned_to}</div>
            </div>
            <div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>TARGET TENANT</div>
              <div style={{ fontSize: '14px', fontWeight: 700, fontFamily: 'var(--argus-mono)', marginTop: 2 }}>{selectedCase.tenant_id}</div>
            </div>
            <div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>RISK CLASSIFICATION</div>
              <div style={{ fontSize: '14px', fontWeight: 900, color: 'var(--argus-dark-steel)', marginTop: 2 }}>{selectedCase.risk_level}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Dossier Navigation Bar */}
      <div style={{ background: '#FFFFFF', borderBottom: '1px solid var(--argus-border-strong)', padding: '12px 56px' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {[
            { id: 'dossier', label: '1. Executive Briefing' },
            { id: 'findings', label: `2. Correlated Findings (${PREVIEW_MOCK_FINDINGS.length})` },
            { id: 'evidence', label: `3. Evidence Manifest (${PREVIEW_MOCK_EVIDENCE.length})` },
            { id: 'notes', label: '4. Investigator Notes' },
            { id: 'audit', label: '5. Auditability Trail' },
            { id: 'sanitized', label: '6. Redacted Logs' },
            { id: 'settings', label: '7. Governance' }
          ].map(view => (
            <button
              key={view.id}
              onClick={() => setActiveView(view.id)}
              style={{
                padding: '6px 16px',
                fontFamily: 'var(--argus-mono)',
                fontSize: '12px',
                fontWeight: 800,
                border: activeView === view.id ? '2px solid var(--argus-graphite)' : '1px solid var(--argus-border-light)',
                background: activeView === view.id ? 'var(--argus-graphite)' : '#FFFFFF',
                color: activeView === view.id ? '#FFFFFF' : 'var(--argus-graphite)',
                cursor: 'pointer'
              }}
            >
              {view.label}
            </button>
          ))}
        </div>
      </div>

      {/* Dossier Content Body */}
      <main style={{ maxWidth: 1200, margin: '0 auto', padding: '40px 56px' }}>
        {activeView === 'dossier' && (
          <div>
            {/* Executive Summary Block */}
            <div className="argus-card" style={{ background: '#FFFFFF', borderLeft: '4px solid var(--argus-steel-blue)' }}>
              <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
                Section I — Executive Incident Summary
              </h2>
              <p style={{ fontSize: '15px', lineHeight: 1.7, color: 'var(--argus-graphite)', margin: '0 0 16px 0' }}>
                {selectedCase.description} Investigation indicates automated Cobalt Strike beaconing from external host 192.168.1.105 with active privilege escalation via NTLMv2 administrator credentials.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, background: 'var(--argus-bg-light)', padding: 16, borderRadius: 4, border: '1px solid var(--argus-border-strong)' }}>
                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>CORRELATED FINDINGS</div>
                  <div style={{ fontSize: '24px', fontWeight: 900, fontFamily: 'var(--argus-mono)' }}>{selectedCase.total_findings}</div>
                </div>
                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>INGESTED ARTIFACTS</div>
                  <div style={{ fontSize: '24px', fontWeight: 900, fontFamily: 'var(--argus-mono)' }}>{selectedCase.total_evidence}</div>
                </div>
                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>CRITICAL THREATS</div>
                  <div style={{ fontSize: '24px', fontWeight: 900, fontFamily: 'var(--argus-mono)', color: 'var(--argus-steel-blue)' }}>{selectedCase.critical_findings}</div>
                </div>
              </div>
            </div>

            {/* Key Correlated Findings Preview */}
            <div className="argus-card" style={{ background: '#FFFFFF' }}>
              <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
                Section II — Key Correlated Forensic Findings
              </h2>
              <table className="argus-table">
                <thead>
                  <tr>
                    <th>FINDING RECORD ID</th>
                    <th>SEVERITY</th>
                    <th>LAYER</th>
                    <th>KEY FACT & SANITIZED EVIDENCE</th>
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

            {/* Signature & Audit Block */}
            <div className="argus-card" style={{ background: '#FFFFFF', textAlign: 'center', border: '2px solid var(--argus-graphite)' }}>
              <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', fontWeight: 800, color: 'var(--argus-text-subtle)', uppercase: 'true' }}>
                ARGUS DIGITAL SIGNATURE & CHAIN OF CUSTODY SEAL
              </div>
              <div style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px', background: 'var(--argus-graphite)', color: '#38BDF8', padding: 12, margin: '12px 0', border: '1px solid var(--argus-graphite)', wordBreak: 'break-all' }}>
                SHA-256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284ddd200126d90699 [VERIFIED]
              </div>
              <div style={{ fontSize: '12px', color: 'var(--argus-text-subtle)' }}>
                Verified by {selectedCase.assigned_to} &bull; Timestamp: 2026-10-10 18:30:00 UTC
              </div>
            </div>
          </div>
        )}

        {activeView === 'findings' && (
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
              Section II — Complete Correlated Findings Matrix
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>FINDING ID</th>
                  <th>SEVERITY</th>
                  <th>MITRE ATT&CK</th>
                  <th>INDICATOR FACT</th>
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

        {activeView === 'evidence' && (
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
              Section III — Ingested Artifact & Evidence Manifest
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>FILENAME</th>
                  <th>TYPE</th>
                  <th>FILE SIZE</th>
                  <th>SHA-256 PROVENANCE</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_EVIDENCE.map((e, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{e.id}</td>
                    <td style={{ fontWeight: 700 }}>{e.filename}</td>
                    <td><span className="argus-badge-steel">{e.artifact_type}</span></td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px' }}>{e.size_mb}</td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '10px', color: 'var(--argus-text-subtle)' }}>{e.hash}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeView === 'notes' && (
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
              Section IV — Investigator Chronological Briefings
            </h2>
            {PREVIEW_MOCK_CASE_NOTES.map((n, i) => (
              <div key={i} style={{ padding: 16, border: '1px solid var(--argus-border-strong)', marginBottom: 12, borderRadius: 4, background: '#FAF8F5' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: '12px' }}>
                  <strong>{n.author} ({n.category})</strong>
                  <span style={{ fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>{n.timestamp}</span>
                </div>
                <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.5 }}>{n.content}</p>
              </div>
            ))}
          </div>
        )}

        {activeView === 'audit' && (
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
              Section V — System Auditability & Immutable Trail
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

        {activeView === 'sanitized' && (
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
              Section VI — PII Redacted Evidence Log Stream
            </h2>
            <table className="argus-table">
              <thead>
                <tr>
                  <th>RECORD</th>
                  <th>SANITIZED SNIPPET</th>
                  <th>RULE APPLIED</th>
                </tr>
              </thead>
              <tbody>
                {PREVIEW_MOCK_SANITIZED_DATA.map((s, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontWeight: 800 }}>{s.record_id}</td>
                    <td style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px' }}>{s.sanitized_snippet}</td>
                    <td style={{ fontSize: '12px', color: 'var(--argus-steel-blue)' }}>{s.rule_applied}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeView === 'settings' && (
          <div className="argus-card" style={{ background: '#FFFFFF' }}>
            <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '20px', fontWeight: 400, borderBottom: '1px solid var(--argus-border-strong)', paddingBottom: 8, marginBottom: 16 }}>
              Section VII — Governance & Compliance Parameters
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
              <div style={{ background: '#FAF8F5', padding: 16, border: '1px solid var(--argus-border-strong)' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>TENANT NAME</div>
                <div style={{ fontSize: '16px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.tenant_name}</div>
              </div>
              <div style={{ background: '#FAF8F5', padding: 16, border: '1px solid var(--argus-border-strong)' }}>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)' }}>ENVIRONMENT</div>
                <div style={{ fontSize: '16px', fontWeight: 800, marginTop: 4 }}>{PREVIEW_MOCK_SETTINGS.environment}</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
