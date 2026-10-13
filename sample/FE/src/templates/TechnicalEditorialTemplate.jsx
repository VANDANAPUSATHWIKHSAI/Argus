import React, { useState } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import { 
  PREVIEW_MOCK_CASES, 
  PREVIEW_MOCK_EVIDENCE, 
  PREVIEW_MOCK_FINDINGS, 
  PREVIEW_MOCK_AUDIT_LOGS 
} from './previewMockData';
import './templates.css';

export default function TechnicalEditorialTemplate() {
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');

  const selectedCase = PREVIEW_MOCK_CASES.find(c => c.case_id === selectedCaseId) || PREVIEW_MOCK_CASES[0];

  return (
    <div className="argus-preview-page" style={{ background: '#FFFFFF', paddingBottom: 80 }}>
      <TemplatePreviewBar activeName="4: Premium Technical Editorial" />

      {/* Dark Steel-Blue Hero Header */}
      <header style={{ background: 'var(--argus-dark-steel)', color: '#FFFFFF', padding: '48px 56px', borderBottom: '4px solid var(--argus-steel-blue)' }}>
        <div style={{ maxWidth: 1400, margin: '0 auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <span style={{ fontFamily: 'var(--argus-mono)', fontSize: '12px', letterSpacing: '0.12em', color: '#94A3B8', uppercase: 'true' }}>
              ARGUS TECHNICAL FORENSIC BRIEFING &bull; VERIFIED DOSSIER
            </span>
            <select 
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              style={{
                background: '#FFFFFF',
                color: 'var(--argus-graphite)',
                border: '2px solid #FFFFFF',
                padding: '8px 16px',
                fontFamily: 'var(--argus-mono)',
                fontSize: '13px',
                fontWeight: 800,
                cursor: 'pointer'
              }}
            >
              {PREVIEW_MOCK_CASES.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.name}</option>
              ))}
            </select>
          </div>

          <h1 style={{ fontFamily: 'var(--argus-serif)', fontSize: '40px', fontWeight: 400, margin: '0 0 16px 0', letterSpacing: '-0.02em', lineHeight: 1.2 }}>
            {selectedCase.name}
          </h1>

          <div style={{ display: 'flex', gap: 40, fontSize: '13px', color: '#CBD5E1', borderTop: '1px solid #4B5563', paddingTop: 16, marginTop: 24 }}>
            <div>DOSSIER ID: <strong style={{ color: '#FFFFFF', fontFamily: 'var(--argus-mono)' }}>{selectedCase.case_id}</strong></div>
            <div>INVESTIGATOR: <strong style={{ color: '#FFFFFF' }}>{selectedCase.assigned_to}</strong></div>
            <div>SCOPE: <strong style={{ color: '#FFFFFF' }}>{selectedCase.tenant_id}</strong></div>
            <div>CREATED: <strong style={{ color: '#FFFFFF' }}>{selectedCase.created_at}</strong></div>
          </div>
        </div>
      </header>

      {/* Asymmetrical Editorial Body */}
      <main style={{ maxWidth: 1400, margin: '0 auto', padding: '48px 56px', display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 48 }}>
        {/* Primary Editorial Findings Column */}
        <div>
          <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '24px', fontWeight: 400, borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, marginBottom: 24 }}>
            Executive Technical Findings
          </h2>

          {PREVIEW_MOCK_FINDINGS.map((f, i) => (
            <div key={i} className="argus-card" style={{ background: '#FBF9F5', borderLeft: '4px solid var(--argus-steel-blue)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontFamily: 'var(--argus-mono)', fontSize: '13px', fontWeight: 800 }}>
                  {f.finding_id}
                </span>
                <span className="argus-badge-steel">
                  {f.severity} SEVERITY
                </span>
              </div>

              <div style={{ fontFamily: 'var(--argus-serif)', fontSize: '18px', lineHeight: 1.5, color: 'var(--argus-graphite)', marginBottom: 16 }}>
                {f.sanitized_fact}
              </div>

              <div style={{ borderTop: '1px solid var(--argus-border-strong)', paddingTop: 12, display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--argus-text-subtle)' }}>
                <span>Layer: <strong style={{ color: 'var(--argus-graphite)' }}>{f.layer}</strong></span>
                <span>Confidence: <strong style={{ color: 'var(--argus-graphite)' }}>{Math.round(f.confidence * 100)}%</strong></span>
                <span>Source: <strong style={{ color: 'var(--argus-steel-blue)', fontFamily: 'var(--argus-mono)' }}>{f.evidence_reference.join(', ')}</strong></span>
              </div>
            </div>
          ))}
        </div>

        {/* Sidebar Specifications */}
        <div>
          <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '24px', fontWeight: 400, borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, marginBottom: 24 }}>
            Evidence Provenance
          </h2>

          <div className="argus-card">
            <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-text-subtle)', uppercase: 'true', fontWeight: 800, marginBottom: 4 }}>
              INGESTED FILE MANIFEST ({PREVIEW_MOCK_EVIDENCE.length})
            </div>
            {PREVIEW_MOCK_EVIDENCE.map((ev, i) => (
              <div key={i} style={{ borderBottom: i === PREVIEW_MOCK_EVIDENCE.length - 1 ? 'none' : '1px solid var(--argus-border-light)', paddingBottom: 10, marginBottom: 10 }}>
                <div style={{ fontSize: '13px', fontWeight: 700 }}>{ev.filename}</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--argus-mono)', color: 'var(--argus-steel-blue)' }}>{ev.artifact_type} &bull; {ev.size_mb}</div>
              </div>
            ))}
          </div>

          <h2 style={{ fontFamily: 'var(--argus-serif)', fontSize: '24px', fontWeight: 400, borderBottom: '2px solid var(--argus-graphite)', paddingBottom: 8, marginBottom: 24 }}>
            Audit Stream
          </h2>
          <div className="argus-card">
            {PREVIEW_MOCK_AUDIT_LOGS.map((log, i) => (
              <div key={i} style={{ padding: '8px 0', borderBottom: i === PREVIEW_MOCK_AUDIT_LOGS.length - 1 ? 'none' : '1px solid var(--argus-border-light)', fontSize: '12px' }}>
                <strong style={{ color: 'var(--argus-graphite)' }}>{log.action}</strong>
                <div style={{ fontSize: '11px', color: 'var(--argus-text-subtle)' }}>{log.details}</div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
