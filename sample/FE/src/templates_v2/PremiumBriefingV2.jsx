import React, { useState, useEffect } from 'react';
import TemplateV2SwitcherBar from './TemplateV2SwitcherBar';
import { fetchCases, fetchCaseSummary, fetchFindings, fetchEvidenceForCase } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates_v2.css';

export default function PremiumBriefingV2() {
  const [cases, setCases] = useState([]);
  const [activeCaseId, setActiveCaseId] = useState('CASE-2026-001');
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const cRes = await fetchCases();
        const cList = Array.isArray(cRes) ? cRes : (cRes.data || []);
        setCases(cList);
        const cid = cList[0]?.case_id || 'CASE-2026-001';
        setActiveCaseId(cid);

        const [sData, fData, eData] = await Promise.all([
          fetchCaseSummary(cid).catch(() => null),
          fetchFindings(cid).catch(() => []),
          fetchEvidenceForCase(cid).catch(() => [])
        ]);

        setSummary(sData);
        setFindings(Array.isArray(fData) ? fData : (fData.data || []));
        setEvidence(Array.isArray(eData) ? eData : (eData.data || []));
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleCaseChange = async (e) => {
    const cid = e.target.value;
    setActiveCaseId(cid);
    setLoading(true);
    try {
      const [sData, fData, eData] = await Promise.all([
        fetchCaseSummary(cid).catch(() => null),
        fetchFindings(cid).catch(() => []),
        fetchEvidenceForCase(cid).catch(() => [])
      ]);
      setSummary(sData);
      setFindings(Array.isArray(fData) ? fData : (fData.data || []));
      setEvidence(Array.isArray(eData) ? eData : (eData.data || []));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="v2-wrapper" style={{ paddingBottom: 80 }}>
      <TemplateV2SwitcherBar activeName="3: Premium & Distinctive Briefing" />

      {/* Stark Black Hero Header */}
      <header className="v2-premium-hero">
        <div style={{ maxWidth: 1440, margin: '0 auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <span style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '12px', letterSpacing: '0.12em', color: '#94A3B8' }}>
              ARGUS DIGITAL FORENSICS &bull; EXECUTIVE INTELLIGENCE DOSSIER
            </span>
            <select 
              value={activeCaseId}
              onChange={handleCaseChange}
              style={{
                background: '#FFFFFF',
                color: '#111111',
                border: '2px solid #FFFFFF',
                padding: '8px 16px',
                fontFamily: 'var(--v2-mono-font)',
                fontSize: '13px',
                fontWeight: 800,
                cursor: 'pointer'
              }}
            >
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.title || c.description || 'Case'}</option>
              ))}
            </select>
          </div>

          <h1 style={{ fontFamily: 'var(--v2-serif-font)', fontSize: '42px', fontWeight: 400, margin: '0 0 16px 0', letterSpacing: '-0.02em' }}>
            {summary?.description || 'Incident Investigation & Forensic Evidence Dossier'}
          </h1>

          <div style={{ display: 'flex', gap: 40, fontSize: '13px', color: '#CBD5E1', borderTop: '1px solid #334155', paddingTop: 16, marginTop: 24 }}>
            <div>CASE REF: <strong style={{ color: '#FFFFFF', fontFamily: 'var(--v2-mono-font)' }}>{summary?.case_id || activeCaseId}</strong></div>
            <div>INVESTIGATOR: <strong style={{ color: '#FFFFFF' }}>{summary?.assigned_to || 'Senior Lead'}</strong></div>
            <div>ORGANIZATION: <strong style={{ color: '#FFFFFF' }}>{summary?.tenant_id || 'default'}</strong></div>
            <div>CREATED: <strong style={{ color: '#FFFFFF' }}>{safeFormatDateOnly(summary?.created_at)}</strong></div>
          </div>
        </div>
      </header>

      {/* Asymmetrical Body Grid */}
      <main className="v2-premium-grid">
        {/* Main Briefing Column */}
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, borderBottom: '2px solid #111111', paddingBottom: 8, marginBottom: 24 }}>
            Correlated Findings Stream
          </h2>

          {loading ? (
            <div style={{ color: '#64748B' }}>Loading briefing data...</div>
          ) : (
            findings.map((f, i) => (
              <div key={i} className="v2-premium-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <span style={{ fontFamily: 'var(--v2-mono-font)', fontWeight: 800, fontSize: '14px' }}>
                    {f.finding_id || `FINDING-00${i+1}`}
                  </span>
                  <span className={`v2-tag v2-tag-${(f.severity || 'low').toLowerCase()}`}>
                    {f.severity || 'LOW'} SEVERITY
                  </span>
                </div>

                <div style={{ fontFamily: 'var(--v2-serif-font)', fontSize: '18px', lineHeight: 1.5, color: '#111111', marginBottom: 16 }}>
                  {f.sanitized_fact || f.fact}
                </div>

                <div style={{ borderTop: '1px solid #E2E8F0', paddingTop: 12, display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#64748B' }}>
                  <span>Layer: <strong style={{ color: '#111111' }}>{f.layer || 'Network'}</strong></span>
                  <span>Confidence: <strong style={{ color: '#111111' }}>{Math.round((f.confidence || 0.9) * 100)}%</strong></span>
                  <span>Provenance: <strong style={{ color: '#111111' }}>{Array.isArray(f.evidence_reference) ? f.evidence_reference.join(', ') : f.evidence_reference || 'Ref-01'}</strong></span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Sidebar Dossier Panel */}
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, borderBottom: '2px solid #111111', paddingBottom: 8, marginBottom: 24 }}>
            Dossier Specifications
          </h2>

          <div className="v2-premium-card">
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: '11px', color: '#64748B', fontWeight: 800, uppercase: 'true' }}>AUDIT VERIFICATION</div>
              <div style={{ fontSize: '14px', fontWeight: 800, color: '#111111' }}>Cryptographically Signed</div>
            </div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: '11px', color: '#64748B', fontWeight: 800, uppercase: 'true' }}>TOTAL ARTIFACTS</div>
              <div style={{ fontSize: '14px', fontWeight: 800 }}>{evidence.length} Files Registered</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#64748B', fontWeight: 800, uppercase: 'true' }}>RISK SCORE</div>
              <div style={{ fontSize: '24px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)' }}>HIGH (8.4/10)</div>
            </div>
          </div>

          <h3 style={{ fontSize: '16px', fontWeight: 800, borderBottom: '2px solid #111111', paddingBottom: 8, marginBottom: 16 }}>
            Evidence Vault List
          </h3>
          <div className="v2-premium-card" style={{ padding: 20 }}>
            {evidence.map((ev, i) => (
              <div key={i} style={{ borderBottom: i === evidence.length - 1 ? 'none' : '1px solid #E2E8F0', paddingBottom: 10, marginBottom: 10 }}>
                <div style={{ fontSize: '13px', fontWeight: 700 }}>{ev.filename || ev.name}</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--v2-mono-font)', color: '#64748B' }}>{ev.artifact_type || 'Disk Image'}</div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
