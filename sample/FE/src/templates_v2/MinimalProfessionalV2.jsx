import React, { useState, useEffect } from 'react';
import TemplateV2SwitcherBar from './TemplateV2SwitcherBar';
import { fetchCases, fetchCaseSummary, fetchFindings, fetchEvidenceForCase } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates_v2.css';

export default function MinimalProfessionalV2() {
  const [cases, setCases] = useState([]);
  const [activeCaseId, setActiveCaseId] = useState('CASE-2026-001');
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dossier');

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const cRes = await fetchCases();
        const cList = Array.isArray(cRes) ? cRes : (cRes.data || []);
        setCases(cList);
        const selectedId = cList[0]?.case_id || 'CASE-2026-001';
        setActiveCaseId(selectedId);

        const [sData, fData, eData] = await Promise.all([
          fetchCaseSummary(selectedId).catch(() => null),
          fetchFindings(selectedId).catch(() => []),
          fetchEvidenceForCase(selectedId).catch(() => [])
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

  const handleCaseSelect = async (cid) => {
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
    <div className="v2-wrapper">
      <TemplateV2SwitcherBar activeName="1: Minimal & Professional" />

      <div className="v2-minimal-layout">
        {/* Left Fixed Navigation Rail */}
        <aside className="v2-minimal-sidebar">
          <div>
            <div style={{ paddingBottom: 20, marginBottom: 20, borderBottom: '2px solid #111111' }}>
              <div style={{ fontFamily: 'var(--v2-mono-font)', fontWeight: 800, fontSize: '18px', letterSpacing: '-0.02em' }}>
                ARGUS
              </div>
              <div style={{ fontSize: '11px', color: '#64748B', fontWeight: 700, uppercase: 'true' }}>
                FORENSICS SUITE
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <button 
                onClick={() => setActiveTab('dossier')}
                style={{
                  textAlign: 'left',
                  padding: '10px 14px',
                  background: activeTab === 'dossier' ? '#111111' : 'transparent',
                  color: activeTab === 'dossier' ? '#FFFFFF' : '#0F172A',
                  border: '1px solid #111111',
                  borderRadius: 4,
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer'
                }}
              >
                1. Case Dossier
              </button>
              <button 
                onClick={() => setActiveTab('findings')}
                style={{
                  textAlign: 'left',
                  padding: '10px 14px',
                  background: activeTab === 'findings' ? '#111111' : 'transparent',
                  color: activeTab === 'findings' ? '#FFFFFF' : '#0F172A',
                  border: '1px solid #111111',
                  borderRadius: 4,
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer'
                }}
              >
                2. Findings ({findings.length})
              </button>
              <button 
                onClick={() => setActiveTab('evidence')}
                style={{
                  textAlign: 'left',
                  padding: '10px 14px',
                  background: activeTab === 'evidence' ? '#111111' : 'transparent',
                  color: activeTab === 'evidence' ? '#FFFFFF' : '#0F172A',
                  border: '1px solid #111111',
                  borderRadius: 4,
                  fontWeight: 700,
                  fontSize: '13px',
                  cursor: 'pointer'
                }}
              >
                3. Evidence Vault ({evidence.length})
              </button>
            </div>
          </div>

          <div style={{ borderTop: '2px solid #111111', paddingTop: 16 }}>
            <div style={{ fontSize: '10px', color: '#64748B', fontWeight: 800, uppercase: 'true' }}>SELECT CASE FILE</div>
            <select 
              value={activeCaseId}
              onChange={(e) => handleCaseSelect(e.target.value)}
              style={{
                width: '100%',
                marginTop: 8,
                padding: '8px',
                border: '2px solid #111111',
                fontFamily: 'var(--v2-mono-font)',
                fontSize: '12px',
                fontWeight: 700,
                background: '#FFFFFF'
              }}
            >
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.case_id}</option>
              ))}
            </select>
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="v2-minimal-main">
          {loading ? (
            <div style={{ padding: 40, color: '#64748B' }}>Loading investigation dossier...</div>
          ) : (
            <>
              {activeTab === 'dossier' && (
                <div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20, marginBottom: 32 }}>
                    <div className="v2-minimal-stat-box">
                      <div style={{ fontSize: '11px', fontWeight: 800, color: '#64748B', uppercase: 'true' }}>TOTAL FINDINGS</div>
                      <div style={{ fontSize: '36px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)' }}>{findings.length}</div>
                    </div>
                    <div className="v2-minimal-stat-box">
                      <div style={{ fontSize: '11px', fontWeight: 800, color: '#64748B', uppercase: 'true' }}>EVIDENCE ARTIFACTS</div>
                      <div style={{ fontSize: '36px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)' }}>{evidence.length}</div>
                    </div>
                    <div className="v2-minimal-stat-box">
                      <div style={{ fontSize: '11px', fontWeight: 800, color: '#64748B', uppercase: 'true' }}>HIGH / CRITICAL RISK</div>
                      <div style={{ fontSize: '36px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)' }}>
                        {summary?.high_severity || summary?.critical_findings || 1}
                      </div>
                    </div>
                  </div>

                  <div className="v2-minimal-card">
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '2px solid #111111', paddingBottom: 12, marginBottom: 16 }}>
                      <span style={{ fontFamily: 'var(--v2-mono-font)', fontWeight: 800, fontSize: '16px' }}>{summary?.case_id || activeCaseId}</span>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: '#64748B' }}>TENANT: {summary?.tenant_id || 'default'}</span>
                    </div>

                    <h2 style={{ fontSize: '22px', fontWeight: 800, margin: '0 0 12px 0' }}>
                      {summary?.description || 'Corporate Network Breach & Data Artifact Analysis'}
                    </h2>

                    <p style={{ fontSize: '14px', lineHeight: 1.6, color: '#334155', marginBottom: 20 }}>
                      All ingested disk images, RAM dumps, and EVTX logs have been processed against sanitization gates and cross-referenced with Threat Intelligence IOC databases.
                    </p>

                    <div style={{ display: 'flex', gap: 32, borderTop: '1px solid #E2E8F0', paddingTop: 16, fontSize: '13px' }}>
                      <div><span style={{ color: '#64748B' }}>Assigned Lead:</span> <strong>{summary?.assigned_to || 'Senior Lead'}</strong></div>
                      <div><span style={{ color: '#64748B' }}>Created On:</span> <strong>{safeFormatDateOnly(summary?.created_at)}</strong></div>
                    </div>
                  </div>

                  <div className="v2-minimal-card">
                    <h3 style={{ fontSize: '16px', fontWeight: 800, borderBottom: '2px solid #111111', paddingBottom: 8, marginBottom: 16 }}>
                      Correlated Findings Summary
                    </h3>
                    {findings.slice(0, 3).map((f, i) => (
                      <div key={i} style={{ padding: '12px 0', borderBottom: i === 2 ? 'none' : '1px solid #E2E8F0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <div style={{ fontFamily: 'var(--v2-mono-font)', fontWeight: 700, fontSize: '13px' }}>{f.finding_id || `F-0${i+1}`}</div>
                          <div style={{ fontSize: '13px', color: '#334155' }}>{f.sanitized_fact || f.fact}</div>
                        </div>
                        <span className={`v2-tag v2-tag-${(f.severity || 'low').toLowerCase()}`}>{f.severity || 'LOW'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === 'findings' && (
                <div className="v2-minimal-card">
                  <h2 style={{ fontSize: '20px', fontWeight: 800, borderBottom: '2px solid #111111', paddingBottom: 12, marginBottom: 20 }}>
                    Correlated Forensic Findings
                  </h2>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid #111111', fontSize: '12px', uppercase: 'true' }}>
                        <th style={{ padding: 12 }}>ID</th>
                        <th style={{ padding: 12 }}>Severity</th>
                        <th style={{ padding: 12 }}>Indicator / Fact</th>
                        <th style={{ padding: 12 }}>Layer</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #E2E8F0', fontSize: '13px' }}>
                          <td style={{ padding: 12, fontFamily: 'var(--v2-mono-font)', fontWeight: 700 }}>{f.finding_id || `F-00${i+1}`}</td>
                          <td style={{ padding: 12 }}><span className={`v2-tag v2-tag-${(f.severity || 'low').toLowerCase()}`}>{f.severity}</span></td>
                          <td style={{ padding: 12 }}>{f.sanitized_fact || f.fact}</td>
                          <td style={{ padding: 12, fontFamily: 'var(--v2-mono-font)', fontSize: '11px', color: '#64748B' }}>{f.layer || 'System'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {activeTab === 'evidence' && (
                <div className="v2-minimal-card">
                  <h2 style={{ fontSize: '20px', fontWeight: 800, borderBottom: '2px solid #111111', paddingBottom: 12, marginBottom: 20 }}>
                    Evidence Artifact Inventory
                  </h2>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid #111111', fontSize: '12px', uppercase: 'true' }}>
                        <th style={{ padding: 12 }}>Filename</th>
                        <th style={{ padding: 12 }}>Type</th>
                        <th style={{ padding: 12 }}>Uploaded Date</th>
                        <th style={{ padding: 12 }}>Hash</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidence.map((ev, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #E2E8F0', fontSize: '13px' }}>
                          <td style={{ padding: 12, fontWeight: 700 }}>{ev.filename || ev.name}</td>
                          <td style={{ padding: 12, color: '#64748B' }}>{ev.artifact_type || 'Artifact'}</td>
                          <td style={{ padding: 12, color: '#64748B' }}>{safeFormatDateOnly(ev.upload_timestamp || ev.submittedOn)}</td>
                          <td style={{ padding: 12, fontFamily: 'var(--v2-mono-font)', fontSize: '11px' }}>{ev.hash ? ev.hash.substring(0, 16) + '...' : 'e3b0c44298fc1c14...'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
