import React, { useState, useEffect } from 'react';
import TemplateSwitcherBar from './TemplateSwitcherBar';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings, fetchActivity } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates.css';

export default function MinimalEditorialTemplate() {
  const [activeTab, setActiveTab] = useState('overview');
  const [cases, setCases] = useState([]);
  const [activeCaseId, setActiveCaseId] = useState('CASE-2026-001');
  const [summary, setSummary] = useState(null);
  const [evidenceList, setEvidenceList] = useState([]);
  const [findingsList, setFindingsList] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const cRes = await fetchCases();
        const cList = Array.isArray(cRes) ? cRes : (cRes.data || []);
        setCases(cList);
        const selectedId = cList[0]?.case_id || 'CASE-2026-001';
        setActiveCaseId(selectedId);

        const [sData, eData, fData, aData] = await Promise.all([
          fetchCaseSummary(selectedId).catch(() => null),
          fetchEvidenceForCase(selectedId).catch(() => []),
          fetchFindings(selectedId).catch(() => []),
          fetchActivity(selectedId).catch(() => [])
        ]);

        setSummary(sData);
        setEvidenceList(Array.isArray(eData) ? eData : (eData.data || []));
        setFindingsList(Array.isArray(fData) ? fData : (fData.data || []));
        setAuditLogs(Array.isArray(aData) ? aData : (aData.data || []));
      } catch (err) {
        console.error('MinimalEditorial load error:', err);
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
      const [sData, eData, fData] = await Promise.all([
        fetchCaseSummary(cid).catch(() => null),
        fetchEvidenceForCase(cid).catch(() => []),
        fetchFindings(cid).catch(() => [])
      ]);
      setSummary(sData);
      setEvidenceList(Array.isArray(eData) ? eData : (eData.data || []));
      setFindingsList(Array.isArray(fData) ? fData : (fData.data || []));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="argus-template-wrapper template-minimal-editorial">
      <TemplateSwitcherBar activeTemplateName="Template A: Minimal Editorial" />

      {/* Editorial Header */}
      <header className="minimal-header">
        <div className="minimal-masthead">
          <div>
            <h1 className="minimal-title">ARGUS Forensics Briefing</h1>
            <div className="minimal-subtitle">Digital Investigation & Artifact Dossier</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span style={{ fontSize: '13px', color: 'var(--argus-gray-muted)' }}>ACTIVE DOSSIER:</span>
            <select 
              value={activeCaseId} 
              onChange={handleCaseChange}
              style={{
                background: '#ffffff',
                border: '1px solid var(--argus-black)',
                padding: '6px 14px',
                fontFamily: 'var(--font-mono)',
                fontSize: '13px',
                color: 'var(--argus-black)',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>
                  {c.case_id} — {c.title || c.description || 'Case'}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Editorial Navigation Tabs */}
        <nav className="minimal-nav">
          <span 
            className={`minimal-nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            I. Investigation Overview
          </span>
          <span 
            className={`minimal-nav-item ${activeTab === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            II. Forensic Findings ({findingsList.length})
          </span>
          <span 
            className={`minimal-nav-item ${activeTab === 'evidence' ? 'active' : ''}`}
            onClick={() => setActiveTab('evidence')}
          >
            III. Evidence Inventory ({evidenceList.length})
          </span>
          <span 
            className={`minimal-nav-item ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            IV. Audit Trail
          </span>
        </nav>
      </header>

      {/* Main Container */}
      <main className="minimal-container">
        {loading ? (
          <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--argus-gray-muted)', fontStyle: 'italic' }}>
            Compiling forensic briefing dossier...
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <>
                {/* Hero Feature Section */}
                <div className="minimal-grid-hero">
                  <div className="minimal-card">
                    <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--argus-gray-muted)', marginBottom: 8 }}>
                      Case Reference: {summary?.case_id || activeCaseId}
                    </div>
                    <h2 className="minimal-hero-title">
                      {summary?.description || 'Corporate Data Exfiltration & System Breach Investigation'}
                    </h2>
                    <p className="minimal-hero-desc">
                      Automated analysis has processed multi-layer artifacts including network alerts, disk images, and authentication logs. All evidence items have been cryptographically hashed and correlated against the MITRE ATT&CK matrix.
                    </p>
                    <div style={{ display: 'flex', gap: '32px', borderTop: '1px solid var(--argus-border-subtle)', paddingTop: 16 }}>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--argus-gray-muted)', textTransform: 'uppercase' }}>Tenant ID</div>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{summary?.tenant_id || 'default'}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--argus-gray-muted)', textTransform: 'uppercase' }}>Created On</div>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{safeFormatDateOnly(summary?.created_at || summary?.timestamp)}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--argus-gray-muted)', textTransform: 'uppercase' }}>Assigned Lead</div>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{summary?.assigned_to || 'Senior Analyst'}</div>
                      </div>
                    </div>
                  </div>

                  {/* Summary Metric Column */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div className="minimal-card">
                      <div className="minimal-stat-num">{summary?.total_findings || findingsList.length || 0}</div>
                      <div className="minimal-stat-label">Correlated Findings</div>
                    </div>
                    <div className="minimal-card">
                      <div className="minimal-stat-num">{summary?.total_evidence || evidenceList.length || 0}</div>
                      <div className="minimal-stat-label">Artifacts Ingested</div>
                    </div>
                    <div className="minimal-card">
                      <div className="minimal-stat-num" style={{ fontSize: '24px', fontWeight: 600 }}>
                        {summary?.high_severity || summary?.critical_findings || 0} High / Critical
                      </div>
                      <div className="minimal-stat-label">Risk Threshold Alert</div>
                    </div>
                  </div>
                </div>

                {/* Editorial Section Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '48px' }}>
                  <div>
                    <h3 style={{ fontFamily: 'var(--font-editorial-serif)', fontSize: '22px', borderBottom: '1px solid var(--argus-black)', paddingBottom: 8, marginBottom: 24 }}>
                      Key Findings Stream
                    </h3>
                    {findingsList.slice(0, 4).map((f, i) => (
                      <div key={i} style={{ borderBottom: '1px solid var(--argus-border-subtle)', paddingBottom: 16, marginBottom: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600 }}>{f.finding_id || f.id || `F-${i}`}</span>
                          <span className={`mono-badge mono-badge-${(f.severity || 'low').toLowerCase()}`}>
                            {f.severity || 'Notice'}
                          </span>
                        </div>
                        <div style={{ fontSize: '14px', lineHeight: 1.5, color: 'var(--argus-black)' }}>
                          {f.sanitized_fact || f.fact || f.description || 'Forensic indicator detected in log streams.'}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div>
                    <h3 style={{ fontFamily: 'var(--font-editorial-serif)', fontSize: '22px', borderBottom: '1px solid var(--argus-black)', paddingBottom: 8, marginBottom: 24 }}>
                      Evidence Manifest
                    </h3>
                    {evidenceList.slice(0, 4).map((ev, i) => (
                      <div key={i} style={{ borderBottom: '1px solid var(--argus-border-subtle)', paddingBottom: 16, marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '14px' }}>{ev.filename || ev.name || `Artifact-${i+1}`}</div>
                          <div style={{ fontSize: '12px', color: 'var(--argus-gray-muted)' }}>{ev.artifact_type || ev.type || 'Disk / Network'}</div>
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--argus-gray-dark)' }}>
                          {ev.file_size_bytes ? `${Math.round(ev.file_size_bytes/1024)} KB` : '4.2 MB'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {activeTab === 'findings' && (
              <div>
                <h2 style={{ fontFamily: 'var(--font-editorial-serif)', fontSize: '28px', marginBottom: 24, borderBottom: '2px solid var(--argus-black)', paddingBottom: 12 }}>
                  All Correlated Findings
                </h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {findingsList.map((f, i) => (
                    <div key={i} className="minimal-card" style={{ borderLeft: '4px solid var(--argus-black)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{f.finding_id || `FINDING-00${i+1}`}</span>
                        <span className={`mono-badge mono-badge-${(f.severity || 'low').toLowerCase()}`}>{f.severity}</span>
                      </div>
                      <div style={{ fontSize: '15px', lineHeight: 1.6, marginBottom: 12 }}>{f.sanitized_fact || f.fact}</div>
                      <div style={{ fontSize: '12px', color: 'var(--argus-gray-muted)', display: 'flex', gap: '24px' }}>
                        <span>Layer: <strong>{f.layer || 'System'}</strong></span>
                        <span>Confidence: <strong>{Math.round((f.confidence || 0.9) * 100)}%</strong></span>
                        <span>Ref: <strong>{Array.isArray(f.evidence_reference) ? f.evidence_reference.join(', ') : f.evidence_reference || 'N/A'}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'evidence' && (
              <div>
                <h2 style={{ fontFamily: 'var(--font-editorial-serif)', fontSize: '28px', marginBottom: 24, borderBottom: '2px solid var(--argus-black)', paddingBottom: 12 }}>
                  Case Evidence Vault
                </h2>
                <table style={{ width: '100%', borderCollapse: 'collapse', background: '#ffffff', border: '1px solid var(--argus-border-subtle)' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid var(--argus-black)', background: 'var(--argus-ivory)', textAlign: 'left', fontSize: '12px', textTransform: 'uppercase' }}>
                      <th style={{ padding: '12px 16px' }}>Filename</th>
                      <th style={{ padding: '12px 16px' }}>Type</th>
                      <th style={{ padding: '12px 16px' }}>Uploaded</th>
                      <th style={{ padding: '12px 16px' }}>Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidenceList.map((ev, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--argus-border-subtle)', fontSize: '14px' }}>
                        <td style={{ padding: '14px 16px', fontWeight: 600 }}>{ev.filename || ev.name}</td>
                        <td style={{ padding: '14px 16px', color: 'var(--argus-gray-dark)' }}>{ev.artifact_type || ev.type}</td>
                        <td style={{ padding: '14px 16px', color: 'var(--argus-gray-muted)' }}>{safeFormatDateOnly(ev.upload_timestamp || ev.submittedOn)}</td>
                        <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{ev.hash ? ev.hash.substring(0, 16) + '...' : 'e3b0c44298fc1c14...'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {activeTab === 'audit' && (
              <div>
                <h2 style={{ fontFamily: 'var(--font-editorial-serif)', fontSize: '28px', marginBottom: 24, borderBottom: '2px solid var(--argus-black)', paddingBottom: 12 }}>
                  Immutable Audit Log
                </h2>
                <div style={{ background: '#ffffff', border: '1px solid var(--argus-border-subtle)', padding: 24 }}>
                  {auditLogs.map((log, i) => (
                    <div key={i} style={{ padding: '12px 0', borderBottom: '1px solid var(--argus-border-subtle)', display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--argus-gray-muted)' }}>{safeFormatDateTime(log.created_at || log.timestamp)}</span>
                      <span style={{ fontWeight: 600, color: 'var(--argus-black)' }}>{log.action || 'INSPECTED_ARTIFACT'}</span>
                      <span style={{ color: 'var(--argus-gray-dark)' }}>{log.details || log.description || 'System operation executed.'}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
