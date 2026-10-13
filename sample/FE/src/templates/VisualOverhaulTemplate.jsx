import React, { useState, useEffect } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings, fetchActivity } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates.css';

export default function VisualOverhaulTemplate() {
  const [activeTab, setActiveTab] = useState('summary');
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState('CASE-2026-001');
  const [summary, setSummary] = useState(null);
  const [evidenceList, setEvidenceList] = useState([]);
  const [findingsList, setFindingsList] = useState([]);
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const cRes = await fetchCases();
        const cList = Array.isArray(cRes) ? cRes : (cRes.data || []);
        setCases(cList);
        const cid = cList[0]?.case_id || 'CASE-2026-001';
        setSelectedCaseId(cid);

        const [sData, eData, fData, aData] = await Promise.all([
          fetchCaseSummary(cid).catch(() => null),
          fetchEvidenceForCase(cid).catch(() => []),
          fetchFindings(cid).catch(() => []),
          fetchActivity(cid).catch(() => [])
        ]);

        setSummary(sData);
        setEvidenceList(Array.isArray(eData) ? eData : (eData.data || []));
        setFindingsList(Array.isArray(fData) ? fData : (fData.data || []));
        setActivities(Array.isArray(aData) ? aData : (aData.data || []));
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
    setSelectedCaseId(cid);
    setLoading(true);
    try {
      const [sData, eData, fData, aData] = await Promise.all([
        fetchCaseSummary(cid).catch(() => null),
        fetchEvidenceForCase(cid).catch(() => []),
        fetchFindings(cid).catch(() => []),
        fetchActivity(cid).catch(() => [])
      ]);
      setSummary(sData);
      setEvidenceList(Array.isArray(eData) ? eData : (eData.data || []));
      setFindingsList(Array.isArray(fData) ? fData : (fData.data || []));
      setActivities(Array.isArray(aData) ? aData : (aData.data || []));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="argus-template-page theme-visual-overhaul">
      <TemplatePreviewBar activeTemplateName="4: Complete Visual Overhaul" />

      {/* Redesigned Studio Header Bar */}
      <header className="studio-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ fontWeight: 800, fontSize: '20px', letterSpacing: '-0.02em', color: '#0F172A' }}>
            ARGUS STUDIO
          </div>
          <span style={{ fontSize: '11px', background: '#2563EB', color: '#FFFFFF', padding: '2px 8px', borderRadius: 4, fontWeight: 700 }}>
            LAYOUT OVERHAUL
          </span>
        </div>

        {/* Tabbed Studio Modules */}
        <div className="studio-nav-tabs">
          <button 
            className={`studio-tab ${activeTab === 'summary' ? 'active' : ''}`}
            onClick={() => setActiveTab('summary')}
          >
            Overview & Metrics
          </button>
          <button 
            className={`studio-tab ${activeTab === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            Findings ({findingsList.length})
          </button>
          <button 
            className={`studio-tab ${activeTab === 'evidence' ? 'active' : ''}`}
            onClick={() => setActiveTab('evidence')}
          >
            Evidence Vault ({evidenceList.length})
          </button>
          <button 
            className={`studio-tab ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            Audit Trail Stream
          </button>
        </div>

        {/* Active Case Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <select 
            value={selectedCaseId} 
            onChange={handleCaseChange}
            style={{
              padding: '6px 12px',
              border: '1px solid #CBD5E1',
              borderRadius: '6px',
              fontSize: '13px',
              fontWeight: 600,
              color: '#0F172A',
              background: '#FFFFFF',
              cursor: 'pointer'
            }}
          >
            {cases.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.title || c.description || 'Case'}</option>
            ))}
          </select>
        </div>
      </header>

      {/* Main Studio Dashboard Canvas */}
      <main className="studio-main">
        {loading ? (
          <div style={{ padding: 40, color: '#64748B' }}>Loading Studio layout...</div>
        ) : (
          <>
            {activeTab === 'summary' && (
              <div className="studio-grid">
                {/* Hero Dossier Card (8 Columns) */}
                <div style={{ gridColumn: 'span 8', background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 8, padding: 28, boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#2563EB', uppercase: 'true', marginBottom: 4 }}>
                    INVESTIGATION DOSSIER &bull; {selectedCaseId}
                  </div>
                  <h2 style={{ fontSize: '24px', fontWeight: 800, margin: '0 0 12px 0', color: '#0F172A' }}>
                    {summary?.description || 'Corporate Data Exfiltration Analysis'}
                  </h2>
                  <p style={{ fontSize: '14px', color: '#334155', lineHeight: 1.6, marginBottom: 24 }}>
                    Horizontal studio layout providing modular visibility into correlated findings, ingested evidence artifacts, and system audit logs.
                  </p>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, borderTop: '1px solid #E2E8F0', paddingTop: 16 }}>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748B', uppercase: 'true' }}>Total Findings</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A' }}>{findingsList.length}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748B', uppercase: 'true' }}>Ingested Evidence</div>
                      <div style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A' }}>{evidenceList.length}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748B', uppercase: 'true' }}>Tenant Scope</div>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: '#0F172A', marginTop: 4 }}>{summary?.tenant_id || 'default'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: '#64748B', uppercase: 'true' }}>Created On</div>
                      <div style={{ fontSize: '14px', fontWeight: 700, color: '#0F172A', marginTop: 4 }}>{safeFormatDateOnly(summary?.created_at)}</div>
                    </div>
                  </div>
                </div>

                {/* Risk Spectrum Card (4 Columns) */}
                <div style={{ gridColumn: 'span 4', background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 8, padding: 28, boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
                  <h3 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0', borderBottom: '1px solid #E2E8F0', paddingBottom: 8 }}>
                    Severity Spectrum
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: 12, background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0' }}>
                      <span style={{ fontSize: '12px', fontWeight: 800, color: '#DC2626' }}>CRITICAL</span>
                      <strong style={{ fontSize: '16px' }}>{summary?.critical_findings || 0}</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: 12, background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0' }}>
                      <span style={{ fontSize: '12px', fontWeight: 800, color: '#D97706' }}>HIGH</span>
                      <strong style={{ fontSize: '16px' }}>{summary?.high_severity || 1}</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: 12, background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0' }}>
                      <span style={{ fontSize: '12px', fontWeight: 800, color: '#2563EB' }}>MEDIUM</span>
                      <strong style={{ fontSize: '16px' }}>{summary?.medium_severity || 2}</strong>
                    </div>
                  </div>
                </div>

                {/* Artifact Stream (12 Columns) */}
                <div style={{ gridColumn: 'span 12', background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 8, padding: 28, boxShadow: '0 1px 3px rgba(0,0,0,0.03)' }}>
                  <h3 style={{ fontSize: '16px', fontWeight: 800, margin: '0 0 16px 0' }}>
                    Findings Grid Preview
                  </h3>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                    {findingsList.map((f, i) => (
                      <div key={i} style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: 6, padding: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                          <span style={{ fontFamily: 'monospace', fontWeight: 800, fontSize: '12px' }}>{f.finding_id || `F-00${i+1}`}</span>
                          <span style={{ fontSize: '11px', fontWeight: 800, color: '#2563EB' }}>{(f.severity || 'LOW').toUpperCase()}</span>
                        </div>
                        <p style={{ fontSize: '13px', lineHeight: 1.5, color: '#334155', margin: 0 }}>
                          {f.sanitized_fact || f.fact}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'findings' && (
              <div style={{ background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 8, padding: 28 }}>
                <h2 style={{ fontSize: '20px', fontWeight: 800, margin: '0 0 16px 0' }}>Correlated Findings Stream</h2>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #0F172A', fontSize: '12px', uppercase: 'true', color: '#64748B' }}>
                      <th style={{ padding: 12 }}>Finding ID</th>
                      <th style={{ padding: 12 }}>Severity</th>
                      <th style={{ padding: 12 }}>Indicator / Fact</th>
                      <th style={{ padding: 12 }}>Layer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findingsList.map((f, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #E2E8F0', fontSize: '13px' }}>
                        <td style={{ padding: 12, fontWeight: 700, fontFamily: 'monospace' }}>{f.finding_id || `F-00${i+1}`}</td>
                        <td style={{ padding: 12, fontWeight: 700, color: '#2563EB' }}>{(f.severity || 'low').toUpperCase()}</td>
                        <td style={{ padding: 12, color: '#334155' }}>{f.sanitized_fact || f.fact}</td>
                        <td style={{ padding: 12, fontFamily: 'monospace', color: '#64748B' }}>{f.layer || 'System'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {activeTab === 'evidence' && (
              <div style={{ background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 8, padding: 28 }}>
                <h2 style={{ fontSize: '20px', fontWeight: 800, margin: '0 0 16px 0' }}>Evidence Vault List</h2>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #0F172A', fontSize: '12px', uppercase: 'true', color: '#64748B' }}>
                      <th style={{ padding: 12 }}>Filename</th>
                      <th style={{ padding: 12 }}>Type</th>
                      <th style={{ padding: 12 }}>Uploaded Date</th>
                      <th style={{ padding: 12 }}>SHA-256 Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidenceList.map((ev, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #E2E8F0', fontSize: '13px' }}>
                        <td style={{ padding: 12, fontWeight: 700 }}>{ev.filename || ev.name}</td>
                        <td style={{ padding: 12, color: '#64748B' }}>{ev.artifact_type || 'Artifact'}</td>
                        <td style={{ padding: 12, color: '#64748B' }}>{safeFormatDateOnly(ev.upload_timestamp || ev.submittedOn)}</td>
                        <td style={{ padding: 12, fontFamily: 'monospace', fontSize: '11px', color: '#2563EB' }}>
                          {ev.hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {activeTab === 'audit' && (
              <div style={{ background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 8, padding: 28 }}>
                <h2 style={{ fontSize: '20px', fontWeight: 800, margin: '0 0 16px 0' }}>Audit Trail Stream</h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {activities.map((act, i) => (
                    <div key={i} style={{ padding: 14, background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0', display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                      <span style={{ fontFamily: 'monospace', color: '#64748B' }}>{safeFormatDateTime(act.created_at)}</span>
                      <strong style={{ color: '#0F172A' }}>{act.action || 'ACTIVITY'}</strong>
                      <span style={{ color: '#334155' }}>{act.details || 'Operation executed'}</span>
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
