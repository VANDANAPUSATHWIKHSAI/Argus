import React, { useState, useEffect } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import TemplateSidebarReplica from './TemplateSidebarReplica';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings, fetchActivity } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates.css';

export default function MinimalProfessionalTemplate() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [cases, setCases] = useState([]);
  const [activeCaseId, setActiveCaseId] = useState('CASE-2026-001');
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
        setActiveCaseId(cid);

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
    setActiveCaseId(cid);
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
    <div className="argus-template-page theme-minimal-professional">
      <TemplatePreviewBar activeTemplateName="1: Minimal Professional" />

      {/* Existing ARGUS Sidebar Foundation */}
      <div className="argus-layout-container">
        <TemplateSidebarReplica 
          themeName="minimal-professional" 
          activeTab={activeTab} 
          onTabChange={setActiveTab} 
        />

        {/* Main Content Area */}
        <main className="argus-main-content">
          {/* Header Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28, borderBottom: '1px solid #E2E8F0', paddingBottom: 16 }}>
            <div>
              <div style={{ fontSize: '12px', color: '#64748B', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Forensic Case Dossier
              </div>
              <h1 style={{ fontSize: '26px', fontWeight: 800, margin: '2px 0 0 0', color: '#0F172A' }}>
                {activeCaseId} — {summary?.description || 'Corporate Data Exfiltration Investigation'}
              </h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <select 
                value={activeCaseId}
                onChange={handleCaseChange}
                style={{
                  padding: '8px 14px',
                  border: '1px solid #E2E8F0',
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
              <span className="tpl-badge-primary">HIGH RISK</span>
            </div>
          </div>

          {loading ? (
            <div style={{ padding: 40, color: '#64748B' }}>Loading case summary...</div>
          ) : (
            <>
              {activeTab === 'dashboard' && (
                <>
                  {/* Stat Cards with Steel-Blue Border Top Accent */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20, marginBottom: 28 }}>
                    <div className="tpl-card tpl-card-accent">
                      <div style={{ fontSize: '11px', fontWeight: 700, color: '#64748B', uppercase: 'true' }}>Total Findings</div>
                      <div style={{ fontSize: '28px', fontWeight: 800, color: '#0F172A', marginTop: 4 }}>{findingsList.length}</div>
                    </div>
                    <div className="tpl-card tpl-card-accent">
                      <div style={{ fontSize: '11px', fontWeight: 700, color: '#64748B', uppercase: 'true' }}>Ingested Evidence</div>
                      <div style={{ fontSize: '28px', fontWeight: 800, color: '#0F172A', marginTop: 4 }}>{evidenceList.length}</div>
                    </div>
                    <div className="tpl-card tpl-card-accent">
                      <div style={{ fontSize: '11px', fontWeight: 700, color: '#64748B', uppercase: 'true' }}>Tenant Isolation</div>
                      <div style={{ fontSize: '16px', fontWeight: 700, color: '#0F172A', marginTop: 10 }}>{summary?.tenant_id || 'default'}</div>
                    </div>
                    <div className="tpl-card tpl-card-accent">
                      <div style={{ fontSize: '11px', fontWeight: 700, color: '#64748B', uppercase: 'true' }}>Created Date</div>
                      <div style={{ fontSize: '16px', fontWeight: 700, color: '#0F172A', marginTop: 10 }}>{safeFormatDateOnly(summary?.created_at)}</div>
                    </div>
                  </div>

                  {/* Findings Stream Card */}
                  <div className="tpl-card">
                    <h2 style={{ fontSize: '18px', fontWeight: 800, margin: '0 0 16px 0', borderBottom: '1px solid #E2E8F0', paddingBottom: 10 }}>
                      Correlated Forensic Findings
                    </h2>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', fontSize: '11px', uppercase: 'true', color: '#64748B' }}>
                          <th style={{ padding: '10px 12px' }}>Finding ID</th>
                          <th style={{ padding: '10px 12px' }}>Severity</th>
                          <th style={{ padding: '10px 12px' }}>Indicator / Fact</th>
                          <th style={{ padding: '10px 12px' }}>Confidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {findingsList.map((f, i) => (
                          <tr key={i} style={{ borderBottom: '1px solid #F1F5F9', fontSize: '13px' }}>
                            <td style={{ padding: '12px', fontWeight: 700, fontFamily: 'monospace' }}>{f.finding_id || `F-00${i+1}`}</td>
                            <td style={{ padding: '12px' }}><span className="tpl-badge-primary">{(f.severity || 'low').toUpperCase()}</span></td>
                            <td style={{ padding: '12px', color: '#334155' }}>{f.sanitized_fact || f.fact}</td>
                            <td style={{ padding: '12px', fontWeight: 600 }}>{Math.round((f.confidence || 0.9) * 100)}%</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}

              {activeTab === 'evidence' && (
                <div className="tpl-card">
                  <h2 style={{ fontSize: '18px', fontWeight: 800, margin: '0 0 16px 0', borderBottom: '1px solid #E2E8F0', paddingBottom: 10 }}>
                    Evidence Inventory Vault
                  </h2>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #E2E8F0', fontSize: '11px', uppercase: 'true', color: '#64748B' }}>
                        <th style={{ padding: '10px 12px' }}>Filename</th>
                        <th style={{ padding: '10px 12px' }}>Type</th>
                        <th style={{ padding: '10px 12px' }}>Uploaded Timestamp</th>
                        <th style={{ padding: '10px 12px' }}>Hash</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidenceList.map((ev, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #F1F5F9', fontSize: '13px' }}>
                          <td style={{ padding: '12px', fontWeight: 700 }}>{ev.filename || ev.name}</td>
                          <td style={{ padding: '12px', color: '#64748B' }}>{ev.artifact_type || 'Artifact'}</td>
                          <td style={{ padding: '12px', color: '#64748B' }}>{safeFormatDateOnly(ev.upload_timestamp || ev.submittedOn)}</td>
                          <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '11px' }}>{ev.hash ? ev.hash.substring(0, 20) + '...' : 'e3b0c44298fc1c14...'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {(activeTab === 'findings' || activeTab === 'cases' || activeTab === 'notes' || activeTab === 'audit') && (
                <div className="tpl-card">
                  <h2 style={{ fontSize: '18px', fontWeight: 800, margin: '0 0 16px 0', borderBottom: '1px solid #E2E8F0', paddingBottom: 10 }}>
                    {activeTab.toUpperCase()} Stream
                  </h2>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {activities.map((act, i) => (
                      <div key={i} style={{ padding: '12px', background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0', display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                        <span style={{ fontFamily: 'monospace', color: '#64748B' }}>{safeFormatDateTime(act.created_at)}</span>
                        <strong style={{ color: '#0F172A' }}>{act.action || 'ACTIVITY'}</strong>
                        <span style={{ color: '#334155' }}>{act.details || 'System operation executed'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
