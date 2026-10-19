import React, { useState, useEffect } from 'react';
import TemplatePreviewBar from './TemplatePreviewBar';
import TemplateSidebarReplica from './TemplateSidebarReplica';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings, fetchActivity } from '../js/api';
import { safeFormatDateOnly, safeFormatDateTime } from '../js/dateUtils';
import './templates.css';

export default function PremiumEditorialTemplate() {
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
    <div className="argus-template-page theme-premium-editorial">
      <TemplatePreviewBar activeTemplateName="3: Premium Editorial" />

      {/* Existing ARGUS Sidebar Foundation */}
      <div className="argus-layout-container">
        <TemplateSidebarReplica 
          themeName="premium-editorial" 
          activeTab={activeTab} 
          onTabChange={setActiveTab} 
        />

        {/* Main Content Area */}
        <main className="argus-main-content">
          {/* Header Bar */}
          <div className="tpl-rule" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', paddingBottom: 16 }}>
            <div>
              <div style={{ fontSize: '12px', letterSpacing: '0.12em', uppercase: 'true', color: '#777777', fontWeight: 600 }}>
                FORENSIC DOSSIER &bull; ARGUS INTELLIGENCE
              </div>
              <h1 className="tpl-serif" style={{ fontSize: '32px', fontWeight: 400, margin: '4px 0 0 0', color: '#111111', letterSpacing: '-0.02em' }}>
                {summary?.description || 'Corporate Data Exfiltration & Systems Analysis'}
              </h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <select 
                value={activeCaseId}
                onChange={handleCaseChange}
                className="tpl-serif"
                style={{
                  padding: '8px 16px',
                  border: '1px solid #111111',
                  borderRadius: '0px',
                  fontSize: '13px',
                  fontWeight: 600,
                  background: '#FFFFFF',
                  color: '#111111',
                  cursor: 'pointer'
                }}
              >
                {cases.map(c => (
                  <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.title || c.description || 'Case'}</option>
                ))}
              </select>
            </div>
          </div>

          {loading ? (
            <div className="tpl-serif" style={{ padding: 40, color: '#777777' }}>Compiling editorial briefing...</div>
          ) : (
            <>
              {activeTab === 'dashboard' && (
                <>
                  {/* Executive Metric Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 24, marginBottom: 32 }}>
                    <div className="tpl-card">
                      <div style={{ fontSize: '11px', uppercase: 'true', letterSpacing: '0.1em', color: '#777777' }}>Findings Stream</div>
                      <div className="tpl-serif" style={{ fontSize: '38px', fontWeight: 300, color: '#111111', marginTop: 4 }}>{findingsList.length}</div>
                    </div>
                    <div className="tpl-card">
                      <div style={{ fontSize: '11px', uppercase: 'true', letterSpacing: '0.1em', color: '#777777' }}>Evidence Files</div>
                      <div className="tpl-serif" style={{ fontSize: '38px', fontWeight: 300, color: '#111111', marginTop: 4 }}>{evidenceList.length}</div>
                    </div>
                    <div className="tpl-card">
                      <div style={{ fontSize: '11px', uppercase: 'true', letterSpacing: '0.1em', color: '#777777' }}>Tenant Scope</div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: '#111111', marginTop: 14 }}>{summary?.tenant_id || 'default'}</div>
                    </div>
                    <div className="tpl-card">
                      <div style={{ fontSize: '11px', uppercase: 'true', letterSpacing: '0.1em', color: '#777777' }}>Initiated On</div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: '#111111', marginTop: 14 }}>{safeFormatDateOnly(summary?.created_at)}</div>
                    </div>
                  </div>

                  {/* Findings Stream */}
                  <div className="tpl-card">
                    <h2 className="tpl-serif" style={{ fontSize: '22px', fontWeight: 400, margin: '0 0 20px 0', borderBottom: '1px solid #111111', paddingBottom: 10 }}>
                      Executive Finding Summaries
                    </h2>
                    {findingsList.map((f, i) => (
                      <div key={i} style={{ borderBottom: i === findingsList.length - 1 ? 'none' : '1px solid #E5DDD5', paddingBottom: 16, marginBottom: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                          <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '13px' }}>{f.finding_id || `F-00${i+1}`}</span>
                          <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.05em', uppercase: 'true', color: '#1E3A8A' }}>
                            {(f.severity || 'low').toUpperCase()} SEVERITY
                          </span>
                        </div>
                        <div className="tpl-serif" style={{ fontSize: '16px', lineHeight: 1.5, color: '#111111' }}>
                          {f.sanitized_fact || f.fact}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}

              {activeTab === 'evidence' && (
                <div className="tpl-card">
                  <h2 className="tpl-serif" style={{ fontSize: '22px', fontWeight: 400, margin: '0 0 20px 0', borderBottom: '1px solid #111111', paddingBottom: 10 }}>
                    Evidence Manifest
                  </h2>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #111111', fontSize: '11px', uppercase: 'true', color: '#777777' }}>
                        <th style={{ padding: '12px' }}>Filename</th>
                        <th style={{ padding: '12px' }}>Type</th>
                        <th style={{ padding: '12px' }}>Uploaded</th>
                        <th style={{ padding: '12px' }}>Hash</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidenceList.map((ev, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #E5DDD5', fontSize: '13px' }}>
                          <td style={{ padding: '14px 12px', fontWeight: 600 }}>{ev.filename || ev.name}</td>
                          <td style={{ padding: '14px 12px', color: '#555555' }}>{ev.artifact_type || 'Artifact'}</td>
                          <td style={{ padding: '14px 12px', color: '#777777' }}>{safeFormatDateOnly(ev.upload_timestamp || ev.submittedOn)}</td>
                          <td style={{ padding: '14px 12px', fontFamily: 'monospace', fontSize: '11px' }}>{ev.hash ? ev.hash.substring(0, 20) + '...' : 'e3b0c44298fc1c14...'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {(activeTab === 'findings' || activeTab === 'cases' || activeTab === 'notes' || activeTab === 'audit') && (
                <div className="tpl-card">
                  <h2 className="tpl-serif" style={{ fontSize: '22px', fontWeight: 400, margin: '0 0 20px 0', borderBottom: '1px solid #111111', paddingBottom: 10 }}>
                    {activeTab.toUpperCase()} Stream
                  </h2>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {activities.map((act, i) => (
                      <div key={i} style={{ padding: '14px', background: '#F5F0EA', border: '1px solid #E5DDD5', borderRadius: 4, display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                        <span style={{ fontFamily: 'monospace', color: '#777777' }}>{safeFormatDateTime(act.created_at)}</span>
                        <strong style={{ color: '#111111' }}>{act.action || 'ACTIVITY'}</strong>
                        <span style={{ color: '#444444' }}>{act.details || 'Operation recorded'}</span>
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
