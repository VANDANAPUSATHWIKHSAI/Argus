import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import NotificationMenu from '../components/NotificationMenu';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings } from '../js/api';
import { safeFormatTime } from '../js/dateUtils';

const SeniorDashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [activeSummary, setActiveSummary] = useState(null);
  const [activeCaseDetails, setActiveCaseDetails] = useState(null);
  const [findings, setFindings] = useState([]);
  const [evidenceStats, setEvidenceStats] = useState({ available: 0, partial: 0, missing: 0 });
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');
  
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const userName = currentUser?.name || 'Senior Analyst';

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  async function loadData() {
    setLoading(true);
    try {
      const res = await fetchCases();
      const caseList = res.data || [];
      let targetCaseId = localStorage.getItem('active_case_id');
      
      if (!targetCaseId && caseList.length > 0) {
        targetCaseId = caseList[0].case_id;
        localStorage.setItem('active_case_id', targetCaseId);
      }
      
      if (targetCaseId) {
        const currentCase = caseList.find(c => c.case_id === targetCaseId);
        if (currentCase) {
          setActiveCaseDetails(currentCase);
        }
        const summaryData = await fetchCaseSummary(targetCaseId).catch(() => null);
        if (summaryData) {
          setActiveSummary(summaryData);
        }

        const findingsRes = await fetchFindings(targetCaseId).catch(() => []);
        const findingsList = Array.isArray(findingsRes) ? findingsRes : (findingsRes.data || []);
        setFindings(findingsList);

        const evRes = await fetchEvidenceForCase(targetCaseId).catch(() => ({ data: [] }));
        const evList = evRes.data || [];
        let available = 0, partial = 0, missing = 0;
        evList.forEach(e => {
            const st = (e.status || '').toLowerCase();
            if (st === 'completed' || st === 'processed' || st === 'analyzed') available++;
            else if (st === 'processing' || st === 'pending' || st === 'uploaded') partial++;
            else missing++;
        });
        setEvidenceStats({ available, partial, missing });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadData(); }, []);

  const criticalHighCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high' || (f.severity || '').toLowerCase() === 'critical').length;
  const mediumCount = findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const lowCount = findings.filter(f => (f.severity || '').toLowerCase() === 'low' || (f.severity || '').toLowerCase() === 'info').length;

  return (
    <>
      <header className="topbar" style={{ justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', padding: '16px 40px', background: 'var(--bg-app)' }}>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: '20px', fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            Welcome, {userName}
          </div>
          <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Senior Analyst Workspace &middot; Review and Validate Case Findings</div>
        </div>
        <div className="topbar-actions">
          <button className="icon-btn" onClick={toggleTheme} title="Toggle Theme" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {theme === 'dark' ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            )}
          </button>
          <NotificationMenu />
          <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="avatar" style={{ background: 'var(--blue-light)', color: 'var(--blue)', fontWeight: 600 }}>SA</div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
              <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-main)' }}>{userName}</span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Senior Analyst</span>
            </div>
          </div>
        </div>
      </header>
      
      <div className="dashboard-scroll" style={{ padding: '32px 40px', background: 'var(--bg-body)' }}>
        
        {/* Case Header */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '12px', padding: '32px', border: '1px solid var(--border-subtle)', marginBottom: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
            <div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '8px' }}>
                <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>Case #{activeSummary?.case_id || 'ARG-2026-001'}</h1>
                <span style={{ background: '#fef3c7', color: '#b45309', padding: '4px 12px', borderRadius: '12px', fontSize: '12px', fontWeight: 600 }}>Ready for Review</span>
              </div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', fontSize: '16px', color: 'var(--text-muted)' }}>
                <span>{activeSummary?.name || activeCaseDetails?.name || 'Investigation Case'}</span>
                <span style={{ color: 'var(--border-strong)' }}>|</span>
                <span style={{ fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                  Analyst: <strong style={{ color: 'var(--text-main)' }}>{activeCaseDetails?.analyst_name || activeCaseDetails?.analyst_id || 'Unassigned'}</strong>
                </span>
              </div>
            </div>
          </div>
          
          <div style={{ background: 'var(--bg-app)', padding: '16px 24px', borderRadius: '8px', borderLeft: '4px solid var(--blue)' }}>
            <p style={{ margin: 0, fontSize: '15px', color: 'var(--text-main)', lineHeight: '1.5' }}>
              "{activeSummary?.description || activeCaseDetails?.description || 'No specific narrative description provided for this case yet. Review individual findings below to validate the intrusion timeline.'}"
            </p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', marginBottom: '24px' }}>
          
          {/* AI Findings Preview */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <div>
                <h2 style={{ margin: '0 0 4px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>AI Findings</h2>
                <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>{findings.length} Findings detected</div>
              </div>
              <div style={{ display: 'flex', gap: '16px', fontSize: '14px', fontWeight: 600 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ef4444' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444' }}></div> {criticalHighCount} High/Critical</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f59e0b' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b' }}></div> {mediumCount} Medium</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#3b82f6' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#3b82f6' }}></div> {lowCount} Low</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '24px' }}>
              {loading ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px' }}>
                  Loading findings...
                </div>
              ) : findings.length > 0 ? (
                [...findings]
                  .sort((a, b) => {
                    const sevMap = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                    const aSev = sevMap[(a.severity || '').toLowerCase()] || 0;
                    const bSev = sevMap[(b.severity || '').toLowerCase()] || 0;
                    if (bSev !== aSev) return bSev - aSev;
                    const aConf = (a.confidence > 1 ? a.confidence : a.confidence * 100) || 0;
                    const bConf = (b.confidence > 1 ? b.confidence : b.confidence * 100) || 0;
                    return bConf - aConf;
                  })
                  .slice(0, 4)
                  .map((f, idx) => {
                    const sev = (f.severity || 'medium').toLowerCase();
                    const sevColor = sev === 'high' || sev === 'critical' ? '#ef4444' : (sev === 'medium' ? '#f59e0b' : '#3b82f6');
                    const conf = Math.round((f.confidence > 1 ? f.confidence : f.confidence * 100) || 0);
                    const fKey = f.finding_id || f.id || `f-${idx}`;
                    return (
                      <div key={fKey} style={{ padding: '16px', background: 'var(--bg-app)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>{fKey} &mdash; {f.fact || 'Finding details recorded'}</div>
                        </div>
                        <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                          <span style={{ color: sevColor, fontWeight: 600, textTransform: 'capitalize' }}>{sev}</span> &middot; {conf}% confidence
                        </div>
                      </div>
                    );
                  })
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px' }}>
                  No AI findings available for this case yet.
                </div>
              )}
            </div>

            <button onClick={() => navigate('/findings')} style={{ width: '100%', padding: '12px', background: 'none', border: '1px solid var(--blue)', color: 'var(--blue)', borderRadius: '6px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s' }}>
              View All Findings
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            
            {/* Evidence Coverage */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px' }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Evidence Coverage</h2>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '14px', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '24px' }}>
                <span style={{ color: '#22c55e' }}>{evidenceStats.available} Available</span>
                <span style={{ color: '#f59e0b' }}>{evidenceStats.partial} Partial</span>
                <span style={{ color: '#ef4444' }}>{evidenceStats.missing} Missing</span>
              </div>
              <button onClick={() => navigate('/evidence-coverage')} style={{ width: '100%', padding: '10px', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', borderRadius: '6px', fontWeight: 600, cursor: 'pointer' }}>
                View Coverage
              </button>
            </div>

            {/* Timeline Preview */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px', flexGrow: 1 }}>
              <h2 style={{ margin: '0 0 4px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Recent Timeline</h2>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '20px' }}>Recorded finding events</div>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
                {loading ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Loading timeline events...</div>
                ) : findings.length > 0 ? (
                  findings.slice(0, 4).map((f, idx) => {
                    const rawTime = f.created_at || f.timestamp;
                    const timeStr = safeFormatTime(rawTime, '--:--');
                    const fKey = f.finding_id || f.id || `tl-${idx}`;
                    return (
                      <div key={fKey} style={{ display: 'flex', gap: '12px', fontSize: '13px' }}>
                        <div style={{ color: 'var(--text-muted)', width: '50px', fontWeight: 600, flexShrink: 0 }}>{timeStr}</div>
                        <div style={{ color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.fact || fKey}</div>
                      </div>
                    );
                  })
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No timeline events recorded yet.</div>
                )}
              </div>

              <button onClick={() => navigate('/timeline')} style={{ width: '100%', padding: '10px', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', borderRadius: '6px', fontWeight: 600, cursor: 'pointer' }}>
                View Full Timeline
              </button>
            </div>

          </div>
        </div>

      </div>
    </>
  );
};

export default SeniorDashboard;

