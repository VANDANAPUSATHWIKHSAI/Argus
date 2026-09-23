import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import NotificationMenu from '../components/NotificationMenu';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase } from '../js/api';

const SeniorDashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [activeSummary, setActiveSummary] = useState(null);
  const [activeCaseDetails, setActiveCaseDetails] = useState(null);
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

  return (
    <>
      <header className="topbar" style={{ justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', padding: '16px 40px', background: 'var(--bg-app)' }}>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
            Senior Analyst Workspace
          </div>
          <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Review and Validate Case Findings</div>
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
                <span>{activeSummary?.name || 'Malware Infection'}</span>
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
              "Windows endpoint shows indicators of malware execution and possible persistence via registry modifications. Review findings to validate the intrusion timeline."
            </p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', marginBottom: '24px' }}>
          
          {/* AI Findings Preview */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <div>
                <h2 style={{ margin: '0 0 4px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>AI Findings</h2>
                <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>6 Findings detected</div>
              </div>
              <div style={{ display: 'flex', gap: '16px', fontSize: '14px', fontWeight: 600 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ef4444' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444' }}></div> 2 High</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f59e0b' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b' }}></div> 3 Medium</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#3b82f6' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#3b82f6' }}></div> 1 Low</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '24px' }}>
              
              <div style={{ padding: '16px', background: 'var(--bg-app)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>F1 &mdash; Suspicious Outbound Connection</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg> 1
                    </span>
                  </div>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  <span style={{ color: '#ef4444', fontWeight: 600 }}>High</span> &middot; 92% confidence
                </div>
              </div>

              <div style={{ padding: '16px', background: 'var(--bg-app)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>F2 &mdash; Registry Persistence</div>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  <span style={{ color: '#ef4444', fontWeight: 600 }}>High</span> &middot; 88% confidence
                </div>
              </div>

              <div style={{ padding: '16px', background: 'var(--bg-app)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>F3 &mdash; Suspicious Executable</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg> 2
                    </span>
                  </div>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  <span style={{ color: '#f59e0b', fontWeight: 600 }}>Medium</span> &middot; 76% confidence
                </div>
              </div>

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
              <button style={{ width: '100%', padding: '10px', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', borderRadius: '6px', fontWeight: 600, cursor: 'pointer' }}>
                View Coverage
              </button>
            </div>

            {/* Timeline Preview */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px', flexGrow: 1 }}>
              <h2 style={{ margin: '0 0 24px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Recent Timeline</h2>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '24px' }}>
                <div style={{ display: 'flex', gap: '12px', fontSize: '13px' }}>
                  <div style={{ color: 'var(--text-muted)', width: '40px', fontWeight: 600 }}>14:23</div>
                  <div style={{ color: 'var(--text-main)' }}>Suspicious outbound connection</div>
                </div>
                <div style={{ display: 'flex', gap: '12px', fontSize: '13px' }}>
                  <div style={{ color: 'var(--text-muted)', width: '40px', fontWeight: 600 }}>14:24</div>
                  <div style={{ color: 'var(--text-main)' }}>Process created (malware.exe)</div>
                </div>
                <div style={{ display: 'flex', gap: '12px', fontSize: '13px' }}>
                  <div style={{ color: 'var(--text-muted)', width: '40px', fontWeight: 600 }}>14:25</div>
                  <div style={{ color: 'var(--text-main)' }}>Registry persistence detected</div>
                </div>
                <div style={{ display: 'flex', gap: '12px', fontSize: '13px' }}>
                  <div style={{ color: 'var(--text-muted)', width: '40px', fontWeight: 600 }}>14:31</div>
                  <div style={{ color: 'var(--text-main)' }}>Multiple failed logins</div>
                </div>
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
