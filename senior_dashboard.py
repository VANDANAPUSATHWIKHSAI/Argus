content = """import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import NotificationMenu from '../components/NotificationMenu';
import { fetchCases, fetchCaseSummary, API_BASE_URL } from '../js/api';

const SeniorDashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [activeSummary, setActiveSummary] = useState(null);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');
  
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const userName = currentUser?.name || 'Priya Sharma';

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  async function loadData() {
    setLoading(true);
    try {
      const activeCaseId = localStorage.getItem('active_case_id');
      if (activeCaseId) {
        const summaryData = await fetchCaseSummary(activeCaseId).catch(() => null);
        if (summaryData) {
          setActiveSummary(summaryData);
        }
      } else {
        // Find a case if none active
        const res = await fetchCases();
        const caseList = res.data || [];
        if (caseList.length > 0) {
          localStorage.setItem('active_case_id', caseList[0].case_id);
          const summaryData = await fetchCaseSummary(caseList[0].case_id).catch(() => null);
          setActiveSummary(summaryData);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadData(); }, []);

  const formatDate = (dateStr) => {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return `${d.getDate()} ${d.toLocaleString('default', { month: 'short' })} ${d.getFullYear()}, ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
  };

  const now = new Date();
  const todayStr = `${now.toLocaleString('default', { weekday: 'short' })}, ${now.getDate()} ${now.toLocaleString('default', { month: 'short' })} ${now.getFullYear()}  ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')} ${now.getHours() >= 12 ? 'PM' : 'AM'}`;

  return (
    <>
      <header className="topbar" style={{ justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', padding: '16px 40px', background: 'var(--bg-app)' }}>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
            Senior Analyst
          </div>
          <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Review. Validate. Ensure Accuracy.</div>
        </div>
        <div className="topbar-actions">
          <NotificationMenu />
          <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className="avatar" style={{ background: 'var(--blue-light)', color: 'var(--blue)', fontWeight: 600 }}>SA</div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
              <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-main)' }}>{userName}</span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Senior Analyst <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ display: 'inline', marginLeft: 2 }}><polyline points="6 9 12 15 18 9"></polyline></svg></span>
            </div>
            {showUserDropdown && (
              <div className="user-dropdown" style={{ display: 'block' }}>
                <div className="user-dropdown-header">
                  <div className="ud-name">{userName}</div>
                  <div className="ud-role">Senior Analyst</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>
      
      <div className="dashboard-scroll" style={{ padding: '32px 40px', background: 'var(--bg-body, #f8f9fa)' }}>
        
        {/* Welcome Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '24px' }}>
          <div>
            <h1 style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-main)', margin: '0 0 8px 0' }}>Welcome, {userName.split(' ')[0]}</h1>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '15px' }}>Review the current investigation and validate the final report.</p>
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '13px', fontWeight: 500 }}>
            {todayStr}
          </div>
        </div>

        {/* Current Case Block */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '12px', padding: '32px', border: '1px solid var(--border-subtle)', boxShadow: '0 4px 20px rgba(0,0,0,0.03)', marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'inline-block', background: 'var(--blue-light)', color: 'var(--blue)', fontSize: '12px', fontWeight: 600, padding: '4px 12px', borderRadius: '4px', marginBottom: '16px' }}>Current Case</div>
            <h2 style={{ margin: '0 0 8px 0', fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>{activeSummary ? activeSummary.case_id : 'ARGUS_950'}</h2>
            <p style={{ margin: '0 0 24px 0', fontSize: '16px', color: 'var(--text-muted)' }}>{activeSummary ? activeSummary.name : 'Suspicious Endpoint Investigation'}</p>
            
            <div style={{ display: 'flex', gap: '48px' }}>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <div style={{ color: 'var(--text-muted)' }}><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg></div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Investigated by</div>
                  <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500 }}>Rahul Verma <span style={{ color: 'var(--text-muted)' }}>(Analyst)</span></div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <div style={{ color: 'var(--text-muted)' }}><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg></div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Submitted for Review</div>
                  <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500 }}>{activeSummary ? formatDate(activeSummary.latest_timestamp) : '22 Sep 2026, 19:45'}</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <div style={{ color: 'var(--text-muted)' }}><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Last Updated</div>
                  <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500 }}>{activeSummary ? formatDate(activeSummary.latest_timestamp) : '22 Sep 2026, 20:10'}</div>
                </div>
              </div>
            </div>
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '24px' }}>
            <div style={{ background: '#fef3c7', color: '#b45309', padding: '8px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              Pending Review
            </div>
            <div style={{ textAlign: 'right' }}>
              <button style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '14px 24px', borderRadius: '8px', fontSize: '15px', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                Open Case Review
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
              </button>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Continue reviewing the investigation</div>
            </div>
          </div>
        </div>

        {/* 3 Summary Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px', marginBottom: '24px' }}>
          <div style={{ background: 'var(--bg-card)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ background: '#fee2e2', color: '#ef4444', width: '48px', height: '48px', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)', lineHeight: '1.2' }}>{activeSummary ? activeSummary.total_findings : '14'}</div>
                <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>AI Findings</div>
              </div>
            </div>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--blue)' }}><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>
          
          <div style={{ background: 'var(--bg-card)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ background: '#dcfce7', color: '#22c55e', width: '48px', height: '48px', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)', lineHeight: '1.2' }}>126</div>
                <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Timeline Events</div>
              </div>
            </div>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--blue)' }}><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '24px', borderRadius: '12px', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ background: '#f3e8ff', color: '#a855f7', width: '48px', height: '48px', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)', lineHeight: '1.2' }}>Report</div>
                <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Ready for Review</div>
              </div>
            </div>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--blue)' }}><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>
        </div>

        {/* Bottom Split */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '24px', marginBottom: '24px' }}>
          
          {/* Recent Activity */}
          <div style={{ background: 'var(--bg-card)', padding: '32px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', margin: 0, color: 'var(--text-main)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                Recent Activity
              </h3>
              <a href="#" style={{ color: 'var(--blue)', fontSize: '14px', fontWeight: 600, textDecoration: 'none' }}>View All</a>
            </div>
            
            <div style={{ position: 'relative', marginLeft: '8px' }}>
              <div style={{ position: 'absolute', top: '10px', bottom: '10px', left: '4px', width: '2px', background: 'var(--border-subtle)' }}></div>
              
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '24px', marginBottom: '24px', position: 'relative' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6', marginTop: '6px', zIndex: 1 }}></div>
                <div style={{ width: '120px', fontSize: '14px', color: 'var(--text-muted)', paddingTop: '2px' }}>22 Sep 2026, 19:45</div>
                <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500, paddingTop: '2px' }}>Report submitted for review</div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '24px', marginBottom: '24px', position: 'relative' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6', marginTop: '6px', zIndex: 1 }}></div>
                <div style={{ width: '120px', fontSize: '14px', color: 'var(--text-muted)', paddingTop: '2px' }}>22 Sep 2026, 18:10</div>
                <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500, paddingTop: '2px' }}>Report generated</div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '24px', marginBottom: '24px', position: 'relative' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f59e0b', marginTop: '6px', zIndex: 1 }}></div>
                <div style={{ width: '120px', fontSize: '14px', color: 'var(--text-muted)', paddingTop: '2px' }}>22 Sep 2026, 17:35</div>
                <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500, paddingTop: '2px' }}>Findings finalized</div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '24px', position: 'relative' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6', marginTop: '6px', zIndex: 1 }}></div>
                <div style={{ width: '120px', fontSize: '14px', color: 'var(--text-muted)', paddingTop: '2px' }}>22 Sep 2026, 16:20</div>
                <div style={{ fontSize: '14px', color: 'var(--text-main)', fontWeight: 500, paddingTop: '2px' }}>Timeline completed</div>
              </div>

            </div>
          </div>

          {/* Quick Actions */}
          <div style={{ background: 'var(--bg-card)', padding: '32px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', margin: '0 0 24px 0', color: 'var(--text-main)' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
              Quick Actions
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <a href="#" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', textDecoration: 'none', color: 'var(--blue)', fontSize: '15px', fontWeight: 500 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '12px' }}><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)' }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> View AI Findings</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
              </a>
              <div style={{ height: '1px', background: 'var(--border-subtle)' }}></div>
              <a href="#" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', textDecoration: 'none', color: 'var(--blue)', fontSize: '15px', fontWeight: 500 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '12px' }}><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)' }}><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg> View Timeline</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
              </a>
              <div style={{ height: '1px', background: 'var(--border-subtle)' }}></div>
              <a href="#" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', textDecoration: 'none', color: 'var(--blue)', fontSize: '15px', fontWeight: 500 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)' }}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg> 
                  View Evidence Reference 
                  <span style={{ background: '#e0e7ff', color: '#4f46e5', fontSize: '11px', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, marginLeft: '8px' }}>Read Only</span>
                </span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
              </a>
              <div style={{ height: '1px', background: 'var(--border-subtle)' }}></div>
              <a href="#" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', textDecoration: 'none', color: 'var(--blue)', fontSize: '15px', fontWeight: 500 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '12px' }}><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)' }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> Open Report</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
              </a>
            </div>
          </div>
        </div>

        {/* Footer Quote */}
        <div style={{ background: 'var(--bg-card)', padding: '24px 32px', borderRadius: '12px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', color: 'var(--text-muted)' }}>
            <span style={{ fontSize: '32px', fontFamily: 'serif', lineHeight: '1', color: 'var(--blue)' }}>&ldquo;</span>
            <span style={{ fontSize: '14px', fontStyle: 'italic', fontWeight: 500 }}>A thorough review today ensures a more secure tomorrow.</span>
          </div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>
            &mdash; ARGUS
          </div>
        </div>

      </div>
    </>
  );
};

export default SeniorDashboard;
"""

with open("sample/FE/src/pages/SeniorDashboard.jsx", "w", encoding="utf-8") as f:
    f.write(content)
