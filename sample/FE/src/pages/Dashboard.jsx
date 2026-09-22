import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import Sidebar from '../components/Sidebar';
import ProfileModal from '../components/ProfileModal';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import AdminDashboard from './AdminDashboard';
import { fetchCases, fetchCaseSummary, API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';

const Dashboard = () => {
  const [cases, setCases] = useState([]);
  const navigate = useNavigate();
  const [activeSummary, setActiveSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const isAdmin = currentUser?.role === 'admin';
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [creating, setCreating] = useState(false);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };


  async function loadDashboard() {
    setLoading(true);
    try {
      const res = await fetchCases();
      const caseList = res.data || [];
      setCases(caseList);
      // Synchronize global active case for all analysts
      const globalActive = caseList.find(c => c.status === 'open');
      if (globalActive) {
        localStorage.setItem('active_case_id', globalActive.case_id);
        if (globalActive.name) localStorage.setItem('active_case_name', globalActive.name);
      } else {
        // Clear it if no open cases exist globally
        localStorage.removeItem('active_case_id');
        localStorage.removeItem('active_case_name');
        localStorage.removeItem('active_case_desc');
      }

      const activeCaseId = localStorage.getItem('active_case_id');
      if (activeCaseId) {
        const summaryData = await fetchCaseSummary(activeCaseId).catch(() => null);
        if (summaryData) {
          setActiveSummary(summaryData);
          if (summaryData.name) {
            localStorage.setItem('active_case_name', summaryData.name);
          }
          if (summaryData.description) {
            localStorage.setItem('active_case_desc', summaryData.description);
          }
        } else {
          setActiveSummary(null);
        }
      } else {
        setActiveSummary(null);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  // Re-initialize graph when dashboard is loaded
  useEffect(() => {
    if (!loading && cases.length > 0) {
      setTimeout(() => {
        if (window.argusApp && typeof window.argusApp.init === 'function') {
          // ensure SVG container exists
          if (document.getElementById('graph-svg')) {
            window.argusApp.init();
          }
        }
      }, 100);
    }
  }, [loading, cases]);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { loadDashboard(); }, []);

  async function handleCreateCase(e) {
    e.preventDefault();
    if (!newCaseName.trim()) return;

    if (cases.some(c => c.name && c.name.toLowerCase() === newCaseName.trim().toLowerCase())) {
      setCustomAlert({ isOpen: true, title: 'Notice', message: 'This case name is already in use. Please choose another.', type: 'warning' });
      return;
    }

    setCreating(true);
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/cases/`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'X-Tenant-ID': DEFAULT_TENANT_ID,
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify({ name: newCaseName, description: newCaseDesc, analyst: 'Analyst' }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      const createdId = data.case_id || data.id;
      localStorage.setItem('active_case_id', createdId);
      localStorage.setItem('active_case_name', newCaseName);
      localStorage.setItem('active_case_desc', newCaseDesc);

      setShowCreateModal(false);
      setNewCaseName('');
      setNewCaseDesc('');
      await loadDashboard();
    } catch (err) {
      setCustomAlert({ isOpen: true, title: 'Error', message: 'Failed to create case: ' + err.message, type: 'warning' });
    } finally {
      setCreating(false);
    }
  }

  const handleOpenCreateCase = () => {
    const activeCaseId = localStorage.getItem('active_case_id');
    const activeCaseName = localStorage.getItem('active_case_name');
    if (activeCaseId && activeCaseId !== '00000000-0000-0000-0000-000000000001' && activeCaseName && activeCaseName !== 'Case 00000000') {
      setCustomAlert({ isOpen: true, title: 'Notice', message: `An active case "${activeCaseName}" is currently open. You cannot create a new case until the active case is closed.`, type: 'warning' });
      return;
    }
    setShowCreateModal(true);
  };

  const handleCloseCase = async () => {
    const activeCaseName = localStorage.getItem('active_case_name') || 'Current case';
    const activeCaseId = localStorage.getItem('active_case_id');
    if (!activeCaseId && !localStorage.getItem('active_case_name')) {
      setCustomAlert({ isOpen: true, title: 'Notice', message: "There is no active case currently open.", type: 'warning' });
      return;
    }
    
    try {
      if (activeCaseId) {
        await fetch(`${API_BASE_URL}/cases/${activeCaseId}/close`, {
          method: 'PUT',
          headers: { 'X-Tenant-ID': DEFAULT_TENANT_ID }
        });
      }
    } catch (e) {
      console.error("Failed to close case globally:", e);
    }

    localStorage.removeItem('active_case_id');
    localStorage.removeItem('active_case_name');
    localStorage.removeItem('active_case_desc');
    setCustomAlert({
       isOpen: true,
       title: 'Success',
       message: `${activeCaseName} has been closed successfully.`,
       type: 'success',
       onClose: () => window.location.reload()
    });
  };

  const criticalHigh = (activeSummary?.severity_breakdown?.critical ?? 0) + (activeSummary?.severity_breakdown?.high ?? 0);

  const timelineSteps = ['Evidence\nCollection', 'Analysis', 'Correlation', 'Findings', 'Report'];
  let completedSteps = 0;
  let activeStep = -1;
  
  if (activeSummary) {
    const evidenceCount = (activeSummary.total_evidence_files || activeSummary.evidence_count || 0);
    const findingsCount  = (activeSummary.findings_count || 0);

    if (findingsCount > 0) {
      // Findings generated → Evidence + Analysis + Correlation + Findings all done
      completedSteps = 4;
      activeStep = 4;
    } else if ((activeSummary.total_artifacts || 0) > 0) {
      // Artifacts extracted → Analysis is COMPLETED (blue), Correlation is ACTIVE
      completedSteps = 2;
      activeStep = 2;
    } else if (evidenceCount > 0) {
      // Evidence uploaded → Evidence Collection is COMPLETED (blue), Analysis is ACTIVE
      completedSteps = 1;
      activeStep = 1;
    } else {
      // Case created but no evidence yet → Evidence Collection is the ACTIVE step
      completedSteps = 0;
      activeStep = 0;
    }
  }

  const stepRatio = Math.max(0, activeStep) / (timelineSteps.length - 1);
  const activeLineWidth = `calc((100% - 80px) * ${stepRatio})`;
  const progressBarWidth = `${(completedSteps / timelineSteps.length) * 100}%`;

  return (
    <>
      <div id="app-shell">
        <AlertModal 
          isOpen={customAlert.isOpen} 
          title={customAlert.title} 
          message={customAlert.message} 
          type={customAlert.type} 
          onClose={closeAlert} 
        />

        {/* ── SIDEBAR ── */}
        <Sidebar />

        {/* ── MAIN CONTENT ── */}
        <main className="main-content">
          {isAdmin ? (
            <>
              {/* ADMIN TOPBAR */}
              <header className="topbar" style={{ justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', padding: '16px 40px' }}>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <div style={{ fontSize: '20px', fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '4px' }}>Welcome, Admin</div>
                  <div style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Manage people, cases, and ensure compliance.</div>
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
                  <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)} style={{ cursor: 'pointer' }}>
                    <div className="avatar" style={{ background: '#4b5563' }}>A</div>
                    <span style={{ fontWeight: 500 }}>Admin</span>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    {showUserDropdown && (
                      <div className="user-dropdown" style={{ display: 'block' }}>
                        <div className="user-dropdown-header">
                          <div className="ud-name">Admin</div>
                          <div className="ud-role">System Administrator</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </header>
              <div className="dashboard-scroll">
                <AdminDashboard />
              </div>
            </>
          ) : (
            <>
              {/* TOPBAR — exact match to HTML */}
              <header className="topbar">
            <div className="search-container">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: '8px' }}><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
              <input type="text" placeholder="Search cases, evidence, or findings..." />
              <span className="search-shortcut">⌘ K</span>
            </div>

            <div className="topbar-actions">
              {/* Live Analysis badge */}
              {localStorage.getItem('active_case_id') && (
                <div className="badge-live">
                  <div className="live-dot"></div>
                  Live Analysis
                </div>
              )}

              {/* Theme Toggle */}
              <button className="icon-btn" onClick={toggleTheme} title="Toggle Theme" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {theme === 'dark' ? (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                ) : (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                )}
              </button>

              {/* Bell */}
              <NotificationMenu />

              {/* User profile */}
              <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
                <div className="avatar">A</div>
                <span style={{ fontWeight: 500 }}>Analyst</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                {showUserDropdown && (
                  <div className="user-dropdown" style={{ display: 'block' }}>
                    <div className="user-dropdown-header">
                      <div className="ud-name">Analyst</div>
                      <div className="ud-role">Digital Forensics Investigator</div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </header>

          {/* DASHBOARD SCROLL */}
          <div className="dashboard-scroll">

            {loading && (
              <div style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>Loading...</div>
            )}

            {!loading && (
              <>
                {/* EMPTY STATE — uses standard CSS variables so it switches properly */}
                {!activeSummary && (
                  <div id="dashboard-empty-state" style={{ display: 'block', textAlign: 'center', padding: '100px 20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', marginBottom: '24px', border: '1px dashed var(--border-strong)' }}>
                    <div style={{ width: '64px', height: '64px', background: 'var(--blue-light)', color: 'var(--blue)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                    </div>
                    <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>No Active Case Selected</h2>
                    <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>Select an existing case or create a new one to begin your investigation and view insights.</p>
                  </div>
                )}

                {/* ACTIVE CONTENT */}
                {activeSummary && (
                  <div id="dashboard-active-content">

                    {/* Case Header */}
                    <div className="header-card" style={{ flexShrink: 0 }}>
                      <div className="header-info-wrap">
                        <div className="header-id">
                          <p>Active Case</p>
                          <h1 id="dashboard-case-name">{activeSummary.name || localStorage.getItem('active_case_name') || 'Unnamed Case'}</h1>
                        </div>
                        <div className="header-details">
                          <h2 id="dashboard-case-id" style={{ fontSize: '14px', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{activeSummary.case_id}</h2>
                          <p id="dashboard-case-desc">{activeSummary.description || localStorage.getItem('active_case_desc') || 'No description provided.'}</p>
                          <div className="header-meta">
                            <div className="badge-danger">
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                              {criticalHigh > 0 ? 'High Risk' : 'Under Review'}
                            </div>
                            <div className="meta-item">
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                              <div>
                                <span>Last Updated</span>
                                <strong>{activeSummary.latest_timestamp ? new Date(activeSummary.latest_timestamp).toLocaleString() : '—'}</strong>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="header-quote">
                        <p>"From digital traces to real answers."</p>
                        <span>— ARGUS</span>
                      </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="stats-grid" style={{ flexShrink: 0 }}>
                      <div className="stat-card">
                        <div className="stat-icon" style={{ backgroundColor: 'var(--blue-light)', color: 'var(--blue)' }}>
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                        </div>
                        <div className="stat-info">
                          <h2>{activeSummary.total_evidence_files ?? 0}</h2>
                          <h4>Evidence Files</h4>
                          <p>Uploaded to this case</p>
                        </div>
                        <div className="trend-badge">Total</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-icon" style={{ backgroundColor: 'var(--purple-light)', color: 'var(--purple)' }}>
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                        </div>
                        <div className="stat-info">
                          <h2>{activeSummary.total_artifacts ?? 0}</h2>
                          <h4>Artifacts</h4>
                          <p>Parsed from evidence</p>
                        </div>
                        <div className="trend-badge">↑ New</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-icon" style={{ backgroundColor: 'var(--cyan-light)', color: 'var(--cyan)' }}>
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                        </div>
                        <div className="stat-info">
                          <h2>{activeSummary.total_findings ?? 0}</h2>
                          <h4>Total Findings</h4>
                          <p>Across all layers</p>
                        </div>
                        <div className="trend-badge">↑ +{activeSummary.total_findings ?? 0}</div>
                      </div>
                      <div className="stat-card">
                        <div className="stat-icon" style={{ backgroundColor: 'var(--red-light)', color: 'var(--red)' }}>
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                        </div>
                        <div className="stat-info">
                          <h2>{criticalHigh}</h2>
                          <h4>Critical / High</h4>
                          <p>Require analyst review</p>
                        </div>
                        <div className="trend-badge trend-danger">↑ Risk</div>
                      </div>
                    </div>

                    {/* Interactive Investigation Map */}
                    <div className="main-grid" id="main-grid" style={{ flexShrink: 0 }}>
                      <div className="panel-card map-panel">
                        <div className="panel-header">
                          <div>
                            <h3>Investigation Map</h3>
                            <p>Explore the relationships between evidence, users, devices, and network activity.</p>
                          </div>
                          <div className="panel-actions">
                            <button className="btn btn-primary" onClick={() => setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Graph View is currently active.', type: 'info'})}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                              Graph View
                            </button>
                            <button className="btn btn-outline" onClick={() => setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Timeline View is not yet implemented in this prototype.', type: 'info'})}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                              Timeline View
                            </button>
                            <button className="btn-icon" onClick={() => setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Fullscreen mode is not yet implemented in this prototype.', type: 'info'})}>
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path></svg>
                            </button>
                          </div>
                        </div>
                        <div className="graph-container" id="graph-container">
                          <div className="graph-legend">
                            <div className="legend-item"><div className="legend-dot legend-evidence"></div> Evidence</div>
                            <div className="legend-item"><div className="legend-dot legend-device"></div> Device</div>
                            <div className="legend-item"><div className="legend-dot legend-user"></div> User</div>
                            <div className="legend-item"><div className="legend-dot legend-process"></div> Process</div>
                            <div className="legend-item"><div className="legend-dot legend-network"></div> Network</div>
                            <div className="legend-item"><div className="legend-dot legend-finding"></div> Finding</div>
                          </div>
                          <div className="graph-controls">
                            <button className="btn btn-icon" id="btn-zoom-in"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>
                            <button className="btn btn-icon" id="btn-zoom-out"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"></line></svg></button>
                            <button className="btn btn-outline" id="btn-fit-view" style={{ background: 'var(--bg-card)' }}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: '6px' }}><polyline points="8 3 3 3 3 8"></polyline><polyline points="16 3 21 3 21 8"></polyline><polyline points="8 21 3 21 3 16"></polyline><polyline points="16 21 21 21 21 16"></polyline></svg><span className="fit-view-label"> Fit View</span></button>
                          </div>
                          <svg className="graph-svg" id="graph-svg"></svg>
                          <div className="graph-html" id="graph-html"></div>
                        </div>
                      </div>

                      {/* Node Details Panel */}
                      <aside className="details-panel" id="details-panel">
                        <div className="panel-header">
                          <h3>Node Details</h3>
                          <div className="panel-actions">
                            <button className="btn-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
                          </div>
                        </div>
                        <div className="details-content" id="details-content">
                          <div className="details-header">
                            <div className="details-icon" id="details-icon"></div>
                            <div className="details-title-wrap">
                              <h4 id="details-title">--</h4>
                              <p id="details-subtitle">--</p>
                            </div>
                            <div id="details-badge"></div>
                          </div>
                          <div className="details-tabs">
                            <div className="tab active">Overview</div>
                            <div className="tab">Related Items (8)</div>
                            <div className="tab">Connections (6)</div>
                          </div>
                          <p className="details-desc" id="details-desc">--</p>
                          <div className="details-list" id="details-list"></div>
                          <div className="risk-score-wrap" id="details-risk-wrap">
                            <div className="risk-header">
                              <span>Risk Score</span>
                              <strong id="details-risk-val">0 / 100</strong>
                            </div>
                            <div className="risk-bar-bg">
                              <div className="risk-bar-fill" id="details-risk-fill" style={{ width: '0%', backgroundColor: 'var(--text-light)' }}></div>
                            </div>
                          </div>
                          <button className="btn btn-outline" style={{ width: '100%', justifyContent: 'center', color: 'var(--blue)', borderColor: 'var(--blue-light)', marginTop: 'auto' }}>
                            View in Timeline →
                          </button>
                        </div>
                      </aside>
                    </div>

                    {/* Investigation Progress */}
                    <div className="timeline-card" style={{ flexShrink: 0 }}>
                      <div className="timeline-header">
                        <div>
                          <h3>Investigation Progress</h3>
                          <p>Track the lifecycle of the active case.</p>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)' }}>{completedSteps} of {timelineSteps.length} stages complete</span>
                          <div style={{ width: '120px', height: '5px', backgroundColor: 'var(--border-strong)', borderRadius: '99px', overflow: 'hidden' }}>
                            <div style={{ width: progressBarWidth, height: '100%', background: 'var(--blue)', borderRadius: '99px', transition: 'width 0.6s ease' }}></div>
                          </div>
                        </div>
                      </div>
                      {/* Single-track timeline — no double lines */}
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', position: 'relative', padding: '8px 0' }}>
                        {timelineSteps.map((label, i) => {
                          const isDone    = i < completedSteps;
                          const isActive  = i === activeStep;
                          const isPending = !isDone && !isActive;
                          const isLast    = i === timelineSteps.length - 1;

                          return (
                            <React.Fragment key={i}>
                              {/* Step node */}
                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', zIndex: 2 }}>
                                <div style={{
                                  width: '32px', height: '32px', borderRadius: '50%',
                                  background: isDone ? 'var(--blue)' : isActive ? 'var(--blue)' : 'var(--bg-app)',
                                  border: isPending ? '2.5px solid var(--border-strong)' : '2.5px solid var(--blue)',
                                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                                  boxShadow: isActive ? '0 0 0 5px rgba(59,130,246,0.18)' : 'none',
                                  animation: isActive ? 'stepPulse 2s ease-in-out infinite' : 'none',
                                  transition: 'all 0.3s ease', flexShrink: 0
                                }}>
                                  {isDone && (
                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                                      <polyline points="20 6 9 17 4 12" />
                                    </svg>
                                  )}
                                  {isActive && (
                                    <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'white' }} />
                                  )}
                                </div>
                                <span style={{
                                  fontSize: '12px', fontWeight: isActive ? 700 : isDone ? 600 : 500,
                                  color: isActive ? 'var(--blue)' : isDone ? 'var(--text-main)' : 'var(--text-muted)',
                                  textAlign: 'center', lineHeight: '1.3', whiteSpace: 'pre-line'
                                }}>{label.replace('\n', '\n')}</span>
                              </div>
                              {/* Connector line between steps */}
                              {!isLast && (
                                <div style={{
                                  flex: 1, height: '2.5px', marginTop: '15px', borderRadius: '99px',
                                  background: i < completedSteps
                                    ? 'var(--blue)'
                                    : 'var(--border-strong)',
                                  transition: 'background 0.5s ease'
                                }} />
                              )}
                            </React.Fragment>
                          );
                        })}
                      </div>
                    </div>

                  </div>
                )}
              </>
            )}
          </div>
            </>
          )}
        </main>
      </div>

      {/* CREATE CASE MODAL — matches HTML exactly */}
      {showCreateModal && (
        <div style={{ display: 'flex', position: 'fixed', inset: 0, background: 'transparent', zIndex: 100, alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ background: 'var(--bg-card)', padding: '30px', borderRadius: 'var(--radius-lg)', width: '400px', border: '1px solid var(--border-strong)', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-main)' }}>Create New Case</h2>
              <button onClick={() => setShowCreateModal(false)} style={{ background: 'none', border: '1px solid var(--border-strong)', borderRadius: '8px', width: '32px', height: '32px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: 'var(--text-muted)' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleCreateCase}>
              <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Case Name</label>
                  <input
                    type="text"
                    value={newCaseName}
                    onChange={e => setNewCaseName(e.target.value)}
                    placeholder="e.g. Ransomware Incident - Alpha Corp"
                    required
                    style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: '14px', outline: 'none', boxSizing: 'border-box', background: 'var(--bg-app)', color: 'var(--text-main)' }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Description</label>
                  <textarea
                    value={newCaseDesc}
                    onChange={e => setNewCaseDesc(e.target.value)}
                    rows={3}
                    placeholder="Brief details about the investigation..."
                    style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: '14px', outline: 'none', resize: 'none', boxSizing: 'border-box', background: 'var(--bg-app)', color: 'var(--text-main)' }}
                  />
                </div>
              </div>
              <div style={{ padding: '16px 24px', background: 'var(--bg-card-modal)', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button type="button" onClick={() => setShowCreateModal(false)} style={{ padding: '8px 16px', borderRadius: 'var(--radius-full)', border: '1px solid var(--border-strong)', background: 'transparent', color: 'var(--text-main)', fontWeight: 600, cursor: 'pointer', fontSize: '13px' }}>Cancel</button>
                <button type="submit" disabled={creating} style={{ padding: '8px 16px', borderRadius: 'var(--radius-full)', border: 'none', background: 'var(--blue)', color: '#fff', fontWeight: 600, cursor: creating ? 'not-allowed' : 'pointer', opacity: creating ? 0.7 : 1, fontSize: '13px' }}>
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <ProfileModal isOpen={showProfileModal} onClose={() => setShowProfileModal(false)} />
    </>
  );
};

export default Dashboard;