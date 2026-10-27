import React, { useState, useEffect } from 'react';
import { useNavigate, Link, Navigate } from 'react-router-dom';
import '../css/style.css';
import Sidebar from '../components/Sidebar';
import ProfileModal from '../components/ProfileModal';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import AdminDashboard from './AdminDashboard';
import SeniorDashboard from './SeniorDashboard';
import AuditorDashboard from './AuditorDashboard';
import ForensicGraph from '../components/ForensicGraph';
import { fetchCases, fetchCaseSummary, fetchAgentResults, API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import { safeFormatDateTime } from '../js/dateUtils';

const Dashboard = () => {
  const [cases, setCases] = useState([]);
  const navigate = useNavigate();
  const [activeSummary, setActiveSummary] = useState(null);
  const [agentSummary, setAgentSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const isAdmin = currentUser?.role === 'admin';
  const isSeniorAnalyst = currentUser?.role === 'senior_analyst';
  const isAuditor = currentUser?.role === 'auditor';
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

      const storedActiveId = localStorage.getItem('active_case_id');
      let currentActiveId = storedActiveId;
      if (storedActiveId) {
        const stillOpen = caseList.find(c => c.case_id === storedActiveId && (c.status === 'open' || c.status === 'in_progress'));
        if (!stillOpen) {
          localStorage.removeItem('active_case_id');
          localStorage.removeItem('active_case_name');
          localStorage.removeItem('active_case_desc');
          currentActiveId = null;
        }
      }

      if (!currentActiveId && caseList.length > 0) {
        const fallback = caseList.find(c => (c.status === 'open' || c.status === 'in_progress') && c.case_id?.startsWith('ARGUS_')) ||
                         caseList.find(c => c.status === 'open' || c.status === 'in_progress');
        if (fallback) {
          localStorage.setItem('active_case_id', fallback.case_id);
          if (fallback.name) localStorage.setItem('active_case_name', fallback.name);
          if (fallback.description) localStorage.setItem('active_case_desc', fallback.description);
          currentActiveId = fallback.case_id;
        }
      }

      const activeCaseId = localStorage.getItem('active_case_id');
      if (activeCaseId) {
        const [summaryData, agentData] = await Promise.all([
          fetchCaseSummary(activeCaseId).catch(() => null),
          fetchAgentResults(activeCaseId).catch(() => null)
        ]);
        if (summaryData) {
          setActiveSummary(summaryData);
          if (summaryData.name) localStorage.setItem('active_case_name', summaryData.name);
          if (summaryData.description) localStorage.setItem('active_case_desc', summaryData.description);
        } else {
          setActiveSummary(null);
        }
        setAgentSummary(agentData);
      } else {
        setActiveSummary(null);
        setAgentSummary(null);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  const activeCaseId = localStorage.getItem('active_case_id');

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
        const token = localStorage.getItem('argus_token');
        await fetch(`${API_BASE_URL}/cases/${activeCaseId}/close`, {
          method: 'PUT',
          headers: { 
            'X-Tenant-ID': DEFAULT_TENANT_ID,
            'Authorization': `Bearer ${token}`
          }
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
    if (activeSummary.investigation_progress) {
      const prog = activeSummary.investigation_progress;
      const stageKeys = ['evidence_collection', 'analysis', 'correlation', 'findings', 'report'];
      const stages = stageKeys.map(k => (typeof prog[k] === 'object' ? prog[k]?.status : prog[k]));
      completedSteps = stages.filter(s => s === 'completed').length;
      const inProgIdx = stages.findIndex(s => s === 'in_progress');
      activeStep = inProgIdx !== -1 ? inProgIdx : (completedSteps >= 5 ? 4 : completedSteps);
    } else {
      const evidenceCount = (activeSummary.total_evidence_files || activeSummary.evidence_count || 0);
      const findingsCount = (activeSummary.total_findings ?? activeSummary.findings_count ?? 0);

      if (findingsCount > 0) {
        // Findings generated → Evidence, Analysis, Correlation completed
        completedSteps = 4;
        activeStep = 4;
      } else if ((activeSummary.total_artifacts || 0) > 0) {
        // Artifacts extracted → Analysis is completed, Correlation is active
        completedSteps = 2;
        activeStep = 2;
      } else if (evidenceCount > 0) {
        // Evidence uploaded → Evidence Collection completed, Analysis is active
        completedSteps = 1;
        activeStep = 1;
      } else {
        // Case created but no evidence yet
        completedSteps = 0;
        activeStep = 0;
      }
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
          {isAuditor ? (
            <AuditorDashboard />
          ) : isSeniorAnalyst ? (
            <SeniorDashboard />
          ) : isAdmin ? (
            <>
              {/* ADMIN TOPBAR */}
              <header className="glass-topbar-capsule topbar">
                <div className="glass-topbar-left">
                  <h2 className="glass-welcome-title">Welcome, {currentUser?.name || 'Admin'}</h2>
                  <p className="glass-welcome-sub">Manage people, cases, and ensure compliance.</p>
                </div>
                <div className="glass-topbar-right topbar-actions">
                  <button
                    id="btn-admin-topbar-create-case"
                    className="btn btn-primary"
                    onClick={() => {
                      const activeId = localStorage.getItem('active_case_id');
                      const activeName = localStorage.getItem('active_case_name');
                      if (activeId && activeName && activeId !== '00000000-0000-0000-0000-000000000001') {
                        setCustomAlert({
                          isOpen: true,
                          title: 'Notice',
                          message: `Active case "${activeName}" is currently open. You cannot create a new case until the active case is closed.`,
                          type: 'warning'
                        });
                        return;
                      }
                      setShowCreateModal(true);
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '7px 16px',
                      fontSize: '13px',
                      fontWeight: 600,
                      borderRadius: '10px',
                      background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
                      color: '#ffffff',
                      boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)',
                      border: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    Create Case
                  </button>
                  <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Theme">
                    {theme === 'dark' ? (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                    ) : (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                    )}
                  </button>
                  <NotificationMenu />
                  <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
                    <div className="glass-profile-avatar-dark avatar">A</div>
                    <span className="glass-profile-name">{currentUser?.name || 'Admin'}</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    {showUserDropdown && (
                      <div className="user-dropdown" style={{ display: 'block' }}>
                        <div className="user-dropdown-header">
                          <div className="ud-name">{currentUser?.name || 'Admin'}</div>
                          <div className="ud-role">System Administrator</div>
                        </div>
                        <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); navigate('/profile'); setShowUserDropdown(false); }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                          My Profile
                        </button>
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
              {/* ANALYST TOPBAR */}
              <header className="glass-topbar-capsule topbar">
                <div className="glass-topbar-left">
                  <h2 className="glass-welcome-title">Welcome, {currentUser?.name || 'Investigator'}</h2>
                  <p className="glass-welcome-sub">Autonomous AI Forensic Investigation Workstation</p>
                </div>

                <div className="glass-topbar-right topbar-actions">
                  {/* Live Analysis badge */}
                  {localStorage.getItem('active_case_id') && (
                    <div className="badge-live">
                      <div className="live-dot"></div>
                      Live Analysis
                    </div>
                  )}



                  {/* Theme Toggle */}
                  <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Theme">
                    {theme === 'dark' ? (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                    ) : (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                    )}
                  </button>

                  {/* Bell */}
                  <NotificationMenu />

                  {/* User profile */}
                  <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
                    <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'S'}</div>
                    <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'sathwik'}</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    {showUserDropdown && (
                      <div className="user-dropdown" style={{ display: 'block' }}>
                        <div className="user-dropdown-header">
                          <div className="ud-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'sathwik'}</div>
                          <div className="ud-role">{currentUser?.role?.replace('_', ' ') || 'Digital Forensics Investigator'}</div>
                        </div>
                        <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); navigate('/profile'); setShowUserDropdown(false); }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                          My Profile
                        </button>
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
                {/* Cases assigned to OTHER analysts — locked banner (analyst view only) */}
                {!isAdmin && (() => {
                  const lockedCases = cases.filter(c => c.status === 'open' && !c.assigned_to_you);
                  if (lockedCases.length === 0) return null;
                  return (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16, flexShrink: 0 }}>
                      {lockedCases.map(c => (
                        <div key={c.case_id} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: '14px 20px', display: 'flex', alignItems: 'center', gap: 14, opacity: 0.75 }}>
                          <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--bg-surface)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, color: 'var(--text-muted)' }}>
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                          </div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-main)', marginBottom: 2 }}>{c.name || c.case_id}</div>
                            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>In Progress — being investigated by another analyst</div>
                          </div>
                          <span style={{ background: 'var(--bg-surface)', color: 'var(--text-muted)', padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700, flexShrink: 0 }}>LOCKED</span>
                        </div>
                      ))}
                    </div>
                  );
                })()}

                {/* EMPTY STATE */}
                {!activeSummary && (
                  <div id="dashboard-empty-state" style={{ display: 'block', textAlign: 'center', padding: '100px 20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', marginBottom: '24px', border: '1px dashed var(--border-strong)' }}>
                    <div style={{ width: '64px', height: '64px', background: 'var(--blue-light)', color: 'var(--blue)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                    </div>
                    <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>
                      {isAdmin ? 'No Active Case Selected' : 'No Case Assigned'}
                    </h2>
                    <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>
                      {isAdmin
                        ? 'Select an existing case or create a new one to begin your investigation.'
                        : 'You have not been assigned to any active case. Please contact your administrator.'}
                    </p>
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
                                <strong>{safeFormatDateTime(activeSummary.latest_timestamp, '—')}</strong>
                              </div>
                            </div>
                          </div>
                        </div>
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


                    {/* ARGUS Multi-Agent Swarm Intelligence Card */}
                    <div style={{
                      background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.08), rgba(99, 102, 241, 0.12))',
                      border: '1px solid rgba(99, 102, 241, 0.35)',
                      borderRadius: 10,
                      padding: '18px 24px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: 16,
                      flexShrink: 0
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                        <div style={{
                          width: 44,
                          height: 44,
                          borderRadius: 8,
                          background: 'rgba(99, 102, 241, 0.2)',
                          color: '#818cf8',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0
                        }}>
                          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{ fontSize: 11, fontWeight: 900, background: '#6366f1', color: '#fff', padding: '2px 8px', borderRadius: 4, letterSpacing: '0.05em' }}>
                              MULTI-AGENT SWARM
                            </span>
                            <span style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-main)' }}>
                              7-Agent Forensic Reasoning Engine
                            </span>
                            <span style={{
                              fontSize: 11,
                              fontWeight: 800,
                              background: agentSummary?.status === 'COMPLETED' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                              color: agentSummary?.status === 'COMPLETED' ? '#10b981' : 'var(--blue)',
                              padding: '2px 8px',
                              borderRadius: 4
                            }}>
                              {agentSummary?.status || 'READY'}
                            </span>
                          </div>
                          <p style={{ margin: 0, fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                            Qwen3-8B Evidence Intelligence, Neo4j Graph Correlation, MITRE ATT&amp;CK Kill-Chain, YARA Heuristics, Threat Intel, and DeBERTa-v3 NLI Verification.
                          </p>
                        </div>
                      </div>

                      <Link
                        to="/agents"
                        style={{
                          background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
                          color: '#fff',
                          padding: '10px 20px',
                          borderRadius: 6,
                          fontSize: 12.5,
                          fontWeight: 800,
                          textDecoration: 'none',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 8,
                          boxShadow: '0 4px 14px rgba(99, 102, 241, 0.35)',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        OPEN AGENT SWARM →
                      </Link>
                    </div>

                    {/* Interactive Investigation Map */}
                    <ForensicGraph caseId={activeCaseId} />

                    {/* Investigation Progress */}
                    <div className="timeline-card" style={{ flexShrink: 0 }}>
                      <div className="timeline-header">
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <h3 style={{ margin: 0 }}>Investigation Progress</h3>
                            {currentUser?.role !== 'analyst' && (
                              <Link 
                                to="/timeline" 
                                style={{ 
                                  fontSize: '11.5px', 
                                  fontWeight: 700, 
                                  color: '#3b82f6', 
                                  textDecoration: 'none', 
                                  display: 'inline-flex', 
                                  alignItems: 'center', 
                                  gap: '4px', 
                                  padding: '3px 8px', 
                                  borderRadius: '6px', 
                                  background: 'rgba(59, 130, 246, 0.1)', 
                                  border: '1px solid rgba(59, 130, 246, 0.25)' 
                                }}
                              >
                                <span>Attack Timeline</span>
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>
                              </Link>
                            )}
                          </div>
                          <p style={{ margin: '4px 0 0 0' }}>Track the lifecycle of the active case.</p>
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