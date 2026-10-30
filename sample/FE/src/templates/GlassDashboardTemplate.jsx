import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import ArgusLogo from '../components/ArgusLogo';
import './GlassDashboardTemplate.css';

export default function GlassDashboardTemplate() {
  const navigate = useNavigate();

  // Theme Management (Light Frosted Glass vs Dark Obsidian Glass)
  const [theme, setTheme] = useState(() => {
    return document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'light';
  });

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // Active Navigation Tab
  const [activeNav, setActiveNav] = useState('dashboard');

  // Interactive Case State matching user's live dashboard
  const [currentCase, setCurrentCase] = useState({
    caseId: 'ARGUS_02',
    name: '14 today case',
    status: 'under_review',
    step: 2, // 1: Investigation, 2: Review, 3: Audit, 4: Closed
    analyst: 'sathwik',
    seniorAnalyst: 'Senior Analyst 6',
    auditor: 'Not Assigned',
    createdOn: 'Oct 14, 2026',
    lastUpdated: 'Oct 14, 2026, 12:43 AM'
  });

  const [stats, setStats] = useState({
    totalEmployees: 11,
    casesSolved: 12
  });

  // Recent Activity matching live data
  const [activities, setActivities] = useState([
    {
      id: 1,
      date: 'Oct 14, 2026',
      time: '12:43 AM',
      user: 'System Administrator',
      userInitial: 'S',
      userRole: 'admin',
      action: 'Created Case',
      actionType: 'created',
      details: 'ARGUS_02...'
    },
    {
      id: 2,
      date: 'Oct 14, 2026',
      time: '12:42 AM',
      user: 'System Administrator',
      userInitial: 'S',
      userRole: 'admin',
      action: 'Closed Case',
      actionType: 'closed',
      details: 'Case ARGUS_01 was closed'
    },
    {
      id: 3,
      date: 'Oct 14, 2026',
      time: '12:42 AM',
      user: 'System Administrator',
      userInitial: 'S',
      userRole: 'admin',
      action: 'Closed Case',
      actionType: 'closed',
      details: 'Case fd688905-8008-4add-8b78-62e6779461b8 was closed'
    },
    {
      id: 4,
      date: 'Oct 6, 2026',
      time: '11:35 PM',
      user: 'System Administrator',
      userInitial: 'S',
      userRole: 'admin',
      action: 'Created Case',
      actionType: 'created',
      details: 'ARGUS_01...'
    },
    {
      id: 5,
      date: 'Sep 25, 2026',
      time: '05:55 PM',
      user: 'Admin User',
      userInitial: 'A',
      userRole: 'admin',
      action: 'Created Case',
      actionType: 'created',
      details: 'fd688905...'
    }
  ]);

  // Create Case Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');

  const handleCreateCaseSubmit = (e) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;

    const newId = `ARGUS_${String(stats.casesSolved + 1).padStart(2, '0')}`;
    setCurrentCase({
      caseId: newId,
      name: newCaseName.trim(),
      status: 'under_review',
      step: 1,
      analyst: 'sathwik',
      seniorAnalyst: 'Senior Analyst 6',
      auditor: 'Not Assigned',
      createdOn: 'Today',
      lastUpdated: 'Just now'
    });

    setActivities(prev => [
      {
        id: Date.now(),
        date: 'Today',
        time: 'Just now',
        user: 'System Administrator',
        userInitial: 'S',
        userRole: 'admin',
        action: 'Created Case',
        actionType: 'created',
        details: `${newId} — ${newCaseName.trim()}`
      },
      ...prev
    ]);

    setStats(prev => ({ ...prev, casesSolved: prev.casesSolved + 1 }));
    setNewCaseName('');
    setNewCaseDesc('');
    setShowCreateModal(false);
  };

  const handleCloseCaseAction = () => {
    setCurrentCase(prev => ({
      ...prev,
      status: 'closed',
      step: 4,
      lastUpdated: 'Just now'
    }));

    setActivities(prev => [
      {
        id: Date.now(),
        date: 'Today',
        time: 'Just now',
        user: 'System Administrator',
        userInitial: 'S',
        userRole: 'admin',
        action: 'Closed Case',
        actionType: 'closed',
        details: `Case ${currentCase.caseId} was marked as closed`
      },
      ...prev
    ]);
  };

  return (
    <div className="glass-dash-wrapper">
      {/* Clean Neutral Glass Backdrop (pure crystal glass, no heavy blue casts) */}
      <div className="glass-dash-ambient-grid" />
      <div className="glass-dash-neutral-glow-1" />
      <div className="glass-dash-neutral-glow-2" />

      {/* ── 1. FLOATING FROSTED GLASS SIDEBAR ── */}
      <aside className="glass-sidebar">
        {/* Brand Header */}
        <div className="glass-sidebar-brand">
          <ArgusLogo size={36} />
          <div className="glass-sidebar-brand-meta">
            <h1 className="glass-sidebar-brand-title">ARGUS</h1>
            <p className="glass-sidebar-brand-sub">AI FOR DIGITAL FORENSICS</p>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="glass-sidebar-nav">
          {[
            {
              id: 'dashboard',
              label: 'Dashboard',
              icon: (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
                  <polyline points="9 22 9 12 15 12 15 22" />
                </svg>
              )
            },
            {
              id: 'cases',
              label: 'Case Overview',
              icon: (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                </svg>
              )
            },
            {
              id: 'employees',
              label: 'Employees',
              icon: (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                  <circle cx="9" cy="7" r="4" />
                  <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                  <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                </svg>
              )
            },
            {
              id: 'audit',
              label: 'Audit Logs',
              icon: (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              )
            },
            {
              id: 'settings',
              label: 'Settings',
              icon: (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <circle cx="12" cy="12" r="3" />
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                </svg>
              )
            }
          ].map((item) => (
            <button
              key={item.id}
              className={`glass-nav-item ${activeNav === item.id ? 'active' : ''}`}
              onClick={() => setActiveNav(item.id)}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
      </aside>

      {/* ── SEPARATE USER PROFILE & LOGOUT GLASS CARD (Integrated Session Anchor) ── */}
      <aside className="glass-user-card">
        {/* User Profile Header */}
        <div className="glass-user-card-header">
          <div className="glass-user-avatar-wrap">
            <div className="glass-avatar-circle">S</div>
            <span className="glass-avatar-status-pip" title="Active Session: Authenticated" />
          </div>
          <div className="glass-user-info-meta">
            <span className="glass-user-name">System Administrator</span>
            <div className="glass-user-role-badge">
              <span className="glass-role-indicator" />
              <span>Admin</span>
            </div>
          </div>
        </div>

        {/* Frosted Hairline Divider */}
        <div className="glass-user-card-divider" />

        {/* Cohesive Logout Action matching Sidebar Nav styling */}
        <button 
          className="glass-user-card-logout" 
          onClick={() => navigate('/login')}
          title="Sign out of Argus session"
        >
          <div className="glass-logout-icon-wrap">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
          </div>
          <span>Sign Out</span>
        </button>
      </aside>

      {/* ── 2. MAIN GLASS WORKSPACE ── */}
      <main className="glass-main-workspace">
        
        {/* Topbar Capsule */}
        <header className="glass-topbar-capsule">
          <div className="glass-topbar-left">
            <h2 className="glass-welcome-title">Welcome, System Administrator</h2>
            <p className="glass-welcome-sub">Manage people, cases, and ensure compliance.</p>
          </div>

          <div className="glass-topbar-right">
            {/* Theme Toggle Button */}
            <button 
              className="glass-icon-btn" 
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to Light Frosted Glass' : 'Switch to Dark Obsidian Glass'}
            >
              {theme === 'dark' ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="5" />
                  <line x1="12" y1="1" x2="12" y2="3" />
                  <line x1="12" y1="21" x2="12" y2="23" />
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                  <line x1="1" y1="12" x2="3" y2="12" />
                  <line x1="21" y1="12" x2="23" y2="12" />
                  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                </svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                </svg>
              )}
            </button>

            {/* Notification Bell */}
            <button className="glass-icon-btn" title="System Notifications">
              <span className="glass-badge-dot" />
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
            </button>

            {/* Profile Dropdown Chip */}
            <div className="glass-profile-pill">
              <div className="glass-profile-avatar-dark">A</div>
              <span className="glass-profile-name">System Administrator</span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="6 9 12 15 18 9" />
              </svg>
            </div>
          </div>
        </header>

        {/* Stage Header */}
        <div className="glass-stage-header">
          <div>
            <h1 className="glass-stage-title">Dashboard</h1>
            <p className="glass-stage-desc">Overview of your organization and current case.</p>
          </div>

          <div className="glass-stage-actions">
            <div className="glass-datetime-badge">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 16 14" />
              </svg>
              <span>Fri, Oct 23, 2026 12:42 PM</span>
            </div>

            <button 
              className="btn-glass-primary"
              onClick={() => setShowCreateModal(true)}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
              <span>Create Case</span>
            </button>
          </div>
        </div>

        {/* ── 3. METRIC STATS ROW (GLASS CARDS) ── */}
        <section className="glass-stats-grid">
          {/* Stat Card 1: Total Employees */}
          <div className="glass-stat-card">
            <div className="glass-stat-icon-wrap blue">
              <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
              </svg>
            </div>
            <div className="glass-stat-body">
              <span className="glass-stat-number">{stats.totalEmployees}</span>
              <span className="glass-stat-title">Total Employees</span>
              <span className="glass-stat-subtitle">Active team members</span>
            </div>
          </div>

          {/* Stat Card 2: Cases Solved */}
          <div className="glass-stat-card">
            <div className="glass-stat-icon-wrap green">
              <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
            </div>
            <div className="glass-stat-body">
              <span className="glass-stat-number">{stats.casesSolved}</span>
              <span className="glass-stat-title">Cases Solved</span>
              <span className="glass-stat-subtitle">Completed successfully</span>
            </div>
          </div>
        </section>

        {/* ── 4. MAIN 2-COLUMN SECTION (CURRENT CASE & RECENT ACTIVITY) ── */}
        <section className="glass-split-cards-grid">
          
          {/* LEFT: Current Case Glass Card */}
          <div className="glass-dossier-card">
            {/* Header with Case ID and Badges */}
            <div className="glass-card-header-row">
              <div className="glass-case-brand-group">
                <div className="glass-case-icon-box">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                  </svg>
                </div>
                <div>
                  <h3 className="glass-case-id-text">{currentCase.caseId}</h3>
                  <p className="glass-case-desc-text">{currentCase.name}</p>
                </div>
              </div>

              <div className="glass-header-badge-group">
                <span className="glass-status-pill review">
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
                  {currentCase.status === 'closed' ? 'Closed' : 'Under Review'}
                </span>
                
                {currentCase.status !== 'closed' && (
                  <button 
                    className="btn-glass-outline-danger"
                    onClick={handleCloseCaseAction}
                    title="Close this active case"
                  >
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <line x1="18" y1="6" x2="6" y2="18" />
                      <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                    <span>Close</span>
                  </button>
                )}
              </div>
            </div>

            {/* Stepper / Timeline Pipeline */}
            <div className="glass-pipeline-container">
              <div className="glass-pipeline-track" />
              <div 
                className="glass-pipeline-progress" 
                style={{ 
                  width: currentCase.step === 1 ? '10%' : currentCase.step === 2 ? '36%' : currentCase.step === 3 ? '68%' : '100%' 
                }} 
              />
              
              <div className="glass-pipeline-nodes">
                <div className="glass-pipeline-node">
                  <div className={`glass-pipeline-dot ${currentCase.step >= 1 ? 'active' : 'pending'}`} />
                  <div>
                    <div className="glass-pipeline-label">Investigation</div>
                    <div className="glass-pipeline-role">(Analyst)</div>
                  </div>
                </div>

                <div className="glass-pipeline-node">
                  <div className={`glass-pipeline-dot ${currentCase.step >= 2 ? 'active' : 'pending'}`} />
                  <div>
                    <div className="glass-pipeline-label">Review</div>
                    <div className="glass-pipeline-role">(Senior Analyst)</div>
                  </div>
                </div>

                <div className="glass-pipeline-node">
                  <div className={`glass-pipeline-dot ${currentCase.step >= 3 ? 'active' : 'pending'}`} />
                  <div>
                    <div className="glass-pipeline-label">Audit</div>
                    <div className="glass-pipeline-role">(Not Assigned)</div>
                  </div>
                </div>

                <div className="glass-pipeline-node">
                  <div className={`glass-pipeline-dot ${currentCase.step >= 4 ? 'active' : 'pending'}`} />
                  <div>
                    <div className="glass-pipeline-label">Closed</div>
                    <div className="glass-pipeline-role">&nbsp;</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Personnel Glass Tray */}
            <div className="glass-personnel-tray">
              <div className="glass-staff-column">
                <div className="glass-staff-icon">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                </div>
                <div className="glass-staff-meta">
                  <span className="glass-staff-role-tag">Analyst</span>
                  <span className="glass-staff-name-val">{currentCase.analyst}</span>
                </div>
              </div>

              <div className="glass-staff-column">
                <div className="glass-staff-icon">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                </div>
                <div className="glass-staff-meta">
                  <span className="glass-staff-role-tag">Senior Analyst</span>
                  <span className="glass-staff-name-val">{currentCase.seniorAnalyst}</span>
                </div>
              </div>

              <div className="glass-staff-column">
                <div className="glass-staff-icon">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                </div>
                <div className="glass-staff-meta">
                  <span className="glass-staff-role-tag">Auditor</span>
                  <span className="glass-staff-name-val dim">{currentCase.auditor}</span>
                </div>
              </div>
            </div>

            {/* Dates Footer Strip */}
            <div className="glass-dossier-footer">
              <div className="glass-date-metric">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                  <line x1="16" y1="2" x2="16" y2="6" />
                  <line x1="8" y1="2" x2="8" y2="6" />
                  <line x1="3" y1="10" x2="21" y2="10" />
                </svg>
                <div>
                  <div className="glass-date-label">Created On</div>
                  <div className="glass-date-val">{currentCase.createdOn}</div>
                </div>
              </div>

              <div className="glass-date-metric">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <polyline points="12 6 12 12 16 14" />
                </svg>
                <div>
                  <div className="glass-date-label">Last Updated</div>
                  <div className="glass-date-val">{currentCase.lastUpdated}</div>
                </div>
              </div>
            </div>
          </div>

          {/* RIGHT: Recent Activity Glass Card */}
          <div className="glass-activity-card">
            <div className="glass-activity-header">
              <h3 className="glass-activity-title">Recent Activity</h3>
              <a href="#view-all" className="glass-view-all-link" onClick={(e) => { e.preventDefault(); alert('Navigating to Audit Logs...'); }}>
                <span>View All</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="9 18 15 12 9 6" />
                </svg>
              </a>
            </div>

            <table className="glass-activity-table">
              <thead>
                <tr>
                  <th>Date &amp; Time</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {activities.map((act) => (
                  <tr key={act.id} className="glass-activity-row">
                    <td>
                      <div className="glass-cell-timestamp">
                        {act.date}<br />
                        {act.time}
                      </div>
                    </td>
                    <td>
                      <div className="glass-user-cell">
                        <div className={`glass-user-bubble ${act.userRole}`}>
                          {act.userInitial}
                        </div>
                        <span style={{ fontWeight: 600, color: 'var(--glass-dash-text-main)' }}>
                          {act.user}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className={`glass-action-badge ${act.actionType}`}>
                        {act.action}
                      </span>
                    </td>
                    <td>
                      <div className="glass-details-text" title={act.details}>
                        {act.details}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {/* ── CREATE CASE GLASS MODAL ── */}
      {showCreateModal && (
        <div 
          style={{
            position: 'fixed',
            inset: 0,
            background: 'transparent',
            backdropFilter: 'none',
            zIndex: 1000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 20
          }}
          onClick={() => setShowCreateModal(false)}
        >
          <div 
            style={{
              width: '100%',
              maxWidth: 480,
              background: 'var(--glass-dash-surface)',
              backdropFilter: 'blur(30px) saturate(180%)',
              border: '1px solid var(--glass-dash-border)',
              borderRadius: 24,
              padding: '36px 32px',
              boxShadow: '0 30px 70px rgba(0,0,0,0.25)',
              position: 'relative'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h2 style={{ fontSize: 20, fontWeight: 800, margin: '0 0 8px', color: 'var(--glass-dash-text-main)' }}>
              Create New Forensic Case
            </h2>
            <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: '0 0 24px' }}>
              Initialize an investigative dossier and deploy forensic agent telemetry.
            </p>

            <form onSubmit={handleCreateCaseSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 700, color: 'var(--glass-dash-text-secondary)', marginBottom: 6 }}>
                  Case Name
                </label>
                <input 
                  type="text" 
                  placeholder="e.g. Memory Dump Incident 42" 
                  value={newCaseName} 
                  onChange={(e) => setNewCaseName(e.target.value)}
                  style={{
                    width: '100%',
                    height: 46,
                    padding: '0 16px',
                    borderRadius: 12,
                    background: 'var(--glass-dash-surface-nested)',
                    border: '1px solid var(--glass-dash-border-subtle)',
                    color: 'var(--glass-dash-text-main)',
                    fontSize: 14,
                    outline: 'none',
                    boxSizing: 'border-box'
                  }}
                  autoFocus
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 700, color: 'var(--glass-dash-text-secondary)', marginBottom: 6 }}>
                  Description (Optional)
                </label>
                <textarea 
                  placeholder="Provide scope, targets, or initial indicators..."
                  value={newCaseDesc}
                  onChange={(e) => setNewCaseDesc(e.target.value)}
                  style={{
                    width: '100%',
                    height: 80,
                    padding: '12px 16px',
                    borderRadius: 12,
                    background: 'var(--glass-dash-surface-nested)',
                    border: '1px solid var(--glass-dash-border-subtle)',
                    color: 'var(--glass-dash-text-main)',
                    fontSize: 13.5,
                    outline: 'none',
                    resize: 'none',
                    boxSizing: 'border-box',
                    fontFamily: 'inherit'
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
                <button 
                  type="button" 
                  onClick={() => setShowCreateModal(false)}
                  style={{
                    flex: 1,
                    height: 44,
                    borderRadius: 12,
                    background: 'transparent',
                    border: '1px solid var(--glass-dash-border-subtle)',
                    color: 'var(--glass-dash-text-muted)',
                    fontWeight: 700,
                    fontSize: 13,
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
                <button 
                  type="submit"
                  className="btn-glass-primary"
                  style={{ flex: 1.5, justifyContent: 'center' }}
                >
                  Create Dossier
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Floating Bottom Navigation Pill */}
      <div className="glass-quick-preview-pill">
        <span>GLASS UI TEMPLATE</span>
        <button className="glass-preview-toggle-btn" onClick={toggleTheme}>
          {theme === 'dark' ? '☀️ Daylight Glass' : '🌙 Obsidian Glass'}
        </button>
        <button className="glass-preview-toggle-btn" onClick={() => navigate('/dashboard')}>
          Back to Live App
        </button>
      </div>
    </div>
  );
}
