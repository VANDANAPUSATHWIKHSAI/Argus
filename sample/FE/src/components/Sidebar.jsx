import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import ArgusLogo from './ArgusLogo';
import { logout } from '../js/authSession';

const Sidebar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const currentPath = location.pathname;
  
  const [unreadNotes, setUnreadNotes] = useState(0);

  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('argus_user'));
    } catch (e) {
      return null;
    }
  });

  // Keep user profile and role dynamically reactive to session and dev switcher changes
  useEffect(() => {
    const syncUser = () => {
      try {
        setUser(JSON.parse(localStorage.getItem('argus_user')));
      } catch (e) {
        setUser(null);
      }
    };
    window.addEventListener('storage', syncUser);
    window.addEventListener('argus:userChanged', syncUser);
    return () => {
      window.removeEventListener('storage', syncUser);
      window.removeEventListener('argus:userChanged', syncUser);
    };
  }, []);

  // Load saved theme or default to dark
  useEffect(() => {
    const savedTheme = localStorage.getItem('argus_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  useEffect(() => {
    if (user?.role === 'senior_analyst') {
      const activeCaseId = localStorage.getItem('active_case_id');
      if (activeCaseId) {
        const token = localStorage.getItem('argus_token');
        fetch(`${API_BASE_URL}/cases/${activeCaseId}/notes`, {
          headers: {
            'X-Tenant-ID': DEFAULT_TENANT_ID,
            'Authorization': `Bearer ${token}`
          }
        })
        .then(res => res.json())
        .then(data => {
          if (data && data.data) {
            const notesData = data.data;
            const totalNotes = notesData.length;
            const seenNotes = parseInt(localStorage.getItem(`seen_notes_${activeCaseId}`) || '0', 10);
            
            const latestUpdate = Math.max(0, ...notesData.map(n => {
              const val = n.updatedAt || n.createdAt;
              const d = val ? new Date(String(val).replace(/\s+/, 'T')) : null;
              return (d && !isNaN(d.getTime())) ? d.getTime() : 0;
            }));
            const lastSeenUpdate = parseInt(localStorage.getItem(`last_seen_update_${activeCaseId}`) || '0', 10);

            let unread = 0;
            if (lastSeenUpdate > 0) {
              unread = notesData.filter(n => {
                const val = n.updatedAt || n.createdAt;
                const d = val ? new Date(String(val).replace(/\s+/, 'T')) : null;
                return d && !isNaN(d.getTime()) && d.getTime() > lastSeenUpdate;
              }).length;
            } else if (totalNotes > seenNotes) {
              unread = totalNotes - seenNotes;
            }
            setUnreadNotes(unread);
          }
        })
        .catch(e => console.error(e));
      }
    }
  }, [location.pathname, user?.role]);

  const handleLogout = () => {
    logout();
  };

  return (
    <>
      {/* ── 1. CENTERED FLOATING NAVIGATION CARD ── */}
      <aside className="glass-sidebar sidebar">
        <div className="glass-sidebar-brand sidebar-logo">
          <ArgusLogo size={36} />
          <div>
            <h1 className="glass-sidebar-brand-title">ARGUS</h1>
            <p className="glass-sidebar-brand-sub">AI Forensic Intelligence</p>
          </div>
        </div>
        
        <nav className="glass-sidebar-nav nav-menu">
          {/* Admin Navigation */}
          {user?.role === 'admin' && (
            <>
              <Link to="/dashboard" className={`glass-nav-item nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
                <span>Dashboard</span>
              </Link>
              <Link to="/cases" className={`glass-nav-item nav-item ${currentPath === '/cases' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                <span>Case Overview</span>
              </Link>
              <Link to="/employees" className={`glass-nav-item nav-item ${currentPath === '/employees' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                <span>Employees</span>
              </Link>
              <Link to="/agents" className={`glass-nav-item nav-item ${currentPath === '/agents' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><circle cx="12" cy="12" r="3" /><circle cx="19" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><path d="M10.4 10.4L6.4 17.6" /><path d="M13.6 13.6L17.6 6.4" /></svg>
                <span>Agents Swarm</span>
              </Link>
              <Link to="/report" className={`glass-nav-item nav-item ${currentPath === '/report' || currentPath === '/reports' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                <span>Report Builder</span>
              </Link>
              <Link to="/audit-logs" className={`glass-nav-item nav-item ${currentPath === '/audit-logs' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                <span>Audit Logs</span>
              </Link>
            </>
          )}

          {/* Senior Analyst Navigation */}
          {user?.role === 'senior_analyst' && (
            <>
              <Link to="/dashboard" className={`glass-nav-item nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                <span>Dashboard</span>
              </Link>
              <Link to="/evidence" className={`glass-nav-item nav-item ${currentPath === '/evidence' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
                <span>Evidence</span>
              </Link>
              <Link to="/agents" className={`glass-nav-item nav-item ${currentPath === '/agents' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><circle cx="12" cy="12" r="3" /><circle cx="19" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><path d="M10.4 10.4L6.4 17.6" /><path d="M13.6 13.6L17.6 6.4" /></svg>
                <span>Agents Swarm</span>
              </Link>
              <Link to="/chatbot" className={`glass-nav-item nav-item ${currentPath === '/chatbot' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                <span>AI Assistant</span>
              </Link>
              <Link to="/case-notes" className={`glass-nav-item nav-item ${currentPath === '/case-notes' ? 'active' : ''}`} style={{ position: 'relative' }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
                <span>Notes</span>
                {unreadNotes > 0 && (
                  <span style={{ 
                    background: 'var(--glass-dash-red, #ef4444)', 
                    color: '#ffffff', 
                    borderRadius: '10px', 
                    padding: '2px 8px', 
                    fontSize: '11px', 
                    fontWeight: '700', 
                    marginLeft: 'auto',
                    boxShadow: '0 2px 8px rgba(239, 68, 68, 0.4)' 
                  }}>
                    {unreadNotes}
                  </span>
                )}
              </Link>
              <Link to="/report" className={`glass-nav-item nav-item ${currentPath === '/report' || currentPath === '/reports' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                <span>Report Builder</span>
              </Link>
            </>
          )}

          {/* Analyst Navigation */}
          {user?.role === 'analyst' && (
            <>
              <Link to="/dashboard" className={`glass-nav-item nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
                <span>Dashboard</span>
              </Link>
              <Link to="/evidence" className={`glass-nav-item nav-item ${currentPath === '/evidence' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
                <span>Evidence</span>
              </Link>
              <Link to="/agents" className={`glass-nav-item nav-item ${currentPath === '/agents' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><circle cx="12" cy="12" r="3" /><circle cx="19" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><path d="M10.4 10.4L6.4 17.6" /><path d="M13.6 13.6L17.6 6.4" /></svg>
                <span>Agents Swarm</span>
              </Link>
              <Link to="/chatbot" className={`glass-nav-item nav-item ${currentPath === '/chatbot' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                <span>AI Assistant</span>
              </Link>
              <Link to="/case-notes" className={`glass-nav-item nav-item ${currentPath === '/case-notes' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
                <span>Case Notes</span>
              </Link>
            </>
          )}

          {/* Auditor Navigation */}
          {user?.role === 'auditor' && (
            <>
              <Link to="/report" className={`glass-nav-item nav-item ${currentPath === '/report' || currentPath === '/reports' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                <span>Report</span>
              </Link>
              <Link to="/audit-logs" className={`glass-nav-item nav-item ${currentPath === '/audit-logs' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                <span>Audit Logs</span>
              </Link>
              <Link to="/chatbot" className={`glass-nav-item nav-item ${currentPath === '/chatbot' ? 'active' : ''}`}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                <span>AI Assistant</span>
              </Link>
            </>
          )}

          {/* Shared Settings */}
          <Link to="/settings" className={`glass-nav-item nav-item ${currentPath === '/settings' ? 'active' : ''}`}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            <span>Settings</span>
          </Link>
        </nav>
      </aside>

      {/* ── 2. SEPARATE ANCHORED USER SESSION CARD ── */}
      <aside className="glass-user-card sidebar-footer-card">
        <div className="glass-user-card-header">
          <div className="glass-user-avatar-wrap">
            <div className="glass-avatar-circle">
              {user?.name ? user.name.charAt(0).toUpperCase() : 'S'}
            </div>
            <span className="glass-avatar-status-pip" title="Active Session: Authenticated" />
          </div>
          <div className="glass-user-info-meta">
            <span className="glass-user-name">{user?.name || 'sathwik'}</span>
            <div className="glass-user-role-badge">
              <span className="glass-role-indicator" />
              <span>{user?.role?.replace('_', ' ') || 'Analyst'}</span>
            </div>
          </div>
        </div>

        <div className="glass-user-card-divider" />

        <button 
          onClick={handleLogout} 
          className="glass-user-card-logout" 
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
    </>
  );
};

export default Sidebar;
