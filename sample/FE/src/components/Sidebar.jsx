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

  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('argus_user'));
  } catch(e) {}

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
    <aside className="sidebar">
      <div className="sidebar-logo">
        <ArgusLogo size={36} />
        <div className="logo-text">
          <h1>ARGUS</h1>
          <p>AI for Digital Forensics</p>
        </div>
      </div>
      
      <nav className="nav-menu" style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '8px' }}>
        {user?.role !== 'senior_analyst' && (
          <Link to="/dashboard" className={`nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
          <span>Dashboard</span>
          </Link>
        )}
        
        {user?.role === 'admin' && (
          <>
            <Link to="/cases" className={`nav-item ${currentPath === '/cases' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
              <span>Case Overview</span>
            </Link>
            <Link to="/employees" className={`nav-item ${currentPath === '/employees' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
              <span>Employees</span>
            </Link>
            <Link to="/agents" className={`nav-item ${currentPath === '/agents' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
              <span>Agents Swarm</span>
            </Link>
            <Link to="/report" className={`nav-item ${currentPath === '/report' || currentPath === '/reports' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              <span>Report Builder</span>
            </Link>
          </>
        )}

        {(user?.role === 'analyst') && (
          <>
            <Link to="/evidence" className={`nav-item ${currentPath === '/evidence' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
              <span>Evidence</span>
            </Link>
            <Link to="/timeline" className={`nav-item ${currentPath === '/timeline' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              <span>Timeline</span>
            </Link>
            <Link to="/agents" className={`nav-item ${currentPath === '/agents' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
              <span>Agents Swarm</span>
            </Link>
            <Link to="/chatbot" className={`nav-item ${currentPath === '/chatbot' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
              <span>AI Assistant</span>
            </Link>
            <Link to="/case-notes" className={`nav-item ${currentPath === '/case-notes' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
              <span>Case Notes</span>
            </Link>
            <Link to="/report" className={`nav-item ${currentPath === '/report' || currentPath === '/reports' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              <span>Report Builder</span>
            </Link>
          </>
        )}

        {user?.role === 'senior_analyst' && (
          <>
            <Link to="/dashboard" className={`nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <span>Dashboard</span>
            </Link>
            <Link to="/evidence" className={`nav-item ${currentPath === '/evidence' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
              <span>Evidence</span>
            </Link>
            <Link to="/agents" className={`nav-item ${currentPath === '/agents' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
              <span>Agents Swarm</span>
            </Link>
            <Link to="/chatbot" className={`nav-item ${currentPath === '/chatbot' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
              <span>AI Assistant</span>
            </Link>
            <Link to="/case-notes" className={`nav-item ${currentPath === '/case-notes' ? 'active' : ''}`} style={{ position: 'relative' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
              <span>Notes</span>
              {unreadNotes > 0 && (
                <div style={{ background: 'var(--red, #ef4444)', color: 'white', borderRadius: '50%', width: '20px', height: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 'bold', marginLeft: 'auto' }}>
                  {unreadNotes}
                </div>
              )}
            </Link>
            <Link to="/report" className={`nav-item ${currentPath === '/report' || currentPath === '/reports' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              <span>Report Builder</span>
            </Link>
          </>
        )}

        {(user?.role === 'admin' || user?.role === 'auditor') && (
          <Link to="/audit-logs" className={`nav-item ${currentPath === '/audit-logs' ? 'active' : ''}`}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            <span>Audit Logs</span>
          </Link>
        )}

        <Link to="/settings" className={`nav-item ${currentPath === '/settings' ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
          <span>Settings</span>
        </Link>
        
        <div style={{ flexGrow: 1 }}></div>
        
      </nav>
      
      <div className="sidebar-footer">
        <div className="sidebar-user-block">
          <div className="sidebar-avatar">
            {user?.name ? user.name.charAt(0).toUpperCase() : 'S'}
          </div>
          <div className="sidebar-user-details">
            <div className="sidebar-user-name">{user?.name || 'sathwik'}</div>
            <div className="sidebar-user-role">{user?.role?.replace('_', ' ') || 'Analyst'}</div>
          </div>
        </div>

        <button onClick={handleLogout} className="sidebar-logout-btn">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
