import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

const Sidebar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const currentPath = location.pathname;

  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('argus_user'));
  } catch(e) {}

  // Load saved theme or default to dark
  React.useEffect(() => {
    const savedTheme = localStorage.getItem('argus_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('argus_token');
    localStorage.removeItem('argus_user');
    localStorage.removeItem('active_case_id');
    localStorage.removeItem('active_case_name');
    navigate('/login');
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon" style={{ width: '36px', height: '36px', borderRadius: '8px', overflow: 'hidden', flexShrink: 0 }}>
          <img src="/argus_logo.jpg" alt="ARGUS Logo" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
        </div>
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
            <Link to="/employees" className={`nav-item ${currentPath === '/employees' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
              <span>Employees</span>
            </Link>
          </>
        )}

        {(user?.role === 'analyst') && (
          <>
            <Link to="/evidence" className={`nav-item ${currentPath === '/evidence' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
              <span>Evidence</span>
            </Link>
            <Link to="/case-notes" className={`nav-item ${currentPath === '/case-notes' ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
          <span>Case Notes</span>
        </Link>
        <Link to="/sanitized" className={`nav-item ${currentPath === '/sanitized' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              <span>Sanitized Output</span>
            </Link>
          </>
        )}

        {user?.role === 'senior_analyst' && (
          <>
            <Link to="/dashboard" className={`nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <span>Dashboard</span>
            </Link>
            <Link to="/chatbot" className={`nav-item ${currentPath === '/chatbot' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
              <span>Chatbot</span>
            </Link>
            <Link to="/case-notes" className={`nav-item ${currentPath === '/case-notes' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
              <span>Notes</span>
            </Link>
          </>
        )}

        {user?.role !== 'senior_analyst' && (
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
        
        {/* Logout Button */}
        <button onClick={handleLogout} className="nav-item" style={{
          background: 'none', 
          border: '1px solid rgba(239, 68, 68, 0.2)', 
          width: '100%', 
          cursor: 'pointer', 
          textAlign: 'left', 
          outline: 'none', 
          color: '#f87171',
          borderRadius: '8px',
          transition: 'all 0.2s ease',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '8px'
        }}
          onMouseOver={(e) => { e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'; e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.4)'; }}
          onMouseOut={(e) => { e.currentTarget.style.background = 'none'; e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.2)'; }}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          <span>Logout</span>
        </button>
      </nav>
            <div className="sidebar-footer" style={{ 
        marginTop: 'auto', 
        width: '100%', 
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'flex-end',
        position: 'relative'
      }}>
        {user?.role === 'senior_analyst' ? (
          <div style={{ position: 'relative', width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            {/* Removed Mountain Silhouette */}
            <div style={{ zIndex: 1, padding: '24px 32px 32px 32px', textAlign: 'left', width: '100%' }}>
              <p style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', margin: '0 0 4px 0', letterSpacing: '1px', textTransform: 'uppercase' }}>
                Truth<br/>Through<br/>Evidence
              </p>
            </div>
          </div>
        ) : (
          <div style={{ padding: '24px 32px', width: '100%', textAlign: 'left' }}>
            <p style={{ fontSize: '13px', fontStyle: 'italic', color: 'var(--text-muted)', marginBottom: '8px' }}>
              "From digital traces<br />to real answers."
            </p>
            <p style={{ fontSize: '14px', fontWeight: 'bold', color: 'var(--text-main)', margin: 0, letterSpacing: '1px' }}>
              ARGUS
            </p>
            <div style={{ width: '20px', height: '1px', backgroundColor: 'var(--border-strong)', marginTop: '8px' }}></div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Sidebar;
