import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import '../css/style.css';

const Notifications = () => {
  const navigate = useNavigate();
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);

  const currentUser = (() => {
    try { return JSON.parse(localStorage.getItem('argus_user') || 'null'); } catch { return null; }
  })();
  const isAdmin = currentUser?.role === 'admin';

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem('argus_token');
        const res = await fetch(`${API_BASE_URL}/cases/activity`, {
          headers: { 'Authorization': `Bearer ${token}`, 'X-Tenant-ID': DEFAULT_TENANT_ID }
        });
        if (!res.ok) return;
        const data = await res.json();
        const items = data.data || [];

        const mapped = items.map((a, i) => {
          const rawTs = a.created_at ? String(a.created_at).replace(/\s+/, 'T') : null;
          const age = rawTs ? Date.now() - new Date(rawTs).getTime() : 0;
          const mins = Math.floor(age / 60000);
          const hrs  = Math.floor(age / 3600000);
          const days = Math.floor(age / 86400000);
          const time = days > 0 ? `${days}d ago` : hrs > 0 ? `${hrs}h ago` : `${mins}m ago`;

          let title = '';
          if (a.action === 'Created Case') {
            title = isAdmin ? `Case ${a.case_id} was created` : `You have been assigned to case ${a.case_id}`;
          } else if (a.action === 'Uploaded Evidence') {
            title = `Evidence "${a.details}" uploaded to ${a.case_id}`;
          } else {
            title = `${a.action} — ${a.case_id}`;
          }
          return { id: `${a.case_id}-${i}`, title, time };
        });

        setNotifications(mapped);
      } catch (e) {
        console.error('Notification load failed:', e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [isAdmin, currentUser?.role]);

  const handleBack = () => {
    if (window.history.length > 1) {
      navigate(-1);
    } else {
      navigate('/dashboard');
    }
  };

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <header className="glass-topbar-capsule topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <button 
              onClick={handleBack} 
              className="glass-icon-btn icon-btn" 
              title="Go Back"
              aria-label="Go Back"
              style={{
                width: '38px',
                height: '38px',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer'
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="19" y1="12" x2="5" y2="12" />
                <polyline points="12 19 5 12 12 5" />
              </svg>
            </button>
            <div className="glass-topbar-left">
              <h2 className="glass-welcome-title" style={{ margin: 0, fontSize: '15px', fontWeight: 700 }}>Notifications</h2>
              <p className="glass-welcome-sub" style={{ margin: 0, fontSize: '11px', opacity: 0.7 }}>System alerts & activity feed</p>
            </div>
          </div>
          <div className="glass-topbar-right topbar-actions" style={{ flex: 1, justifyContent: 'flex-end', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button 
              onClick={handleBack} 
              className="btn btn-outline"
              style={{ 
                border: '1px solid var(--glass-dash-border-subtle)', 
                color: 'var(--glass-dash-text-main)', 
                background: 'var(--glass-dash-surface-nested)', 
                padding: '7px 16px', 
                borderRadius: 'var(--radius-full)', 
                fontWeight: 600, 
                display: 'flex', 
                alignItems: 'center', 
                gap: 7, 
                cursor: 'pointer', 
                fontSize: '12.5px',
                transition: 'all 0.2s ease'
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="19" y1="12" x2="5" y2="12" />
                <polyline points="12 19 5 12 12 5" />
              </svg>
              <span>Back</span>
            </button>
            <div className="glass-profile-pill user-profile">
              <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}</div>
              <span className="glass-profile-name" style={{ fontWeight: 500, textTransform: 'capitalize' }}>{currentUser?.name || 'User'}</span>
            </div>
          </div>
        </header>

        <div className="dashboard-scroll" style={{ maxWidth: 900, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24, width: '100%' }}>
          {/* Page Title & Breadcrumb */}
          <div>
            <button
              onClick={handleBack}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--glass-dash-blue, #3b82f6)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
                padding: '0 0 10px 0',
                transition: 'opacity 0.2s ease'
              }}
              onMouseEnter={(e) => e.currentTarget.style.opacity = '0.75'}
              onMouseLeave={(e) => e.currentTarget.style.opacity = '1'}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="19" y1="12" x2="5" y2="12" />
                <polyline points="12 19 5 12 12 5" />
              </svg>
              Back to Previous
            </button>
            <h2 style={{ fontFamily: "'Poppins', sans-serif", fontSize: 28, fontWeight: 800, color: 'var(--text-main)', marginBottom: 6 }}>
              Notifications
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
              Recent updates and alerts for your account
            </p>
          </div>

          <div className="panel-card" style={{ borderRadius: 16, overflow: 'hidden' }}>
            {loading ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading...</div>
            ) : notifications.length === 0 ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>No notifications</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {notifications.map((n, i) => (
                  <div key={n.id} style={{ 
                    padding: '24px 32px', 
                    borderBottom: i === notifications.length - 1 ? 'none' : '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    background: 'var(--bg-surface)',
                    transition: 'background 0.2s'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>{n.title}</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500 }}>{n.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default Notifications;
