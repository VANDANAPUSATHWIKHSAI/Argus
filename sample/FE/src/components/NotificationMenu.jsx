import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import { setActiveCase } from '../js/caseEvents';

const NotificationMenu = () => {
  const [isOpen, setIsOpen] = useState(false);
  const navigate = useNavigate();
  const menuRef = useRef(null);
  const [notifications, setNotifications] = useState([]);
  const [readIds, setReadIds] = useState(() => {
    try { return new Set(JSON.parse(localStorage.getItem('argus_notif_read') || '[]')); }
    catch { return new Set(); }
  });

  const currentUser = (() => {
    try { return JSON.parse(localStorage.getItem('argus_user') || 'null'); } catch { return null; }
  })();
  const isAdmin = currentUser?.role === 'admin';

  useEffect(() => {
    const load = async () => {
      try {
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
          return { id: `${a.case_id}-${i}`, caseId: a.case_id, title, time };
        });

        setNotifications(mapped);
      } catch (e) {
        console.error('Notification load failed:', e);
      }
    };
    load();

    const handleInterval = () => {
      if (document.visibilityState === 'visible') {
        load();
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        load();
      }
    };

    const iv = setInterval(handleInterval, 30000);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      clearInterval(iv);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [isAdmin]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) setIsOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isRead = (id) => readIds.has(id);

  const markRead = (id) => {
    const next = new Set(readIds); next.add(id);
    setReadIds(next);
    localStorage.setItem('argus_notif_read', JSON.stringify([...next]));
  };

  const markAllRead = () => {
    const next = new Set(notifications.map(n => n.id));
    setReadIds(next);
    localStorage.setItem('argus_notif_read', JSON.stringify([...next]));
  };

  const unreadCount = notifications.filter(n => !isRead(n.id)).length;

  return (
    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }} ref={menuRef}>
      <button 
        className="glass-icon-btn icon-btn" 
        onClick={() => setIsOpen(!isOpen)} 
        title="Notifications"
        aria-label="Notifications"
        aria-expanded={isOpen}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
        {unreadCount > 0 && <span className="glass-badge-dot notification-dot" />}
      </button>

      {isOpen && (
        <div 
          className="glass-notification-dropdown"
          style={{ 
            position: 'absolute', 
            top: 'calc(100% + 14px)', 
            right: 0, 
            width: '360px', 
            background: 'var(--glass-dash-surface-gradient)', 
            backdropFilter: 'blur(32px) saturate(200%)',
            WebkitBackdropFilter: 'blur(32px) saturate(200%)',
            border: '1px solid var(--glass-dash-border)', 
            borderRadius: '18px', 
            boxShadow: 'var(--glass-dash-shadow-card)', 
            zIndex: 1000, 
            overflow: 'hidden',
            animation: 'dropdownFade 0.15s cubic-bezier(0.16, 1, 0.3, 1)'
          }}
        >
          <div style={{ 
            padding: '16px 20px', 
            borderBottom: '1px solid var(--glass-dash-border-subtle)', 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            background: 'var(--glass-dash-surface-nested)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--glass-dash-text-main)', letterSpacing: '0.2px' }}>Notifications</h3>
              {unreadCount > 0 && (
                <span style={{ 
                  background: 'var(--glass-dash-blue)', 
                  color: '#ffffff', 
                  fontSize: '11px', 
                  fontWeight: 700, 
                  padding: '1px 7px', 
                  borderRadius: '9999px',
                  boxShadow: '0 2px 6px rgba(37,99,235,0.4)'
                }}>
                  {unreadCount}
                </span>
              )}
            </div>
            {unreadCount > 0 && (
              <button 
                type="button"
                onClick={markAllRead} 
                style={{ 
                  fontSize: '12px', 
                  color: 'var(--glass-dash-blue)', 
                  background: 'none', 
                  border: 'none', 
                  cursor: 'pointer', 
                  fontWeight: 600,
                  padding: 0
                }}
              >
                Mark all as read
              </button>
            )}
          </div>

          <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
            {notifications.length === 0 ? (
              <div style={{ padding: '36px 20px', textAlign: 'center', color: 'var(--glass-dash-text-muted)', fontSize: '13px' }}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ opacity: 0.5, marginBottom: '8px', display: 'inline-block' }}>
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                  <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                </svg>
                <div>No new notifications</div>
              </div>
            ) : notifications.map(n => (
              <div 
                key={n.id} 
                onClick={() => {
                  markRead(n.id);
                  if (n.caseId) {
                    setActiveCase(n.caseId);
                    setIsOpen(false);
                    navigate('/dashboard');
                  }
                }} 
                style={{ 
                  padding: '14px 18px', 
                  borderBottom: '1px solid var(--glass-dash-border-subtle)', 
                  background: isRead(n.id) ? 'transparent' : 'rgba(37, 99, 235, 0.05)', 
                  cursor: 'pointer', 
                  transition: 'background 0.2s',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px'
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'var(--glass-dash-surface-hover)'}
                onMouseLeave={(e) => e.currentTarget.style.background = isRead(n.id) ? 'transparent' : 'rgba(37, 99, 235, 0.05)'}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
                  <div style={{ fontSize: '12.5px', fontWeight: isRead(n.id) ? 500 : 600, color: 'var(--glass-dash-text-main)', lineHeight: '1.4' }}>
                    {n.title}
                  </div>
                  {!isRead(n.id) && (
                    <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: 'var(--glass-dash-blue)', flexShrink: 0, marginTop: '5px', boxShadow: '0 0 6px rgba(37,99,235,0.7)' }} />
                  )}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)' }}>{n.time}</div>
              </div>
            ))}
          </div>

          <div style={{ 
            padding: '12px 16px', 
            textAlign: 'center', 
            borderTop: '1px solid var(--glass-dash-border-subtle)', 
            background: 'var(--glass-dash-surface-nested)' 
          }}>
            <button 
              type="button"
              onClick={() => { setIsOpen(false); navigate('/notifications'); }} 
              style={{ 
                fontSize: '12.5px', 
                color: 'var(--glass-dash-blue)', 
                background: 'none', 
                border: 'none', 
                cursor: 'pointer', 
                fontWeight: 600 
              }}
            >
              View all notifications →
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default NotificationMenu;
