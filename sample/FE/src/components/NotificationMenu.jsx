import React, { useState, useRef, useEffect } from 'react';
import { API_BASE_URL } from '../js/api';

const NotificationMenu = () => {
  const [isOpen, setIsOpen] = useState(false);
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
          headers: { 'Authorization': `Bearer ${token}`, 'X-Tenant-ID': 'dev-team' }
        });
        if (!res.ok) return;
        const data = await res.json();
        const items = data.data || [];

        const mapped = items.map((a, i) => {
          const age = a.created_at ? Date.now() - new Date(a.created_at).getTime() : 0;
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
      }
    };
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
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
      <button className="icon-btn" onClick={() => setIsOpen(!isOpen)} title="Notifications">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
        {unreadCount > 0 && <div className="notification-dot"></div>}
      </button>

      {isOpen && (
        <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: '12px', width: '320px', background: 'var(--bg-card)', border: '1px solid var(--border-strong)', borderRadius: '12px', boxShadow: '0 10px 40px rgba(0,0,0,0.6)', zIndex: 1000, overflow: 'hidden' }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--text-main)' }}>Notifications</h3>
            {unreadCount > 0 && (
              <span onClick={markAllRead} style={{ fontSize: '12px', color: 'var(--blue)', cursor: 'pointer', fontWeight: 500 }}>Mark all as read</span>
            )}
          </div>
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {notifications.length === 0 ? (
              <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>No notifications</div>
            ) : notifications.map(n => (
              <div key={n.id} onClick={() => markRead(n.id)} style={{ padding: '16px', borderBottom: '1px solid var(--border-subtle)', background: isRead(n.id) ? 'transparent' : 'var(--bg-surface)', cursor: 'pointer', transition: 'background 0.2s' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <div style={{ fontSize: '13px', fontWeight: isRead(n.id) ? 500 : 600, color: 'var(--text-main)', paddingRight: '12px' }}>{n.title}</div>
                  {!isRead(n.id) && <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--blue)', flexShrink: 0, marginTop: '4px' }}></div>}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{n.time}</div>
              </div>
            ))}
          </div>
          <div style={{ padding: '12px', textAlign: 'center', borderTop: '1px solid var(--border-subtle)', background: 'var(--bg-surface)' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-main)', cursor: 'pointer', fontWeight: 500 }}>View all notifications</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default NotificationMenu;
