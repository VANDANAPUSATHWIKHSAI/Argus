import React, { useState, useRef, useEffect } from 'react';

const NotificationMenu = () => {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const [notifications, setNotifications] = useState([
    { id: 1, title: 'Case ARGUS_786 created successfully', time: '5m ago', read: false },
    { id: 2, title: 'Evidence upload completed for device A', time: '1h ago', read: false },
    { id: 3, title: 'System audit log exported', time: '2h ago', read: true },
  ]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const markAllRead = () => {
    setNotifications(notifications.map(n => ({ ...n, read: true })));
  };

  const toggleRead = (id) => {
    setNotifications(notifications.map(n => 
      n.id === id ? { ...n, read: !n.read } : n
    ));
  };

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
        <div style={{ 
          position: 'absolute', 
          top: '100%', 
          right: 0, 
          marginTop: '12px', 
          width: '320px', 
          background: 'var(--bg-card)', 
          border: '1px solid var(--border-strong)', 
          borderRadius: '12px', 
          boxShadow: '0 10px 40px rgba(0,0,0,0.6)', 
          zIndex: 1000,
          overflow: 'hidden'
        }}>
          <div style={{ padding: '16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--text-main)' }}>Notifications</h3>
            {unreadCount > 0 && (
              <span onClick={markAllRead} style={{ fontSize: '12px', color: 'var(--blue)', cursor: 'pointer', fontWeight: 500 }}>Mark all as read</span>
            )}
          </div>
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {notifications.map(n => (
              <div 
                key={n.id} 
                onClick={() => toggleRead(n.id)}
                style={{ 
                  padding: '16px', 
                  borderBottom: '1px solid var(--border-subtle)', 
                  background: n.read ? 'transparent' : 'var(--bg-surface)',
                  cursor: 'pointer',
                  transition: 'background 0.2s'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <div style={{ fontSize: '13px', fontWeight: n.read ? 500 : 600, color: 'var(--text-main)', paddingRight: '12px' }}>{n.title}</div>
                  {!n.read && <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--blue)', flexShrink: 0, marginTop: '4px' }}></div>}
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
