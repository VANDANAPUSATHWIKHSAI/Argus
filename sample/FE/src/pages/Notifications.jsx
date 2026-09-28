import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { API_BASE_URL } from '../js/api';
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

        let mockNotifs = [];
        if (isAdmin) {
          mockNotifs = [
            { id: 'mock-a1', title: 'System health check completed successfully', time: '10m ago' },
            { id: 'mock-a2', title: 'New analyst account created: Jane Doe', time: '1h ago' },
            { id: 'mock-a3', title: 'Weekly compliance report generated', time: '2h ago' }
          ];
        } else if (currentUser?.role === 'senior_analyst') {
          mockNotifs = [
            { id: 'mock-s1', title: 'Case ARGUS_952 is ready for final review', time: '5m ago' },
            { id: 'mock-s2', title: 'High severity finding detected in PC-01', time: '20m ago' },
            { id: 'mock-s3', title: 'Agent consensus reached on lateral movement', time: '45m ago' }
          ];
        } else {
          mockNotifs = [
            { id: 'mock-1', title: 'Evidence processing failed — memdump.raw', time: '5m ago' },
            { id: 'mock-2', title: 'Evidence uploaded successfully — PC-01-Security.evtx', time: '12m ago' },
            { id: 'mock-3', title: 'Evidence parsing started — firewall.log', time: '15m ago' }
          ];
        }

        const finalNotifs = [...mockNotifs, ...mapped];
        setNotifications(finalNotifs);
      } catch (e) {
        console.error('Notification load failed:', e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [isAdmin, currentUser?.role]);

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div style={{ padding: '32px 48px', maxWidth: 800, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 28, width: '100%' }}>
          {/* Page Title */}
          <div>
            <h2 style={{ fontFamily: "'Poppins', sans-serif", fontSize: 28, fontWeight: 800, color: 'var(--text-main)', marginBottom: 6 }}>
              Notifications
            </h2>
            <p style={{ fontSize: 14, color: 'var(--text-muted)' }}>
              Recent updates and alerts for your account
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', borderRadius: 16, border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)' }}>
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
