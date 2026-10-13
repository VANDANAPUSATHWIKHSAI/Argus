import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function TemplateSidebarReplica({ themeName, activeTab, onTabChange }) {
  const location = useLocation();

  let user = { name: 'Senior Analyst', role: 'senior_analyst' };
  try {
    const saved = localStorage.getItem('argus_user');
    if (saved) user = JSON.parse(saved);
  } catch(e) {}

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z' },
    { id: 'cases', label: 'Cases', icon: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z' },
    { id: 'evidence', label: 'Evidence Vault', icon: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' },
    { id: 'findings', label: 'Findings Stream', icon: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z' },
    { id: 'graph', label: 'Graph Topology', icon: 'M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z' },
    { id: 'notes', label: 'Case Notes', icon: 'M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7' },
    { id: 'sanitized', label: 'Sanitized Output', icon: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z' },
    { id: 'audit', label: 'Audit Logs', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
    { id: 'settings', label: 'Settings', icon: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z' },
  ];

  return (
    <aside className="argus-sidebar-replica">
      <div>
        {/* ARGUS Logo Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, paddingBottom: 24, marginBottom: 20, borderBottom: '1px solid currentColor', opacity: 0.85 }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
          <div>
            <div style={{ fontWeight: 800, fontSize: '18px', letterSpacing: '-0.02em', lineHeight: 1 }}>ARGUS</div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.12em', opacity: 0.7, marginTop: 2 }}>Digital Forensics</div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: 'none',
                  background: isActive ? (themeName === 'minimal-professional' ? '#2563EB' : themeName === 'technical-minimal' ? '#090D16' : '#111111') : 'transparent',
                  color: isActive ? '#FFFFFF' : 'inherit',
                  fontWeight: isActive ? 700 : 500,
                  fontSize: '13px',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease'
                }}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d={item.icon} />
                </svg>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* User Profile Badge */}
      <div style={{ borderTop: '1px solid currentColor', paddingTop: 16, opacity: 0.9, display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ width: 34, height: 34, borderRadius: '50%', background: '#2563EB', color: '#FFFFFF', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: '13px' }}>
          {user.name ? user.name.charAt(0) : 'A'}
        </div>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, lineHeight: 1.2 }}>{user.name || 'Analyst'}</div>
          <div style={{ fontSize: '11px', opacity: 0.75, textTransform: 'uppercase' }}>{user.role || 'Forensics Lead'}</div>
        </div>
      </div>
    </aside>
  );
}
