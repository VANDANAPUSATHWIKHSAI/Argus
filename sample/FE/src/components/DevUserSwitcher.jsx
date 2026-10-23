import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin } from '../js/api';

const DEV_USERS = [
  {
    id: 'admin',
    label: 'Admin',
    icon: '👑',
    role: 'admin',
    desc: 'System Admin'
  },
  {
    id: 'analyst',
    label: 'Analyst',
    icon: '🔍',
    role: 'analyst',
    desc: 'Junior Analyst'
  },
  {
    id: 'senior_analyst',
    label: 'Senior Analyst',
    icon: '🧠',
    role: 'senior_analyst',
    desc: 'Senior Reviewer'
  },
  {
    id: 'auditor',
    label: 'Auditor',
    icon: '📋',
    role: 'auditor',
    desc: 'Compliance Auditor'
  }
];

export default function DevUserSwitcher() {
  const [isOpen, setIsOpen] = useState(false);
  const [switchingTo, setSwitchingTo] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  let currentUser = null;
  try {
    currentUser = JSON.parse(localStorage.getItem('argus_user'));
  } catch (e) {}

  const handleSwitchUser = async (userConfig) => {
    setSwitchingTo(userConfig.id);
    setError(null);
    try {
      // Authenticate directly against backend
      const data = await apiLogin(userConfig.id, 'password123');
      localStorage.setItem('argus_token', data.token);
      localStorage.setItem('argus_user', JSON.stringify(data.user));
      
      // Clear active case selection on role switch so the new role re-initializes clean
      localStorage.removeItem('active_case_id');
      localStorage.removeItem('active_case_name');

      setIsOpen(false);
      
      // Reload to dashboard to re-initialize the UI with the selected role context
      window.location.href = '/dashboard';
    } catch (err) {
      console.error('Dev switch failed:', err);
      setError(err.message || 'Failed to switch user');
      setSwitchingTo(null);
    }
  };

  const currentRole = currentUser?.role || 'Guest';

  return (
    <div
      style={{
        position: 'fixed',
        bottom: '20px',
        right: '24px',
        zIndex: 999999,
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif'
      }}
    >
      {/* EXPANDED MENU */}
      {isOpen && (
        <div
          style={{
            position: 'absolute',
            bottom: '56px',
            right: '0',
            width: '260px',
            background: 'rgba(15, 23, 42, 0.95)',
            backdropFilter: 'blur(16px)',
            WebkitBackdropFilter: 'blur(16px)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            boxShadow: '0 12px 36px rgba(0, 0, 0, 0.5), 0 0 20px rgba(59, 130, 246, 0.2)',
            borderRadius: '14px',
            padding: '14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            color: '#f8fafc',
            animation: 'fadeIn 0.15s ease-out'
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
              paddingBottom: '8px',
              marginBottom: '4px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '13px', fontWeight: '700', color: '#60a5fa', letterSpacing: '0.5px' }}>
                ⚡ DEV ROLE SWITCHER
              </span>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#94a3b8',
                cursor: 'pointer',
                fontSize: '16px',
                padding: '0 4px',
                lineHeight: 1
              }}
            >
              ✕
            </button>
          </div>

          <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '4px' }}>
            Current: <strong style={{ color: '#38bdf8', textTransform: 'capitalize' }}>{currentRole.replace('_', ' ')}</strong>
          </div>

          {error && (
            <div style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', color: '#fca5a5', fontSize: '11px', padding: '6px', borderRadius: '6px' }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {DEV_USERS.map((u) => {
              const isActive = currentUser?.role === u.role;
              const isCurrentSwitching = switchingTo === u.id;

              return (
                <button
                  key={u.id}
                  disabled={isCurrentSwitching}
                  onClick={() => handleSwitchUser(u)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    border: isActive
                      ? '1px solid #3b82f6'
                      : '1px solid rgba(255, 255, 255, 0.08)',
                    background: isActive
                      ? 'rgba(59, 130, 246, 0.25)'
                      : 'rgba(30, 41, 59, 0.7)',
                    color: isActive ? '#93c5fd' : '#e2e8f0',
                    cursor: isCurrentSwitching ? 'wait' : 'pointer',
                    transition: 'all 0.15s ease',
                    textAlign: 'left'
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) e.currentTarget.style.background = 'rgba(59, 130, 246, 0.15)';
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) e.currentTarget.style.background = 'rgba(30, 41, 59, 0.7)';
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '16px' }}>{u.icon}</span>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: '600' }}>{u.label}</div>
                      <div style={{ fontSize: '10px', color: '#94a3b8' }}>{u.desc}</div>
                    </div>
                  </div>

                  {isActive && (
                    <span
                      style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        backgroundColor: '#10b981',
                        boxShadow: '0 0 8px #10b981'
                      }}
                    />
                  )}
                  {isCurrentSwitching && (
                    <span style={{ fontSize: '11px', color: '#60a5fa' }}>...</span>
                  )}
                </button>
              );
            })}
          </div>

          <div
            style={{
              marginTop: '4px',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)',
              paddingTop: '6px',
              fontSize: '10px',
              color: '#64748b',
              textAlign: 'center'
            }}
          >
            Development Only • Auto-auth with password123
          </div>
        </div>
      )}

      {/* TRIGGER FLOATING PILL */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 16px',
          borderRadius: '9999px',
          background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
          border: '1px solid rgba(59, 130, 246, 0.4)',
          color: '#f8fafc',
          boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4), 0 0 12px rgba(59, 130, 246, 0.25)',
          cursor: 'pointer',
          fontWeight: '600',
          fontSize: '12px',
          letterSpacing: '0.3px',
          transition: 'transform 0.15s ease, box-shadow 0.15s ease'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'translateY(-2px)';
          e.currentTarget.style.boxShadow = '0 6px 20px rgba(0, 0, 0, 0.5), 0 0 16px rgba(59, 130, 246, 0.4)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'translateY(0px)';
          e.currentTarget.style.boxShadow = '0 4px 16px rgba(0, 0, 0, 0.4), 0 0 12px rgba(59, 130, 246, 0.25)';
        }}
      >
        <span style={{ fontSize: '14px' }}>⚡</span>
        <span>
          Dev Switcher (<strong style={{ color: '#38bdf8', textTransform: 'capitalize' }}>{currentRole.replace('_', ' ')}</strong>)
        </span>
        <span style={{ fontSize: '10px', color: '#94a3b8' }}>{isOpen ? '▼' : '▲'}</span>
      </button>
    </div>
  );
}
