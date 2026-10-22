import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { login as apiLogin } from '../js/api';

const DEV_ACCOUNTS = [
  {
    roleKey: 'admin',
    label: 'Admin',
    userid: '2',
    name: 'System Administrator',
    badgeColor: '#ef4444',
    defaultRoute: '/dashboard',
    allowedRoutes: [
      { name: 'Dashboard', path: '/dashboard' },
      { name: 'Previous Cases', path: '/cases' },
      { name: 'Employees', path: '/employees' },
      { name: 'Agents Swarm', path: '/agents' },
      { name: 'Forensic Report', path: '/report' },
      { name: 'Audit Logs', path: '/audit-logs' },
      { name: 'Settings', path: '/settings' },
    ]
  },
  {
    roleKey: 'analyst',
    label: 'Analyst',
    userid: '4',
    name: 'sathwik (Analyst)',
    badgeColor: '#3b82f6',
    defaultRoute: '/dashboard',
    allowedRoutes: [
      { name: 'Dashboard', path: '/dashboard' },
      { name: 'Evidence', path: '/evidence' },
      { name: 'Agents Swarm', path: '/agents' },
      { name: 'AI Assistant', path: '/chatbot' },
      { name: 'Case Notes', path: '/case-notes' },
      { name: 'Sanitized Output', path: '/sanitized' },
      { name: 'Settings', path: '/settings' },
    ]
  },
  {
    roleKey: 'senior_analyst',
    label: 'Senior Analyst',
    userid: '6',
    name: 'Senior Analyst 6',
    badgeColor: '#8b5cf6',
    defaultRoute: '/dashboard',
    allowedRoutes: [
      { name: 'Dashboard', path: '/dashboard' },
      { name: 'Agents Swarm', path: '/agents' },
      { name: 'Chatbot', path: '/chatbot' },
      { name: 'Notes', path: '/case-notes' },
      { name: 'Forensic Report', path: '/report' },
      { name: 'Settings', path: '/settings' },
    ]
  },
  {
    roleKey: 'auditor',
    label: 'Auditor',
    userid: '12',
    name: 'Auditor 12',
    badgeColor: '#10b981',
    defaultRoute: '/report',
    allowedRoutes: [
      { name: 'Forensic Report', path: '/report' }
    ]
  }
];

const DevRoleSwitcher = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [isExpanded, setIsExpanded] = useState(false);
  const [loadingRole, setLoadingRole] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);

  // Sync user state on change or storage events
  useEffect(() => {
    const syncUser = () => {
      try {
        const stored = localStorage.getItem('argus_user');
        setCurrentUser(stored ? JSON.parse(stored) : null);
      } catch (e) {
        setCurrentUser(null);
      }
    };
    syncUser();
    window.addEventListener('storage', syncUser);
    return () => window.removeEventListener('storage', syncUser);
  }, [location.pathname]);

  const handleSwitchRole = async (account, targetPath = null) => {
    setLoadingRole(account.roleKey);
    let loggedInUser = null;
    let token = null;

    // Try API login with candidate user IDs and passwords
    const userIdsToTry = [account.userid, account.roleKey, account.label.toLowerCase().replace(/\s+/g, '_')];
    const passwordsToTry = ['123', 'password123', 'password', 'sathwik', 'admin'];

    for (const uid of userIdsToTry) {
      for (const pwd of passwordsToTry) {
        try {
          const response = await apiLogin(uid, pwd);
          if (response && response.token && response.user) {
            token = response.token;
            loggedInUser = response.user;
            break;
          }
        } catch (e) {
          // ignore error and try next
        }
      }
      if (loggedInUser) break;
    }

    // Fallback for DevRoleSwitcher to guarantee seamless switching even if API is offline or unseeded
    if (!loggedInUser || !token) {
      token = 'dev_role_token_' + Date.now();
      loggedInUser = {
        id: account.userid,
        name: account.name,
        email: `${account.roleKey}@argus.local`,
        role: account.roleKey
      };
    }

    localStorage.setItem('argus_token', token);
    localStorage.setItem('argus_user', JSON.stringify(loggedInUser));
    setCurrentUser(loggedInUser);

    const routeToNavigate = targetPath || account.defaultRoute;
    navigate(routeToNavigate);

    setTimeout(() => {
      window.dispatchEvent(new Event('storage'));
    }, 50);

    setLoadingRole(null);
  };

  const currentRoleKey = currentUser?.role || 'none';
  const currentAccount = DEV_ACCOUNTS.find(a => a.roleKey === currentRoleKey) || {
    label: currentUser ? currentUser.role : 'Guest',
    badgeColor: '#64748b'
  };

  return (
    <div
      style={{
        position: 'fixed',
        bottom: '20px',
        right: '20px',
        zIndex: 99999,
        fontFamily: 'Inter, system-ui, -apple-system, sans-serif'
      }}
    >
      {/* MINIMIZED BADGE / TOGGLE */}
      {!isExpanded ? (
        <button
          onClick={() => setIsExpanded(true)}
          style={{
            background: 'rgba(15, 23, 42, 0.9)',
            border: `1px solid ${currentAccount.badgeColor}`,
            boxShadow: `0 4px 20px rgba(0, 0, 0, 0.5), 0 0 10px ${currentAccount.badgeColor}40`,
            backdropFilter: 'blur(12px)',
            color: '#f8fafc',
            padding: '8px 14px',
            borderRadius: '24px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '13px',
            fontWeight: 600,
            transition: 'all 0.2s ease',
            outline: 'none'
          }}
          title="Click to open Dev Role Switcher"
        >
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: currentAccount.badgeColor,
              boxShadow: `0 0 8px ${currentAccount.badgeColor}`
            }}
          />
          <span style={{ color: '#94a3b8', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            DEV ROLE:
          </span>
          <span style={{ color: '#f1f5f9' }}>{currentAccount.label}</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <polyline points="18 15 12 9 6 15" />
          </svg>
        </button>
      ) : (
        /* EXPANDED DEV PANEL */
        <div
          style={{
            width: '320px',
            background: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6), 0 0 20px rgba(59, 130, 246, 0.15)',
            backdropFilter: 'blur(16px)',
            borderRadius: '16px',
            padding: '16px',
            color: '#f8fafc',
            animation: 'fadeIn 0.2s ease-in-out'
          }}
        >
          {/* HEADER */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
              paddingBottom: '10px',
              marginBottom: '12px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span
                style={{
                  background: 'rgba(59, 130, 246, 0.2)',
                  color: '#60a5fa',
                  padding: '2px 8px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 700,
                  letterSpacing: '0.5px'
                }}
              >
                DEV ONLY
              </span>
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#e2e8f0' }}>Role & Screen Switcher</span>
            </div>
            <button
              onClick={() => setIsExpanded(false)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#94a3b8',
                cursor: 'pointer',
                padding: '4px',
                display: 'flex',
                borderRadius: '4px'
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>

          {/* ACTIVE USER STATUS */}
          <div
            style={{
              background: 'rgba(30, 41, 59, 0.6)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: '8px',
              padding: '10px',
              marginBottom: '14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}
          >
            <div>
              <div style={{ fontSize: '10px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Active Session
              </div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginTop: '2px' }}>
                {currentUser ? `${currentUser.name} (${currentUser.id})` : 'Not Authenticated'}
              </div>
            </div>
            <span
              style={{
                background: `${currentAccount.badgeColor}25`,
                color: currentAccount.badgeColor,
                border: `1px solid ${currentAccount.badgeColor}60`,
                fontSize: '11px',
                fontWeight: 600,
                padding: '3px 8px',
                borderRadius: '12px'
              }}
            >
              {currentAccount.label}
            </span>
          </div>

          {/* ROLES SELECTOR LIST */}
          <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '8px', fontWeight: 600, textTransform: 'uppercase' }}>
            Switch Role & Load Screen
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '240px', overflowY: 'auto' }}>
            {DEV_ACCOUNTS.map(acc => {
              const isActive = currentRoleKey === acc.roleKey;
              const isLoading = loadingRole === acc.roleKey;

              return (
                <div
                  key={acc.roleKey}
                  style={{
                    background: isActive ? 'rgba(59, 130, 246, 0.12)' : 'rgba(30, 41, 59, 0.4)',
                    border: `1px solid ${isActive ? acc.badgeColor : 'rgba(255, 255, 255, 0.08)'}`,
                    borderRadius: '10px',
                    padding: '8px 10px',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span
                        style={{
                          width: '8px',
                          height: '8px',
                          borderRadius: '50%',
                          background: acc.badgeColor,
                          boxShadow: `0 0 6px ${acc.badgeColor}`
                        }}
                      />
                      <span style={{ fontSize: '13px', fontWeight: 600, color: isActive ? '#ffffff' : '#cbd5e1' }}>
                        {acc.label}
                      </span>
                    </div>

                    <button
                      onClick={() => handleSwitchRole(acc)}
                      disabled={isLoading}
                      style={{
                        background: isActive ? acc.badgeColor : 'rgba(255, 255, 255, 0.08)',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '6px',
                        padding: '4px 10px',
                        fontSize: '11px',
                        fontWeight: 600,
                        cursor: isLoading ? 'not-allowed' : 'pointer',
                        opacity: isLoading ? 0.7 : 1,
                        transition: 'all 0.15s ease'
                      }}
                    >
                      {isLoading ? 'Switching...' : isActive ? 'Active' : 'Switch Role'}
                    </button>
                  </div>

                  {/* QUICK SCREEN LINKS FOR THIS ROLE */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                    {acc.allowedRoutes.map(route => (
                      <button
                        key={route.path}
                        onClick={() => handleSwitchRole(acc, route.path)}
                        style={{
                          background: 'rgba(15, 23, 42, 0.6)',
                          border: '1px solid rgba(255, 255, 255, 0.08)',
                          color: location.pathname === route.path && isActive ? '#60a5fa' : '#94a3b8',
                          borderRadius: '4px',
                          padding: '2px 6px',
                          fontSize: '10px',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease'
                        }}
                        onMouseOver={e => {
                          e.currentTarget.style.color = '#f8fafc';
                          e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.2)';
                        }}
                        onMouseOut={e => {
                          e.currentTarget.style.color = location.pathname === route.path && isActive ? '#60a5fa' : '#94a3b8';
                          e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                        }}
                      >
                        → {route.name}
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          <button
            onClick={() => navigate('/templates')}
            style={{
              width: '100%',
              marginTop: '10px',
              background: '#FAF8F5',
              color: '#111111',
              border: '1px solid #FAF8F5',
              borderRadius: '6px',
              padding: '8px 12px',
              fontSize: '11px',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            🎨 Explore 4 White-Themed Templates
          </button>

          <div
            style={{
              marginTop: '12px',
              paddingTop: '8px',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)',
              fontSize: '10px',
              color: '#64748b',
              textAlign: 'center'
            }}
          >
            Password for all dev accounts: <code style={{ color: '#38bdf8' }}>123</code>
          </div>
        </div>
      )}
    </div>
  );
};

export default DevRoleSwitcher;
