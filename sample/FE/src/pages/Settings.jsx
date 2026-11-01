import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { updatePassword } from '../js/api';
import '../css/style.css';

const inputStyle = {
  width: '100%',
  padding: '16px 20px',
  border: '1px solid var(--border-strong)',
  borderRadius: 12,
  fontFamily: 'inherit',
  fontSize: 15,
  background: 'var(--bg-app)',
  color: 'var(--text-main)',
  outline: 'none',
  boxSizing: 'border-box',
  transition: 'border-color 0.2s',
};

const labelStyle = {
  display: 'block',
  fontSize: 14,
  fontWeight: 600,
  color: 'var(--text-muted)',
  marginBottom: 10,
};

const formGroup = { marginBottom: 26 };

const Settings = () => {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('argus_theme') || 'dark');
  const [keepActive, setKeepActive] = useState(() => localStorage.getItem('argus_keep_active') !== 'false');

  const handleToggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
  };

  const handleToggleKeepActive = () => {
    const nextState = !keepActive;
    setKeepActive(nextState);
    localStorage.setItem('argus_keep_active', String(nextState));
  };

  const handlePasswordUpdate = async (e) => {
    e.preventDefault();
    setPasswordError('');
    setPasswordSuccess('');
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError('All fields are required.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('New password and confirm password do not match.');
      return;
    }
    if (newPassword.length < 6) {
      setPasswordError('New password must be at least 6 characters.');
      return;
    }

    try {
      setIsUpdatingPassword(true);
      const result = await updatePassword(currentPassword, newPassword);
      setPasswordSuccess(result.message || 'Password successfully updated!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setPasswordSuccess(''), 4000);
    } catch (err) {
      setPasswordError(err.message || 'Failed to update password');
    } finally {
      setIsUpdatingPassword(false);
    }
  };

  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <header className="glass-topbar-capsule topbar">
          <div className="glass-topbar-left">
            <h2 className="glass-welcome-title">Settings</h2>
            <p className="glass-welcome-sub">Manage your account preferences and security credentials</p>
          </div>
          <div className="glass-topbar-right topbar-actions">
            <div 
              className="glass-profile-pill user-profile" 
              onClick={() => navigate('/profile')} 
              style={{ cursor: 'pointer' }}
              title="View My Profile"
            >
              <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}</div>
              <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'User'}</span>
            </div>
          </div>
        </header>

        <div 
          className="dashboard-scroll" 
          style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center', 
            justifyContent: 'center', 
            minHeight: 'calc(100vh - 160px)', 
            width: '100%',
            boxSizing: 'border-box',
            padding: '20px 0'
          }}
        >
          <div style={{ maxWidth: 940, width: '100%', margin: '0 auto', padding: '0 16px', boxSizing: 'border-box' }}>
            {/* System & Session Preferences Card */}
            <div className="panel-card" style={{ padding: '36px 48px', borderRadius: 24, boxShadow: '0 8px 32px rgba(0, 0, 0, 0.08)', marginBottom: 28 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                <div style={{ width: 44, height: 44, borderRadius: 12, background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--glass-dash-text-main)', margin: 0 }}>System & Session Preferences</h3>
                  <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 4 }}>Configure appearance and workstation session persistence.</p>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
                {/* Theme Toggle Card */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderRadius: 14, background: 'var(--bg-app)', border: '1px solid var(--border-subtle)' }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)', marginBottom: 2 }}>Workspace Theme</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Currently set to {theme === 'dark' ? 'Dark Mode' : 'Light Mode'}</div>
                  </div>
                  <button
                    onClick={handleToggleTheme}
                    className="btn btn-secondary"
                    style={{ padding: '8px 16px', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}
                  >
                    {theme === 'dark' ? (
                      <>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                        Light Mode
                      </>
                    ) : (
                      <>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                        Dark Mode
                      </>
                    )}
                  </button>
                </div>

                {/* Session Keep Active Toggle Card */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderRadius: 14, background: 'var(--bg-app)', border: '1px solid var(--border-subtle)' }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)', marginBottom: 2 }}>Session Keep Active</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{keepActive ? 'Keep session alive across tabs' : 'Tab-scoped session'}</div>
                  </div>
                  <button
                    onClick={handleToggleKeepActive}
                    className="btn btn-secondary"
                    style={{
                      padding: '8px 16px',
                      fontSize: 13,
                      cursor: 'pointer',
                      background: keepActive ? 'rgba(16, 185, 129, 0.15)' : 'var(--bg-card)',
                      color: keepActive ? '#10b981' : 'var(--text-muted)',
                      border: keepActive ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid var(--border-strong)'
                    }}
                  >
                    {keepActive ? 'Enabled' : 'Disabled'}
                  </button>
                </div>
              </div>
            </div>

            {/* Settings Content Card - Change Password */}
            <div className="panel-card" style={{ padding: '52px 56px', borderRadius: 24, boxShadow: '0 8px 32px rgba(0, 0, 0, 0.08)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 28, paddingBottom: 20, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                <div style={{ width: 48, height: 48, borderRadius: 14, background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 20, fontWeight: 700, color: 'var(--glass-dash-text-main)', margin: 0 }}>Change Password</h3>
                  <p style={{ fontSize: 14, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 4 }}>Ensure your account stays secure by using a strong password.</p>
                </div>
              </div>

            {passwordError && (
              <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '12px 16px', borderRadius: 12, fontSize: 13, fontWeight: 500, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                {passwordError}
              </div>
            )}

            {passwordSuccess && (
              <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '12px 16px', borderRadius: 12, fontSize: 13, fontWeight: 500, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 6L9 17l-5-5"/></svg>
                {passwordSuccess}
              </div>
            )}

            <form onSubmit={handlePasswordUpdate}>
              <div style={formGroup}>
                <label style={labelStyle}>Current Password</label>
                <input
                  type="password"
                  style={inputStyle}
                  placeholder="Enter current password"
                  value={currentPassword}
                  onChange={e => setCurrentPassword(e.target.value)}
                />
              </div>

              <div style={formGroup}>
                <label style={labelStyle}>New Password</label>
                <input
                  type="password"
                  style={inputStyle}
                  placeholder="Enter new password (min. 6 characters)"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                />
              </div>

              <div style={formGroup}>
                <label style={labelStyle}>Confirm New Password</label>
                <input
                  type="password"
                  style={inputStyle}
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', marginTop: 36 }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isUpdatingPassword}
                  style={{
                    background: 'var(--blue)',
                    padding: '14px 34px',
                    borderRadius: 9999,
                    fontWeight: 600,
                    fontSize: 15,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    cursor: isUpdatingPassword ? 'not-allowed' : 'pointer',
                    opacity: isUpdatingPassword ? 0.7 : 1,
                    boxShadow: '0 4px 16px rgba(37, 99, 235, 0.35)',
                    transition: 'all 0.2s ease',
                  }}
                >
                  {isUpdatingPassword ? 'Updating Password...' : 'Update Password'}
                </button>
              </div>
            </form>
          </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Settings;