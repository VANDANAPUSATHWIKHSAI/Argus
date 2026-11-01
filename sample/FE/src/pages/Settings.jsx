import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { updatePassword } from '../js/api';
import '../css/style.css';

const inputStyle = {
  width: '100%',
  padding: '12px 16px',
  border: '1px solid var(--border-strong)',
  borderRadius: 8,
  fontFamily: 'inherit',
  fontSize: 14,
  background: 'var(--bg-app)',
  color: 'var(--text-main)',
  outline: 'none',
  boxSizing: 'border-box',
  transition: 'border-color 0.2s',
};

const labelStyle = {
  display: 'block',
  fontSize: 13,
  fontWeight: 600,
  color: 'var(--text-muted)',
  marginBottom: 8,
};

const formGroup = { marginBottom: 24 };

const Settings = () => {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);

  // Appearance & Theme settings
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');
  const [keepActive, setKeepActive] = useState(localStorage.getItem('argus_keep_active') !== 'false');

  const handleThemeChange = (newTheme) => {
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('argus_theme', newTheme);
  };

  const handleKeepActiveToggle = (e) => {
    const val = e.target.checked;
    setKeepActive(val);
    localStorage.setItem('argus_keep_active', val ? 'true' : 'false');
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
            <p className="glass-welcome-sub">Manage your application preferences, session policy, and security credentials</p>
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

        <div className="dashboard-scroll">
          <div style={{ maxWidth: 760, margin: '0 auto', width: '100%', display: 'flex', flexDirection: 'column', gap: 24 }}>
            {/* Quick Profile Link Card */}
            <div 
              style={{ 
                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(30, 41, 59, 0.4) 100%)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: 16,
                padding: '16px 20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 12
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'var(--blue, #3b82f6)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700 }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main, #f8fafc)' }}>
                    Personnel Profile & Security Clearance
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted, #94a3b8)' }}>
                    Manage personal details, contact number, and view your verified capabilities.
                  </div>
                </div>
              </div>
              <button
                onClick={() => navigate('/profile')}
                style={{
                  background: 'var(--blue, #3b82f6)',
                  border: 'none',
                  color: '#fff',
                  padding: '8px 16px',
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Open My Profile →
              </button>
            </div>

            {/* Appearance & Interface Card */}
            <div className="panel-card" style={{ padding: 28, borderRadius: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, paddingBottom: 14, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--glass-dash-text-main)', margin: 0 }}>Appearance & Interface</h3>
                  <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 2 }}>Customize your visual theme and workstation mode</p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)' }}>Theme Preference</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>Choose between high-contrast dark mode and forensic light mode</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    type="button"
                    onClick={() => handleThemeChange('dark')}
                    style={{
                      padding: '8px 16px',
                      borderRadius: 8,
                      fontSize: 13,
                      fontWeight: 600,
                      border: theme === 'dark' ? '2px solid var(--blue, #3b82f6)' : '1px solid var(--border-subtle)',
                      background: theme === 'dark' ? 'var(--blue-soft, rgba(59,130,246,0.15))' : 'var(--bg-app)',
                      color: theme === 'dark' ? 'var(--blue, #3b82f6)' : 'var(--text-muted)',
                      cursor: 'pointer'
                    }}
                  >
                    🌙 Dark Mode
                  </button>
                  <button
                    type="button"
                    onClick={() => handleThemeChange('light')}
                    style={{
                      padding: '8px 16px',
                      borderRadius: 8,
                      fontSize: 13,
                      fontWeight: 600,
                      border: theme === 'light' ? '2px solid var(--blue, #3b82f6)' : '1px solid var(--border-subtle)',
                      background: theme === 'light' ? 'var(--blue-soft, rgba(59,130,246,0.15))' : 'var(--bg-app)',
                      color: theme === 'light' ? 'var(--blue, #3b82f6)' : 'var(--text-muted)',
                      cursor: 'pointer'
                    }}
                  >
                    ☀️ Light Mode
                  </button>
                </div>
              </div>
            </div>

            {/* Session Management Card */}
            <div className="panel-card" style={{ padding: 28, borderRadius: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, paddingBottom: 14, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--glass-dash-text-main)', margin: 0 }}>Session & Security Policy</h3>
                  <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 2 }}>Manage browser persistence and authentication expiration</p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)' }}>Keep Session Active</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>Maintain your session across browser restarts instead of tab-scoping</div>
                </div>
                <label style={{ display: 'inline-flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={keepActive}
                    onChange={handleKeepActiveToggle}
                    style={{ width: 18, height: 18, accentColor: 'var(--blue, #3b82f6)', cursor: 'pointer' }}
                  />
                </label>
              </div>
            </div>

            {/* Authoritative Change Password Card */}
            <div className="panel-card" style={{ padding: 32, borderRadius: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                <div style={{ width: 42, height: 42, borderRadius: 12, background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--glass-dash-text-main)', margin: 0 }}>Change Password</h3>
                  <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 2 }}>Ensure your account stays secure by using a strong, unique password.</p>
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
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                {passwordSuccess}
              </div>
            )}

            <form onSubmit={handlePasswordUpdate}>
              <div style={formGroup}>
                <label style={labelStyle}>Current Password</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Enter current password"
                  style={inputStyle}
                  required
                />
              </div>

              <div style={formGroup}>
                <label style={labelStyle}>New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password (min. 6 characters)"
                  style={inputStyle}
                  required
                />
              </div>

              <div style={formGroup}>
                <label style={labelStyle}>Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  style={inputStyle}
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isUpdatingPassword}
                style={{
                  width: '100%',
                  padding: '14px 20px',
                  background: 'var(--blue, #3b82f6)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: 10,
                  fontSize: 14,
                  fontWeight: 600,
                  cursor: isUpdatingPassword ? 'not-allowed' : 'pointer',
                  opacity: isUpdatingPassword ? 0.7 : 1,
                  transition: 'background 0.2s',
                  marginTop: 10,
                }}
              >
                {isUpdatingPassword ? 'Updating Password...' : 'Update Password'}
              </button>
            </form>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Settings;
