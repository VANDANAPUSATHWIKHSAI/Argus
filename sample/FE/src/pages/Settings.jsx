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
            <div className="glass-profile-pill user-profile">
              <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}</div>
              <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'User'}</span>
            </div>
          </div>
        </header>

        <div className="dashboard-scroll">
          <div style={{ maxWidth: 760, margin: '0 auto', width: '100%' }}>
            {/* Settings Content Card - Change Password */}
            <div className="panel-card" style={{ padding: 36, borderRadius: 22 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                <div style={{ width: 42, height: 42, borderRadius: 12, background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <div>
                  <h3 style={{ fontSize: 18, fontWeight: 700, color: 'var(--glass-dash-text-main)', margin: 0 }}>Change Password</h3>
                  <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 2 }}>Ensure your account stays secure by using a strong password.</p>
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

              <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', marginTop: 32 }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isUpdatingPassword}
                  style={{
                    background: 'var(--blue)',
                    padding: '12px 28px',
                    borderRadius: 9999,
                    fontWeight: 600,
                    fontSize: 14,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    cursor: isUpdatingPassword ? 'not-allowed' : 'pointer',
                    opacity: isUpdatingPassword ? 0.7 : 1,
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