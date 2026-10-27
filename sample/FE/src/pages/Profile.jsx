import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import NotificationMenu from '../components/NotificationMenu';
import { fetchCurrentUserProfile, updateCurrentUserProfile, updatePassword, getActiveTenantId } from '../js/api';
import { getAuthUser } from '../js/authSession';
import '../css/style.css';

const Profile = () => {
  const navigate = useNavigate();

  // Local state for user profile - initialized from auth session
  const [profile, setProfile] = useState(() => {
    return getAuthUser() || {
      id: 'user',
      name: 'Forensic Investigator',
      email: 'user@argus.local',
      role: 'analyst',
      phone: '+1-555-0101',
      doj: '2025-01-15'
    };
  });

  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState('');
  const [theme, setTheme] = useState(() => localStorage.getItem('argus_theme') || 'dark');

  // Edit mode state
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const [editEmail, setEditEmail] = useState('');
  const [editPhone, setEditPhone] = useState('');
  const [saveLoading, setSaveLoading] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState('');
  const [saveError, setSaveError] = useState('');

  // Password update state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwdLoading, setPwdLoading] = useState(false);
  const [pwdSuccess, setPwdSuccess] = useState('');
  const [pwdError, setPwdError] = useState('');

  // Active tab in profile: 'overview' | 'permissions' | 'security'
  const [activeTab, setActiveTab] = useState('overview');
  const [copiedBadge, setCopiedBadge] = useState(false);

  // Sync theme
  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('argus_theme', next);
    document.documentElement.setAttribute('data-theme', next);
  };

  // Listen for external theme changes
  useEffect(() => {
    const handleStorageChange = () => {
      const currentTheme = localStorage.getItem('argus_theme') || 'dark';
      setTheme(currentTheme);
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  // Load profile from API
  const loadProfile = async () => {
    try {
      setLoading(true);
      setApiError('');
      const data = await fetchCurrentUserProfile();
      if (data) {
        setProfile(data);
        setEditName(data.name || '');
        setEditEmail(data.email || '');
        setEditPhone(data.phone || '');

        // Sync with localStorage
        const storedUser = getAuthUser() || {};
        const updatedUser = {
          ...storedUser,
          id: data.id,
          name: data.name,
          email: data.email,
          role: data.role,
          phone: data.phone,
          doj: data.doj
        };
        localStorage.setItem('argus_user', JSON.stringify(updatedUser));
        window.dispatchEvent(new CustomEvent('argus:userChanged', { detail: updatedUser }));
      }
    } catch (err) {
      console.error('Failed to load profile from API:', err);
      setApiError(err.message || 'Unable to sync live profile from server');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProfile();
  }, []);

  // Handle Profile Update
  const handleProfileSave = async (e) => {
    e.preventDefault();
    setSaveError('');
    setSaveSuccess('');

    if (!editName.trim()) {
      setSaveError('Full Name is required.');
      return;
    }
    if (!editEmail.trim()) {
      setSaveError('Email Address is required.');
      return;
    }

    try {
      setSaveLoading(true);
      const updated = await updateCurrentUserProfile({
        name: editName.trim(),
        email: editEmail.trim(),
        phone: editPhone.trim()
      });

      setProfile(updated);
      setSaveSuccess('Profile details successfully updated!');
      setIsEditing(false);

      // Sync across app
      const storedUser = getAuthUser() || {};
      const updatedUser = {
        ...storedUser,
        id: updated.id,
        name: updated.name,
        email: updated.email,
        role: updated.role,
        phone: updated.phone,
        doj: updated.doj
      };
      localStorage.setItem('argus_user', JSON.stringify(updatedUser));
      window.dispatchEvent(new CustomEvent('argus:userChanged', { detail: updatedUser }));

      setTimeout(() => setSaveSuccess(''), 4000);
    } catch (err) {
      setSaveError(err.message || 'Failed to update profile');
    } finally {
      setSaveLoading(false);
    }
  };

  // Handle Password Update
  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setPwdError('');
    setPwdSuccess('');

    if (!currentPassword || !newPassword || !confirmPassword) {
      setPwdError('All fields are required.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwdError('New password and confirmation do not match.');
      return;
    }
    if (newPassword.length < 6) {
      setPwdError('New password must be at least 6 characters.');
      return;
    }

    try {
      setPwdLoading(true);
      const res = await updatePassword(currentPassword, newPassword);
      setPwdSuccess(res.message || 'Password successfully updated!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setPwdSuccess(''), 4000);
    } catch (err) {
      setPwdError(err.message || 'Failed to update password');
    } finally {
      setPwdLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedBadge(true);
      setTimeout(() => setCopiedBadge(false), 2000);
    }
  };

  const roleName = profile?.role ? profile.role.replace('_', ' ') : 'Analyst';
  const roleDisplayTitle = profile?.title || (
    profile?.role === 'admin' ? 'System Administrator' :
    profile?.role === 'senior_analyst' ? 'Senior Forensic Reviewer' :
    profile?.role === 'auditor' ? 'Compliance Auditor' :
    'Digital Forensics Investigator'
  );

  const clearanceLabel = profile?.clearance_level || (
    profile?.role === 'admin' ? 'Level 5 - Autonomous System Administrator' :
    profile?.role === 'senior_analyst' ? 'Level 4 - Advanced Case Review & Verification' :
    profile?.role === 'auditor' ? 'Level 2 - Independent Compliance Verification' :
    'Level 3 - Evidence Ingestion & Artifact Preprocessing'
  );

  const badgeId = profile?.badge_id || `SEC-${(profile?.role || 'ANA').slice(0, 3).toUpperCase()}-${String(profile?.id || '001').toUpperCase()}`;
  const department = profile?.department || 'Digital Forensics & Incident Response Division';
  const tenantId = getActiveTenantId();
  const keepActiveSetting = localStorage.getItem('argus_keep_active') !== 'false' ? 'Persistent Session (Keep Active)' : 'Tab-Scoped Session';

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        {/* TOPBAR CAPSULE */}
        <header className="glass-topbar-capsule topbar">
          <div className="glass-topbar-left">
            <h2 className="glass-welcome-title">My Profile</h2>
            <p className="glass-welcome-sub">Authenticated Personnel Credentials & Security Clearance</p>
          </div>

          <div className="glass-topbar-right topbar-actions">
            {/* Live Case Badge if active */}
            {localStorage.getItem('active_case_id') && (
              <div className="badge-live" title="Active investigation in workspace">
                <div className="live-dot" />
                Live Analysis
              </div>
            )}

            {/* Theme Toggle */}
            <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Dark/Light Mode">
              {theme === 'dark' ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5" /><line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" /><line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" /><line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" /><line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" /></svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" /></svg>
              )}
            </button>

            {/* Notification Menu */}
            <NotificationMenu />

            {/* Profile Avatar Pill */}
            <div className="glass-profile-pill user-profile" style={{ cursor: 'default' }}>
              <div className="glass-profile-avatar-dark avatar">
                {profile?.name ? profile.name.charAt(0).toUpperCase() : 'U'}
              </div>
              <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>
                {profile?.name || 'Investigator'}
              </span>
            </div>
          </div>
        </header>

        {/* PROFILE BODY SCROLL CONTAINER */}
        <div className="dashboard-scroll" style={{ width: '100%', boxSizing: 'border-box' }}>
          <div style={{ maxWidth: 1040, margin: '0 auto', width: '100%', padding: '0 12px 48px' }}>
            
            {/* API Warning/Error if any */}
            {apiError && (
              <div style={{
                background: 'var(--glass-dash-red-soft, rgba(239, 68, 68, 0.12))',
                border: '1px solid var(--glass-dash-red-border, rgba(239, 68, 68, 0.3))',
                color: 'var(--glass-dash-red, #ef4444)',
                padding: '12px 18px',
                borderRadius: 14,
                marginBottom: 20,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: 13
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                  <span>{apiError} (Displaying cached session data)</span>
                </div>
                <button
                  onClick={loadProfile}
                  style={{
                    background: 'var(--glass-dash-red, #ef4444)',
                    border: 'none',
                    color: '#fff',
                    padding: '4px 12px',
                    borderRadius: 6,
                    cursor: 'pointer',
                    fontSize: 12
                  }}
                >
                  Retry Sync
                </button>
              </div>
            )}

            {/* ── 1. IDENTITY & CLEARANCE HERO CARD ── */}
            <div className="glass-profile-hero">
              {/* Background ambient badge watermark */}
              <div
                style={{
                  position: 'absolute',
                  right: -20,
                  top: -20,
                  width: 240,
                  height: 240,
                  borderRadius: '50%',
                  background: 'radial-gradient(circle, var(--glass-dash-blue-soft, rgba(59, 130, 246, 0.15)) 0%, transparent 70%)',
                  pointerEvents: 'none',
                  zIndex: 0
                }}
              />

              <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 24 }}>
                {/* User Avatar + Identity Meta */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
                  <div style={{ position: 'relative' }}>
                    <div
                      style={{
                        width: 88,
                        height: 88,
                        borderRadius: '50%',
                        background: 'linear-gradient(135deg, var(--glass-dash-blue, #3b82f6) 0%, #1d4ed8 100%)',
                        color: '#ffffff',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 34,
                        fontWeight: 800,
                        boxShadow: '0 8px 24px rgba(59, 130, 246, 0.35)',
                        border: '3px solid var(--glass-dash-border, rgba(255, 255, 255, 0.4))',
                        textTransform: 'uppercase'
                      }}
                    >
                      {profile?.name ? profile.name.charAt(0) : 'U'}
                    </div>
                    {/* Live Online Pip */}
                    <span
                      title="Authenticated & Active"
                      style={{
                        position: 'absolute',
                        bottom: 4,
                        right: 4,
                        width: 18,
                        height: 18,
                        borderRadius: '50%',
                        backgroundColor: '#10b981',
                        border: theme === 'light' ? '3px solid #ffffff' : '3px solid #181a20',
                        boxShadow: '0 0 10px #10b981'
                      }}
                    />
                  </div>

                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                      <h1 style={{ fontSize: 26, fontWeight: 800, margin: 0, color: 'var(--glass-dash-text-main)', letterSpacing: '-0.02em' }}>
                        {profile?.name || 'Investigator'}
                      </h1>
                      <span
                        style={{
                          background: 'var(--glass-dash-blue-soft, rgba(59, 130, 246, 0.12))',
                          border: '1px solid var(--glass-dash-blue-border, rgba(59, 130, 246, 0.35))',
                          color: 'var(--glass-dash-blue, #2563eb)',
                          padding: '3px 12px',
                          borderRadius: 9999,
                          fontSize: 12,
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          letterSpacing: '0.05em'
                        }}
                      >
                        {roleName}
                      </span>
                    </div>

                    <p style={{ margin: '6px 0 12px', fontSize: 15, color: 'var(--glass-dash-text-muted)', fontWeight: 500 }}>
                      {roleDisplayTitle}
                    </p>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', fontSize: 13, color: 'var(--glass-dash-text-dim)' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--glass-dash-text-secondary)' }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="7" width="20" height="14" rx="2" ry="2" /><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" /></svg>
                        {department}
                      </span>
                      <span>•</span>
                      <span
                        onClick={() => copyToClipboard(badgeId)}
                        style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--glass-dash-blue)' }}
                        title="Click to copy Badge ID"
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                        Badge: {badgeId} {copiedBadge && <span style={{ color: 'var(--glass-dash-green)', fontSize: 11 }}>✓ Copied</span>}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Right Status Actions */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 12 }}>
                  <div
                    style={{
                      background: 'var(--glass-dash-green-soft, rgba(16, 185, 129, 0.12))',
                      border: '1px solid var(--glass-dash-green-border, rgba(16, 185, 129, 0.35))',
                      color: 'var(--glass-dash-green, #10b981)',
                      padding: '8px 16px',
                      borderRadius: 12,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: 13,
                      fontWeight: 600
                    }}
                  >
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
                    Clearance: Active
                  </div>

                  <button
                    onClick={() => {
                      setIsEditing(!isEditing);
                      setSaveError('');
                      setSaveSuccess('');
                      if (!isEditing) {
                        setEditName(profile?.name || '');
                        setEditEmail(profile?.email || '');
                        setEditPhone(profile?.phone || '');
                      }
                    }}
                    style={{
                      background: isEditing ? 'var(--glass-dash-red-soft, rgba(239, 68, 68, 0.15))' : 'var(--glass-dash-blue, #3b82f6)',
                      border: isEditing ? '1px solid var(--glass-dash-red-border, rgba(239, 68, 68, 0.4))' : 'none',
                      color: isEditing ? 'var(--glass-dash-red, #ef4444)' : '#ffffff',
                      padding: '8px 18px',
                      borderRadius: 10,
                      fontSize: 13,
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      transition: 'all 0.2s ease',
                      boxShadow: '0 4px 12px rgba(37, 99, 235, 0.25)'
                    }}
                  >
                    {isEditing ? (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                        Cancel Edit
                      </>
                    ) : (
                      <>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg>
                        Edit Profile
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Success / Error Banners for Profile Edit */}
            {saveSuccess && (
              <div style={{
                background: 'var(--glass-dash-green-soft, rgba(16, 185, 129, 0.15))',
                border: '1px solid var(--glass-dash-green-border, rgba(16, 185, 129, 0.4))',
                color: 'var(--glass-dash-green, #10b981)',
                padding: '12px 18px',
                borderRadius: 12,
                fontSize: 14,
                fontWeight: 600,
                marginBottom: 20,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                animation: 'fadeIn 0.2s ease-out'
              }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 6L9 17l-5-5" /></svg>
                {saveSuccess}
              </div>
            )}
            {saveError && (
              <div style={{
                background: 'var(--glass-dash-red-soft, rgba(239, 68, 68, 0.15))',
                border: '1px solid var(--glass-dash-red-border, rgba(239, 68, 68, 0.4))',
                color: 'var(--glass-dash-red, #ef4444)',
                padding: '12px 18px',
                borderRadius: 12,
                fontSize: 14,
                fontWeight: 600,
                marginBottom: 20,
                display: 'flex',
                alignItems: 'center',
                gap: 10
              }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                {saveError}
              </div>
            )}

            {/* ── 2. TAB NAVIGATION ── */}
            <div className="glass-profile-tab-bar">
              <button
                onClick={() => setActiveTab('overview')}
                className={`glass-profile-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                Personal Credentials
              </button>


              <button
                onClick={() => setActiveTab('security')}
                className={`glass-profile-tab-btn ${activeTab === 'security' ? 'active' : ''}`}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                Security & Password
              </button>
            </div>

            {/* ── TAB 1: PERSONAL CREDENTIALS / OVERVIEW ── */}
            {activeTab === 'overview' && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 24 }}>
                {/* Details / Edit Form Card */}
                <div className="glass-profile-section-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                    <h3 className="glass-profile-heading">
                      Personnel Details
                    </h3>
                    <span style={{ fontSize: 12, color: 'var(--glass-dash-text-muted)' }}>
                      {isEditing ? 'Editing Mode' : 'Read-Only Verification'}
                    </span>
                  </div>

                  {isEditing ? (
                    <form onSubmit={handleProfileSave}>
                      <div style={{ marginBottom: 18 }}>
                        <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 6 }}>
                          Full Name *
                        </label>
                        <input
                          type="text"
                          className="glass-profile-input"
                          value={editName}
                          onChange={(e) => setEditName(e.target.value)}
                          required
                        />
                      </div>

                      <div style={{ marginBottom: 18 }}>
                        <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 6 }}>
                          Official Email Address *
                        </label>
                        <input
                          type="email"
                          className="glass-profile-input"
                          value={editEmail}
                          onChange={(e) => setEditEmail(e.target.value)}
                          required
                        />
                      </div>

                      <div style={{ marginBottom: 24 }}>
                        <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 6 }}>
                          Contact Phone Number
                        </label>
                        <input
                          type="tel"
                          className="glass-profile-input"
                          value={editPhone}
                          onChange={(e) => setEditPhone(e.target.value)}
                          placeholder="+1-555-0100"
                        />
                      </div>

                      <div style={{ display: 'flex', gap: 12 }}>
                        <button
                          type="submit"
                          disabled={saveLoading}
                          style={{
                            background: 'var(--glass-dash-blue, #3b82f6)',
                            border: 'none',
                            color: '#ffffff',
                            padding: '10px 22px',
                            borderRadius: 10,
                            fontSize: 14,
                            fontWeight: 600,
                            cursor: saveLoading ? 'not-allowed' : 'pointer',
                            opacity: saveLoading ? 0.7 : 1,
                            boxShadow: '0 4px 12px rgba(37, 99, 235, 0.25)'
                          }}
                        >
                          {saveLoading ? 'Saving...' : 'Save Changes'}
                        </button>
                        <button
                          type="button"
                          onClick={() => setIsEditing(false)}
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--glass-dash-border-subtle)',
                            color: 'var(--glass-dash-text-muted)',
                            padding: '10px 18px',
                            borderRadius: 10,
                            fontSize: 14,
                            fontWeight: 600,
                            cursor: 'pointer'
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </form>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                      <div className="glass-profile-row">
                        <span className="glass-profile-label">Account Identifier</span>
                        <span className="glass-profile-val" style={{ fontFamily: 'monospace' }}>
                          {profile?.id}
                        </span>
                      </div>

                      <div className="glass-profile-row">
                        <span className="glass-profile-label">Full Legal Name</span>
                        <span className="glass-profile-val">
                          {profile?.name}
                        </span>
                      </div>

                      <div className="glass-profile-row">
                        <span className="glass-profile-label">Email Address</span>
                        <span className="glass-profile-val" style={{ color: 'var(--glass-dash-blue)' }}>
                          {profile?.email}
                        </span>
                      </div>

                      <div className="glass-profile-row">
                        <span className="glass-profile-label">Phone Contact</span>
                        <span className="glass-profile-val">
                          {profile?.phone || 'Not Registered'}
                        </span>
                      </div>

                      <div className="glass-profile-row">
                        <span className="glass-profile-label">Date of Commission</span>
                        <span className="glass-profile-val">
                          {profile?.doj || '2025-01-15'}
                        </span>
                      </div>

                      <div className="glass-profile-row">
                        <span className="glass-profile-label">Organization Unit</span>
                        <span className="glass-profile-val">
                          {department}
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Operational Session Telemetry Card */}
                <div className="glass-profile-section-card">
                  <h3 className="glass-profile-heading" style={{ marginBottom: 20 }}>
                    Session Telemetry & Environment
                  </h3>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div className="glass-profile-nested-box">
                      <div style={{ fontSize: 12, color: 'var(--glass-dash-text-muted)', marginBottom: 4 }}>
                        Tenant Identifier
                      </div>
                      <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--glass-dash-text-main)', fontFamily: 'monospace' }}>
                        {tenantId}
                      </div>
                    </div>

                    <div className="glass-profile-nested-box">
                      <div style={{ fontSize: 12, color: 'var(--glass-dash-text-muted)', marginBottom: 4 }}>
                        Session Persistence Policy
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--glass-dash-text-main)' }}>
                        {keepActiveSetting}
                      </div>
                    </div>

                    <div className="glass-profile-nested-box">
                      <div style={{ fontSize: 12, color: 'var(--glass-dash-text-muted)', marginBottom: 4 }}>
                        Authentication Protocol
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--glass-dash-green)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} />
                        JWT Bearer Token • HS256 Verified
                      </div>
                    </div>

                    {/* Quick navigation links */}
                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 10 }}>
                        Quick Navigation
                      </div>
                      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                        <button
                          onClick={() => navigate('/dashboard')}
                          style={{
                            background: 'var(--glass-dash-blue-soft, rgba(59, 130, 246, 0.1))',
                            border: '1px solid var(--glass-dash-blue-border, rgba(59, 130, 246, 0.3))',
                            color: 'var(--glass-dash-blue, #2563eb)',
                            padding: '6px 14px',
                            borderRadius: 8,
                            fontSize: 13,
                            fontWeight: 600,
                            cursor: 'pointer'
                          }}
                        >
                          Dashboard →
                        </button>
                        {profile?.role === 'admin' && (
                          <button
                            onClick={() => navigate('/cases')}
                            style={{
                              background: 'var(--glass-dash-surface-nested)',
                              border: '1px solid var(--glass-dash-border-subtle)',
                              color: 'var(--glass-dash-text-main)',
                              padding: '6px 14px',
                              borderRadius: 8,
                              fontSize: 13,
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            Cases →
                          </button>
                        )}
                        {(profile?.role === 'analyst' || profile?.role === 'senior_analyst') && (
                          <button
                            onClick={() => navigate('/evidence')}
                            style={{
                              background: 'var(--glass-dash-surface-nested)',
                              border: '1px solid var(--glass-dash-border-subtle)',
                              color: 'var(--glass-dash-text-main)',
                              padding: '6px 14px',
                              borderRadius: 8,
                              fontSize: 13,
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            Evidence →
                          </button>
                        )}
                        <button
                          onClick={() => navigate('/settings')}
                          style={{
                            background: 'var(--glass-dash-surface-nested)',
                            border: '1px solid var(--glass-dash-border-subtle)',
                            color: 'var(--glass-dash-text-main)',
                            padding: '6px 14px',
                            borderRadius: 8,
                            fontSize: 13,
                            fontWeight: 600,
                            cursor: 'pointer'
                          }}
                        >
                          Settings →
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}


            {/* ── TAB 3: SECURITY & PASSWORD MANAGEMENT ── */}
            {activeTab === 'security' && (
              <div style={{ maxWidth: 640, margin: '0 auto' }}>
                <div className="glass-profile-section-card" style={{ padding: 32 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                    <div style={{
                      width: 44,
                      height: 44,
                      borderRadius: 12,
                      background: 'var(--glass-dash-blue-soft, rgba(59, 130, 246, 0.15))',
                      color: 'var(--glass-dash-blue, #2563eb)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                    </div>
                    <div>
                      <h3 className="glass-profile-heading" style={{ fontSize: 18 }}>
                        Update Access Credentials
                      </h3>
                      <p style={{ fontSize: 13, color: 'var(--glass-dash-text-muted)', margin: 0, marginTop: 2 }}>
                        Ensure your investigator account password adheres to security protocols.
                      </p>
                    </div>
                  </div>

                  {pwdSuccess && (
                    <div style={{
                      background: 'var(--glass-dash-green-soft, rgba(16, 185, 129, 0.15))',
                      border: '1px solid var(--glass-dash-green-border, rgba(16, 185, 129, 0.4))',
                      color: 'var(--glass-dash-green, #10b981)',
                      padding: '12px 16px',
                      borderRadius: 10,
                      fontSize: 13,
                      fontWeight: 600,
                      marginBottom: 20,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10
                    }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 6L9 17l-5-5" /></svg>
                      {pwdSuccess}
                    </div>
                  )}

                  {pwdError && (
                    <div style={{
                      background: 'var(--glass-dash-red-soft, rgba(239, 68, 68, 0.15))',
                      border: '1px solid var(--glass-dash-red-border, rgba(239, 68, 68, 0.4))',
                      color: 'var(--glass-dash-red, #ef4444)',
                      padding: '12px 16px',
                      borderRadius: 10,
                      fontSize: 13,
                      fontWeight: 600,
                      marginBottom: 20,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10
                    }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                      {pwdError}
                    </div>
                  )}

                  <form onSubmit={handlePasswordSubmit}>
                    <div style={{ marginBottom: 18 }}>
                      <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 6 }}>
                        Current Password
                      </label>
                      <input
                        type="password"
                        className="glass-profile-input"
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        placeholder="Enter current password"
                      />
                    </div>

                    <div style={{ marginBottom: 18 }}>
                      <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 6 }}>
                        New Password (minimum 6 characters)
                      </label>
                      <input
                        type="password"
                        className="glass-profile-input"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="Enter new password"
                      />
                    </div>

                    <div style={{ marginBottom: 24 }}>
                      <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--glass-dash-text-muted)', marginBottom: 6 }}>
                        Confirm New Password
                      </label>
                      <input
                        type="password"
                        className="glass-profile-input"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Confirm new password"
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={pwdLoading}
                      style={{
                        background: 'var(--glass-dash-blue, #3b82f6)',
                        border: 'none',
                        color: '#ffffff',
                        padding: '12px 28px',
                        borderRadius: 10,
                        fontSize: 14,
                        fontWeight: 600,
                        cursor: pwdLoading ? 'not-allowed' : 'pointer',
                        opacity: pwdLoading ? 0.7 : 1,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        boxShadow: '0 4px 14px rgba(37, 99, 235, 0.28)'
                      }}
                    >
                      {pwdLoading ? 'Updating Password...' : 'Update Password'}
                    </button>
                  </form>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default Profile;
