import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchCurrentUserProfile, updateCurrentUserProfile } from '../js/api';
import { getAuthUser } from '../js/authSession';

const ProfileModal = ({ isOpen, onClose }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(() => getAuthUser() || {});
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [role, setRole] = useState('Analyst');
  const [clearance, setClearance] = useState('Level 3 - Evidence Ingestion');
  const [badgeId, setBadgeId] = useState('');
  
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    const initialUser = getAuthUser() || {};
    setUser(initialUser);
    setName(initialUser.name || '');
    setEmail(initialUser.email || '');
    setPhone(initialUser.phone || '');
    setRole(initialUser.role || 'analyst');

    fetchCurrentUserProfile()
      .then((data) => {
        if (data) {
          setUser(data);
          setName(data.name || '');
          setEmail(data.email || '');
          setPhone(data.phone || '');
          setRole(data.role || 'analyst');
          setClearance(data.clearance_level || '');
          setBadgeId(data.badge_id || '');
        }
      })
      .catch((err) => {
        console.error('Could not load profile in modal:', err);
      });
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    if (!name.trim()) {
      setErrorMsg('Name cannot be empty');
      return;
    }
    if (!email.trim()) {
      setErrorMsg('Email cannot be empty');
      return;
    }

    try {
      setLoading(true);
      const updated = await updateCurrentUserProfile({
        name: name.trim(),
        email: email.trim(),
        phone: phone.trim()
      });

      setUser(updated);
      setSaved(true);

      // Sync across app
      const stored = getAuthUser() || {};
      const updatedUser = {
        ...stored,
        name: updated.name,
        email: updated.email,
        phone: updated.phone
      };
      localStorage.setItem('argus_user', JSON.stringify(updatedUser));
      window.dispatchEvent(new CustomEvent('argus:userChanged', { detail: updatedUser }));

      setTimeout(() => {
        setSaved(false);
        onClose();
      }, 1000);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to save changes');
    } finally {
      setLoading(false);
    }
  };

  const roleTitle = user?.title || (
    user?.role === 'admin' ? 'System Administrator' :
    user?.role === 'senior_analyst' ? 'Senior Forensic Reviewer' :
    user?.role === 'auditor' ? 'Compliance Auditor' :
    'Digital Forensics Investigator'
  );

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(0, 0, 0, 0.7)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'var(--bg-card, #121826)',
          border: '1px solid var(--border-strong, #1e293b)',
          borderRadius: 20,
          width: '100%',
          maxWidth: 520,
          boxShadow: '0 24px 48px rgba(0, 0, 0, 0.6), 0 0 24px rgba(59, 130, 246, 0.15)',
          overflow: 'hidden',
          animation: 'fadeInScale 0.2s ease-out',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--border-strong, #1e293b)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'linear-gradient(180deg, rgba(30, 41, 59, 0.5) 0%, transparent 100%)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: '50%',
                background: 'linear-gradient(135deg, var(--blue, #3b82f6) 0%, #1d4ed8 100%)',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 800,
                fontSize: 18,
                boxShadow: '0 4px 12px rgba(59, 130, 246, 0.3)',
                textTransform: 'uppercase'
              }}
            >
              {name ? name.charAt(0) : 'U'}
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--text-main, #f8fafc)' }}>
                {name || 'Investigator Profile'}
              </h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted, #cbd5e1)' }}>
                {roleTitle} • ID: {user?.id || '—'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted, #94a3b8)',
              cursor: 'pointer',
              padding: 6,
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        {/* Body Form */}
        <form onSubmit={handleSave} style={{ padding: 24 }}>
          {saved && (
            <div
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                color: '#34d399',
                padding: '10px 14px',
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 600,
                marginBottom: 20,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M20 6L9 17l-5-5"></path>
              </svg>
              Profile details successfully saved!
            </div>
          )}

          {errorMsg && (
            <div
              style={{
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                color: '#f87171',
                padding: '10px 14px',
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 600,
                marginBottom: 20,
              }}
            >
              {errorMsg}
            </div>
          )}

          {/* Name */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--text-muted, #cbd5e1)', marginBottom: 6 }}>
              Full Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 8,
                border: '1px solid var(--border-strong, #334155)',
                background: 'var(--bg-app, #0f1423)',
                color: 'var(--text-main, #f8fafc)',
                fontSize: 14,
                outline: 'none',
                boxSizing: 'border-box',
              }}
              required
            />
          </div>

          {/* Email Address */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--text-muted, #cbd5e1)', marginBottom: 6 }}>
              Official Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 8,
                border: '1px solid var(--border-strong, #334155)',
                background: 'var(--bg-app, #0f1423)',
                color: 'var(--text-main, #f8fafc)',
                fontSize: 14,
                outline: 'none',
                boxSizing: 'border-box',
              }}
              required
            />
          </div>

          {/* Phone */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--text-muted, #cbd5e1)', marginBottom: 6 }}>
              Phone Contact
            </label>
            <input
              type="tel"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+1-555-0100"
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 8,
                border: '1px solid var(--border-strong, #334155)',
                background: 'var(--bg-app, #0f1423)',
                color: 'var(--text-main, #f8fafc)',
                fontSize: 14,
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          </div>

          {/* Role & Clearance */}
          <div style={{ marginBottom: 16, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--text-muted, #cbd5e1)', marginBottom: 6 }}>
                Assigned Role
              </label>
              <input
                type="text"
                value={user?.role ? user.role.replace('_', ' ') : 'Analyst'}
                disabled
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  borderRadius: 8,
                  border: '1px solid var(--border-strong, #334155)',
                  background: 'rgba(30, 41, 59, 0.4)',
                  color: 'var(--text-dim, #94a3b8)',
                  fontSize: 13,
                  textTransform: 'capitalize',
                  boxSizing: 'border-box',
                  cursor: 'not-allowed'
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--text-muted, #cbd5e1)', marginBottom: 6 }}>
                Commission Date
              </label>
              <input
                type="text"
                value={user?.doj || '2025-01-15'}
                disabled
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  borderRadius: 8,
                  border: '1px solid var(--border-strong, #334155)',
                  background: 'rgba(30, 41, 59, 0.4)',
                  color: 'var(--text-dim, #94a3b8)',
                  fontSize: 13,
                  boxSizing: 'border-box',
                  cursor: 'not-allowed'
                }}
              />
            </div>
          </div>

          {/* Status & Badge */}
          <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '6px 14px',
                borderRadius: 20,
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: '#34d399',
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }} />
              Active Clearance
            </div>

            <button
              type="button"
              onClick={() => {
                onClose();
                navigate('/profile');
              }}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#60a5fa',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}
            >
              View Full Profile Page →
            </button>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 18px',
                borderRadius: 8,
                border: '1px solid var(--border-strong, #334155)',
                background: 'transparent',
                color: 'var(--text-main, #f8fafc)',
                fontSize: 14,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '10px 22px',
                borderRadius: 8,
                border: 'none',
                background: 'var(--blue)',
                color: '#ffffff',
                fontSize: 14,
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.7 : 1
              }}
            >
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>

      <style>{`
        @keyframes fadeInScale {
          from { opacity: 0; transform: scale(0.95); }
          to { opacity: 1; transform: scale(1); }
        }
      `}</style>
    </div>
  );
};

export default ProfileModal;
