import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin } from '../../js/api';
import ArgusLogo from '../../components/ArgusLogo';
import GlassTemplateSwitcherBar from './GlassTemplateSwitcherBar';
import ForensicGlobeCanvas from './ForensicGlobeCanvas';
import './GlassSystem.css';
import './Template5Prismatic.css';

export default function Template5Prismatic() {
  const navigate = useNavigate();

  // Form State
  const [userid, setUserid] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [keepActive, setKeepActive] = useState(true);
  const [isForgotPasswordMode, setIsForgotPasswordMode] = useState(false);
  const [isOtpMode, setIsOtpMode] = useState(false);
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');

  // Status & Feedback
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const handleQuickFill = () => {
    setUserid('2');
    setPassword('123');
    setError(null);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (isForgotPasswordMode) {
      if (!userid.trim()) {
        setError('Please enter your Analyst ID or email.');
        return;
      }
      setIsLoggingIn(true);
      try {
        const res = await fetch((import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000') + '/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userid: userid.trim() })
        });
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'Analyst identity not recognized.');
        }
        setSuccessMsg('Prismatic verification token dispatched.');
        setIsForgotPasswordMode(false);
        setIsOtpMode(true);
      } catch (err) {
        setError(err.message || 'Transmission failed.');
      } finally {
        setIsLoggingIn(false);
      }
      return;
    }

    if (isOtpMode) {
      if (!otp.trim() || !newPassword.trim()) {
        setError('Please input both OTP token and your replacement key.');
        return;
      }
      setIsLoggingIn(true);
      try {
        const res = await fetch((import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000') + '/auth/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userid: userid.trim(), otp: otp.trim(), new_password: newPassword })
        });
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'OTP token invalid or expired.');
        }
        setSuccessMsg('Security key successfully recalibrated. Sign in below.');
        setIsOtpMode(false);
        setPassword('');
      } catch (err) {
        setError(err.message || 'OTP verification failed.');
      } finally {
        setIsLoggingIn(false);
      }
      return;
    }

    if (!userid.trim() || !password) {
      setError('Please provide your Analyst ID and Security Key.');
      return;
    }

    try {
      setIsLoggingIn(true);
      const data = await apiLogin(userid.trim(), password);
      localStorage.setItem('argus_token', data.token);
      localStorage.setItem('argus_user', JSON.stringify(data.user));
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const prismaticCapabilities = [
    {
      title: 'Spectral Multi-Modal Dispersion',
      badge: 'DISPERSION MATRIX',
      desc: 'Separates composite forensic disk & memory dumps into deterministic artifact bands with nanosecond precision.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="12 2 2 22 22 22 12 2" />
          <line x1="12" y1="2" x2="12" y2="22" />
        </svg>
      )
    },
    {
      title: 'Diamond-Bevel Process Trees',
      badge: 'HIERARCHICAL GRAPH',
      desc: 'Parental process execution reconstruction revealing stealth process hollowing, thread injects, and memory hooks.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="5" r="3" />
          <line x1="12" y1="8" x2="12" y2="14" />
          <path d="M5 14h14" />
          <circle cx="5" cy="19" r="3" />
          <circle cx="19" cy="19" r="3" />
        </svg>
      )
    },
    {
      title: 'MITRE Spectral ATT&CK Mapping',
      badge: 'TACTIC CLUSTERS',
      desc: 'Continuous real-time alignment with enterprise attack matrices for immediate tactical containment and court reporting.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="7" height="7" />
          <rect x="14" y="3" width="7" height="7" />
          <rect x="14" y="14" width="7" height="7" />
          <rect x="3" y="14" width="7" height="7" />
        </svg>
      )
    }
  ];

  return (
    <div className="tpl5-page">
      {/* Top Floating Glass Navigation */}
      <GlassTemplateSwitcherBar currentTemplate="prismatic" onQuickFill={handleQuickFill} />

      {/* Restored Authentic 3D Forensic Globe Canvas with Multi-Spectral Glints */}
      <ForensicGlobeCanvas 
        centerXRatio={0.34} 
        centerYRatio={0.52} 
        radiusRatio={0.38} 
        nodeColor="#a78bfa"
        lineColor="#6366f1"
        threatColor="#f43f5e"
        pointCount={750}
        className="tpl5-globe-layer"
      />

      {/* Prismatic Dispersion Ambient Backdrop */}
      <div className="tpl5-prismatic-backdrop" aria-hidden="true">
        <div className="tpl5-facet-light-1" />
        <div className="tpl5-facet-light-2" />
        <div className="tpl5-facet-light-3" />
      </div>

      <main className="tpl5-stage">
        {/* Left Prismatic Narrative Showcase */}
        <section className="tpl5-showcase">
          <div className="tpl5-facet-pill">
            <span className="tpl5-prism-icon" />
            <span className="tpl5-prism-text">PRISMATIC GLASS &bull; TPL-05</span>
            <span className="tpl5-prism-badge">SPECTRAL 3.2</span>
          </div>

          <h1 className="tpl5-title">
            Optical Dispersion &amp;{' '}
            <span className="tpl5-title-rainbow">Multi-Spectral Forensic</span> Depth
          </h1>

          <p className="tpl5-desc">
            Delicate chromatic fringe reflections along diamond-cut bevels and crystal glass facets, separating complex adversary activity into distinct, verifiable investigative wavelengths.
          </p>

          {/* Telemetry Row */}
          <div className="tpl5-telemetry-row">
            <span className="btn-glass-pill">
              <span className="tpl5-pulse-dot" /> Spectral Nodes Aligned
            </span>
            <span className="btn-glass-pill">Refractive Index 1.54</span>
            <span className="btn-glass-pill">750 Threat Indicators</span>
          </div>

          {/* Floating Prismatic Crystal Feature Tiles */}
          <div className="tpl5-facets-stack">
            {prismaticCapabilities.map((item, idx) => (
              <div key={idx} className="tpl5-facet-card glass-tile-card">
                <div className="tpl5-card-rainbow-rim" />
                <div className="tpl5-card-icon-cradle">
                  {item.icon}
                </div>
                <div className="tpl5-card-body">
                  <div className="tpl5-card-header-line">
                    <h4>{item.title}</h4>
                    <span className="tpl5-card-badge">{item.badge}</span>
                  </div>
                  <p>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Right Prismatic Glass Terminal */}
        <section className="tpl5-portal-zone">
          <div className="tpl5-crystal-card">
            {/* Spectral Hairline Edge Highlight */}
            <div className="tpl5-card-rainbow-top" />
            <div className="tpl5-crystal-ambient" />

            <div className="tpl5-crystal-header">
              <div className="tpl5-logo-crystal">
                <ArgusLogo size={42} />
              </div>
              <h2 className="tpl5-crystal-title">ARGUS FORENSICS</h2>
              <p className="tpl5-crystal-subtitle">
                {isOtpMode 
                  ? 'Verify Security Passcode' 
                  : isForgotPasswordMode 
                    ? 'Security Credential Recovery' 
                    : 'Classified Investigation Portal'}
              </p>
            </div>

            {error && (
              <div className="tpl5-alert-box error" role="alert">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="tpl5-alert-box success" role="status">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span>{successMsg}</span>
              </div>
            )}

            <form className="tpl5-form" onSubmit={handleLogin}>
              {!isOtpMode && (
                <div className="tpl5-field-group">
                  <label htmlFor="tpl5-userid" className="tpl5-field-label">Analyst ID or Work Email</label>
                  <div className="tpl5-input-container">
                    <svg className="tpl5-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                    <input
                      id="tpl5-userid"
                      type="text"
                      className="tpl5-input"
                      placeholder="e.g. 2 or analyst@argus.internal"
                      value={userid}
                      onChange={(e) => setUserid(e.target.value)}
                      required
                      autoComplete="username"
                    />
                  </div>
                </div>
              )}

              {isOtpMode && (
                <>
                  <div className="tpl5-field-group">
                    <label htmlFor="tpl5-otp" className="tpl5-field-label">One-Time Security Passcode</label>
                    <div className="tpl5-input-container">
                      <input
                        id="tpl5-otp"
                        type="text"
                        className="tpl5-input"
                        placeholder="Enter 6-digit OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        maxLength={6}
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="tpl5-field-group">
                    <label htmlFor="tpl5-newpw" className="tpl5-field-label">New Security Key</label>
                    <div className="tpl5-input-container">
                      <input
                        id="tpl5-newpw"
                        type={showPassword ? 'text' : 'password'}
                        className="tpl5-input"
                        placeholder="Set new password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        required
                      />
                    </div>
                  </div>
                </>
              )}

              {!isForgotPasswordMode && !isOtpMode && (
                <div className="tpl5-field-group">
                  <label htmlFor="tpl5-password" className="tpl5-field-label">Security Clearance Key</label>
                  <div className="tpl5-input-container">
                    <svg className="tpl5-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <input
                      id="tpl5-password"
                      type={showPassword ? 'text' : 'password'}
                      className="tpl5-input"
                      placeholder="Enter security clearance key"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="tpl5-reveal-btn"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label="Toggle password visibility"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        {showPassword ? (
                          <>
                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                            <line x1="1" y1="1" x2="23" y2="23" />
                          </>
                        ) : (
                          <>
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                            <circle cx="12" cy="12" r="3" />
                          </>
                        )}
                      </svg>
                    </button>
                  </div>
                </div>
              )}

              {!isForgotPasswordMode && !isOtpMode && (
                <div className="tpl5-row-controls">
                  <label className="tpl5-checkbox-label">
                    <input
                      type="checkbox"
                      className="tpl5-checkbox"
                      checked={keepActive}
                      onChange={(e) => setKeepActive(e.target.checked)}
                    />
                    <span>Keep session active</span>
                  </label>
                  <a
                    href="#forgot"
                    className="tpl5-text-link"
                    onClick={(e) => {
                      e.preventDefault();
                      setIsForgotPasswordMode(true);
                      setError(null);
                      setSuccessMsg(null);
                    }}
                  >
                    Forgot credentials?
                  </a>
                </div>
              )}

              {/* Reusable Outlined Primary Glass Button */}
              <button
                type="submit"
                className="btn-glass-primary tpl5-action-btn"
                disabled={isLoggingIn}
              >
                <span>
                  {isLoggingIn
                    ? 'AUTHENTICATING...'
                    : (isOtpMode 
                        ? 'VERIFY PASSCODE' 
                        : (isForgotPasswordMode ? 'DISPATCH RESET CODE' : 'INITIALIZE PRISMATIC CLEARANCE'))}
                </span>
                {!isLoggingIn && (
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <line x1="5" y1="12" x2="19" y2="12" />
                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                )}
              </button>

              {(isForgotPasswordMode || isOtpMode) && (
                <div style={{ textAlign: 'center', marginTop: 10 }}>
                  <button
                    type="button"
                    className="btn-glass-outline"
                    style={{ fontSize: 12, padding: '7px 16px' }}
                    onClick={() => {
                      setIsForgotPasswordMode(false);
                      setIsOtpMode(false);
                      setError(null);
                      setSuccessMsg(null);
                    }}
                  >
                    ← Back to standard login
                  </button>
                </div>
              )}
            </form>

            <div className="tpl5-crystal-footer">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>CLASSIFIED DIGITAL FORENSIC ENVIRONMENT &bull; PRISMATIC SPEC-05</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
