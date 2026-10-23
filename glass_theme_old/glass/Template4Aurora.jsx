import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin } from '../../js/api';
import ArgusLogo from '../../components/ArgusLogo';
import GlassTemplateSwitcherBar from './GlassTemplateSwitcherBar';
import ForensicGlobeCanvas from './ForensicGlobeCanvas';
import './GlassSystem.css';
import './Template4Aurora.css';

export default function Template4Aurora() {
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
        setError('Please provide your Analyst ID or email.');
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
          throw new Error(errData.detail || 'Analyst ID not recognized.');
        }
        setSuccessMsg('Recovery code dispatched to security channel.');
        setIsForgotPasswordMode(false);
        setIsOtpMode(true);
      } catch (err) {
        setError(err.message || 'Failed to dispatch reset code.');
      } finally {
        setIsLoggingIn(false);
      }
      return;
    }

    if (isOtpMode) {
      if (!otp.trim() || !newPassword.trim()) {
        setError('Please enter both OTP code and new password.');
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
          throw new Error(errData.detail || 'OTP verification expired or invalid.');
        }
        setSuccessMsg('Security key successfully updated. Sign in below.');
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
      setError('Please enter both User ID and Security Key.');
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

  const auroraCapabilities = [
    {
      title: 'Boreal Correlation Engine',
      badge: 'MITRE ATT&CK',
      desc: 'Automated hypothesis generation, threat actor attribution, and forensic timeline correlation across cases.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
        </svg>
      )
    },
    {
      title: 'Evidence Ingestion Lake',
      badge: '42 PIPELINES',
      desc: 'Seamless aggregation across 42 forensic artifact pipelines including memory dumps, EVTX, and PCAP streams.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z" />
        </svg>
      )
    },
    {
      title: 'Continuous Custody Ledger',
      badge: 'IMMUTABLE SEALS',
      desc: 'Cryptographic SHA-256 seal verification safeguarding digital chain of custody from seizure to courtroom.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      )
    }
  ];

  return (
    <div className="tpl4-page">
      {/* Top Floating Glass Navigation */}
      <GlassTemplateSwitcherBar currentTemplate="aurora" onQuickFill={handleQuickFill} />

      {/* Restored Authentic 3D Forensic Globe Canvas with Emerald/Boreal Accents */}
      <ForensicGlobeCanvas 
        centerXRatio={0.34} 
        centerYRatio={0.52} 
        radiusRatio={0.38} 
        nodeColor="#2dd4bf"
        lineColor="#0d9488"
        threatColor="#f43f5e"
        pointCount={750}
        className="tpl4-globe-layer"
      />

      {/* Atmospheric Aurora Borealis Backing */}
      <div className="tpl4-aurora-backdrop" aria-hidden="true">
        <div className="tpl4-aurora-glow-1" />
        <div className="tpl4-aurora-glow-2" />
        <div className="tpl4-aurora-glow-3" />
      </div>

      <main className="tpl4-stage">
        {/* Left Boreal Narrative Showcase */}
        <section className="tpl4-showcase">
          <div className="tpl4-pill">
            <span className="tpl4-pill-dot" />
            <span className="tpl4-pill-text">AURORA GLASS &bull; TPL-04</span>
            <span className="tpl4-pill-badge">BOREAL FIELD</span>
          </div>

          <h1 className="tpl4-title">
            Atmospheric Intelligence with{' '}
            <span className="tpl4-title-gradient">Aurora Light Layers</span>
          </h1>

          <p className="tpl4-desc">
            Translucent frosted crystal plates layered over dynamic boreal light curtains, illuminating multi-agent investigations with deep ethereal contrast and pristine judicial clarity.
          </p>

          {/* Telemetry Pills */}
          <div className="tpl4-telemetry-row">
            <span className="btn-glass-pill">
              <span className="tpl4-pulse-dot" /> Boreal Stream Synced
            </span>
            <span className="btn-glass-pill">42 Artifact Parsers</span>
            <span className="btn-glass-pill">750 Threat Nodes Active</span>
          </div>

          {/* Floating Translucent Boreal Glass Tiles */}
          <div className="tpl4-feature-stack">
            {auroraCapabilities.map((item, index) => (
              <div key={index} className="tpl4-feature-card glass-tile-card">
                <div className="tpl4-card-aurora-edge" />
                <div className="tpl4-feature-icon">
                  {item.icon}
                </div>
                <div className="tpl4-feature-content">
                  <div className="tpl4-feature-head">
                    <h4>{item.title}</h4>
                    <span className="tpl4-feature-badge">{item.badge}</span>
                  </div>
                  <p>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Right Aurora Glass Terminal */}
        <section className="tpl4-form-container">
          <div className="tpl4-login-card">
            {/* Top Specular Edge */}
            <div className="tpl4-specular-edge" />
            <div className="tpl4-card-aurora-glow" />

            <div className="tpl4-card-header">
              <div className="tpl4-logo-cradle">
                <ArgusLogo size={42} />
              </div>
              <h2 className="tpl4-card-title">ARGUS FORENSICS</h2>
              <p className="tpl4-card-subtitle">
                {isOtpMode 
                  ? 'Verify Security Passcode' 
                  : isForgotPasswordMode 
                    ? 'Security Credential Recovery' 
                    : 'Classified Investigation Portal'}
              </p>
            </div>

            {error && (
              <div className="tpl4-banner error" role="alert">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="tpl4-banner success" role="status">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span>{successMsg}</span>
              </div>
            )}

            <form className="tpl4-form" onSubmit={handleLogin}>
              {!isOtpMode && (
                <div className="tpl4-field">
                  <label htmlFor="tpl4-userid" className="tpl4-label">Analyst ID or Work Email</label>
                  <div className="tpl4-input-container">
                    <svg className="tpl4-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                    <input
                      id="tpl4-userid"
                      type="text"
                      className="tpl4-input"
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
                  <div className="tpl4-field">
                    <label htmlFor="tpl4-otp" className="tpl4-label">One-Time Security Passcode</label>
                    <div className="tpl4-input-container">
                      <input
                        id="tpl4-otp"
                        type="text"
                        className="tpl4-input"
                        placeholder="Enter 6-digit OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        maxLength={6}
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="tpl4-field">
                    <label htmlFor="tpl4-newpw" className="tpl4-label">New Security Key</label>
                    <div className="tpl4-input-container">
                      <input
                        id="tpl4-newpw"
                        type={showPassword ? 'text' : 'password'}
                        className="tpl4-input"
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
                <div className="tpl4-field">
                  <label htmlFor="tpl4-password" className="tpl4-label">Security Clearance Key</label>
                  <div className="tpl4-input-container">
                    <svg className="tpl4-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <input
                      id="tpl4-password"
                      type={showPassword ? 'text' : 'password'}
                      className="tpl4-input"
                      placeholder="Enter security clearance key"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="tpl4-reveal-btn"
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
                <div className="tpl4-meta-row">
                  <label className="tpl4-checkbox-label">
                    <input
                      type="checkbox"
                      className="tpl4-checkbox"
                      checked={keepActive}
                      onChange={(e) => setKeepActive(e.target.checked)}
                    />
                    <span>Keep session active</span>
                  </label>
                  <a
                    href="#forgot"
                    className="tpl4-link"
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

              {/* Reusable Primary Glass Action Button */}
              <button
                type="submit"
                className="btn-glass-primary tpl4-submit-btn"
                disabled={isLoggingIn}
              >
                <span>
                  {isLoggingIn
                    ? 'AUTHENTICATING...'
                    : (isOtpMode 
                        ? 'VERIFY PASSCODE' 
                        : (isForgotPasswordMode ? 'DISPATCH RESET CODE' : 'INITIALIZE AURORA SESSION'))}
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

            <div className="tpl4-card-footer">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>CLASSIFIED DIGITAL FORENSIC ENVIRONMENT &bull; ZERO TRUST</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
