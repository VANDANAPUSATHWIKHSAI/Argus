import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin } from '../../js/api';
import ArgusLogo from '../../components/ArgusLogo';
import GlassTemplateSwitcherBar from './GlassTemplateSwitcherBar';
import ForensicGlobeCanvas from './ForensicGlobeCanvas';
import './GlassSystem.css';
import './Template1Architectural.css';

export default function Template1Architectural() {
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
          throw new Error(errData.detail || 'User ID not registered.');
        }
        setSuccessMsg('Security OTP dispatched. Check your security contact.');
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
        setError('Please provide both the 6-digit OTP and your new password.');
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
          throw new Error(errData.detail || 'Invalid or expired OTP.');
        }
        setSuccessMsg('Password updated. You may now sign in.');
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
      setError('Please provide your Analyst ID and Security Clearance Key.');
      return;
    }

    try {
      setIsLoggingIn(true);
      const data = await apiLogin(userid.trim(), password);
      localStorage.setItem('argus_token', data.token);
      localStorage.setItem('argus_user', JSON.stringify(data.user));
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Authentication rejected. Verify credentials.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const architecturalTiles = [
    {
      title: 'Cryptographic Chain of Custody',
      badge: 'SHA-256 LEDGER',
      desc: 'Immutable evidence hashing with strict audit trail across multi-source forensic repositories.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      )
    },
    {
      title: 'Multi-Agent Artifact Ingestion',
      badge: 'AUTONOMOUS PARSERS',
      desc: 'Deterministic parallel parsing across raw memory dumps, disk images, EVTX streams, and registry hives.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
          <line x1="8" y1="21" x2="16" y2="21" />
          <line x1="12" y1="17" x2="12" y2="21" />
        </svg>
      )
    },
    {
      title: 'Forensic Correlation Graph',
      badge: 'TEMPORAL NODES',
      desc: 'Adversarial 3D link analysis connecting IOC clusters, threat actors, and lateral movement timelines.',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="18" cy="5" r="3" />
          <circle cx="6" cy="12" r="3" />
          <circle cx="18" cy="19" r="3" />
          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
        </svg>
      )
    }
  ];

  return (
    <div className="tpl1-page">
      {/* Top Floating Glass Navigation */}
      <GlassTemplateSwitcherBar currentTemplate="architectural" onQuickFill={handleQuickFill} />

      {/* Restored Authentic 3D Forensic Globe Canvas */}
      <ForensicGlobeCanvas 
        centerXRatio={0.34} 
        centerYRatio={0.52} 
        radiusRatio={0.38} 
        pointCount={750}
        className="tpl1-globe-layer"
      />

      {/* Background Architectural Grid & Ambient Depth Layer */}
      <div className="tpl1-backdrop" aria-hidden="true">
        <div className="tpl1-grid-plane" />
        <div className="tpl1-light-column-1" />
        <div className="tpl1-light-column-2" />
      </div>

      <main className="tpl1-stage">
        {/* Left Narrative Showcase with Floating Glass Tiles */}
        <section className="tpl1-showcase">
          <div className="tpl1-meta-pill">
            <span className="tpl1-meta-dot" />
            <span className="tpl1-meta-text">ARCHITECTURAL FROSTED GLASS &bull; TPL-01</span>
            <span className="tpl1-meta-badge">RESTRICTED // LEVEL 4</span>
          </div>

          <h1 className="tpl1-title">
            Enterprise Digital Forensics &amp;{' '}
            <span className="tpl1-title-accent">Multi-Agent Intelligence</span>
          </h1>

          <p className="tpl1-desc">
            Engineered with modern OS-grade frosted acrylic surfaces, subtle background diffusion, and restrained cobalt edge reflections for mission-critical investigation environments.
          </p>

          {/* Quick Telemetry Pills */}
          <div className="tpl1-telemetry-row">
            <span className="btn-glass-pill">
              <span className="tpl1-pulse-dot" /> 750 Forensic Nodes Active
            </span>
            <span className="btn-glass-pill">SHA-256 Hashing Enforced</span>
            <span className="btn-glass-pill">Zero-Hallucination Gate</span>
          </div>

          {/* Floating Translucent Glass Feature Tiles */}
          <div className="tpl1-tiles-grid">
            {architecturalTiles.map((tile, i) => (
              <div key={i} className="tpl1-tile glass-tile-card">
                <div className="tpl1-tile-icon-cradle">
                  {tile.icon}
                </div>
                <div className="tpl1-tile-content">
                  <div className="tpl1-tile-header">
                    <h4>{tile.title}</h4>
                    <span className="tpl1-tile-badge">{tile.badge}</span>
                  </div>
                  <p>{tile.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Right Frosted Glass Terminal Card */}
        <section className="tpl1-card-stage">
          <div className="tpl1-card">
            {/* Top Specular Glint Highlight */}
            <div className="tpl1-card-specular-edge" />

            <div className="tpl1-card-header">
              <div className="tpl1-logo-wrap">
                <ArgusLogo size={42} />
              </div>
              <h2 className="tpl1-card-title">ARGUS FORENSICS</h2>
              <p className="tpl1-card-subtitle">
                {isOtpMode 
                  ? 'Verify Security Passcode' 
                  : isForgotPasswordMode 
                    ? 'Security Credential Recovery' 
                    : 'Classified Investigation Portal'}
              </p>
            </div>

            {error && (
              <div className="tpl1-banner error" role="alert">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="tpl1-banner success" role="status">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span>{successMsg}</span>
              </div>
            )}

            <form className="tpl1-form" onSubmit={handleLogin}>
              {!isOtpMode && (
                <div className="tpl1-field">
                  <label htmlFor="tpl1-userid" className="tpl1-label">Analyst ID or Work Email</label>
                  <div className="tpl1-input-box">
                    <svg className="tpl1-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                    <input
                      id="tpl1-userid"
                      type="text"
                      className="tpl1-input"
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
                  <div className="tpl1-field">
                    <label htmlFor="tpl1-otp" className="tpl1-label">One-Time Security Passcode</label>
                    <div className="tpl1-input-box">
                      <input
                        id="tpl1-otp"
                        type="text"
                        className="tpl1-input"
                        placeholder="Enter 6-digit OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        maxLength={6}
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="tpl1-field">
                    <label htmlFor="tpl1-newpw" className="tpl1-label">New Security Key</label>
                    <div className="tpl1-input-box">
                      <input
                        id="tpl1-newpw"
                        type={showPassword ? 'text' : 'password'}
                        className="tpl1-input"
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
                <div className="tpl1-field">
                  <label htmlFor="tpl1-password" className="tpl1-label">Security Clearance Key</label>
                  <div className="tpl1-input-box">
                    <svg className="tpl1-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <input
                      id="tpl1-password"
                      type={showPassword ? 'text' : 'password'}
                      className="tpl1-input"
                      placeholder="Enter security clearance key"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="tpl1-reveal-btn"
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
                <div className="tpl1-subactions">
                  <label className="tpl1-checkbox-label">
                    <input
                      type="checkbox"
                      className="tpl1-checkbox"
                      checked={keepActive}
                      onChange={(e) => setKeepActive(e.target.checked)}
                    />
                    <span>Keep session active</span>
                  </label>
                  <a
                    href="#forgot"
                    className="tpl1-link"
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

              {/* Reusable Glass Primary Action Button */}
              <button
                type="submit"
                className="btn-glass-primary tpl1-submit-btn"
                disabled={isLoggingIn}
              >
                <span>
                  {isLoggingIn
                    ? 'AUTHENTICATING...'
                    : (isOtpMode 
                        ? 'VERIFY PASSCODE' 
                        : (isForgotPasswordMode ? 'DISPATCH RESET CODE' : 'INITIALIZE CLEARANCE SESSION'))}
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

            <div className="tpl1-card-footer">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>RESTRICTED ACCESS ONLY &bull; LAW ENFORCEMENT &amp; FORENSICS</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
