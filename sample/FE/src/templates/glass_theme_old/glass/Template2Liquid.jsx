import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin } from '../../js/api';
import ArgusLogo from '../../components/ArgusLogo';
import GlassTemplateSwitcherBar from './GlassTemplateSwitcherBar';
import ForensicGlobeCanvas from './ForensicGlobeCanvas';
import './GlassSystem.css';
import './Template2Liquid.css';

export default function Template2Liquid() {
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
        setSuccessMsg('Security code dispatched. Check your security contact.');
        setIsForgotPasswordMode(false);
        setIsOtpMode(true);
      } catch (err) {
        setError(err.message || 'Failed to dispatch code.');
      } finally {
        setIsLoggingIn(false);
      }
      return;
    }

    if (isOtpMode) {
      if (!otp.trim() || !newPassword.trim()) {
        setError('Please enter the 6-digit OTP and your new password.');
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
        setSuccessMsg('Password updated successfully. You may now sign in.');
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
      setError('Please provide both User ID and Security Key.');
      return;
    }

    try {
      setIsLoggingIn(true);
      const data = await apiLogin(userid.trim(), password);
      localStorage.setItem('argus_token', data.token);
      localStorage.setItem('argus_user', JSON.stringify(data.user));
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Authentication failed. Please check credentials.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const liquidCapabilities = [
    {
      title: 'Fluid Graph Topology',
      tag: 'DYNAMIC MESH',
      desc: 'Organic real-time cluster relaxation tracking malware persistence mechanisms and lateral movement.',
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="6" cy="6" r="3" />
          <circle cx="18" cy="18" r="3" />
          <circle cx="18" cy="6" r="3" />
          <line x1="8.5" y1="7.5" x2="15.5" y2="16.5" />
          <line x1="9" y1="6" x2="15" y2="6" />
        </svg>
      )
    },
    {
      title: 'Optical Depth Ingestion',
      tag: 'VOLATILE MEMORY',
      desc: 'Seamless multi-layer event alignment linking volatile memory artifacts with disk timeline traces.',
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          <path d="M2 12h20" />
        </svg>
      )
    },
    {
      title: 'Continuous Forensic Caustics',
      tag: 'ZERO HALLUCINATIONS',
      desc: 'Supervisor agent engine cross-verifies deterministic parser facts against deep analytical deductions.',
      icon: (
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M16 3h5v5" />
          <path d="M4 20L21 3" />
          <path d="M21 16v5h-5" />
          <path d="M15 15l6 6" />
          <path d="M4 4l5 5" />
        </svg>
      )
    }
  ];

  return (
    <div className="tpl2-page">
      {/* Top Floating Glass Navigation */}
      <GlassTemplateSwitcherBar currentTemplate="liquid" onQuickFill={handleQuickFill} />

      {/* Restored Authentic 3D Forensic Globe Canvas with Cerulean Accents */}
      <ForensicGlobeCanvas 
        centerXRatio={0.34} 
        centerYRatio={0.52} 
        radiusRatio={0.39}
        pointCount={750}
        className="tpl2-globe-layer"
      />

      {/* Fluid Caustic Ambient Backdrop */}
      <div className="tpl2-liquid-backdrop" aria-hidden="true">
        <div className="tpl2-caustic-wave-1" />
        <div className="tpl2-caustic-wave-2" />
        <div className="tpl2-mesh-diffuse" />
      </div>

      <main className="tpl2-stage">
        {/* Left Fluid Glass Narrative Section */}
        <section className="tpl2-hero">
          <div className="tpl2-liquid-pill">
            <span className="tpl2-liquid-droplet" />
            <span className="tpl2-liquid-pill-text">LIQUID GLASS &bull; TPL-02</span>
            <span className="tpl2-fluid-badge">REFRACTIVE FLUID</span>
          </div>

          <h1 className="tpl2-hero-title">
            Fluid Forensics with{' '}
            <span className="tpl2-title-shimmer">Refractive Multi-Agent</span> Vision
          </h1>

          <p className="tpl2-hero-desc">
            Defined by organic rounded meniscuses, directional surface reflections, and deep ambient oceanic caustics that illuminate live forensic artifacts in real time.
          </p>

          {/* Liquid Telemetry Pills */}
          <div className="tpl2-telemetry-row">
            <span className="btn-glass-pill">
              <span className="tpl2-pulse-dot" /> Live Memory Caustics
            </span>
            <span className="btn-glass-pill">Fluid Mesh Correlation</span>
            <span className="btn-glass-pill">750 Threat Nodes Projected</span>
          </div>

          {/* Floating Liquid Curved Feature Tiles */}
          <div className="tpl2-cards-stack">
            {liquidCapabilities.map((item, index) => (
              <div key={index} className="tpl2-liquid-card glass-tile-card">
                <div className="tpl2-card-specular-top" />
                <div className="tpl2-card-icon-bubble">
                  {item.icon}
                </div>
                <div className="tpl2-card-info">
                  <div className="tpl2-card-header-row">
                    <h3>{item.title}</h3>
                    <span className="tpl2-card-tag">{item.tag}</span>
                  </div>
                  <p>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Right Liquid Glass Login Terminal */}
        <section className="tpl2-card-container">
          <div className="tpl2-auth-card">
            {/* Liquid Meniscus Top Specular Edge */}
            <div className="tpl2-meniscus-edge" />
            <div className="tpl2-card-caustic-glow" />

            <div className="tpl2-auth-header">
              <div className="tpl2-logo-bubble">
                <ArgusLogo size={42} />
              </div>
              <h2 className="tpl2-auth-title">ARGUS FORENSICS</h2>
              <p className="tpl2-auth-subtitle">
                {isOtpMode 
                  ? 'Verify Security Passcode' 
                  : isForgotPasswordMode 
                    ? 'Security Credential Recovery' 
                    : 'Classified Investigation Portal'}
              </p>
            </div>

            {error && (
              <div className="tpl2-banner error" role="alert">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="tpl2-banner success" role="status">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span>{successMsg}</span>
              </div>
            )}

            <form className="tpl2-auth-form" onSubmit={handleLogin}>
              {!isOtpMode && (
                <div className="tpl2-field-group">
                  <label htmlFor="tpl2-userid" className="tpl2-field-label">Analyst ID or Work Email</label>
                  <div className="tpl2-input-wrapper">
                    <svg className="tpl2-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                    <input
                      id="tpl2-userid"
                      type="text"
                      className="tpl2-input"
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
                  <div className="tpl2-field-group">
                    <label htmlFor="tpl2-otp" className="tpl2-field-label">One-Time Security Passcode</label>
                    <div className="tpl2-input-wrapper">
                      <input
                        id="tpl2-otp"
                        type="text"
                        className="tpl2-input"
                        placeholder="Enter 6-digit OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        maxLength={6}
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="tpl2-field-group">
                    <label htmlFor="tpl2-newpw" className="tpl2-field-label">New Security Key</label>
                    <div className="tpl2-input-wrapper">
                      <input
                        id="tpl2-newpw"
                        type={showPassword ? 'text' : 'password'}
                        className="tpl2-input"
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
                <div className="tpl2-field-group">
                  <label htmlFor="tpl2-password" className="tpl2-field-label">Security Clearance Key</label>
                  <div className="tpl2-input-wrapper">
                    <svg className="tpl2-input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <input
                      id="tpl2-password"
                      type={showPassword ? 'text' : 'password'}
                      className="tpl2-input"
                      placeholder="Enter security clearance key"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="tpl2-reveal-btn"
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
                <div className="tpl2-options-row">
                  <label className="tpl2-remember-label">
                    <input
                      type="checkbox"
                      className="tpl2-checkbox"
                      checked={keepActive}
                      onChange={(e) => setKeepActive(e.target.checked)}
                    />
                    <span>Keep session active</span>
                  </label>
                  <a
                    href="#forgot"
                    className="tpl2-forgot-link"
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

              {/* Reusable Outlined Glass Action Button */}
              <button
                type="submit"
                className="btn-glass-primary tpl2-submit-btn"
                disabled={isLoggingIn}
              >
                <span>
                  {isLoggingIn
                    ? 'AUTHENTICATING...'
                    : (isOtpMode 
                        ? 'VERIFY PASSCODE' 
                        : (isForgotPasswordMode ? 'DISPATCH RESET CODE' : 'INITIALIZE LIQUID SESSION'))}
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

            <div className="tpl2-auth-footer">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>CLASSIFIED DIGITAL FORENSIC ENVIRONMENT &bull; E-DISCOVERY</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
