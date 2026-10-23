import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login as apiLogin } from '../../js/api';
import ArgusLogo from '../../components/ArgusLogo';
import GlassTemplateSwitcherBar from './GlassTemplateSwitcherBar';
import ForensicGlobeCanvas from './ForensicGlobeCanvas';
import './GlassSystem.css';
import './Template3Obsidian.css';

export default function Template3Obsidian() {
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
        setError('SPECIFY OPERATOR ID FOR CIPHER DISPATCH.');
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
          throw new Error(errData.detail || 'OPERATOR ID NOT FOUND.');
        }
        setSuccessMsg('SECURITY OTP TRANSMITTED TO PRIMARY COMMS.');
        setIsForgotPasswordMode(false);
        setIsOtpMode(true);
      } catch (err) {
        setError(err.message || 'TRANSMISSION FAILED.');
      } finally {
        setIsLoggingIn(false);
      }
      return;
    }

    if (isOtpMode) {
      if (!otp.trim() || !newPassword.trim()) {
        setError('INPUT 6-DIGIT OTP AND NEW CLEARANCE KEY.');
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
          throw new Error(errData.detail || 'INVALID TOKEN.');
        }
        setSuccessMsg('CREDENTIALS REKEYED SUCCESSFULLY.');
        setIsOtpMode(false);
        setPassword('');
      } catch (err) {
        setError(err.message || 'VERIFICATION REJECTED.');
      } finally {
        setIsLoggingIn(false);
      }
      return;
    }

    if (!userid.trim() || !password) {
      setError('AUTHENTICATION BLOCKED: CREDENTIALS REQUIRED.');
      return;
    }

    try {
      setIsLoggingIn(true);
      const data = await apiLogin(userid.trim(), password);
      localStorage.setItem('argus_token', data.token);
      localStorage.setItem('argus_user', JSON.stringify(data.user));
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'ACCESS DENIED: CLEARANCE REJECTED.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const telemetryRows = [
    {
      label: 'MULTI-AGENT CLUSTER',
      detail: '7 Autonomous Parsers & Correlation Engine',
      status: 'ONLINE',
      code: 'NODE-07',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
      )
    },
    {
      label: 'IMMUTABLE EVIDENCE LEDGER',
      detail: 'SHA-256 Real-time Custody Verification',
      status: 'VERIFIED',
      code: 'HASH-256',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      )
    },
    {
      label: 'ADVERSARIAL IOC GATE',
      detail: 'Confidence-Gated Zero Hallucination Pipeline',
      status: 'SECURE',
      code: 'GATE-01',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      )
    }
  ];

  return (
    <div className="tpl3-page">
      {/* Top Floating Glass Navigation */}
      <GlassTemplateSwitcherBar currentTemplate="obsidian" onQuickFill={handleQuickFill} />

      {/* Restored Authentic 3D Forensic Globe Canvas with Electric Cyan Accents */}
      <ForensicGlobeCanvas 
        centerXRatio={0.34} 
        centerYRatio={0.52} 
        radiusRatio={0.38} 
        nodeColor="#38bdf8"
        lineColor="#0284c7"
        threatColor="#f43f5e"
        pointCount={750}
        className="tpl3-globe-layer"
      />

      {/* Atmospheric Smoked Obsidian Backdrop */}
      <div className="tpl3-dark-backdrop" aria-hidden="true">
        <div className="tpl3-scanlines" />
        <div className="tpl3-stealth-light-1" />
        <div className="tpl3-stealth-light-2" />
      </div>

      <main className="tpl3-stage">
        {/* Left Obsidian HUD Console */}
        <section className="tpl3-terminal-hud">
          <div className="tpl3-sys-tag">
            <span className="tpl3-tag-blink" />
            <span className="tpl3-tag-text">OBSIDIAN GLASS // CONSOLE TPL-03</span>
            <span className="tpl3-tag-level">DEFCON 2</span>
          </div>

          <h1 className="tpl3-hud-title">
            Smoked Obsidian Console &amp;{' '}
            <span className="tpl3-hud-highlight">Tactical Telemetry</span>
          </h1>

          <p className="tpl3-hud-desc">
            Deep volcanic charcoal glass, razor-sharp cool-white edge bevels, and tactical monospace telemetry racks designed for secure operational watch centers and digital forensics units.
          </p>

          {/* Tactical Telemetry Badges */}
          <div className="tpl3-telemetry-row">
            <span className="btn-glass-pill">
              <span className="tpl3-pulse-dot" /> 750 Nodes Linked
            </span>
            <span className="btn-glass-pill">LATENCY &lt; 0.04ms</span>
            <span className="btn-glass-pill">RESTRICTED CIPHER</span>
          </div>

          {/* Translucent Smoked Glass Feature Tiles */}
          <div className="tpl3-telemetry-panel">
            {telemetryRows.map((row, idx) => (
              <div key={idx} className="tpl3-telemetry-row-card glass-tile-card">
                <div className="tpl3-telemetry-icon">
                  {row.icon}
                </div>
                <div className="tpl3-telemetry-body">
                  <div className="tpl3-telemetry-header">
                    <span className="tpl3-telemetry-label">{row.label}</span>
                    <span className="tpl3-telemetry-code">{row.code}</span>
                  </div>
                  <div className="tpl3-telemetry-detail">{row.detail}</div>
                </div>
                <div className="tpl3-telemetry-status">
                  <span className="tpl3-status-dot" />
                  <span>{row.status}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Right Obsidian Glass Terminal */}
        <section className="tpl3-card-zone">
          <div className="tpl3-console-card">
            {/* Top Razor-Sharp Bevel Highlight */}
            <div className="tpl3-card-bevel" />

            <div className="tpl3-card-topbar">
              <div className="tpl3-topbar-left">
                <ArgusLogo size={36} />
                <div>
                  <div className="tpl3-topbar-brand">ARGUS FORENSICS</div>
                  <div className="tpl3-topbar-sub">TACTICAL OS // OBSIDIAN GLASS</div>
                </div>
              </div>
              <div className="tpl3-security-pill">
                <span>ENCRYPTED</span>
              </div>
            </div>

            {error && (
              <div className="tpl3-alert-box error" role="alert">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {successMsg && (
              <div className="tpl3-alert-box success" role="status">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span>{successMsg}</span>
              </div>
            )}

            <form className="tpl3-form-grid" onSubmit={handleLogin}>
              {!isOtpMode && (
                <div className="tpl3-form-field">
                  <label htmlFor="tpl3-userid" className="tpl3-label">
                    <span>OPERATOR ID</span>
                    <span className="tpl3-label-req">[REQUIRED]</span>
                  </label>
                  <div className="tpl3-input-housing">
                    <input
                      id="tpl3-userid"
                      type="text"
                      className="tpl3-input-field"
                      placeholder="ENTER OPERATOR ID (e.g. 2)"
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
                  <div className="tpl3-form-field">
                    <label htmlFor="tpl3-otp" className="tpl3-label">
                      <span>VERIFICATION CIPHER (OTP)</span>
                    </label>
                    <div className="tpl3-input-housing">
                      <input
                        id="tpl3-otp"
                        type="text"
                        className="tpl3-input-field"
                        placeholder="ENTER 6-DIGIT OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        maxLength={6}
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="tpl3-form-field">
                    <label htmlFor="tpl3-newpw" className="tpl3-label">
                      <span>NEW CLEARANCE PASSKEY</span>
                    </label>
                    <div className="tpl3-input-housing">
                      <input
                        id="tpl3-newpw"
                        type={showPassword ? 'text' : 'password'}
                        className="tpl3-input-field"
                        placeholder="DEFINE NEW PASSKEY"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        required
                      />
                    </div>
                  </div>
                </>
              )}

              {!isForgotPasswordMode && !isOtpMode && (
                <div className="tpl3-form-field">
                  <label htmlFor="tpl3-password" className="tpl3-label">
                    <span>CLEARANCE PASSKEY</span>
                    <span className="tpl3-label-req">[AES-256]</span>
                  </label>
                  <div className="tpl3-input-housing">
                    <input
                      id="tpl3-password"
                      type={showPassword ? 'text' : 'password'}
                      className="tpl3-input-field"
                      placeholder="ENTER CLEARANCE KEY"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="tpl3-visibility-toggle"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label="Toggle password view"
                    >
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
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
                <div className="tpl3-row-aux">
                  <label className="tpl3-checkbox-label">
                    <input
                      type="checkbox"
                      className="tpl3-checkbox"
                      checked={keepActive}
                      onChange={(e) => setKeepActive(e.target.checked)}
                    />
                    <span>MAINTAIN TERMINAL STATE</span>
                  </label>
                  <a
                    href="#forgot"
                    className="tpl3-action-link"
                    onClick={(e) => {
                      e.preventDefault();
                      setIsForgotPasswordMode(true);
                      setError(null);
                      setSuccessMsg(null);
                    }}
                  >
                    RECOVER CLEARANCE
                  </a>
                </div>
              )}

              {/* Reusable Outlined Primary Glass Button */}
              <button
                type="submit"
                className="btn-glass-primary tpl3-action-btn"
                disabled={isLoggingIn}
              >
                <span>
                  {isLoggingIn
                    ? 'VERIFYING CIPHER...'
                    : (isOtpMode 
                        ? 'CONFIRM PASSCODE' 
                        : (isForgotPasswordMode ? 'DISPATCH CIPHER' : 'AUTHENTICATE SESSION'))}
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
                    style={{ fontSize: 11, padding: '7px 16px' }}
                    onClick={() => {
                      setIsForgotPasswordMode(false);
                      setIsOtpMode(false);
                      setError(null);
                      setSuccessMsg(null);
                    }}
                  >
                    ← RETURN TO TERMINAL LOGIN
                  </button>
                </div>
              )}
            </form>

            <div className="tpl3-console-footer">
              <div className="tpl3-footer-marker" />
              <span>TERMINAL STATUS: LEVEL-4 CLEARANCE RESTRICTED</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
