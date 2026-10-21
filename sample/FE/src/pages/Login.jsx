import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { login as apiLogin } from '../js/api';
import { setAuthSession } from '../js/authSession';
import ArgusLogo from '../components/ArgusLogo';
import '../css/style.css';
import '../css/login.css';

// 3 Verified Forensic Capability Cards
const VERIFIED_CARDS = [
  {
    id: 'intake',
    title: 'Artifact Ingestion',
    desc: 'Automated extraction across disk images, memory dumps, EVTX logs, and registry hives.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
        <line x1="12" y1="22.08" x2="12" y2="12" />
      </svg>
    )
  },
  {
    id: 'correlation',
    title: 'Cross Correlation',
    desc: 'Unified chronological reconstruction and cross-source threat indicator correlation.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
        <line x1="18" y1="20" x2="18" y2="10" />
        <line x1="12" y1="20" x2="12" y2="4" />
        <line x1="6" y1="20" x2="6" y2="14" />
      </svg>
    )
  },
  {
    id: 'graph',
    title: 'Forensic Graph',
    desc: 'Interactive topological mapping of forensic entities, process trees, and IOC graphs.',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
        <circle cx="18" cy="5" r="3" />
        <circle cx="6" cy="12" r="3" />
        <circle cx="18" cy="19" r="3" />
        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
      </svg>
    )
  }
];

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const canvasRef = useRef(null);

  // Form State (supports Remember Me / Keep Session Active)
  const [userid, setUserid] = useState(() => localStorage.getItem('argus_remembered_userid') || '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [keepActive, setKeepActive] = useState(() => localStorage.getItem('argus_keep_active') !== 'false');
  const [isForgotPasswordMode, setIsForgotPasswordMode] = useState(false);
  const [isOtpMode, setIsOtpMode] = useState(false);
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');

  // Status & Feedback Banners
  const [error, setError] = useState(null);
  const [sessionNotice, setSessionNotice] = useState(null);
  const [resetSuccess, setResetSuccess] = useState(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isSendingReset, setIsSendingReset] = useState(false);

  // Theme Management
  const [theme, setTheme] = useState(() => {
    return document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  });

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
    if (window.toggleTheme) window.toggleTheme();
  };

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // Session & Idle Timeout URL notices
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const reason = params.get('reason');
    if (reason === 'session_expired') {
      setSessionNotice('Your session has expired. Please sign in again.');
    } else if (reason === 'idle_timeout') {
      setSessionNotice('You were automatically signed out due to 30 minutes of inactivity.');
    }
  }, [location.search]);

  // Approved 3D-Projected Forensic Particle Network Globe Engine (750 Points)
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // Generate 3D sphere points (750 nodes for dense network)
    const POINT_COUNT = 750;
    const RADIUS = Math.min(width, height) * 0.38;
    const points = [];

    for (let i = 0; i < POINT_COUNT; i++) {
      const phi = Math.acos(-1 + (2 * i) / POINT_COUNT);
      const theta = Math.sqrt(POINT_COUNT * Math.PI) * phi;
      points.push({
        x: RADIUS * Math.cos(theta) * Math.sin(phi),
        y: RADIUS * Math.sin(theta) * Math.sin(phi),
        z: RADIUS * Math.cos(phi),
        isThreat: i % 18 === 0,
        pulse: Math.random() * Math.PI
      });
    }

    let rotX = 0.3;
    let rotY = -0.5;
    let isDragging = false;
    let lastMouseX = 0;
    let lastMouseY = 0;
    let frameId;

    const handleMouseDown = (e) => {
      if (e.target.closest('.forensic-login-card') || e.target.closest('.top-telemetry-bar')) return;
      isDragging = true;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
    };

    const handleMouseMove = (e) => {
      if (!isDragging) return;
      const dx = e.clientX - lastMouseX;
      const dy = e.clientY - lastMouseY;
      rotY += dx * 0.005;
      rotX += dy * 0.005;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
    };

    const handleMouseUp = () => {
      isDragging = false;
    };

    window.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    function renderGlobe() {
      ctx.clearRect(0, 0, width, height);

      // Auto-rotation
      if (!isDragging) {
        rotY += 0.0025;
        rotX += 0.0005;
      }

      // Center sphere on left side for desktop, centered for mobile
      const isMobile = width <= 1080;
      const centerX = isMobile ? width * 0.5 : width * 0.33;
      const centerY = height * 0.52;

      const cosX = Math.cos(rotX);
      const sinX = Math.sin(rotX);
      const cosY = Math.cos(rotY);
      const sinY = Math.sin(rotY);

      const projected = [];

      for (let i = 0; i < points.length; i++) {
        const p = points[i];
        p.pulse += 0.03;

        // Rotation Y & X
        let x1 = p.x * cosY - p.z * sinY;
        let z1 = p.z * cosY + p.x * sinY;
        let y2 = p.y * cosX - z1 * sinX;
        let z2 = z1 * cosX + p.y * sinX;

        // Perspective 3D to 2D
        const fov = 800;
        const scale = fov / (fov + z2 + 100);
        const x2D = centerX + x1 * scale;
        const y2D = centerY + y2 * scale;

        projected.push({
          x: x2D,
          y: y2D,
          z: z2,
          scale,
          isThreat: p.isThreat,
          pulse: p.pulse
        });
      }

      // Depth sorting
      projected.sort((a, b) => b.z - a.z);

      const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
      ctx.lineWidth = 0.65;

      // Draw dynamic interconnected network lines
      for (let i = 0; i < projected.length; i += 2) {
        for (let j = i + 1; j < Math.min(i + 8, projected.length); j++) {
          const p1 = projected[i];
          const p2 = projected[j];
          const dist = Math.hypot(p1.x - p2.x, p1.y - p2.y);

          if (dist < 68 && (p1.z > -120 || p2.z > -120)) {
            const alpha = Math.max(0, (1 - dist / 68) * 0.24);
            ctx.strokeStyle = isDark
              ? (p1.isThreat || p2.isThreat ? `rgba(239, 68, 68, ${alpha * 1.5})` : `rgba(56, 189, 248, ${alpha})`)
              : (p1.isThreat || p2.isThreat ? `rgba(220, 38, 38, ${alpha * 1.5})` : `rgba(37, 99, 235, ${alpha * 0.85})`);

            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      }

      // Draw nodes (blue particles & pulsing crimson threat nodes)
      for (let i = 0; i < projected.length; i++) {
        const p = projected[i];
        if (p.z < -280) continue;

        const size = (p.isThreat ? 3.2 : 2.0) * p.scale;
        const alpha = Math.min(1, Math.max(0.18, (p.z + 320) / 640));

        if (p.isThreat) {
          const pulseSize = size * (1.2 + 0.5 * Math.sin(p.pulse));
          ctx.fillStyle = isDark ? `rgba(239, 68, 68, ${alpha * 0.3})` : `rgba(220, 38, 38, ${alpha * 0.25})`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, pulseSize * 2, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = isDark ? `rgba(239, 68, 68, ${alpha})` : `rgba(220, 38, 38, ${alpha})`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
          ctx.fill();
        } else {
          ctx.fillStyle = isDark ? `rgba(56, 189, 248, ${alpha})` : `rgba(37, 99, 235, ${alpha * 0.9})`;
          ctx.beginPath();
          ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      frameId = requestAnimationFrame(renderGlobe);
    }

    renderGlobe();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  // Form Handlers
  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setResetSuccess(null);

    // 1. Forgot password request (OTP dispatch)
    if (isForgotPasswordMode) {
      if (!userid.trim()) {
        setError('Please enter your User ID to send the OTP.');
        return;
      }
      setIsSendingReset(true);
      try {
        const response = await fetch((import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000') + '/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userid: userid.trim() })
        });

        if (!response.ok) {
          const errorData = await response.json();
          setError(errorData.detail || 'This User ID is not registered.');
          setIsSendingReset(false);
          return;
        }

        const successData = await response.json();
        setResetSuccess(successData.message || 'OTP dispatched to registered security contact.');
        setIsSendingReset(false);
        setIsForgotPasswordMode(false);
        setIsOtpMode(true);
      } catch (err) {
        setError('Network error. Failed to connect to authentication service.');
        setIsSendingReset(false);
      }
      return;
    }

    // 2. OTP Verification & Password Reset
    if (isOtpMode) {
      if (!otp.trim() || !newPassword.trim()) {
        setError('Please enter the OTP sent to your contact and your new password.');
        return;
      }
      setIsSendingReset(true);
      try {
        const response = await fetch((import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000') + '/auth/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userid: userid.trim(), otp: otp.trim(), new_password: newPassword })
        });

        if (!response.ok) {
          const errorData = await response.json();
          setError(errorData.detail || 'Invalid OTP. Please check and try again.');
          setIsSendingReset(false);
          return;
        }

        const successData = await response.json();
        setResetSuccess(successData.message || 'Password updated successfully. Please sign in with your new credentials.');
        setIsSendingReset(false);
        setIsOtpMode(false);
        setIsForgotPasswordMode(false);
        setOtp('');
        setNewPassword('');
        setPassword('');
      } catch (err) {
        setError('Network error. Failed to connect to authentication service.');
        setIsSendingReset(false);
      }
      return;
    }

    // 3. Primary Authentication
    if (!userid.trim() || !password) {
      setError('Please enter both your User ID and password.');
      return;
    }

    try {
      setIsLoggingIn(true);
      const data = await apiLogin(userid.trim(), password);
      setAuthSession(data.token, data.user, keepActive);
      if (keepActive) {
        localStorage.setItem('argus_remembered_userid', userid.trim());
      } else {
        localStorage.removeItem('argus_remembered_userid');
      }
      if (data.user?.role === 'auditor') {
        navigate('/report');
      } else {
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
      setIsLoggingIn(false);
    }
  };

  const handleCancelRecovery = (e) => {
    if (e) e.preventDefault();
    setIsForgotPasswordMode(false);
    setIsOtpMode(false);
    setError(null);
    setResetSuccess(null);
    setOtp('');
    setNewPassword('');
  };

  return (
    <div className="login-viewport-root">
      {/* 3D-Projected Forensic Canvas & Grid Backdrop */}
      <canvas ref={canvasRef} id="forensic-canvas" />
      <div className="ambient-cyber-backdrop" />

      {/* Top Application Header */}
      <header className="top-telemetry-bar">
        <div className="brand-telemetry-left">
          <div className="brand-badge">
            <ArgusLogo size={36} />
            <h1>ARGUS</h1>
          </div>
        </div>

        <div className="telemetry-meta-right">
          {/* Verified Environment Security Indicator */}
          <div className="classification-tag">
            <span className="status-pulse-dot" />
            SECURE ENVIRONMENT
          </div>

          {/* Theme Toggle Button */}
          <button 
            type="button" 
            className="theme-toggle-btn" 
            aria-label="Toggle Theme" 
            title={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
            onClick={toggleTheme}
          >
            {theme === 'dark' ? (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="5" />
                <line x1="12" y1="1" x2="12" y2="3" />
                <line x1="12" y1="21" x2="12" y2="23" />
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                <line x1="1" y1="12" x2="3" y2="12" />
                <line x1="21" y1="12" x2="23" y2="12" />
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
              </svg>
            ) : (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
              </svg>
            )}
          </button>
        </div>
      </header>

      {/* Main Split-Stage Layout */}
      <main className="preview-stage-container">

        {/* Left Column: Project Overview & 3 Verified Capability Cards */}
        <section className="mission-showcase-column">
          <h2 className="mission-title">
            Multi-Agent Forensic Investigation &amp; <span className="highlight-gradient">Evidence Synthesis</span>
          </h2>

          <p className="mission-desc">
            ARGUS empowers digital investigators with automated multi-agent artifact parsing, immutable chain of custody verification, and AI-driven cross-source correlation across disk, memory, registry, and event logs.
          </p>

          {/* 3 Compact Feature Cards in 1 Row */}
          <div className="feature-capabilities-grid">
            {VERIFIED_CARDS.map((card) => (
              <div key={card.id} className="capability-card">
                <div className="capability-icon-wrap">
                  {card.icon}
                </div>
                <h4>{card.title}</h4>
                <p>{card.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Right Column: Prominent Login Card */}
        <section className="auth-card-stage">
          <div className="forensic-login-card">

            {/* Card Brand Header */}
            <div className="card-header-block">
              <div className="logo-halo-wrapper">
                <ArgusLogo size={52} />
              </div>
              <h1 className="card-title-text">ARGUS</h1>
              <p className="card-subtitle-text">
                {isOtpMode 
                  ? 'Verify Security Code' 
                  : isForgotPasswordMode 
                    ? 'Account Recovery' 
                    : 'Digital Forensic Intelligence'}
              </p>
              <div className="card-tagline-divider">
                <span>EVIDENCE • ANALYZE • TRUTH</span>
              </div>
            </div>

            {/* Notification Banners */}
            {sessionNotice && !error && (
              <div className="alert-feedback-banner session">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}>
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{sessionNotice}</span>
              </div>
            )}

            {error && (
              <div className="alert-feedback-banner error">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}>
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            {resetSuccess && (
              <div className="alert-feedback-banner success">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0, marginTop: 1 }}>
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                <span>{resetSuccess}</span>
              </div>
            )}

            {/* Authentication Form */}
            <form className="login-form" onSubmit={handleLogin}>
              
              {/* Analyst ID Field */}
              {!isOtpMode && (
                <div className="form-field-group">
                  <div className="field-label-row">
                    <label htmlFor="login-userid" className="field-label">Analyst ID or Work Email</label>
                  </div>
                  <div className="input-container-box">
                    <svg className="field-leading-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                    <input 
                      id="login-userid"
                      type="text"
                      className="form-text-input"
                      placeholder="Enter your User ID"
                      value={userid}
                      onChange={(e) => setUserid(e.target.value)}
                      autoComplete="username"
                      required
                    />
                  </div>
                </div>
              )}

              {/* OTP Field (Password Reset Mode) */}
              {isOtpMode && (
                <>
                  <div className="form-field-group">
                    <div className="field-label-row">
                      <label htmlFor="login-otp" className="field-label">One-Time Password</label>
                    </div>
                    <div className="input-container-box">
                      <svg className="field-leading-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <input 
                        id="login-otp"
                        type="text"
                        className="form-text-input"
                        placeholder="Enter 6-digit OTP"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                        autoComplete="one-time-code"
                        maxLength={6}
                        required
                      />
                    </div>
                  </div>

                  <div className="form-field-group">
                    <div className="field-label-row">
                      <label htmlFor="login-new-password" className="field-label">New Password</label>
                    </div>
                    <div className="input-container-box">
                      <svg className="field-leading-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <input 
                        id="login-new-password"
                        type={showPassword ? 'text' : 'password'}
                        className="form-text-input"
                        placeholder="Enter new password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        autoComplete="new-password"
                        required
                      />
                      <button 
                        type="button" 
                        className="pw-reveal-button"
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
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
                </>
              )}

              {/* Password Field (Standard Mode) */}
              {!isForgotPasswordMode && !isOtpMode && (
                <div className="form-field-group">
                  <div className="field-label-row">
                    <label htmlFor="login-password" className="field-label">Security Clearance Key</label>
                  </div>
                  <div className="input-container-box">
                    <svg className="field-leading-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                    <input 
                      id="login-password"
                      type={showPassword ? 'text' : 'password'}
                      className="form-text-input"
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      required
                    />
                    <button 
                      type="button" 
                      className="pw-reveal-button"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
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

              {/* Subactions (Remember & Forgot Link) */}
              {!isForgotPasswordMode && !isOtpMode && (
                <div className="form-subactions-row">
                  <label className="remember-label">
                    <input 
                      type="checkbox" 
                      className="remember-checkbox" 
                      checked={keepActive}
                      onChange={(e) => setKeepActive(e.target.checked)}
                    />
                    <span>Keep session active</span>
                  </label>
                  <a 
                    href="#forgot" 
                    className="forgot-pw-link"
                    onClick={(e) => {
                      e.preventDefault();
                      setIsForgotPasswordMode(true);
                      setError(null);
                      setResetSuccess(null);
                    }}
                  >
                    Forgot credentials?
                  </a>
                </div>
              )}

              {/* Submit Button */}
              <button 
                type="submit" 
                className="btn-submit-action"
                disabled={isLoggingIn || isSendingReset}
              >
                <span>
                  {isLoggingIn 
                    ? 'AUTHENTICATING...' 
                    : (isSendingReset 
                      ? (isOtpMode ? 'VERIFYING...' : 'SENDING...') 
                      : (isOtpMode ? 'VERIFY OTP' : (isForgotPasswordMode ? 'SEND OTP' : 'SECURE LOGIN')))}
                </span>
                {!isLoggingIn && !isSendingReset && (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <line x1="5" y1="12" x2="19" y2="12" />
                    <polyline points="12 5 19 12 12 19" />
                  </svg>
                )}
              </button>

              {/* Recovery Navigation */}
              {(isForgotPasswordMode || isOtpMode) && (
                <a 
                  href="#login" 
                  className="back-to-login-link"
                  onClick={handleCancelRecovery}
                >
                  ← Back to login
                </a>
              )}
            </form>

            {/* Bottom Security Classification Note */}
            <div className="card-bottom-warning">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>RESTRICTED ACCESS ONLY — LAW ENFORCEMENT &amp; FORENSICS</span>
            </div>

          </div>
        </section>

      </main>
    </div>
  );
};

export default Login;