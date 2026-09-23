import React, { useEffect, useRef, useState } from 'react';
import '../css/login.css';
import '../css/style.css'; 
import { useNavigate } from 'react-router-dom';
import * as THREE from 'three';
import { login as apiLogin } from '../js/api';

const Login = () => {
  const navigate = useNavigate();
  const canvasRef = useRef(null);
  const [userid, setUserid] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [isForgotPasswordMode, setIsForgotPasswordMode] = useState(false);
  const [isOtpMode, setIsOtpMode] = useState(false);
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isSendingReset, setIsSendingReset] = useState(false);
  const [resetSuccess, setResetSuccess] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  useEffect(() => {
    if (!canvasRef.current) return;

    const GLOBE_RADIUS = 3.2;
    let scene, camera, renderer, globeGroup, orbitalRingsGroup, nodeGroup, arcGroup;
    let targetRotation = { x: 0.15, y: -0.4 };
    let currentRotation = { x: 0.15, y: -0.4 };
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };
    let targetCameraZ = 9.5;
    let lastUserInteraction = 0;
    let frameId;

    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x0a0f1c, 0.015);

    camera = new THREE.PerspectiveCamera(40, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 0, targetCameraZ);

    renderer = new THREE.WebGLRenderer({ canvas: canvasRef.current, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.2);
    scene.add(ambientLight);
    const blueLight = new THREE.DirectionalLight(0x2563EB, 1.6);
    blueLight.position.set(5, 5, 5);
    scene.add(blueLight);
    const cyanLight = new THREE.DirectionalLight(0x06B6D4, 1.2);
    cyanLight.position.set(-5, -4, 4);
    scene.add(cyanLight);

    globeGroup = new THREE.Group();
    globeGroup.position.x = -2; // Shift to the left
    scene.add(globeGroup);

    // Sleek High-Tech Icosahedron Wireframe Sphere
    const wireframeGeo = new THREE.IcosahedronGeometry(GLOBE_RADIUS, 3);
    const wireframeMat = new THREE.MeshBasicMaterial({ color: 0x3B82F6, wireframe: true, transparent: true, opacity: 0.35 });
    const wireframeMesh = new THREE.Mesh(wireframeGeo, wireframeMat);
    globeGroup.add(wireframeMesh);

    // Inner Translucent Core Sphere
    const coreGeo = new THREE.SphereGeometry(GLOBE_RADIUS * 0.98, 48, 48);
    const coreMat = new THREE.MeshBasicMaterial({ color: 0xE0F2FE, transparent: true, opacity: 0.28 });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    globeGroup.add(coreMesh);

    // Latitude Rings / Contours
    const latGroup = new THREE.Group();
    for (let i = -4; i <= 4; i++) {
      const angle = (i * 18) * Math.PI / 180;
      const r = Math.cos(angle) * (GLOBE_RADIUS * 1.002);
      const y = Math.sin(angle) * (GLOBE_RADIUS * 1.002);
      const ringGeo = new THREE.BufferGeometry();
      const pts = [];
      for (let j = 0; j <= 90; j++) {
        const theta = (j / 90) * Math.PI * 2;
        pts.push(new THREE.Vector3(Math.cos(theta) * r, y, Math.sin(theta) * r));
      }
      ringGeo.setFromPoints(pts);
      const ringMat = new THREE.LineBasicMaterial({ color: 0x2563EB, transparent: true, opacity: 0.25 });
      latGroup.add(new THREE.Line(ringGeo, ringMat));
    }
    globeGroup.add(latGroup);

    // Longitude Meridians
    for (let i = 0; i < 12; i++) {
      const ringGeo = new THREE.BufferGeometry();
      const pts = [];
      const rotY = (i / 12) * Math.PI;
      for (let j = 0; j <= 90; j++) {
        const theta = (j / 90) * Math.PI * 2;
        const x = Math.cos(theta) * (GLOBE_RADIUS * 1.002);
        const y = Math.sin(theta) * (GLOBE_RADIUS * 1.002);
        pts.push(new THREE.Vector3(x * Math.cos(rotY), y, x * Math.sin(rotY)));
      }
      ringGeo.setFromPoints(pts);
      const ringMat = new THREE.LineBasicMaterial({ color: 0x06B6D4, transparent: true, opacity: 0.18 });
      globeGroup.add(new THREE.Line(ringGeo, ringMat));
    }

    // Orbital Concentric Rings
    orbitalRingsGroup = new THREE.Group();
    for (let k = 0; k < 3; k++) {
      const ringRadius = GLOBE_RADIUS * (1.18 + k * 0.12);
      const orbGeo = new THREE.BufferGeometry();
      const pts = [];
      for (let j = 0; j <= 120; j++) {
        const a = (j / 120) * Math.PI * 2;
        pts.push(new THREE.Vector3(Math.cos(a) * ringRadius, 0, Math.sin(a) * ringRadius));
      }
      orbGeo.setFromPoints(pts);
      const orbMat = new THREE.LineBasicMaterial({ color: 0x06B6D4, transparent: true, opacity: 0.35 });
      const ringLine = new THREE.Line(orbGeo, orbMat);
      ringLine.rotation.x = (k + 1) * 0.5;
      ringLine.rotation.y = (k + 1) * 0.3;
      orbitalRingsGroup.add(ringLine);
    }
    globeGroup.add(orbitalRingsGroup);

    // Particles Cloud
    const partCount = 1000;
    const partGeo = new THREE.BufferGeometry();
    const partPos = new Float32Array(partCount * 3);
    const partColors = new Float32Array(partCount * 3);
    const colorBlue = new THREE.Color(0x3B82F6);
    const colorRed = new THREE.Color(0xef4444);

    for (let i = 0; i < partCount; i++) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = GLOBE_RADIUS * (1.05 + Math.random() * 0.3);
      partPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      partPos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      partPos[i * 3 + 2] = r * Math.cos(phi);

      if (Math.random() > 0.90) {
        partColors[i * 3] = colorRed.r;
        partColors[i * 3 + 1] = colorRed.g;
        partColors[i * 3 + 2] = colorRed.b;
      } else {
        partColors[i * 3] = colorBlue.r;
        partColors[i * 3 + 1] = colorBlue.g;
        partColors[i * 3 + 2] = colorBlue.b;
      }
    }
    partGeo.setAttribute('position', new THREE.BufferAttribute(partPos, 3));
    partGeo.setAttribute('color', new THREE.BufferAttribute(partColors, 3));
    const partMat = new THREE.PointsMaterial({ size: 0.05, vertexColors: true, transparent: true, opacity: 0.75 });
    globeGroup.add(new THREE.Points(partGeo, partMat));

    // Glowing Forensic Nodes & Connection Arcs
    const latLonToVector3 = (lat, lon, radius) => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (lon + 180) * (Math.PI / 180);
      const x = -(radius * Math.sin(phi) * Math.cos(theta));
      const z = (radius * Math.sin(phi) * Math.sin(theta));
      const y = (radius * Math.cos(phi));
      return new THREE.Vector3(x, y, z);
    };

    nodeGroup = new THREE.Group();
    arcGroup = new THREE.Group();

    const nodeCoords = [
      { lat: 40.71, lon: -74.00 }, { lat: 51.50, lon: -0.12 }, { lat: 35.67, lon: 139.65 },
      { lat: 1.35, lon: 103.81 }, { lat: -33.86, lon: 151.20 }, { lat: 52.52, lon: 13.40 },
      { lat: 37.77, lon: -122.41 }, { lat: 28.61, lon: 77.20 }
    ];

    const nodePositions = [];
    nodeCoords.forEach((coord) => {
      const pos = latLonToVector3(coord.lat, coord.lon, GLOBE_RADIUS * 1.015);
      nodePositions.push(pos);
      const isRed = Math.random() > 0.6;
      const dotColor = isRed ? 0xef4444 : 0x06B6D4;
      const haloColor = isRed ? 0xef4444 : 0x3B82F6;

      const nodeGeo = new THREE.SphereGeometry(0.08, 16, 16);
      const nodeMat = new THREE.MeshBasicMaterial({ color: dotColor });
      const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
      nodeMesh.position.copy(pos);
      nodeGroup.add(nodeMesh);

      const haloGeo = new THREE.SphereGeometry(0.16, 16, 16);
      const haloMat = new THREE.MeshBasicMaterial({ color: haloColor, transparent: true, opacity: 0.45 });
      const haloMesh = new THREE.Mesh(haloGeo, haloMat);
      haloMesh.position.copy(pos);
      nodeGroup.add(haloMesh);
    });
    globeGroup.add(nodeGroup);

    for (let i = 0; i < nodePositions.length - 1; i += 2) {
      const start = nodePositions[i];
      const end = nodePositions[(i + 1) % nodePositions.length];
      const mid = start.clone().add(end).multiplyScalar(0.5);
      const distance = start.distanceTo(end);
      mid.normalize().multiplyScalar(GLOBE_RADIUS * (1.15 + distance * 0.06));

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(50);
      const arcGeo = new THREE.BufferGeometry().setFromPoints(points);
      const arcMat = new THREE.LineBasicMaterial({ color: 0x06B6D4, transparent: true, opacity: 0.6 });
      arcGroup.add(new THREE.Line(arcGeo, arcMat));
    }
    globeGroup.add(arcGroup);

    // Event Listeners
    const onPointerDown = (e) => {
      if (e.target.closest('.login-card-container') || e.target.closest('.argus-header')) return;
      isDragging = true;
      previousMousePosition = { x: e.clientX, y: e.clientY };
      lastUserInteraction = Date.now();
    };

    const onPointerMove = (e) => {
      lastUserInteraction = Date.now();
      // Always rotate from mouse delta — same behaviour whether clicking or just hovering
      const deltaX = e.clientX - previousMousePosition.x;
      const deltaY = e.clientY - previousMousePosition.y;
      targetRotation.y += deltaX * 0.0015;
      targetRotation.x += deltaY * 0.0015;
      targetRotation.x = Math.max(-Math.PI / 2, Math.min(Math.PI / 2, targetRotation.x));
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onPointerUp = () => { isDragging = false; };

    const onWheel = (e) => {
      if (e.target.closest('.login-card-container')) return;
      lastUserInteraction = Date.now();
      targetCameraZ += e.deltaY * 0.004;
      targetCameraZ = Math.max(3.5, Math.min(25, targetCameraZ));
    };
    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };

    window.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp);
    window.addEventListener('wheel', onWheel, { passive: true });
    window.addEventListener('resize', onResize);

    // Animation Loop
    const animate = () => {
      frameId = requestAnimationFrame(animate);

      // Auto-spin only when user hasn't moved the mouse recently
      if (Date.now() - lastUserInteraction > 3000) {
        targetRotation.y += 0.002;
      }

      currentRotation.x += (targetRotation.x - currentRotation.x) * 0.08;
      currentRotation.y += (targetRotation.y - currentRotation.y) * 0.08;

      globeGroup.rotation.x = currentRotation.x;
      globeGroup.rotation.y = currentRotation.y;

      if (orbitalRingsGroup) {
        orbitalRingsGroup.rotation.z += 0.001;
      }

      camera.position.z += (targetCameraZ - camera.position.z) * 0.08;
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerup', onPointerUp);
      window.removeEventListener('wheel', onWheel);
      window.removeEventListener('resize', onResize);
      renderer.dispose();
    };
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    setResetSuccess(false);

    if (isForgotPasswordMode) {
      if (!userid) {
        setError('Please enter your User ID to send the OTP.');
        return;
      }
      setIsSendingReset(true);
      try {
        const response = await fetch('http://localhost:8000/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userid })
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          setError(errorData.detail || 'This User ID is not registered.');
          setIsSendingReset(false);
          return;
        }
        
        const successData = await response.json();
        setResetSuccess(successData.message);
        setIsSendingReset(false);
        setIsForgotPasswordMode(false);
        setIsOtpMode(true);
      } catch (err) {
        setError('Network error. Failed to connect to server.');
        setIsSendingReset(false);
      }
      return;
    }

    if (isOtpMode) {
      if (!otp || !newPassword) {
        setError('Please enter the OTP sent to your email and your new password.');
        return;
      }
      setIsSendingReset(true);
      try {
        const response = await fetch('http://localhost:8000/auth/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userid, otp, new_password: newPassword })
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          setError(errorData.detail || 'Invalid OTP. Please check and try again.');
          setIsSendingReset(false);
          return;
        }
        
        const successData = await response.json();
        setResetSuccess(successData.message);
        setIsSendingReset(false);
        setIsOtpMode(false);
        setIsForgotPasswordMode(false);
        setOtp('');
        setNewPassword('');
        setPassword('');
      } catch (err) {
        setError('Network error. Failed to connect to server.');
        setIsSendingReset(false);
      }
      return;
    }

    if (!userid || !password) {
      setError('Please enter both your User ID and password.');
      return;
    }
    try {
      setIsLoggingIn(true);
      const data = await apiLogin(userid, password);
      localStorage.setItem('argus_token', data.token);
      localStorage.setItem('argus_user', JSON.stringify(data.user));
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Network error. Please try again later.');
      setIsLoggingIn(false);
    }
  };

  return (
    <div style={{width: '100vw', height: '100vh', overflow: 'hidden', position: 'relative'}}>
      {/* BACKGROUND AMBIENT GRADIENT LAYER */}
      <div className="bg-ambient-gradient"></div>

      {/* FULLSCREEN 3D GLOBE CANVAS */}
      <canvas ref={canvasRef} id="webgl-canvas"></canvas>

      {/* HEADER */}
      <header className="argus-header" style={{zIndex: 10, position: 'relative'}}>
        <div className="header-left">
          <div className="header-logo-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <circle cx="12" cy="12" r="9"/>
              <circle cx="12" cy="12" r="3"/>
              <line x1="12" y1="3" x2="12" y2="6"/>
              <line x1="12" y1="18" x2="12" y2="21"/>
              <line x1="3" y1="12" x2="6" y2="12"/>
              <line x1="18" y1="12" x2="21" y2="12"/>
            </svg>
          </div>
          <div className="header-brand-title">
            <span className="brand-name">ARGUS</span>
            <span className="brand-sub">Digital Forensic Intelligence</span>
          </div>
        </div>

        <div className="header-right">
          {/* THEME TOGGLE BUTTON */}
          <button 
            type="button" 
            className="theme-toggle-btn" 
            aria-label="Toggle Theme" 
            onClick={() => {
              const root = document.documentElement;
              const newTheme = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
              if (newTheme === 'light') {
                root.setAttribute('data-theme', 'light');
              } else {
                root.removeAttribute('data-theme');
              }
              if (window.toggleTheme) window.toggleTheme();
              else {
                localStorage.setItem('argus_theme', newTheme);
              }
            }}
            style={{background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text-main)', cursor: 'pointer', padding: '10px', borderRadius: '50%', marginRight: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 2px 8px rgba(0,0,0,0.1)'}}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
            </svg>
          </button>

          <div className="security-badge">
            <div className="badge-top-row">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              <span>SECURE ENVIRONMENT</span>
              <span className="status-dot-green"></span>
            </div>
            <span className="badge-sub-row">TRUST • ANALYZE • PROTECT</span>
          </div>
        </div>
      </header>

      {/* FEATURE BADGES LIST (VERTICAL ON LEFT) */}
      <div className="feature-badges-list" style={{ 
        position: 'fixed', top: '50%', left: '4vw', transform: 'translateY(-50%)', 
        display: 'flex', flexDirection: 'column', gap: '32px', zIndex: 15, pointerEvents: 'none'
      }}>
        <div className="feature-badge-item">
          <div className="badge-icon-circle" style={{ width: '42px', height: '42px' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <circle cx="11" cy="11" r="8"/>
              <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
          </div>
          <div className="badge-text-group">
            <span className="badge-title">INVESTIGATE</span>
            <span className="badge-sub">DEEPER</span>
          </div>
        </div>

        <div className="feature-badge-item">
          <div className="badge-icon-circle" style={{ width: '42px', height: '42px' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <line x1="18" y1="20" x2="18" y2="10"/>
              <line x1="12" y1="20" x2="12" y2="4"/>
              <line x1="6" y1="20" x2="6" y2="14"/>
            </svg>
          </div>
          <div className="badge-text-group">
            <span className="badge-title">UNLOCK</span>
            <span className="badge-sub">INSIGHTS</span>
          </div>
        </div>

        <div className="feature-badge-item">
          <div className="badge-icon-circle" style={{ width: '42px', height: '42px' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div className="badge-text-group">
            <span className="badge-title">PROTECT</span>
            <span className="badge-sub">WHAT MATTERS</span>
          </div>
        </div>

        <div className="feature-badge-item">
          <div className="badge-icon-circle" style={{ width: '42px', height: '42px' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <circle cx="18" cy="5" r="3"/>
              <circle cx="6" cy="12" r="3"/>
              <circle cx="18" cy="19" r="3"/>
              <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
              <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
            </svg>
          </div>
          <div className="badge-text-group">
            <span className="badge-title">CONNECT</span>
            <span className="badge-sub">THE EVIDENCE</span>
          </div>
        </div>
      </div>

      {/* RIGHT STAGE LOGIN CARD */}
      <main className="page-center-stage" style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', zIndex: 10, display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: '12vw', pointerEvents: 'none' }}>
        <div className="login-card-container" style={{ pointerEvents: 'auto' }}>
          <div className="login-card">
            
            {/* CARD TOP LOGO */}
            <div className="card-logo-circle">
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <circle cx="12" cy="12" r="9"/>
                <circle cx="12" cy="12" r="3"/>
                <line x1="12" y1="3" x2="12" y2="6"/>
                <line x1="12" y1="18" x2="12" y2="21"/>
                <line x1="3" y1="12" x2="6" y2="12"/>
                <line x1="18" y1="12" x2="21" y2="12"/>
              </svg>
            </div>

            <div className="card-title-group">
              <h1 className="card-brand-title">ARGUS</h1>
              <p className="card-brand-sub">Digital Forensic Intelligence</p>
              <div className="blue-divider-line"></div>
              <span className="card-micro-tagline">EVIDENCE • ANALYZE • DELIVER TRUTH</span>
            </div>

            {/* FORM */}
            <form id="login-form" className="login-form" onSubmit={handleLogin}>
              {error && <div className="error-banner">{error}</div>}
              {resetSuccess && (
                <div className="error-banner" style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid var(--success-green)', color: 'var(--success-green)' }}>
                  {typeof resetSuccess === 'string' ? resetSuccess : 'OTP sent successfully'}
                </div>
              )}

              {/* ANALYST ID FIELD */}
              {!isOtpMode && (
                <div className="input-field-group">
                  <label className="field-label" htmlFor="login-userid">Analyst ID</label>
                  <div className="input-box-wrapper">
                    <svg className="field-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                      <circle cx="12" cy="7" r="4"/>
                    </svg>
                    <input type="text" id="login-userid" className="form-input" placeholder="Enter your User ID" value={userid} onChange={(e) => setUserid(e.target.value)} required autoComplete="username" />
                  </div>
                </div>
              )}

              {/* OTP FIELD */}
              {isOtpMode && (
                <>
                  <div className="input-field-group">
                    <label className="field-label" htmlFor="login-otp">One-Time Password</label>
                    <div className="input-box-wrapper">
                      <svg className="field-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                      </svg>
                      <input type="text" id="login-otp" className="form-input" placeholder="Enter 6-digit OTP" value={otp} onChange={(e) => setOtp(e.target.value)} required autoComplete="off" maxLength={6} />
                    </div>
                  </div>
                  <div className="input-field-group">
                    <label className="field-label" htmlFor="login-new-password">New Password</label>
                    <div className="input-box-wrapper">
                      <svg className="field-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                      </svg>
                      <input type={showPassword ? "text" : "password"} id="login-new-password" className="form-input" placeholder="Enter new password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required autoComplete="new-password" />
                      <button type="button" className="pw-toggle-btn" aria-label="Toggle password visibility" onClick={() => setShowPassword(!showPassword)}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          {showPassword ? (
                            <>
                              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                              <line x1="1" y1="1" x2="23" y2="23"/>
                            </>
                          ) : (
                            <>
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                              <circle cx="12" cy="12" r="3"/>
                            </>
                          )}
                        </svg>
                      </button>
                    </div>
                  </div>
                </>
              )}

              {/* PASSWORD FIELD */}
              {!isForgotPasswordMode && !isOtpMode && (
                <div className="input-field-group">
                  <label className="field-label" htmlFor="login-password">Password</label>
                  <div className="input-box-wrapper">
                    <svg className="field-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    <input type={showPassword ? "text" : "password"} id="login-password" className="form-input" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
                    <button type="button" className="pw-toggle-btn" aria-label="Toggle password visibility" onClick={() => setShowPassword(!showPassword)}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        {showPassword ? (
                          <>
                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                            <line x1="1" y1="1" x2="23" y2="23"/>
                          </>
                        ) : (
                          <>
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                          </>
                        )}
                      </svg>
                    </button>
                  </div>
                </div>
              )}

              {!isForgotPasswordMode && !isOtpMode && (
                <div className="forgot-row" style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '-12px', marginBottom: '24px' }}>
                  <a href="#" className="forgot-link" onClick={(e) => { e.preventDefault(); setIsForgotPasswordMode(true); setError(null); setResetSuccess(false); }} style={{ color: 'var(--brand-blue)', fontSize: '13px', fontWeight: '600', textDecoration: 'none', transition: 'opacity 0.2s' }}>Forgot credentials?</a>
                </div>
              )}

              <button type="submit" className="btn-login-submit" style={{ opacity: (isSendingReset || isLoggingIn) ? 0.8 : 1, cursor: (isSendingReset || isLoggingIn) ? 'not-allowed' : 'pointer' }}>
                {isLoggingIn ? 'AUTHENTICATING...' : (isSendingReset ? (isOtpMode ? 'VERIFYING...' : 'SENDING...') : (isOtpMode ? 'VERIFY OTP' : (isForgotPasswordMode ? 'SEND OTP' : 'SECURE LOGIN')))}
                {!isForgotPasswordMode && !isOtpMode && !isSendingReset && !isLoggingIn && <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>}
              </button>

              {(isForgotPasswordMode || isOtpMode) && (
                <div className="forgot-row" style={{ display: 'flex', justifyContent: 'center', marginTop: '16px' }}>
                  <a href="#" className="forgot-link" onClick={(e) => { e.preventDefault(); setIsForgotPasswordMode(false); setIsOtpMode(false); setError(null); setResetSuccess(false); }} style={{ color: 'var(--text-muted)', fontSize: '13px', fontWeight: '600', textDecoration: 'none', transition: 'color 0.2s' }}>← Back to login</a>
                </div>
              )}
            </form>
            
            <div className="card-footer-note">RESTRICTED ACCESS ONLY</div>
          </div>
        </div>
      </main>

    </div>
  );
};

export default Login;