import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import { uploadEvidenceFile } from '../js/api';

import Sidebar from '../components/Sidebar';
import ProfileModal from '../components/ProfileModal';
import AlertModal from '../components/AlertModal';

const Upload = () => {
  const navigate = useNavigate();
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const isAdmin = currentUser?.role === 'admin';
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const modalFileInputRef = useRef(null);

  const [queue, setQueue] = useState([]);
  const [dragOver, setDragOver] = useState(false);
  const [argusEnabled, setArgusEnabled] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };

  const handleOpenCreateCase = () => {
    const activeCaseId = localStorage.getItem('active_case_id');
    const activeCaseName = localStorage.getItem('active_case_name');
    if (activeCaseId && activeCaseId !== '00000000-0000-0000-0000-000000000001' && activeCaseName && activeCaseName !== 'Case 00000000') {
      setCustomAlert({ isOpen: true, title: 'Notice', message: `An active case "${activeCaseName}" is currently open. Please close the active case before creating a new case.`, type: 'warning' });
      return;
    }
    setShowModal(true);
  };

  const handleCloseCase = () => {
    const activeCaseName = localStorage.getItem('active_case_name') || 'Current case';
    const activeCaseId = localStorage.getItem('active_case_id');
    if (!activeCaseId && !localStorage.getItem('active_case_name')) {
      setCustomAlert({ isOpen: true, title: 'Notice', message: "There is no active case currently open.", type: 'warning' });
      return;
    }
    localStorage.removeItem('active_case_id');
    localStorage.removeItem('active_case_name');
    localStorage.removeItem('active_case_desc');
    setCustomAlert({
       isOpen: true,
       title: 'Success',
       message: `${activeCaseName} has been closed successfully.`,
       type: 'success',
       onClose: () => window.location.reload()
    });
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    addFiles(files);
  };

  const addFiles = (files) => {
    const newItems = files.map((f, i) => ({
      id: Date.now() + i,
      name: f.name,
      size: formatSize(f.size),
      type: 'Auto Detect',
      status: 'ready',
      file: f
    }));
    setQueue(prev => [...prev, ...newItems]);
  };

  const formatSize = (bytes) => {
    if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB';
    if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
    if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB';
    return bytes + ' B';
  };

  const removeItem = (id) => setQueue(prev => prev.filter(i => i.id !== id));
  const clearAll = () => setQueue([]);

  const handleUpload = async () => {
    if (queue.length === 0) return;
    setUploading(true);
    setQueue(prev => prev.map(i => i.status === 'ready' ? { ...i, status: 'uploading' } : i));

    let caseId = localStorage.getItem('active_case_id');
    if (!caseId || caseId === '00000000-0000-0000-0000-000000000001') {
      setCustomAlert({ isOpen: true, title: 'Notice', message: "Please select or create an active case before uploading evidence.", type: 'warning' });
      setUploading(false);
      setQueue(prev => prev.map(i => i.status === 'uploading' ? { ...i, status: 'ready' } : i));
      return;
    }

    const uploadPromises = queue.filter(item => item.status === 'uploading' || item.status === 'ready').map(async (item) => {
      try {
        await uploadEvidenceFile(item.file, caseId);
        setQueue(prev => prev.map(i => i.id === item.id ? { ...i, status: 'done' } : i));
      } catch (err) {
        console.error(`Upload failed for ${item.name}`, err);
        setQueue(prev => prev.map(i => i.id === item.id ? { ...i, status: 'error' } : i));
      }
    });

    await Promise.all(uploadPromises);
    setUploading(false);
  };

  const statusBadge = (status) => {
    const map = {
      ready: { color: 'var(--blue)', bg: 'var(--blue-light)', label: 'Ready' },
      uploading: { color: 'var(--orange)', bg: 'var(--orange-light)', label: 'Uploading...' },
      done: { color: '#10b981', bg: '#e6f6ec', label: 'Done' },
      error: { color: '#ef4444', bg: '#fee2e2', label: 'Failed' },
    };
    const s = map[status] || map.ready;
    return (
      <span style={{ background: s.bg, color: s.color, padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 600 }}>
        {s.label}
      </span>
    );
  };

  return (
    <>
      <div id="app-shell">
        <AlertModal 
          isOpen={customAlert.isOpen} 
          title={customAlert.title} 
          message={customAlert.message} 
          type={customAlert.type} 
          onClose={closeAlert} 
        />
        <Sidebar active="upload" />

        <main className="main-content">
          {/* TOPBAR */}
          <header className="topbar">
            <div className="search-container">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: 8 }}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input type="text" placeholder="Search cases, evidence, or findings..." />
              <span className="search-shortcut">⌘ K</span>
            </div>
            <div className="topbar-actions" style={{ flex: 1, justifyContent: 'flex-end', display: 'flex' }}>
              <button
                type="button"
                onClick={handleCloseCase}
                className="btn btn-outline"
                style={{ border: '1px solid var(--border-strong)', color: 'var(--text-main)', background: 'var(--bg-card)', padding: '8px 16px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
                Close Case
              </button>
              {isAdmin && (
                <button
                  type="button"
                  onClick={handleOpenCreateCase}
                  className="btn btn-primary"
                  style={{ background: 'linear-gradient(135deg, var(--blue), var(--purple))', border: 'none', boxShadow: '0 4px 12px rgba(59,130,246,0.3)', padding: '8px 16px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, color: '#fff', cursor: 'pointer' }}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                  Create Case
                </button>
              )}
              {localStorage.getItem('active_case_id') && <div className="badge-live"><div className="live-dot"></div> Live Analysis</div>}
              <button className="icon-btn">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                <div className="notification-dot">3</div>
              </button>
              <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
                <div className="avatar">A</div>
                <span style={{ fontWeight: 500 }}>Analyst</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
                {showUserDropdown && (
                  <div className="user-dropdown" style={{ display: 'block' }}>
                    <div className="user-dropdown-header">
                      <div className="ud-name">Analyst</div>
                      <div className="ud-role">Digital Forensics Investigator</div>
                    </div>
                    <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); setShowProfileModal(true); setShowUserDropdown(false); }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                      My Profile
                    </button>
                  </div>
                )}
              </div>
            </div>
          </header>

          <div className="dashboard-scroll">
            {/* Case Header */}
            <div className="header-card" style={{ flexShrink: 0 }}>
              <div className="header-info-wrap">
                <div className="header-id"><h1>UPLOAD EVIDENCE</h1></div>
                <div className="header-details">
                  <h2 style={{ fontSize: 16, fontWeight: 500, color: 'var(--text-muted)' }}>Add digital artifacts to the active investigation for ARGUS analysis.</h2>
                  <div className="header-meta" style={{ marginTop: 12, gap: 12 }}>
                    <div className="meta-item" style={{ color: 'var(--text-main)', background: 'var(--bg-card)', padding: '4px 12px', borderRadius: 20, border: '1px solid var(--border-subtle)', display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                      <div>
                        <span style={{ fontSize: 12, fontWeight: 600 }}>{localStorage.getItem('active_case_id') || 'Unknown ID'}</span>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 4 }}>{localStorage.getItem('active_case_name') || 'Unnamed Case'}</span>
                      </div>
                    </div>
                    <div className="badge-danger">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                      High Risk
                    </div>
                  </div>
                </div>
              </div>
              <div className="header-quote">
                <p>"From digital traces to real answers."</p>
                <span>— ARGUS</span>
              </div>
            </div>

            {/* Evidence Tabs */}
            <div className="panel-card" style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', overflow: 'hidden', flexShrink: 0 }}>
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-strong)', padding: '0 24px', background: 'var(--bg-app)' }}>
                <a href="/evidence" style={{ padding: '16px 20px', fontWeight: 500, fontSize: 14, color: 'var(--text-muted)', textDecoration: 'none' }}>Evidence Items</a>
                <div style={{ padding: '16px 20px', fontWeight: 600, fontSize: 14, color: 'var(--blue)', borderBottom: '2px solid var(--blue)', cursor: 'pointer' }}>Upload Evidence</div>
                <div style={{ padding: '16px 20px', fontWeight: 500, fontSize: 14, color: 'var(--text-muted)', cursor: 'pointer' }}>Coverage</div>
              </div>

              {/* Main Upload Workspace */}
              <div style={{ display: 'grid', gridTemplateColumns: '2.5fr 1fr', gap: 24, padding: 24 }}>

                {/* Left Column */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

                  {/* Dropzone */}
                  <div
                    onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                    onDragLeave={() => setDragOver(false)}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    style={{
                      borderRadius: 'var(--radius-lg)',
                      border: `2px dashed ${dragOver ? 'var(--purple)' : 'var(--blue)'}`,
                      background: dragOver ? 'var(--purple-light, #f3e8ff)' : 'var(--bg-card)',
                      textAlign: 'center',
                      padding: '60px 40px',
                      position: 'relative',
                      overflow: 'hidden',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      cursor: 'pointer',
                      transition: 'all 0.3s ease',
                    }}
                  >
                    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, background: 'radial-gradient(circle at center, rgba(37,99,235,0.04) 0%, transparent 70%)', pointerEvents: 'none' }} />
                    <div style={{ background: 'var(--blue-light)', color: 'var(--blue)', width: 64, height: 64, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 24, boxShadow: '0 4px 12px rgba(37,99,235,0.1)' }}>
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    </div>
                    <h2 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>Upload Evidence</h2>
                    <p style={{ fontSize: 15, color: 'var(--text-muted)', marginBottom: 16 }}>Drag and drop files here<br />or</p>
                    <div style={{ display: 'flex', gap: 12, marginBottom: 24, position: 'relative', zIndex: 2 }}>
                      <button className="btn btn-primary" id="btn-browse-files" onClick={e => { e.stopPropagation(); fileInputRef.current?.click(); }} style={{ padding: '10px 20px', fontSize: 14, borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', gap: 8 }}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        Browse Files
                      </button>
                      <button className="btn btn-outline" id="btn-browse-folders" onClick={e => { e.stopPropagation(); folderInputRef.current?.click(); }} style={{ padding: '10px 20px', fontSize: 14, borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-card)' }}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                        Browse Folder
                      </button>
                    </div>
                    <input ref={fileInputRef} type="file" multiple style={{ display: 'none' }} onChange={e => addFiles(Array.from(e.target.files))} />
                    <input ref={folderInputRef} type="file" multiple webkitdirectory="true" style={{ display: 'none' }} onChange={e => addFiles(Array.from(e.target.files))} />
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                      Supported evidence: Disk Images · Memory Dumps · Logs · PCAP · Documents · Archives
                    </div>
                  </div>

                  {/* Metadata Fields */}
                  <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', padding: 24, display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 32 }}>
                    <div>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 12 }}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                        Evidence Type
                      </label>
                      <select style={{ width: '100%', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 14, color: 'var(--text-main)', background: 'var(--bg-app)', outline: 'none' }}>
                        <option>Auto Detect</option>
                        <option>Disk Image</option>
                        <option>Memory Dump</option>
                        <option>Network Capture</option>
                        <option>Windows Event Log</option>
                        <option>Linux Log</option>
                        <option>Registry Hive</option>
                        <option>File / Document</option>
                        <option>Archive</option>
                        <option>Other</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 12 }}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="2"><rect x="2" y="4" width="20" height="16" rx="2" ry="2"/><path d="M10 4v4"/><path d="M14 4v4"/><path d="M2 8h20"/></svg>
                        Evidence Source
                      </label>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                        <div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Source Device</div>
                          <input type="text" id="source-device-input" defaultValue="DESKTOP-7G2K" style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 13, color: 'var(--text-main)', background: 'var(--bg-app)', outline: 'none', boxSizing: 'border-box' }} />
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Collection Date</div>
                          <input type="text" defaultValue="Nov 14, 2024 09:41 AM" style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 13, color: 'var(--text-main)', background: 'var(--bg-app)', outline: 'none', boxSizing: 'border-box' }} />
                        </div>
                        <div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Collected By</div>
                          <select style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 13, color: 'var(--text-main)', background: 'var(--bg-app)', outline: 'none' }}>
                            <option>Analyst</option>
                          </select>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Upload Queue */}
                  <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', display: 'flex', flexDirection: 'column' }}>
                    <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-strong)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-main)' }}>
                        Upload Queue <span style={{ fontWeight: 400, color: 'var(--text-muted)', fontSize: 14 }}>({queue.length} files)</span>
                      </h3>
                      <button onClick={clearAll} style={{ fontSize: 12, color: 'var(--blue)', padding: '4px 8px', border: 'none', background: 'transparent', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        Clear All
                      </button>
                    </div>

                    {queue.length === 0 ? (
                      <div style={{ padding: '40px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                        No files in queue. Drop files or click Browse.
                      </div>
                    ) : (
                      <div style={{ padding: '16px 24px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {queue.map(item => (
                          <div key={item.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', background: 'var(--bg-app)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                            <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--blue-light)', color: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.name}</div>
                              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{item.type} · {item.size}</div>
                            </div>
                            {statusBadge(item.status)}
                            <button onClick={() => removeItem(item.id)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4, flexShrink: 0 }}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            </button>
                          </div>
                        ))}
                      </div>
                    )}

                    <div style={{ padding: '20px 24px', borderTop: '1px solid var(--border-strong)', display: 'flex', justifyContent: 'flex-end', gap: 16, marginTop: 'auto', background: 'var(--bg-app)', borderBottomLeftRadius: 'var(--radius-lg)', borderBottomRightRadius: 'var(--radius-lg)' }}>
                      <button className="btn btn-outline" style={{ padding: '12px 24px', fontWeight: 600 }}>Cancel</button>
                      <button id="btn-upload" className="btn btn-primary" onClick={handleUpload} disabled={uploading || queue.length === 0} style={{ padding: '12px 24px', fontWeight: 600, opacity: queue.length === 0 ? 0.5 : 1 }}>
                        {uploading ? 'Uploading...' : 'Upload & Analyze →'}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Right Column */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  {/* ARGUS Analysis Toggle */}
                  <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', padding: 24 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'var(--blue-light)', color: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
                        </div>
                        <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)' }}>ARGUS ANALYSIS</h3>
                      </div>
                      <label style={{ position: 'relative', display: 'inline-block', width: 44, height: 24, flexShrink: 0 }}>
                        <input type="checkbox" checked={argusEnabled} onChange={() => setArgusEnabled(v => !v)} style={{ opacity: 0, width: 0, height: 0 }} />
                        <span onClick={() => setArgusEnabled(v => !v)} style={{ position: 'absolute', cursor: 'pointer', top: 0, left: 0, right: 0, bottom: 0, background: argusEnabled ? 'var(--blue)' : 'var(--border-strong)', borderRadius: 24, transition: '0.3s' }}>
                          <span style={{ position: 'absolute', height: 18, width: 18, left: argusEnabled ? 23 : 3, bottom: 3, background: '#fff', borderRadius: '50%', transition: '0.3s' }} />
                        </span>
                      </label>
                    </div>
                    <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 8 }}>Analyze evidence automatically after upload</h4>
                    <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>ARGUS agents will automatically extract metadata, identify artifacts, correlate evidence and detect potential findings.</p>
                  </div>

                  {/* Evidence Integrity */}
                  <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', padding: 24 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                      <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'var(--bg-app)', color: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border-strong)' }}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                      </div>
                      <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)' }}>EVIDENCE INTEGRITY</h3>
                    </div>
                    <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>ARGUS automatically calculates and records a cryptographic hash (SHA-256) for uploaded evidence to preserve forensic integrity.</p>
                  </div>

                  {/* Tips */}
                  <div style={{ background: 'var(--bg-app)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-strong)', padding: 24, flexGrow: 1 }}>
                    <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-main)', marginBottom: 24, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                      Tips
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                      {[
                        { bg: 'var(--blue-light)', col: 'var(--blue)', title: 'Supported formats', desc: 'RAW, E01, VMDK, VHD, MEM, PCAP, EVTX, LOG, ZIP, RAR, and more.', icon: <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/> },
                        { bg: 'var(--purple-light, #f3e8ff)', col: 'var(--purple)', title: 'Larger files', desc: 'For files larger than 10 GB, use segmented upload or network ingestion.', icon: <><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></> },
                        { bg: '#e6f6ec', col: '#10b981', title: 'Case association', desc: `All uploaded evidence will be automatically associated with ${localStorage.getItem('active_case_name') || 'the active case'}.`, icon: <><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></> },
                        { bg: 'var(--orange-light)', col: 'var(--orange)', title: 'Next steps', desc: 'Once uploaded, ARGUS will ingest, parse and analyze the evidence automatically.', icon: <polygon points="5 3 19 12 5 21 5 3"/> },
                      ].map((tip, i) => (
                        <div key={i} style={{ display: 'flex', gap: 16 }}>
                          <div style={{ width: 32, height: 32, borderRadius: '50%', background: tip.bg, color: tip.col, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">{tip.icon}</svg>
                          </div>
                          <div>
                            <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 4 }}>{tip.title}</h4>
                            <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{tip.desc}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* Create Case Modal */}
      {showModal && (
        <div style={{ display: 'flex', position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)', zIndex: 100, alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', width: 480, boxShadow: '0 20px 40px rgba(0,0,0,0.2)', overflow: 'hidden' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: 18, fontWeight: 600 }}>Create New Case</h2>
              <button className="btn-icon" onClick={() => setShowModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Case Name</label>
                <input type="text" placeholder="e.g. Ransomware Incident - Alpha Corp" style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 14, outline: 'none', background: 'var(--bg-app)', color: 'var(--text-main)', boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Description</label>
                <textarea rows={3} placeholder="Brief details about the investigation..." style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 14, outline: 'none', resize: 'none', background: 'var(--bg-app)', color: 'var(--text-main)', boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Assigned Analysts</label>
                <input type="text" defaultValue="john.doe@company.com" style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 14, outline: 'none', background: 'var(--bg-app)', color: 'var(--text-main)', boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Initial Evidence (Optional)</label>
                <div onClick={() => modalFileInputRef.current?.click()} style={{ border: '1px dashed var(--blue)', borderRadius: 'var(--radius-md)', padding: 16, textAlign: 'center', background: 'var(--blue-light)', color: 'var(--blue)', fontSize: 13, cursor: 'pointer' }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginBottom: 4 }}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg><br />
                  Click to browse or drop files here
                </div>
                <input ref={modalFileInputRef} type="file" multiple style={{ display: 'none' }} />
              </div>
            </div>
            <div style={{ padding: '16px 24px', background: 'var(--bg-app)', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button className="btn btn-outline" onClick={() => setShowModal(false)} style={{ padding: '8px 16px' }}>Cancel</button>
              <button className="btn btn-primary" onClick={() => setShowModal(false)} style={{ padding: '8px 16px' }}>Create Case</button>
            </div>
          </div>
        </div>
      )}

      <ProfileModal isOpen={showProfileModal} onClose={() => setShowProfileModal(false)} />
    </>
  );
};

export default Upload;
