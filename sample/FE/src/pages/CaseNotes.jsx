import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import ProfileModal from '../components/ProfileModal';
import { API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import { safeFormatDateTime } from '../js/dateUtils';
import '../css/style.css';

const CaseNotes = () => {
  const navigate = useNavigate();
  const activeCaseId = localStorage.getItem('active_case_id');
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;

  const [showProfileModal, setShowProfileModal] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  const [notes, setNotes] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('All');
  const [filterPriority, setFilterPriority] = useState('All');
  const [sortOrder, setSortOrder] = useState('newest');

  const [showModal, setShowModal] = useState(false);
  const [editingNote, setEditingNote] = useState(null);
  
  // Form State
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [type, setType] = useState('Observation');
  const [priority, setPriority] = useState('Normal');
  const [relatedEvidence, setRelatedEvidence] = useState('');
  const [relatedFinding, setRelatedFinding] = useState('');

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null);
  const [alertConfig, setAlertConfig] = useState({ isOpen: false, title: '', message: '' });

  const fetchNotes = async () => {
    if (!activeCaseId) return;
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${activeCaseId}/notes`, {
        headers: {
          'X-Tenant-ID': DEFAULT_TENANT_ID,
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        const notesData = data.data || [];
        setNotes(notesData);
        localStorage.setItem(`seen_notes_${activeCaseId}`, notesData.length);
        
        const latestUpdate = Math.max(0, ...notesData.map(n => {
          const d = new Date(n.updatedAt || n.createdAt);
          return isNaN(d.getTime()) ? 0 : d.getTime();
        }));
        if (latestUpdate > 0) {
          localStorage.setItem(`last_seen_update_${activeCaseId}`, latestUpdate);
        }
      }
    } catch (e) {
      console.error('Error fetching notes', e);
    }
  };

  useEffect(() => {
    fetchNotes();

    const handleInterval = () => {
      if (document.visibilityState === 'visible') {
        fetchNotes();
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        fetchNotes();
      }
    };

    const intervalId = setInterval(handleInterval, 10000);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [activeCaseId]);

  const handleSave = async () => {
    if (!title || !content) {
      setAlertConfig({ isOpen: true, title: 'Validation Error', message: 'Note Title and Content are required!' });
      return;
    }
    const noteData = {
      title,
      content,
      type,
      priority,
      related_evidence_id: relatedEvidence || null,
      related_finding_id: relatedFinding || null
    };

    try {
      const url = editingNote 
        ? `${API_BASE_URL}/cases/${activeCaseId}/notes/${editingNote.noteId}`
        : `${API_BASE_URL}/cases/${activeCaseId}/notes`;
      const method = editingNote ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': DEFAULT_TENANT_ID,
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        },
        body: JSON.stringify(noteData)
      });
      if (res.ok) {
        setShowModal(false);
        fetchNotes();
      } else {
        const errorText = await res.text();
        setAlertConfig({ isOpen: true, title: 'Server Error', message: "Failed to save note: " + errorText });
      }
    } catch (e) {
      setAlertConfig({ isOpen: true, title: 'Network Error', message: "Error saving note: " + e.message });
      console.error('Error saving note', e);
    }
  };

  const handleDelete = async (noteId) => {
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${activeCaseId}/notes/${noteId}`, {
        method: 'DELETE',
        headers: {
          'X-Tenant-ID': DEFAULT_TENANT_ID,
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        }
      });
      if (res.ok) {
        setShowDeleteConfirm(null);
        fetchNotes();
      }
    } catch (e) {
      console.error('Error deleting note', e);
    }
  };

  const openNewNote = () => {
    setEditingNote(null);
    setTitle('');
    setContent('');
    setType('Observation');
    setPriority('Normal');
    setRelatedEvidence('');
    setRelatedFinding('');
    setShowModal(true);
  };

  const openEditNote = (note) => {
    setEditingNote(note);
    setTitle(note.title);
    setContent(note.content);
    setType(note.type);
    setPriority(note.priority);
    setRelatedEvidence(note.relatedEvidenceId || '');
    setRelatedFinding(note.relatedFindingId || '');
    setShowModal(true);
  };

  const isFollowUpNote = (n) => {
    const t = (n.type || '').toLowerCase();
    return t.includes('follow') || Boolean(n.relatedEvidenceId || n.relatedFindingId);
  };

  const filteredNotes = notes
    .filter(n => {
      if (filterType !== 'All') {
        if (filterType === 'Follow-up') {
          if (!isFollowUpNote(n)) return false;
        } else if (n.type !== filterType) {
          return false;
        }
      }
      if (filterPriority !== 'All' && n.priority !== filterPriority) return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return n.title.toLowerCase().includes(q) || 
               n.content.toLowerCase().includes(q) || 
               (n.relatedEvidenceId && n.relatedEvidenceId.toLowerCase().includes(q)) ||
               (n.relatedFindingId && n.relatedFindingId.toLowerCase().includes(q));
      }
      return true;
    })
    .sort((a, b) => {
      const timeA = new Date(a.createdAt || a.updatedAt || 0).getTime();
      const timeB = new Date(b.createdAt || b.updatedAt || 0).getTime();
      return sortOrder === 'newest' ? timeB - timeA : timeA - timeB;
    });

  const totalNotes = notes.length;
  const importantNotes = notes.filter(n => ['Important', 'Critical'].includes(n.priority)).length;
  const followUpNotes = notes.filter(n => isFollowUpNote(n)).length;

  const formatDate = (iso) => {
    return safeFormatDateTime(iso, '-');
  };

  const getPriorityColor = (p) => {
    if (p === 'Critical') return 'var(--red)';
    if (p === 'Important') return '#f59e0b';
    return 'var(--blue)';
  };

  return (
    <div id="app-shell" style={{ background: '#f8fafc' }}>
      {showProfileModal && <ProfileModal onClose={() => setShowProfileModal(false)} />}
      <Sidebar />
      <main className="main-content">
        {/* TOPBAR — matching Dashboard */}
        <header className="topbar">
          <div className="search-container">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: '8px' }}>
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input 
              type="text" 
              placeholder="Search cases, evidence, or findings..." 
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
            <span className="search-shortcut">⌘ K</span>
          </div>

          <div className="topbar-actions" style={{ position: 'relative' }}>
            {/* Live Analysis badge */}
            {activeCaseId && (
              <div className="badge-live">
                <div className="live-dot"></div>
                Live Analysis
              </div>
            )}

            {/* Theme Toggle */}
            <button className="icon-btn" onClick={toggleTheme} title="Toggle Theme" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              {theme === 'dark' ? (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
              ) : (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
              )}
            </button>

            {/* Notifications */}
            <NotificationMenu />

            {/* User Profile */}
            <div
              className="user-profile"
              onClick={() => setShowUserDropdown(!showUserDropdown)}
              style={{ cursor: 'pointer', position: 'relative' }}
            >
              <div className="avatar">
                {currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'S'}
              </div>
              <span style={{ fontWeight: 500, textTransform: 'capitalize' }}>
                {currentUser?.name || 'sathwik'}
              </span>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>

              {showUserDropdown && (
                <div
                  style={{
                    position: 'absolute',
                    top: '120%',
                    right: 0,
                    background: 'var(--bg-card, #fff)',
                    border: '1px solid var(--border-subtle, #e2e8f0)',
                    borderRadius: '8px',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.12)',
                    padding: '8px 0',
                    zIndex: 100,
                    minWidth: '160px'
                  }}
                >
                  <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border-subtle, #e2e8f0)' }}>
                    <div style={{ fontWeight: 600, fontSize: '13px', textTransform: 'capitalize', color: 'var(--text-main, #0f172a)' }}>{currentUser?.name || 'sathwik'}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted, #64748b)' }}>{currentUser?.role?.replace('_', ' ') || 'Digital Forensics Investigator'}</div>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowUserDropdown(false); setShowProfileModal(true); }}
                    style={{ width: '100%', padding: '8px 16px', background: 'transparent', border: 'none', color: 'var(--text-main, #0f172a)', textAlign: 'left', cursor: 'pointer', fontSize: '13px' }}
                  >
                    My Profile
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* MAIN SCROLL AREA */}
        <div className="dashboard-scroll" style={{ padding: '32px 40px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Header Section: Page Title, Badges & + New Note button */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
                <h1 style={{ fontSize: '26px', margin: 0, color: 'var(--text-main, #0f172a)', fontWeight: 700, letterSpacing: '-0.01em' }}>
                  Case Notes
                </h1>
                {activeCaseId ? (
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', background: '#eff6ff', color: '#2563eb', padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, border: '1px solid #dbeafe' }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                      {activeCaseId}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', background: '#ecfdf5', color: '#059669', padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, border: '1px solid #a7f3d0' }}>
                      <div style={{ width: '6px', height: '6px', background: '#10b981', borderRadius: '50%' }}></div>
                      Active
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: '#f1f5f9', color: '#64748b', padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600 }}>
                    No active case selected
                  </div>
                )}
              </div>
              <p style={{ margin: 0, color: 'var(--text-muted, #64748b)', fontSize: '14px' }}>
                Investigation observations, follow-ups, and case details.
              </p>
            </div>

            {activeCaseId && (
              <button 
                onClick={openNewNote} 
                style={{ 
                  background: '#2563eb', 
                  border: 'none', 
                  padding: '10px 18px', 
                  borderRadius: '8px', 
                  color: '#fff', 
                  cursor: 'pointer', 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '8px', 
                  fontSize: '13px', 
                  fontWeight: 600,
                  boxShadow: '0 2px 6px rgba(37, 99, 235, 0.25)',
                  transition: 'all 0.15s ease'
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                New Note
              </button>
            )}
          </div>
            
            {/* Stats Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '20px' }}>
              <div 
                onClick={() => { setFilterType('All'); setFilterPriority('All'); }}
                style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '10px', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', cursor: 'pointer', transition: 'all 0.15s ease' }}
              >
                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: '#eff6ff', color: '#2563eb', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Total Notes</div>
                  <div style={{ color: '#0f172a', fontSize: '22px', fontWeight: 700 }}>{totalNotes}</div>
                </div>
              </div>

              <div 
                onClick={() => setFilterPriority('Important')}
                style={{ background: '#fef2f2', border: '1px solid #fee2e2', borderRadius: '10px', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', cursor: 'pointer', transition: 'all 0.15s ease' }}
              >
                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: '#fee2e2', color: '#ef4444', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                </div>
                <div>
                  <div style={{ color: '#ef4444', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Important</div>
                  <div style={{ color: '#0f172a', fontSize: '22px', fontWeight: 700 }}>{importantNotes}</div>
                </div>
              </div>

              <div 
                onClick={() => setFilterType('Follow-up')}
                style={{ background: '#ecfdf5', border: '1px solid #d1fae5', borderRadius: '10px', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px', cursor: 'pointer', transition: 'all 0.15s ease' }}
              >
                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: '#d1fae5', color: '#10b981', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                </div>
                <div>
                  <div style={{ color: '#059669', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Follow-ups</div>
                  <div style={{ color: '#0f172a', fontSize: '22px', fontWeight: 700 }}>{followUpNotes}</div>
                </div>
              </div>
            </div>

            {/* Modernized Filter Bar */}
            <div style={{ 
              background: '#fff', 
              border: '1px solid #e2e8f0', 
              borderRadius: '12px', 
              padding: '12px 16px', 
              display: 'flex', 
              justifyContent: 'space-between',
              alignItems: 'center', 
              gap: '14px', 
              marginBottom: '24px',
              flexWrap: 'wrap',
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)'
            }}>
              {/* Search Box */}
              <div style={{ 
                flex: '1 1 240px', 
                display: 'flex', 
                alignItems: 'center', 
                gap: '10px', 
                background: '#f8fafc', 
                padding: '8px 14px', 
                borderRadius: '8px', 
                border: '1px solid #e2e8f0'
              }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
                  <circle cx="11" cy="11" r="8"></circle>
                  <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                <input 
                  type="text" 
                  placeholder="Search notes..." 
                  value={searchTerm} 
                  onChange={e => setSearchTerm(e.target.value)} 
                  style={{ 
                    width: '100%', 
                    border: 'none', 
                    background: 'transparent', 
                    outline: 'none', 
                    color: '#0f172a', 
                    fontSize: '13px',
                    fontWeight: 500
                  }} 
                />
                {searchTerm && (
                  <button 
                    onClick={() => setSearchTerm('')} 
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#94a3b8' }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                  </button>
                )}
              </div>

              {/* Styled Dropdowns Group */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                {/* Type Filter */}
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <select 
                    value={filterType} 
                    onChange={e => setFilterType(e.target.value)} 
                    style={{ 
                      appearance: 'none',
                      WebkitAppearance: 'none',
                      MozAppearance: 'none',
                      background: filterType !== 'All' ? '#eff6ff' : '#f8fafc', 
                      border: `1px solid ${filterType !== 'All' ? '#93c5fd' : '#e2e8f0'}`, 
                      borderRadius: '8px', 
                      padding: '8px 30px 8px 12px', 
                      fontSize: '13px', 
                      fontWeight: 600, 
                      color: filterType !== 'All' ? '#1d4ed8' : '#334155', 
                      cursor: 'pointer', 
                      outline: 'none'
                    }}
                  >
                    <option value="All">All Types</option>
                    <option value="Observation">Observation</option>
                    <option value="Investigation">Investigation</option>
                    <option value="Evidence">Evidence</option>
                    <option value="Follow-up">Follow-up</option>
                  </select>
                  <svg style={{ position: 'absolute', right: '10px', pointerEvents: 'none', color: filterType !== 'All' ? '#2563eb' : '#64748b' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="6 9 12 15 18 9"></polyline>
                  </svg>
                </div>

                {/* Priority Filter */}
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <select 
                    value={filterPriority} 
                    onChange={e => setFilterPriority(e.target.value)} 
                    style={{ 
                      appearance: 'none',
                      WebkitAppearance: 'none',
                      MozAppearance: 'none',
                      background: filterPriority !== 'All' ? '#fef2f2' : '#f8fafc', 
                      border: `1px solid ${filterPriority !== 'All' ? '#fca5a5' : '#e2e8f0'}`, 
                      borderRadius: '8px', 
                      padding: '8px 30px 8px 12px', 
                      fontSize: '13px', 
                      fontWeight: 600, 
                      color: filterPriority !== 'All' ? '#b91c1c' : '#334155', 
                      cursor: 'pointer', 
                      outline: 'none'
                    }}
                  >
                    <option value="All">All Priorities</option>
                    <option value="Normal">Normal</option>
                    <option value="Important">Important</option>
                    <option value="Critical">Critical</option>
                  </select>
                  <svg style={{ position: 'absolute', right: '10px', pointerEvents: 'none', color: filterPriority !== 'All' ? '#dc2626' : '#64748b' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="6 9 12 15 18 9"></polyline>
                  </svg>
                </div>

                {/* Sort Order */}
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <select 
                    value={sortOrder} 
                    onChange={e => setSortOrder(e.target.value)} 
                    style={{ 
                      appearance: 'none',
                      WebkitAppearance: 'none',
                      MozAppearance: 'none',
                      background: '#f8fafc', 
                      border: '1px solid #e2e8f0', 
                      borderRadius: '8px', 
                      padding: '8px 30px 8px 12px', 
                      fontSize: '13px', 
                      fontWeight: 600, 
                      color: '#334155', 
                      cursor: 'pointer', 
                      outline: 'none'
                    }}
                  >
                    <option value="newest">Sort by Date</option>
                    <option value="oldest">Oldest First</option>
                  </select>
                  <svg style={{ position: 'absolute', right: '10px', pointerEvents: 'none', color: '#64748b' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="6 9 12 15 18 9"></polyline>
                  </svg>
                </div>

                {/* Reset button if active */}
                {(searchTerm || filterType !== 'All' || filterPriority !== 'All') && (
                  <button
                    onClick={() => {
                      setSearchTerm('');
                      setFilterType('All');
                      setFilterPriority('All');
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#2563eb',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      padding: '6px 8px',
                      textDecoration: 'underline'
                    }}
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {/* Notes List */}
            <div style={{ marginBottom: '24px' }}>
              <h3 style={{ fontSize: '16px', color: '#0f172a', margin: '0 0 12px 0', fontWeight: 600 }}>Notes ({filteredNotes.length})</h3>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {filteredNotes.length === 0 ? (
                  <div style={{ background: '#fff', border: '1px dashed #cbd5e1', borderRadius: '8px', padding: '32px', textAlign: 'center', color: '#64748b' }}>
                    <p style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600 }}>No Case Notes Found</p>
                    <p style={{ margin: '0 0 16px 0', fontSize: '13px' }}>Document your observations and investigation progress.</p>
                    {activeCaseId && (
                      <button onClick={openNewNote} style={{ background: '#10b981', border: 'none', padding: '6px 12px', borderRadius: '4px', color: '#fff', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600 }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        Create First Note
                      </button>
                    )}
                  </div>
                ) : (
                  filteredNotes.map(note => (
                    <div 
                      key={note.noteId} 
                      style={{ 
                        background: '#ffffff', 
                        border: '1px solid #e2e8f0', 
                        borderRadius: '14px', 
                        padding: '24px 28px', 
                        display: 'flex', 
                        flexDirection: 'column', 
                        gap: '16px',
                        boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
                        transition: 'box-shadow 0.2s ease, border-color 0.2s ease'
                      }}
                    >
                      <div style={{ display: 'flex', gap: '18px', alignItems: 'flex-start' }}>
                        {/* Leading note avatar icon */}
                        <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%)', border: '1px solid #bfdbfe', color: '#2563eb', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        </div>
                        
                        <div style={{ flexGrow: 1, minWidth: 0 }}>
                          {/* Header row: Title + ID on left, Badges on right */}
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '14px', flexWrap: 'wrap', marginBottom: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <h4 style={{ margin: 0, fontSize: '18px', color: '#0f172a', fontWeight: 700, letterSpacing: '-0.01em' }}>{note.title}</h4>
                              <span style={{ fontSize: '11px', color: '#94a3b8', background: '#f1f5f9', padding: '2px 8px', borderRadius: '5px', fontWeight: 600 }}>#{note.noteId}</span>
                            </div>

                            {/* Right-aligned badges (nicely sized & styled) */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              {/* Type Badge */}
                              <span style={{ 
                                background: '#eff6ff', 
                                border: '1px solid #bfdbfe', 
                                color: '#1d4ed8', 
                                padding: '5px 12px', 
                                borderRadius: '20px', 
                                fontSize: '12px', 
                                fontWeight: 600, 
                                display: 'inline-flex', 
                                alignItems: 'center', 
                                gap: '6px' 
                              }}>
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                                {note.type}
                              </span>

                              {/* Priority Badge */}
                              <span style={{ 
                                background: note.priority === 'Critical' ? '#fef2f2' : note.priority === 'Important' ? '#fffbeb' : '#f8fafc', 
                                border: `1px solid ${note.priority === 'Critical' ? '#fecaca' : note.priority === 'Important' ? '#fde68a' : '#e2e8f0'}`, 
                                color: note.priority === 'Critical' ? '#dc2626' : note.priority === 'Important' ? '#d97706' : '#475569', 
                                padding: '5px 12px', 
                                borderRadius: '20px', 
                                fontSize: '12px', 
                                fontWeight: 600, 
                                display: 'inline-flex', 
                                alignItems: 'center', 
                                gap: '6px' 
                              }}>
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>
                                {note.priority}
                              </span>

                              {/* Evidence Badge */}
                              {note.relatedEvidenceId && (
                                <span 
                                  onClick={() => navigate('/evidence')}
                                  title="View Evidence"
                                  style={{ 
                                    background: '#f8fafc', 
                                    border: '1px solid #cbd5e1', 
                                    color: '#475569', 
                                    padding: '5px 12px', 
                                    borderRadius: '20px', 
                                    fontSize: '12px', 
                                    fontWeight: 500, 
                                    display: 'inline-flex', 
                                    alignItems: 'center', 
                                    gap: '6px',
                                    cursor: 'pointer',
                                    transition: 'all 0.15s ease'
                                  }}
                                >
                                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                                  <span>Evidence:</span>
                                  <span style={{ color: '#2563eb', fontWeight: 700, textDecoration: 'underline' }}>{note.relatedEvidenceId}</span>
                                </span>
                              )}

                              {/* Finding Badge */}
                              {note.relatedFindingId && (
                                <span 
                                  onClick={() => navigate('/dashboard')}
                                  title="View Finding"
                                  style={{ 
                                    background: '#fffbeb', 
                                    border: '1px solid #fde68a', 
                                    color: '#92400e', 
                                    padding: '5px 12px', 
                                    borderRadius: '20px', 
                                    fontSize: '12px', 
                                    fontWeight: 500, 
                                    display: 'inline-flex', 
                                    alignItems: 'center', 
                                    gap: '6px',
                                    cursor: 'pointer'
                                  }}
                                >
                                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
                                  <span>Finding:</span>
                                  <span style={{ color: '#2563eb', fontWeight: 700, textDecoration: 'underline' }}>{note.relatedFindingId}</span>
                                </span>
                              )}
                            </div>
                          </div>
                          
                          {/* Note Content Block */}
                          <div style={{ marginTop: '12px', padding: '14px 18px', background: '#f8fafc', borderRadius: '10px', border: '1px solid #f1f5f9', fontSize: '14px', color: '#334155', lineHeight: '1.6', wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>
                            {note.content}
                          </div>
                        </div>
                      </div>
                      
                      <div style={{ height: '1px', background: '#f1f5f9', margin: '4px 0' }}></div>
                      
                      {/* Footer: Metadata on left, Actions on right */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                        <div style={{ display: 'flex', gap: '20px', color: '#64748b', fontSize: '13px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            Created by: <span style={{ color: '#0f172a', fontWeight: 600 }}>{note.createdBy}</span>
                          </div>
                          <div style={{ width: '1px', height: '14px', background: '#e2e8f0' }}></div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                            {formatDate(note.createdAt)}
                          </div>
                        </div>
                        
                        <div style={{ display: 'flex', gap: '12px' }}>
                          <button onClick={() => openEditNote(note)} style={{ background: '#ffffff', border: '1px solid #cbd5e1', color: '#2563eb', padding: '8px 20px', borderRadius: '8px', fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '7px', cursor: 'pointer', transition: 'all 0.15s ease', boxShadow: '0 1px 2px rgba(0,0,0,0.03)' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                            Edit
                          </button>
                          <button onClick={() => setShowDeleteConfirm(note.noteId)} style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#ef4444', padding: '8px 20px', borderRadius: '8px', fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '7px', cursor: 'pointer', transition: 'all 0.15s ease' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </main>

      {/* Delete Confirmation */}
      {showDeleteConfirm && (
        <div className="drawer-overlay" style={{ justifyContent: 'center', alignItems: 'center' }}>
          <div style={{ background: 'var(--bg-card)', padding: '24px', borderRadius: '8px', width: '400px', border: '1px solid var(--border-strong)', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}>
            <h3 style={{ margin: '0 0 16px 0', color: 'var(--text-main)' }}>Delete this note?</h3>
            <p style={{ margin: '0 0 24px 0', color: 'var(--text-muted)', fontSize: '14px' }}>This action will permanently remove this case note.</p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button onClick={() => setShowDeleteConfirm(null)} style={{ background: '#6b7280', border: 'none', padding: '8px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', fontWeight: 600 }}>Cancel</button>
              <button onClick={() => handleDelete(showDeleteConfirm)} style={{ background: 'var(--red)', border: 'none', padding: '8px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', fontWeight: 600 }}>Delete Note</button>
            </div>
          </div>
        </div>
      )}

      {/* Create / Edit Modal/Drawer */}
      {showModal && (
        <div className="drawer-overlay" onClick={() => setShowModal(false)}>
          <div className="audit-drawer" onClick={e => e.stopPropagation()} style={{ width: '500px' }}>
            <div className="drawer-header">
              <h3>{editingNote ? 'Edit Note' : 'New Note'}</h3>
              <button className="close-btn" onClick={() => setShowModal(false)}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <div className="drawer-content" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase' }}>Note Title</label>
                <input type="text" value={title} onChange={e => setTitle(e.target.value)} placeholder="e.g. Suspicious PowerShell Activity" style={{ width: '100%', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none' }} />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase' }}>Content</label>
                <textarea value={content} onChange={e => setContent(e.target.value)} placeholder="Enter detailed observations..." style={{ width: '100%', minHeight: '150px', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none', resize: 'vertical', fontFamily: 'inherit' }} />
              </div>

              <div style={{ display: 'flex', gap: '16px' }}>
                <div style={{ flex: 1 }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase' }}>Note Type</label>
                  <select value={type} onChange={e => setType(e.target.value)} style={{ width: '100%', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none' }}>
                    <option value="Observation">Observation</option>
                    <option value="Investigation">Investigation</option>
                    <option value="Evidence">Evidence</option>
                    <option value="Follow-up">Follow-up</option>
                    <option value="Question">Question</option>
                    <option value="Important">Important</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase' }}>Priority</label>
                  <select value={priority} onChange={e => setPriority(e.target.value)} style={{ width: '100%', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none' }}>
                    <option value="Normal">Normal</option>
                    <option value="Important">Important</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase' }}>Related Evidence (Optional)</label>
                <input type="text" value={relatedEvidence} onChange={e => setRelatedEvidence(e.target.value)} placeholder="e.g. EV-001" style={{ width: '100%', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none' }} />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase' }}>Related Finding (Optional)</label>
                <input type="text" value={relatedFinding} onChange={e => setRelatedFinding(e.target.value)} placeholder="e.g. F-104" style={{ width: '100%', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none' }} />
              </div>

              {editingNote && (
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px' }}>
                  Last updated: {formatDate(editingNote.updatedAt)}
                </div>
              )}

            </div>
            
            <div className="drawer-footer" style={{ justifyContent: 'flex-end', gap: '12px' }}>
              <button onClick={() => setShowModal(false)} style={{ background: '#6b7280', border: 'none', padding: '10px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', fontWeight: 600 }}>Cancel</button>
              <button onClick={handleSave} style={{ background: '#10b981', border: 'none', padding: '10px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', fontWeight: 600 }}>{editingNote ? 'Update Note' : 'Create Note'}</button>
            </div>
          </div>
        </div>
      )}

      <AlertModal 
        isOpen={alertConfig.isOpen} 
        title={alertConfig.title} 
        message={alertConfig.message} 
        onClose={() => setAlertConfig({ ...alertConfig, isOpen: false })} 
      />
    </div>
  );
};

export default CaseNotes;
