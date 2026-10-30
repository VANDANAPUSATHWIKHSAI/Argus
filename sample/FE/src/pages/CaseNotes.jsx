import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import ProfileModal from '../components/ProfileModal';
import CaseLockBanner from '../components/CaseLockBanner';
import CaseNotAssigned from '../components/CaseNotAssigned';
import { fetchWithAuth } from '../js/api';
import { safeFormatDateTime, formatEvidenceId } from '../js/dateUtils';
import { getActiveCaseId, subscribeToActiveCase } from '../js/caseEvents';
import { syncCaseLock, subscribeToCaseLock } from '../js/caseLockService';
import '../css/style.css';

const CaseNotes = () => {
  const navigate = useNavigate();
  const [activeCaseId, setActiveCaseId] = useState(getActiveCaseId());
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;

  const [showProfileModal, setShowProfileModal] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');
  const [caseLock, setCaseLock] = useState(null);

  // Synchronize active case across tabs and components
  useEffect(() => {
    if (activeCaseId) {
      syncCaseLock(activeCaseId).then(setCaseLock);
    } else {
      setCaseLock(null);
    }
    const unsubLock = subscribeToCaseLock(setCaseLock);
    const unsubCase = subscribeToActiveCase(({ caseId }) => {
      setActiveCaseId(caseId);
      if (caseId) {
        syncCaseLock(caseId).then(setCaseLock);
      } else {
        setCaseLock(null);
      }
    });
    return () => {
      unsubLock();
      unsubCase();
    };
  }, [activeCaseId]);

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
      const data = await fetchWithAuth(`/cases/${activeCaseId}/notes`);
      const serverNotes = (data && data.data) ? data.data : (Array.isArray(data) ? data : []);
      const localNotes = JSON.parse(localStorage.getItem(`case_notes_${activeCaseId}`) || '[]');
      const serverIds = new Set(serverNotes.map(n => n.noteId));
      const unsyncedLocal = localNotes
        .filter(n => !serverIds.has(n.noteId))
        .map(n => ({ ...n, syncStatus: n.syncStatus || 'unsynced' }));
      const combined = [...unsyncedLocal, ...serverNotes];
      setNotes(combined);
      localStorage.setItem(`seen_notes_${activeCaseId}`, combined.length);
      
      const latestUpdate = Math.max(0, ...combined.map(n => {
        const d = new Date(n.updatedAt || n.createdAt);
        return isNaN(d.getTime()) ? 0 : d.getTime();
      }));
      if (latestUpdate > 0) {
        localStorage.setItem(`last_seen_update_${activeCaseId}`, latestUpdate);
      }
    } catch (e) {
      console.error('Error fetching notes', e);
      const localNotes = JSON.parse(localStorage.getItem(`case_notes_${activeCaseId}`) || '[]');
      const marked = localNotes.map(n => ({ ...n, syncStatus: 'unsynced' }));
      if (marked.length > 0) setNotes(marked);
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
    if (caseLock?.readOnly) {
      setAlertConfig({
        isOpen: true,
        title: '🔒 Case Locked — Read-Only Mode',
        message: `Cannot save note. Case ${activeCaseId} is currently locked by analyst ${caseLock.lockedBy?.name || 'another user'}. You have Read-Only access.`
      });
      return;
    }
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
      const path = editingNote 
        ? `/cases/${activeCaseId}/notes/${editingNote.noteId}`
        : `/cases/${activeCaseId}/notes`;
      const method = editingNote ? 'PUT' : 'POST';

      await fetchWithAuth(path, {
        method,
        body: JSON.stringify(noteData)
      });
      setShowModal(false);
      fetchNotes();
    } catch (e) {
      setAlertConfig({ isOpen: true, title: 'Server Error', message: "Failed to persist note: " + (e.message || 'Backend rejection') });
      console.error('Error saving note', e);
    }
  };

  const handleDelete = async (noteId) => {
    if (caseLock?.readOnly) {
      setAlertConfig({
        isOpen: true,
        title: '🔒 Case Locked — Read-Only Mode',
        message: `Cannot delete note. Case ${activeCaseId} is currently locked by analyst ${caseLock.lockedBy?.name || 'another user'}. You have Read-Only access.`
      });
      return;
    }
    try {
      await fetchWithAuth(`/cases/${activeCaseId}/notes/${noteId}`, {
        method: 'DELETE'
      });
      setShowDeleteConfirm(null);
      fetchNotes();
    } catch (e) {
      console.error('Error deleting note', e);
      setAlertConfig({ isOpen: true, title: 'Error Deleting Note', message: e.message || 'Failed to delete note from backend.' });
    }
  };

  const openNewNote = () => {
    if (caseLock?.readOnly) {
      setAlertConfig({
        isOpen: true,
        title: '🔒 Case Locked — Read-Only Mode',
        message: `Cannot create notes. Case ${activeCaseId} is currently locked by analyst ${caseLock.lockedBy?.name || 'another user'}. You have Read-Only access.`
      });
      return;
    }
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
    if (caseLock?.readOnly) {
      setAlertConfig({
        isOpen: true,
        title: '🔒 Case Locked — Read-Only Mode',
        message: `Cannot edit notes. Case ${activeCaseId} is currently locked by analyst ${caseLock.lockedBy?.name || 'another user'}. You have Read-Only access.`
      });
      return;
    }
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
    <div id="app-shell">
      {showProfileModal && <ProfileModal onClose={() => setShowProfileModal(false)} />}
      <Sidebar />
      <main className="main-content">
        {/* TOPBAR — matching Dashboard */}
        <header className="glass-topbar-capsule topbar">
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

          <div className="glass-topbar-right topbar-actions" style={{ position: 'relative' }}>
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
              className="glass-profile-pill user-profile"
              onClick={() => setShowUserDropdown(!showUserDropdown)}
              style={{ cursor: 'pointer', position: 'relative' }}
            >
              <div className="glass-profile-avatar-dark avatar">
                {currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'S'}
              </div>
              <span className="glass-profile-name" style={{ fontWeight: 500, textTransform: 'capitalize' }}>
                {currentUser?.name || 'sathwik'}
              </span>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>

              {showUserDropdown && (
                <div
                  style={{
                    position: 'absolute',
                    top: '120%',
                    right: 0,
                    background: 'var(--glass-dash-surface-gradient)',
                    backdropFilter: 'blur(16px)',
                    border: '1px solid var(--glass-dash-border)',
                    borderRadius: '16px',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.25)',
                    padding: '8px 0',
                    zIndex: 100,
                    minWidth: '160px'
                  }}
                >
                  <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--glass-dash-border-subtle)' }}>
                    <div style={{ fontWeight: 600, fontSize: '13px', textTransform: 'capitalize', color: 'var(--glass-dash-text-main)' }}>{currentUser?.name || 'sathwik'}</div>
                    <div style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)' }}>{currentUser?.role?.replace('_', ' ') || 'Digital Forensics Investigator'}</div>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowUserDropdown(false); navigate('/profile'); }}
                    style={{ width: '100%', padding: '8px 16px', background: 'transparent', border: 'none', color: 'var(--glass-dash-text-main)', textAlign: 'left', cursor: 'pointer', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    My Profile
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* MAIN SCROLL AREA */}
        <div className="dashboard-scroll" style={{ padding: '32px 40px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {!activeCaseId ? (
            <CaseNotAssigned />
          ) : (
            <>
          {/* Header Section: Page Title, Badges & + New Note button */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
                <h1 style={{ fontSize: '26px', margin: 0, color: 'var(--glass-dash-text-main)', fontWeight: 700, letterSpacing: '-0.01em' }}>
                  Case Notes
                </h1>
                {activeCaseId ? (
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', padding: '4px 12px', borderRadius: '9999px', fontSize: '12px', fontWeight: 600, border: '1px solid var(--glass-dash-border)' }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                      {activeCaseId}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', padding: '4px 12px', borderRadius: '9999px', fontSize: '12px', fontWeight: 600, border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                      <div style={{ width: '6px', height: '6px', background: '#10b981', borderRadius: '50%' }}></div>
                      Active
                    </div>
                    {caseLock?.readOnly && <CaseLockBanner compact lockState={caseLock} />}
                  </div>
                ) : (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'var(--glass-dash-surface-nested)', color: 'var(--glass-dash-text-muted)', padding: '4px 12px', borderRadius: '9999px', fontSize: '12px', fontWeight: 600 }}>
                    No active case selected
                  </div>
                )}
              </div>
              <p style={{ margin: 0, color: 'var(--glass-dash-text-muted)', fontSize: '14px' }}>
                Investigation observations, follow-ups, and case details.
              </p>
            </div>

            {activeCaseId && (
              <button 
                onClick={openNewNote} 
                style={{ 
                  background: caseLock?.readOnly ? 'rgba(245, 158, 11, 0.2)' : 'linear-gradient(135deg, #3b82f6, #1d4ed8)', 
                  border: caseLock?.readOnly ? '1px solid rgba(245, 158, 11, 0.4)' : 'none', 
                  padding: '10px 22px', 
                  borderRadius: '9999px', 
                  color: caseLock?.readOnly ? '#f59e0b' : '#fff', 
                  cursor: caseLock?.readOnly ? 'not-allowed' : 'pointer', 
                  opacity: caseLock?.readOnly ? 0.75 : 1,
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '8px', 
                  fontSize: '13px', 
                  fontWeight: 600,
                  boxShadow: caseLock?.readOnly ? 'none' : '0 4px 14px rgba(59, 130, 246, 0.4)',
                  transition: 'all 0.15s ease'
                }}
                title={caseLock?.readOnly ? `Read-Only: Case is locked by ${caseLock.lockedBy?.name || 'another analyst'}` : 'New Note'}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                {caseLock?.readOnly ? 'Read-Only Mode' : 'New Note'}
              </button>
            )}
          </div>
            
          {/* Case Lock Banner for Active Case */}
          <CaseLockBanner lockState={caseLock} caseId={activeCaseId} onLockRefreshed={setCaseLock} />

          {/* Stats Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '20px' }}>
              <div 
                className="stat-card panel-card"
                onClick={() => { setFilterType('All'); setFilterPriority('All'); }}
                style={{ background: 'var(--glass-dash-surface-gradient)', border: '1px solid var(--glass-dash-border)', borderRadius: '20px', padding: '18px 22px', display: 'flex', alignItems: 'center', gap: '16px', cursor: 'pointer', transition: 'all 0.15s ease' }}
              >
                <div style={{ width: '42px', height: '42px', borderRadius: '14px', background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                </div>
                <div>
                  <div style={{ color: 'var(--glass-dash-text-muted)', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Total Notes</div>
                  <div style={{ color: 'var(--glass-dash-text-main)', fontSize: '24px', fontWeight: 800 }}>{totalNotes}</div>
                </div>
              </div>

              <div 
                className="stat-card panel-card"
                onClick={() => setFilterPriority('Important')}
                style={{ background: 'var(--glass-dash-surface-gradient)', border: '1px solid var(--glass-dash-border)', borderRadius: '20px', padding: '18px 22px', display: 'flex', alignItems: 'center', gap: '16px', cursor: 'pointer', transition: 'all 0.15s ease' }}
              >
                <div style={{ width: '42px', height: '42px', borderRadius: '14px', background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                </div>
                <div>
                  <div style={{ color: '#ef4444', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Important</div>
                  <div style={{ color: 'var(--glass-dash-text-main)', fontSize: '24px', fontWeight: 800 }}>{importantNotes}</div>
                </div>
              </div>

              <div 
                className="stat-card panel-card"
                onClick={() => setFilterType('Follow-up')}
                style={{ background: 'var(--glass-dash-surface-gradient)', border: '1px solid var(--glass-dash-border)', borderRadius: '20px', padding: '18px 22px', display: 'flex', alignItems: 'center', gap: '16px', cursor: 'pointer', transition: 'all 0.15s ease' }}
              >
                <div style={{ width: '42px', height: '42px', borderRadius: '14px', background: 'rgba(16, 185, 129, 0.15)', color: '#10b981', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                </div>
                <div>
                  <div style={{ color: '#10b981', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Follow-ups</div>
                  <div style={{ color: 'var(--glass-dash-text-main)', fontSize: '24px', fontWeight: 800 }}>{followUpNotes}</div>
                </div>
              </div>
            </div>

            {/* Modernized Filter Bar */}
            <div className="panel-card" style={{ 
              background: 'var(--glass-dash-surface-gradient)', 
              border: '1px solid var(--glass-dash-border)', 
              borderRadius: '20px', 
              padding: '14px 20px', 
              display: 'flex', 
              flexDirection: 'row',
              justifyContent: 'space-between',
              alignItems: 'center', 
              height: 'auto',
              gap: '14px', 
              marginBottom: '24px',
              flexWrap: 'wrap',
              boxShadow: 'var(--glass-dash-shadow)'
            }}>
              {/* Search Box */}
              <div className="search-container" style={{ 
                flex: '1 1 260px', 
                maxWidth: '420px',
                height: '42px',
                boxSizing: 'border-box'
              }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: '16px', height: '16px', minWidth: '16px', flexShrink: 0 }}>
                  <circle cx="11" cy="11" r="8"></circle>
                  <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                <input 
                  type="text" 
                  placeholder="Search notes..." 
                  value={searchTerm} 
                  onChange={e => setSearchTerm(e.target.value)} 
                />
                {searchTerm && (
                  <button 
                    onClick={() => setSearchTerm('')} 
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--glass-dash-text-muted)' }}
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
                      background: 'var(--glass-dash-surface-nested)', 
                      border: `1px solid ${filterType !== 'All' ? 'var(--glass-dash-blue)' : 'var(--glass-dash-border)'}`, 
                      borderRadius: '9999px', 
                      padding: '8px 32px 8px 14px', 
                      fontSize: '13px', 
                      fontWeight: 600, 
                      color: filterType !== 'All' ? 'var(--glass-dash-blue)' : 'var(--glass-dash-text-main)', 
                      cursor: 'pointer', 
                      outline: 'none'
                    }}
                  >
                    <option value="All" style={{ background: '#181a20', color: '#eef2f7' }}>All Types</option>
                    <option value="Observation" style={{ background: '#181a20', color: '#eef2f7' }}>Observation</option>
                    <option value="Investigation" style={{ background: '#181a20', color: '#eef2f7' }}>Investigation</option>
                    <option value="Evidence" style={{ background: '#181a20', color: '#eef2f7' }}>Evidence</option>
                    <option value="Follow-up" style={{ background: '#181a20', color: '#eef2f7' }}>Follow-up</option>
                  </select>
                  <svg style={{ position: 'absolute', right: '12px', pointerEvents: 'none', color: filterType !== 'All' ? 'var(--glass-dash-blue)' : 'var(--glass-dash-text-muted)' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
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
                      background: 'var(--glass-dash-surface-nested)', 
                      border: `1px solid ${filterPriority !== 'All' ? '#ef4444' : 'var(--glass-dash-border)'}`, 
                      borderRadius: '9999px', 
                      padding: '8px 32px 8px 14px', 
                      fontSize: '13px', 
                      fontWeight: 600, 
                      color: filterPriority !== 'All' ? '#ef4444' : 'var(--glass-dash-text-main)', 
                      cursor: 'pointer', 
                      outline: 'none'
                    }}
                  >
                    <option value="All" style={{ background: '#181a20', color: '#eef2f7' }}>All Priorities</option>
                    <option value="Normal" style={{ background: '#181a20', color: '#eef2f7' }}>Normal</option>
                    <option value="Important" style={{ background: '#181a20', color: '#eef2f7' }}>Important</option>
                    <option value="Critical" style={{ background: '#181a20', color: '#eef2f7' }}>Critical</option>
                  </select>
                  <svg style={{ position: 'absolute', right: '12px', pointerEvents: 'none', color: filterPriority !== 'All' ? '#ef4444' : 'var(--glass-dash-text-muted)' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
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
                      background: 'var(--glass-dash-surface-nested)', 
                      border: '1px solid var(--glass-dash-border)', 
                      borderRadius: '9999px', 
                      padding: '8px 32px 8px 14px', 
                      fontSize: '13px', 
                      fontWeight: 600, 
                      color: 'var(--glass-dash-text-main)', 
                      cursor: 'pointer', 
                      outline: 'none'
                    }}
                  >
                    <option value="newest" style={{ background: '#181a20', color: '#eef2f7' }}>Sort by Date</option>
                    <option value="oldest" style={{ background: '#181a20', color: '#eef2f7' }}>Oldest First</option>
                  </select>
                  <svg style={{ position: 'absolute', right: '12px', pointerEvents: 'none', color: 'var(--glass-dash-text-muted)' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
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
                      color: 'var(--glass-dash-blue)',
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
              <h3 style={{ fontSize: '16px', color: 'var(--glass-dash-text-main)', margin: '0 0 14px 0', fontWeight: 700 }}>Notes ({filteredNotes.length})</h3>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {filteredNotes.length === 0 ? (
                  <div className="panel-card" style={{ background: 'var(--glass-dash-surface-gradient)', border: '1px dashed var(--glass-dash-border)', borderRadius: '22px', padding: '48px 24px', textAlign: 'center', color: 'var(--glass-dash-text-muted)', boxShadow: 'var(--glass-dash-shadow)' }}>
                    <p style={{ margin: '0 0 8px 0', fontSize: '16px', fontWeight: 700, color: 'var(--glass-dash-text-main)' }}>No Case Notes Found</p>
                    <p style={{ margin: '0 0 20px 0', fontSize: '13px' }}>Document your observations and investigation progress.</p>
                    {activeCaseId && (
                      <button onClick={openNewNote} style={{ background: 'linear-gradient(135deg, #10b981, #059669)', border: 'none', padding: '10px 22px', borderRadius: '9999px', color: '#fff', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 600, boxShadow: '0 4px 14px rgba(16, 185, 129, 0.4)' }}>
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        Create First Note
                      </button>
                    )}
                  </div>
                ) : (
                  filteredNotes.map(note => (
                    <div 
                      key={note.noteId} 
                      className="panel-card"
                      style={{ 
                        background: 'var(--glass-dash-surface-gradient)', 
                        border: '1px solid var(--glass-dash-border)', 
                        borderRadius: '20px', 
                        padding: '24px 28px', 
                        display: 'flex', 
                        flexDirection: 'column', 
                        gap: '16px',
                        boxShadow: 'var(--glass-dash-shadow)',
                        transition: 'box-shadow 0.2s ease, border-color 0.2s ease'
                      }}
                    >
                      <div style={{ display: 'flex', gap: '18px', alignItems: 'flex-start' }}>
                        {/* Leading note avatar icon */}
                        <div style={{ width: '44px', height: '44px', borderRadius: '14px', background: 'var(--glass-dash-blue-soft)', border: '1px solid var(--glass-dash-border)', color: 'var(--glass-dash-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        </div>
                        
                        <div style={{ flexGrow: 1, minWidth: 0 }}>
                          {/* Header row: Title + ID on left, Badges on right */}
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '14px', flexWrap: 'wrap', marginBottom: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <h4 style={{ margin: 0, fontSize: '18px', color: 'var(--glass-dash-text-main)', fontWeight: 700, letterSpacing: '-0.01em' }}>{note.title}</h4>
                              <span style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--glass-dash-border-subtle)', padding: '2px 8px', borderRadius: '9999px', fontWeight: 600 }}>#{note.noteId}</span>
                              {note.syncStatus === 'unsynced' && (
                                <span style={{
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  color: '#b45309',
                                  background: 'rgba(245, 158, 11, 0.15)',
                                  border: '1px solid #f59e0b',
                                  padding: '2px 10px',
                                  borderRadius: '9999px'
                                }}>
                                  ⚠️ Unsynced Draft
                                </span>
                              )}
                            </div>

                            {/* Right-aligned badges (nicely sized & styled) */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              {/* Type Badge */}
                              <span style={{ 
                                background: 'var(--glass-dash-blue-soft)', 
                                border: '1px solid var(--glass-dash-border)', 
                                color: 'var(--glass-dash-blue)', 
                                padding: '5px 12px', 
                                borderRadius: '9999px', 
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
                                background: note.priority === 'Critical' ? 'rgba(239, 68, 68, 0.15)' : note.priority === 'Important' ? 'rgba(245, 158, 11, 0.15)' : 'var(--glass-dash-surface-nested)', 
                                border: `1px solid ${note.priority === 'Critical' ? 'rgba(239, 68, 68, 0.3)' : note.priority === 'Important' ? 'rgba(245, 158, 11, 0.3)' : 'var(--glass-dash-border)'}`, 
                                color: note.priority === 'Critical' ? '#ef4444' : note.priority === 'Important' ? '#f59e0b' : 'var(--glass-dash-text-muted)', 
                                padding: '5px 12px', 
                                borderRadius: '9999px', 
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
                                    background: 'var(--glass-dash-surface-nested)', 
                                    border: '1px solid var(--glass-dash-border)', 
                                    color: 'var(--glass-dash-text-muted)', 
                                    padding: '5px 12px', 
                                    borderRadius: '9999px', 
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
                                  <span style={{ color: 'var(--glass-dash-blue)', fontWeight: 700, textDecoration: 'underline' }}>{formatEvidenceId(note.relatedEvidenceId)}</span>
                                </span>
                              )}

                              {/* Finding Badge */}
                              {note.relatedFindingId && (
                                <span 
                                  onClick={() => navigate('/dashboard')}
                                  title="View Finding"
                                  style={{ 
                                    background: 'rgba(245, 158, 11, 0.15)', 
                                    border: '1px solid rgba(245, 158, 11, 0.3)', 
                                    color: '#f59e0b', 
                                    padding: '5px 12px', 
                                    borderRadius: '9999px', 
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
                                  <span style={{ color: 'var(--glass-dash-blue)', fontWeight: 700, textDecoration: 'underline' }}>{note.relatedFindingId}</span>
                                </span>
                              )}
                            </div>
                          </div>
                          
                          {/* Note Content Block */}
                          <div style={{ marginTop: '12px', padding: '16px 20px', background: 'var(--glass-dash-surface-nested)', borderRadius: '16px', border: '1px solid var(--glass-dash-border-subtle)', fontSize: '14px', color: 'var(--glass-dash-text-main)', lineHeight: '1.6', wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>
                            {note.content}
                          </div>
                        </div>
                      </div>
                      
                      <div style={{ height: '1px', background: 'var(--glass-dash-border-subtle)', margin: '4px 0' }}></div>
                      
                      {/* Footer: Metadata on left, Actions on right */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                        <div style={{ display: 'flex', gap: '20px', color: 'var(--glass-dash-text-muted)', fontSize: '13px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            Created by: <span style={{ color: 'var(--glass-dash-text-main)', fontWeight: 600 }}>{note.createdBy}</span>
                          </div>
                          <div style={{ width: '1px', height: '14px', background: 'var(--glass-dash-border-subtle)' }}></div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                            {formatDate(note.createdAt)}
                          </div>
                        </div>
                        
                        <div style={{ display: 'flex', gap: '12px' }}>
                          <button
                            onClick={() => openEditNote(note)}
                            title={caseLock?.readOnly ? `Read-only mode: Editing disabled (Locked by ${caseLock.lockedBy?.name || 'analyst'})` : 'Edit Note'}
                            style={{
                              background: 'var(--glass-dash-surface-nested)',
                              border: '1px solid var(--glass-dash-border)',
                              color: caseLock?.readOnly ? 'var(--text-muted)' : 'var(--glass-dash-blue)',
                              padding: '8px 22px',
                              borderRadius: '9999px',
                              fontSize: '13px',
                              fontWeight: 600,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '7px',
                              cursor: caseLock?.readOnly ? 'not-allowed' : 'pointer',
                              opacity: caseLock?.readOnly ? 0.7 : 1,
                              transition: 'all 0.15s ease',
                              boxShadow: 'var(--glass-dash-shadow)'
                            }}
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                            Edit
                          </button>
                          <button
                            onClick={() => setShowDeleteConfirm(note.noteId)}
                            title={caseLock?.readOnly ? `Read-only mode: Deletion disabled (Locked by ${caseLock.lockedBy?.name || 'analyst'})` : 'Delete Note'}
                            style={{
                              background: 'rgba(239, 68, 68, 0.15)',
                              border: '1px solid rgba(239, 68, 68, 0.3)',
                              color: '#ef4444',
                              padding: '8px 22px',
                              borderRadius: '9999px',
                              fontSize: '13px',
                              fontWeight: 600,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '7px',
                              cursor: caseLock?.readOnly ? 'not-allowed' : 'pointer',
                              opacity: caseLock?.readOnly ? 0.7 : 1,
                              transition: 'all 0.15s ease'
                            }}
                          >
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
            </>
          )}
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
                <input type="text" value={relatedEvidence} onChange={e => setRelatedEvidence(e.target.value)} placeholder="e.g. e-01" style={{ width: '100%', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '10px 12px', borderRadius: '6px', outline: 'none' }} />
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
