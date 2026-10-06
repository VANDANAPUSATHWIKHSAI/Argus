import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import { API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import '../css/style.css';

const CaseNotes = () => {
  const navigate = useNavigate();
  const activeCaseId = localStorage.getItem('active_case_id');

  const [notes, setNotes] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('All');
  const [filterPriority, setFilterPriority] = useState('All');

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
    const intervalId = setInterval(fetchNotes, 10000);
    return () => clearInterval(intervalId);
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

  const filteredNotes = notes.filter(n => {
    if (filterType !== 'All' && n.type !== filterType) return false;
    if (filterPriority !== 'All' && n.priority !== filterPriority) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return n.title.toLowerCase().includes(q) || 
             n.content.toLowerCase().includes(q) || 
             (n.relatedEvidenceId && n.relatedEvidenceId.toLowerCase().includes(q)) ||
             (n.relatedFindingId && n.relatedFindingId.toLowerCase().includes(q));
    }
    return true;
  });

  const totalNotes = notes.length;
  const importantNotes = notes.filter(n => ['Important', 'Critical'].includes(n.priority)).length;
  const followUpNotes = notes.filter(n => n.type === 'Follow-up').length;

  const formatDate = (iso) => {
    try {
      const d = new Date(iso);
      return `${d.getDate()} ${d.toLocaleString('default', { month: 'short' })} ${d.getFullYear()}, ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
    } catch (e) {
      return iso;
    }
  };

  const getPriorityColor = (p) => {
    if (p === 'Critical') return 'var(--red)';
    if (p === 'Important') return '#f59e0b';
    return 'var(--blue)';
  };

  return (
    <div id="app-shell" style={{ background: '#f8fafc' }}>
      <Sidebar />
      <main className="main-content" style={{ background: '#f8fafc', overflowY: 'auto', flex: 1, minWidth: 0 }}>
        <div className="audit-logs-container" style={{ width: '100%', maxWidth: 'none', margin: '0' }}>
          
          {/* Top Header */}
          <div className="audit-header" style={{ padding: '16px 24px', borderBottom: '1px solid #e2e8f0', background: '#fff' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <h2 style={{ fontSize: '24px', margin: '0 0 4px 0', color: '#0f172a', fontWeight: 600 }}>
                  Case Notes
                </h2>
                <p style={{ margin: '0 0 12px 0', color: '#64748b', fontSize: '13px' }}>Investigation observations, follow-ups, and case details.</p>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {activeCaseId ? (
                    <>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: '#eff6ff', color: '#2563eb', padding: '4px 10px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                        {activeCaseId}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: '#ecfdf5', color: '#059669', padding: '4px 10px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
                        <div style={{ width: '6px', height: '6px', background: '#10b981', borderRadius: '50%' }}></div>
                        Active
                      </div>
                    </>
                  ) : (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: '#f1f5f9', color: '#64748b', padding: '4px 10px', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
                      No active case selected
                    </div>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <div style={{ position: 'relative', color: '#64748b', cursor: 'pointer' }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>
                  <div style={{ position: 'absolute', top: 0, right: 0, width: '6px', height: '6px', background: '#ef4444', borderRadius: '50%', border: '2px solid #fff' }}></div>
                </div>
                <div style={{ width: '28px', height: '28px', background: '#e2e8f0', color: '#0f172a', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 600, fontSize: '12px' }}>
                  S
                </div>
                {activeCaseId && (
                  <button onClick={openNewNote} style={{ background: '#2563eb', border: 'none', padding: '6px 12px', borderRadius: '6px', color: '#fff', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', fontWeight: 600, marginLeft: '8px' }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    New Note
                  </button>
                )}
              </div>
            </div>
          </div>

          <div style={{ padding: '24px' }}>
            
            {/* Stats Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '20px' }}>
              <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: '#eff6ff', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Total Notes</div>
                  <div style={{ color: '#0f172a', fontSize: '20px', fontWeight: 700 }}>{totalNotes}</div>
                </div>
              </div>

              <div style={{ background: '#fef2f2', border: '1px solid #fee2e2', borderRadius: '8px', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: '#fee2e2', color: '#ef4444', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                </div>
                <div>
                  <div style={{ color: '#ef4444', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Important</div>
                  <div style={{ color: '#0f172a', fontSize: '20px', fontWeight: 700 }}>{importantNotes}</div>
                </div>
              </div>

              <div style={{ background: '#ecfdf5', border: '1px solid #d1fae5', borderRadius: '8px', padding: '16px 20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
                <div style={{ width: '36px', height: '36px', borderRadius: '8px', background: '#d1fae5', color: '#10b981', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: '12px', fontWeight: 600, marginBottom: '2px' }}>Follow-ups</div>
                  <div style={{ color: '#0f172a', fontSize: '20px', fontWeight: 700 }}>{followUpNotes}</div>
                </div>
              </div>
            </div>

            {/* Filter Bar */}
            <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '8px 12px', display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ flexGrow: 1, display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <input type="text" placeholder="Search notes..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} style={{ width: '100%', border: 'none', background: 'transparent', outline: 'none', color: '#0f172a', fontSize: '13px' }} />
              </div>
              <div style={{ width: '1px', height: '20px', background: '#e2e8f0' }}></div>
              <select value={filterType} onChange={e => setFilterType(e.target.value)} style={{ border: 'none', background: 'transparent', outline: 'none', color: '#0f172a', fontSize: '13px', fontWeight: 500, cursor: 'pointer' }}>
                <option value="All">All Types</option>
                <option value="Observation">Observation</option>
                <option value="Investigation">Investigation</option>
                <option value="Evidence">Evidence</option>
                <option value="Follow-up">Follow-up</option>
              </select>
              <div style={{ width: '1px', height: '20px', background: '#e2e8f0' }}></div>
              <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)} style={{ border: 'none', background: 'transparent', outline: 'none', color: '#0f172a', fontSize: '13px', fontWeight: 500, cursor: 'pointer' }}>
                <option value="All">All Priorities</option>
                <option value="Normal">Normal</option>
                <option value="Important">Important</option>
                <option value="Critical">Critical</option>
              </select>
              <div style={{ width: '1px', height: '20px', background: '#e2e8f0' }}></div>
              <select style={{ border: 'none', background: 'transparent', outline: 'none', color: '#0f172a', fontSize: '13px', fontWeight: 500, cursor: 'pointer' }}>
                <option>Newest</option>
                <option>Oldest</option>
              </select>
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
                    <div key={note.noteId} style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      <div style={{ display: 'flex', gap: '24px' }}>
                        <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: '#eff6ff', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        </div>
                        
                        <div style={{ flexGrow: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                            <h4 style={{ margin: 0, fontSize: '18px', color: '#0f172a', fontWeight: 700 }}>{note.title}</h4>
                            <button style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 0 }}>
                              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="1.5"></circle><circle cx="12" cy="5" r="1.5"></circle><circle cx="12" cy="19" r="1.5"></circle></svg>
                            </button>
                          </div>
                          
                          <p style={{ margin: '0 0 16px 0', fontSize: '14px', color: '#64748b', lineHeight: '1.6', wordBreak: 'break-word' }}>
                            {note.content}
                          </p>
                          
                          <div style={{ display: 'flex', gap: '12px' }}>
                            <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', color: '#2563eb', padding: '6px 14px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                              {note.type}
                            </div>
                            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', color: '#475569', padding: '6px 14px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/></svg>
                              {note.priority}
                            </div>
                          </div>

                          {(note.relatedEvidenceId || note.relatedFindingId) && (
                            <div style={{ padding: '10px 16px', background: '#f8fafc', borderRadius: '6px', border: '1px solid #e2e8f0', display: 'flex', gap: '24px', width: 'fit-content', marginTop: '16px' }}>
                              {note.relatedEvidenceId && (
                                <div style={{ fontSize: '12px', color: '#0f172a' }}>
                                  <span style={{ color: '#64748b' }}>Evidence:</span>{' '}
                                  <span style={{ color: '#2563eb', cursor: 'pointer', textDecoration: 'underline', fontWeight: 500 }} onClick={() => navigate('/evidence')}>{note.relatedEvidenceId}</span>
                                </div>
                              )}
                              {note.relatedFindingId && (
                                <div style={{ fontSize: '12px', color: '#0f172a' }}>
                                  <span style={{ color: '#64748b' }}>Finding:</span>{' '}
                                  <span style={{ color: '#2563eb', cursor: 'pointer', textDecoration: 'underline', fontWeight: 500 }} onClick={() => navigate('/dashboard')}>{note.relatedFindingId}</span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div style={{ height: '1px', background: '#e2e8f0', margin: '4px 0' }}></div>
                      
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', gap: '24px', color: '#64748b', fontSize: '13px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                            Created by: <span style={{ color: '#0f172a', fontWeight: 500 }}>{note.createdBy}</span>
                          </div>
                          <div style={{ width: '1px', height: '16px', background: '#cbd5e1' }}></div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                            {formatDate(note.createdAt)}
                          </div>
                        </div>
                        
                        <div style={{ display: 'flex', gap: '16px' }}>
                          <button onClick={() => openEditNote(note)} style={{ background: '#f8fafc', border: '1px solid #cbd5e1', color: '#2563eb', padding: '8px 24px', borderRadius: '8px', fontSize: '14px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', transition: 'all 0.2s' }}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                            Edit
                          </button>
                          <button onClick={() => setShowDeleteConfirm(note.noteId)} style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#ef4444', padding: '8px 24px', borderRadius: '8px', fontSize: '14px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', transition: 'all 0.2s' }}>
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
