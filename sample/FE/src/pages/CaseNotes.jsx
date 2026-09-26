import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import { API_BASE_URL } from '../js/api';
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

  const fetchNotes = async () => {
    if (!activeCaseId) return;
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${activeCaseId}/notes`, {
        headers: {
          'X-Tenant-ID': 'dev-team',
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setNotes(data.data || []);
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
    if (!title || !content) return;
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
          'X-Tenant-ID': 'dev-team',
          'Authorization': `Bearer ${localStorage.getItem('argus_token')}`
        },
        body: JSON.stringify(noteData)
      });
      if (res.ok) {
        setShowModal(false);
        fetchNotes();
      }
    } catch (e) {
      console.error('Error saving note', e);
    }
  };

  const handleDelete = async (noteId) => {
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${activeCaseId}/notes/${noteId}`, {
        method: 'DELETE',
        headers: {
          'X-Tenant-ID': 'dev-team',
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
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div className="audit-logs-container" style={{ padding: '0' }}>
          
          <div className="audit-header" style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', marginBottom: '24px' }}>
            <div className="header-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', width: '100%' }}>
              <div>
                <h2 style={{ fontSize: '24px', margin: '0 0 8px 0', color: 'var(--text-main)' }}>
                  Case Notes
                </h2>
                <p style={{ margin: '0 0 8px 0', color: 'var(--text-muted)' }}>Record investigation observations, follow-ups, and important case details.</p>
                {activeCaseId ? (
                  <p style={{ margin: 0, color: 'var(--blue)', fontWeight: 600 }}>Current Case: {activeCaseId}</p>
                ) : (
                  <p style={{ margin: 0, color: 'var(--text-muted)' }}>No active case selected.</p>
                )}
              </div>
              {activeCaseId && (
                <button className="btn-export" style={{ background: 'var(--blue)', border: 'none', padding: '8px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 600 }} onClick={openNewNote}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                  New Note
                </button>
              )}
            </div>
          </div>

          {!activeCaseId ? (
            <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <h3>No Case Notes Yet</h3>
              <p>Document your observations and investigation progress as you work through this case.</p>
            </div>
          ) : (
            <div style={{ padding: '0 24px' }}>
              <div className="audit-stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                <div className="audit-stat-card">
                  <div className="stat-label">Total Notes</div>
                  <div className="stat-value">{totalNotes}</div>
                </div>
                <div className="audit-stat-card">
                  <div className="stat-label">Important</div>
                  <div className="stat-value">{importantNotes}</div>
                </div>
                <div className="audit-stat-card">
                  <div className="stat-label">Follow-ups</div>
                  <div className="stat-value">{followUpNotes}</div>
                </div>
              </div>

              <div className="audit-filter-bar" style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap', background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '24px' }}>
                <input type="text" placeholder="Search notes..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} style={{ flexGrow: 1, minWidth: '200px', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '8px 12px', borderRadius: '6px' }} />
                
                <select value={filterType} onChange={e => setFilterType(e.target.value)} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '8px 12px', borderRadius: '6px' }}>
                  <option value="All">All Types</option>
                  <option value="Observation">Observation</option>
                  <option value="Investigation">Investigation</option>
                  <option value="Evidence">Evidence</option>
                  <option value="Follow-up">Follow-up</option>
                  <option value="Question">Question</option>
                  <option value="Important">Important</option>
                </select>

                <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '8px 12px', borderRadius: '6px' }}>
                  <option value="All">All Priorities</option>
                  <option value="Normal">Normal</option>
                  <option value="Important">Important</option>
                  <option value="Critical">Critical</option>
                </select>
              </div>

              <div className="notes-list" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '20px', paddingBottom: '40px' }}>
                {filteredNotes.length === 0 ? (
                  <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                    <p style={{ margin: '0 0 16px 0', fontSize: '18px', fontWeight: 600 }}>No Case Notes Yet</p>
                    <p style={{ margin: '0 0 24px 0' }}>Document your observations and investigation progress as you work through this case.</p>
                    <button className="btn-export" style={{ background: 'var(--blue)', border: 'none', padding: '8px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 600 }} onClick={openNewNote}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                      Create First Note
                    </button>
                  </div>
                ) : (
                  filteredNotes.map(note => (
                    <div key={note.noteId} className="note-card" style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '20px', display: 'flex', flexDirection: 'column' }}>
                      <h4 style={{ margin: '0 0 12px 0', fontSize: '16px', color: 'var(--text-main)' }}>{note.title}</h4>
                      <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--text-muted)', lineHeight: '1.5', whiteSpace: 'pre-wrap', flexGrow: 1 }}>
                        {note.content}
                      </p>
                      
                      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '11px', fontWeight: 600, padding: '4px 8px', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: '4px', color: 'var(--text-main)' }}>{note.type}</span>
                        <span style={{ fontSize: '11px', fontWeight: 600, padding: '4px 8px', background: 'var(--bg-app)', border: `1px solid ${getPriorityColor(note.priority)}`, borderRadius: '4px', color: getPriorityColor(note.priority) }}>{note.priority}</span>
                      </div>

                      {(note.relatedEvidenceId || note.relatedFindingId) && (
                        <div style={{ padding: '12px', background: 'var(--bg-app)', borderRadius: '6px', marginBottom: '16px', border: '1px solid var(--border-strong)' }}>
                          {note.relatedEvidenceId && (
                            <div style={{ fontSize: '12px', color: 'var(--text-main)' }}>
                              <span style={{ color: 'var(--text-muted)' }}>Related Evidence:</span> <br/>
                              <span style={{ color: 'var(--blue)', cursor: 'pointer', textDecoration: 'underline' }} onClick={() => navigate('/evidence')}>{note.relatedEvidenceId}</span>
                            </div>
                          )}
                          {note.relatedFindingId && (
                            <div style={{ fontSize: '12px', color: 'var(--text-main)', marginTop: note.relatedEvidenceId ? '8px' : '0' }}>
                              <span style={{ color: 'var(--text-muted)' }}>Related Finding:</span> <br/>
                              <span style={{ color: 'var(--blue)', cursor: 'pointer', textDecoration: 'underline' }} onClick={() => navigate('/dashboard')}>{note.relatedFindingId}</span>
                            </div>
                          )}
                        </div>
                      )}

                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 'auto', borderTop: '1px solid var(--border-strong)', paddingTop: '16px' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          <div>Created by: <span style={{ color: 'var(--text-main)' }}>{note.createdBy}</span></div>
                          <div style={{ marginTop: '4px' }}>{formatDate(note.createdAt)}</div>
                        </div>
                        <div style={{ display: 'flex', gap: '12px' }}>
                          <button onClick={() => openEditNote(note)} style={{ background: 'none', border: 'none', color: 'var(--blue)', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}>Edit</button>
                          <button onClick={() => setShowDeleteConfirm(note.noteId)} style={{ background: 'none', border: 'none', color: 'var(--red)', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}>Delete</button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
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
              <button onClick={() => setShowDeleteConfirm(null)} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', padding: '8px 16px', borderRadius: '6px', color: 'var(--text-main)', cursor: 'pointer', fontWeight: 600 }}>Cancel</button>
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
              <button onClick={() => setShowModal(false)} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', padding: '10px 16px', borderRadius: '6px', color: 'var(--text-main)', cursor: 'pointer', fontWeight: 600 }}>Cancel</button>
              <button onClick={handleSave} style={{ background: 'var(--blue)', border: 'none', padding: '10px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', fontWeight: 600 }}>{editingNote ? 'Save Changes' : 'Save Note'}</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default CaseNotes;
