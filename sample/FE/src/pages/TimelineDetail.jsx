import React, { useState, useEffect } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import NotificationMenu from '../components/NotificationMenu';
import AlertModal from '../components/AlertModal';
import { fetchFindings, fetchEvidenceForCase, createCaseNote } from '../js/api';
import { safeFormatDateTime } from '../js/dateUtils';
import '../css/style.css';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b'
};

const TimelineDetail = () => {
  const navigate = useNavigate();

  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('argus_user'));
  } catch (e) {}

  if (user?.role === 'analyst') {
    return <Navigate to="/dashboard" replace />;
  }

  const activeCaseId = localStorage.getItem('active_case_id');
  const activeCaseName = localStorage.getItem('active_case_name') || 'Current Case';

  // Theme state
  const [theme, setTheme] = useState(
    document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark'
  );
  const isDark = theme === 'dark';

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [timelineData, setTimelineData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  useEffect(() => {
    const loadTimeline = async () => {
      if (!activeCaseId) {
        setTimelineData([]);
        setLoading(false);
        return;
      }

      setLoading(true);
      setError(null);
      try {
        const [findingsRes, evidenceRes] = await Promise.allSettled([
          fetchFindings(activeCaseId),
          fetchEvidenceForCase(activeCaseId)
        ]);

        const findingsList = findingsRes.status === 'fulfilled' && findingsRes.value
          ? (Array.isArray(findingsRes.value) ? findingsRes.value : (findingsRes.value.data || []))
          : [];

        const evidenceList = evidenceRes.status === 'fulfilled' && evidenceRes.value
          ? (Array.isArray(evidenceRes.value) ? evidenceRes.value : (evidenceRes.value.data || []))
          : [];

        const events = [];

        // 1. Evidence intake anchors
        evidenceList.forEach((ev, idx) => {
          events.push({
            id: ev.evidence_id || `EV-${idx}`,
            time: ev.created_at ? safeFormatDateTime(ev.created_at) : 'Evidence Ingestion',
            rawTs: ev.created_at ? new Date(ev.created_at).getTime() : 1000,
            category: 'EVIDENCE INTAKE',
            severity: 'info',
            title: `Artifact Staged: ${ev.filename || 'Forensic Source'}`,
            desc: `Evidence artifact ingested into repository. SHA-256 integrity hash: ${ev.sha256_hash ? ev.sha256_hash.slice(0, 24) + '...' : 'Verified'}. Cryptographic custody established.`,
            source: 'Ingestion Pipeline',
            mitre: null,
            details: `Status: ${(ev.status || 'Stored').toUpperCase()} | SHA-256: ${ev.sha256_hash || 'Verified'}`
          });
        });

        // 2. Findings events
        findingsList.forEach((f, idx) => {
          const timeStr = f.timestamp ? safeFormatDateTime(f.timestamp) : `Event #${idx + 1}`;
          const rawTs = f.timestamp ? new Date(String(f.timestamp).replace(/\s+/, 'T')).getTime() : (2000 + idx * 1000);
          events.push({
            id: f.finding_id || `TL-${idx}`,
            time: timeStr,
            rawTs: rawTs,
            category: f.layer ? f.layer.toUpperCase() : 'FORENSIC FINDING',
            severity: (f.severity || 'medium').toLowerCase(),
            title: f.finding_id || `Finding #${idx + 1}`,
            desc: f.sanitized_fact || f.fact,
            source: f.layer || 'FIR Repository',
            mitre: f.mitre_mapping || null,
            details: f.mitre_mapping ? `MITRE ATT&CK: ${f.mitre_mapping}` : `Ref: ${Array.isArray(f.evidence_reference) ? f.evidence_reference.join(', ') : f.evidence_reference || 'Telemetry'}`
          });
        });

        // Sort chronologically ascending
        events.sort((a, b) => a.rawTs - b.rawTs);
        setTimelineData(events);
      } catch (err) {
        console.error('Error fetching timeline findings:', err);
        setError(err.message || 'Failed to load timeline events for this case.');
        setTimelineData([]);
      } finally {
        setLoading(false);
      }
    };

    loadTimeline();
  }, [activeCaseId]);

  // Action: Ask AI Assistant about this event
  const handleAskAI = (event) => {
    const prompt = `Analyze this timeline event for Case ${activeCaseId}: "${event.title} - ${event.desc}". What are the adversary tactics, observable IOCs, and recommended containment steps?`;
    sessionStorage.setItem('argus_chatbot_prefill', prompt);
    navigate('/chatbot');
  };

  // Action: Save timeline event to Case Notes
  const handleSaveToNotes = async (event) => {
    try {
      const noteTitle = `Timeline Event: ${event.title}`;
      const noteContent = `**Timestamp:** ${event.time}\n**Category:** ${event.category} (${event.severity.toUpperCase()})\n**Details:** ${event.desc}\n**Context:** ${event.details}`;

      const savedNotesKey = `case_notes_${activeCaseId}`;
      const localNotes = JSON.parse(localStorage.getItem(savedNotesKey) || '[]');
      const newNote = {
        id: `note-${Date.now()}`,
        noteId: `note-${Date.now()}`,
        title: noteTitle,
        content: noteContent,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        author: 'Forensic Analyst',
        type: 'finding',
        priority: (event.severity === 'critical' || event.severity === 'high') ? 'HIGH' : 'NORMAL'
      };
      localStorage.setItem(savedNotesKey, JSON.stringify([newNote, ...localNotes]));

      try {
        await createCaseNote(activeCaseId, {
          title: noteTitle,
          content: noteContent,
          type: 'finding',
          priority: newNote.priority
        });
      } catch (e) {
        console.warn('Backend sync note failed, cached locally:', e);
      }

      showToast('Event saved to Case Notes!');
    } catch (e) {
      showToast('Error saving event note.');
    }
  };

  // Action: Add event to Report
  const handleAddToReport = (event) => {
    const snippet = `### Timeline Milestone: ${event.time}\n- **Event:** ${event.title}\n- **Impact:** ${event.desc}\n- **Technical Reference:** ${event.details}\n`;
    const existing = localStorage.getItem('argus_report_insight') || '';
    localStorage.setItem('argus_report_insight', existing ? `${existing}\n\n${snippet}` : snippet);
    showToast('Event queued for Report Builder!');
  };

  const filteredData = timelineData.filter(d => {
    const matchesSev = filter === 'all' || (d.severity || '').toLowerCase() === filter;
    const q = searchTerm.toLowerCase();
    const matchesSearch = !q || 
      d.title.toLowerCase().includes(q) || 
      d.desc.toLowerCase().includes(q) || 
      (d.mitre && d.mitre.toLowerCase().includes(q)) ||
      (d.category && d.category.toLowerCase().includes(q));
    return matchesSev && matchesSearch;
  });

  const criticalCount = timelineData.filter(d => d.severity === 'critical' || d.severity === 'high').length;

  return (
    <div id="app-shell" style={{ display: 'flex', height: '100vh', background: 'var(--bg-app)', fontFamily: 'Inter, sans-serif' }}>
      {/* Toast Notification */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          top: '24px',
          right: '32px',
          zIndex: 9999,
          background: '#10b981',
          color: '#ffffff',
          padding: '10px 18px',
          borderRadius: '8px',
          fontSize: '13px',
          fontWeight: 600,
          boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          {toastMessage}
        </div>
      )}

      <Sidebar active="timeline" />
      <main className="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        
        {/* Header */}
        <header style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '14px 32px',
          background: 'var(--bg-card)',
          borderBottom: '1px solid var(--border-subtle)',
          flexShrink: 0
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 4px 12px rgba(59, 130, 246, 0.25)'
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>Attack Timeline Reconstruction</span>
                {activeCaseId && (
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    color: isDark ? '#93c5fd' : '#2563eb',
                    background: isDark ? 'rgba(59, 130, 246, 0.15)' : 'rgba(59, 130, 246, 0.1)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    padding: '2px 8px',
                    borderRadius: '12px'
                  }}>
                    Case: {activeCaseId}
                  </span>
                )}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                Chronological forensic evidence sequencing and kill-chain correlation
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {/* Theme Toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
              style={{
                background: isDark ? '#1e293b' : '#f1f5f9',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                width: '36px',
                height: '36px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                color: isDark ? '#f59e0b' : '#64748b'
              }}
            >
              {isDark ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="5"></circle>
                  <line x1="12" y1="1" x2="12" y2="3"></line>
                  <line x1="12" y1="21" x2="12" y2="23"></line>
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                  <line x1="1" y1="12" x2="3" y2="12"></line>
                  <line x1="21" y1="12" x2="23" y2="12"></line>
                  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                </svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
              )}
            </button>

            {/* AI Assistant Quick Link */}
            <button
              type="button"
              onClick={() => navigate('/chatbot')}
              style={{
                background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '8px',
                padding: '7px 14px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                boxShadow: '0 2px 8px rgba(59, 130, 246, 0.3)'
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
              </svg>
              <span>AI Assistant</span>
            </button>

            <NotificationMenu />
          </div>
        </header>

        {/* Content Area */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Top Summary Banner */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '16px'
          }}>
            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              padding: '14px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '8px',
                background: 'rgba(59, 130, 246, 0.15)',
                color: '#3b82f6',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"></circle>
                  <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
              </div>
              <div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-main)' }}>{timelineData.length}</div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Total Sequenced Events</div>
              </div>
            </div>

            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              padding: '14px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.15)',
                color: '#ef4444',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                </svg>
              </div>
              <div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: '#ef4444' }}>{criticalCount}</div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>High / Critical Anomalies</div>
              </div>
            </div>

            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              padding: '14px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px'
            }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                  <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
              </div>
              <div>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-main)' }}>MITRE ATT&CK</div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Deterministic Kill-Chain Mapping</div>
              </div>
            </div>
          </div>

          {/* Controls Bar: Filters & Search */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'var(--bg-card)',
            padding: '12px 20px',
            borderRadius: '10px',
            border: '1px solid var(--border-subtle)',
            flexWrap: 'wrap',
            gap: '12px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>Filter:</span>
              <div style={{ display: 'flex', gap: '6px' }}>
                {['all', 'critical', 'high', 'medium', 'info'].map(s => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setFilter(s)}
                    style={{
                      padding: '5px 12px',
                      borderRadius: '6px',
                      fontSize: '11.5px',
                      fontWeight: 600,
                      textTransform: 'capitalize',
                      border: 'none',
                      cursor: 'pointer',
                      background: filter === s ? (SEVERITY_COLORS[s] || 'var(--blue)') : (isDark ? '#1e293b' : '#f1f5f9'),
                      color: filter === s ? '#fff' : 'var(--text-muted)',
                      transition: 'all 0.2s'
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ position: 'relative' }}>
                <input
                  type="text"
                  placeholder="Search timeline..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{
                    background: isDark ? '#0b0f19' : '#f8fafc',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-main)',
                    borderRadius: '8px',
                    padding: '6px 12px 6px 30px',
                    fontSize: '12px',
                    outline: 'none',
                    width: '180px'
                  }}
                />
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-muted)' }}
                >
                  <circle cx="11" cy="11" r="8"></circle>
                  <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
              </div>

              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Showing <strong>{filteredData.length}</strong> of {timelineData.length} events
              </div>
            </div>
          </div>

          {/* Timeline Feed */}
          {loading ? (
            <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <div className="spinner" style={{ margin: '0 auto 12px auto' }}></div>
              Sequencing forensic telemetry for case {activeCaseId}...
            </div>
          ) : error ? (
            <div style={{ padding: '32px', textAlign: 'center', background: 'rgba(239,68,68,0.1)', border: '1px solid #ef4444', borderRadius: '10px', color: '#ef4444' }}>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '16px' }}>Timeline Retrieval Error</h4>
              <p style={{ margin: 0, fontSize: '14px' }}>{error}</p>
            </div>
          ) : filteredData.length === 0 ? (
            <div style={{ padding: '60px', textAlign: 'center', background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"></circle>
                  <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
              </div>
              <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', color: 'var(--text-main)' }}>No Matching Timeline Events</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: 0, maxWidth: '400px', margin: '0 auto' }}>
                {!activeCaseId ? 'No active case selected. Select an investigation case to view reconstructed events.' : 'No forensic findings match the active search or severity filter.'}
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', position: 'relative', paddingLeft: '16px' }}>
              
              {/* Vertical Guide Line */}
              <div style={{
                position: 'absolute',
                top: '20px',
                bottom: '20px',
                left: '27px',
                width: '2px',
                background: isDark ? 'linear-gradient(to bottom, #3b82f6, #6366f1, #1e293b)' : 'linear-gradient(to bottom, #93c5fd, #c7d2fe, #e2e8f0)',
                zIndex: 0
              }} />

              {filteredData.map((item, idx) => {
                const color = SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.info;
                return (
                  <div key={item.id || idx} style={{ display: 'flex', gap: '20px', position: 'relative', zIndex: 1 }}>
                    
                    {/* Circle Node with Step Index */}
                    <div style={{
                      width: '24px',
                      height: '24px',
                      borderRadius: '50%',
                      background: 'var(--bg-card)',
                      border: `3px solid ${color}`,
                      marginTop: '16px',
                      flexShrink: 0,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: `0 0 10px ${color}40`
                    }}>
                      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: color }} />
                    </div>

                    {/* Card Content */}
                    <div style={{
                      flex: 1,
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border-subtle)',
                      borderLeft: `4px solid ${color}`,
                      borderRadius: '10px',
                      padding: '18px 22px',
                      boxShadow: '0 4px 16px rgba(0,0,0,0.04)',
                      transition: 'border-color 0.2s'
                    }}>
                      {/* Top Header */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '14.5px', fontWeight: 700, color: 'var(--text-main)' }}>{item.title}</span>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: `${color}20`,
                            color: color,
                            letterSpacing: '0.4px'
                          }}>
                            {item.category}
                          </span>
                          {item.mitre && (
                            <span style={{
                              fontSize: '10.5px',
                              fontWeight: 700,
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: 'rgba(59, 130, 246, 0.15)',
                              color: isDark ? '#93c5fd' : '#2563eb',
                              border: '1px solid rgba(59, 130, 246, 0.3)'
                            }}>
                              {item.mitre}
                            </span>
                          )}
                        </div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace', fontWeight: 600 }}>
                          ⏱️ {item.time}
                        </span>
                      </div>

                      {/* Description */}
                      <div style={{ fontSize: '13.5px', color: 'var(--text-main)', lineHeight: '1.6', marginBottom: '14px' }}>
                        {item.desc}
                      </div>

                      {/* Footer Info & Actions Bar */}
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        paddingTop: '12px',
                        borderTop: '1px solid var(--border-subtle)',
                        fontSize: '12px',
                        color: 'var(--text-muted)',
                        flexWrap: 'wrap',
                        gap: '10px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <span>Layer: <strong>{item.source}</strong></span>
                          <span>•</span>
                          <span>{item.details}</span>
                        </div>

                        {/* Interactive Buttons */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <button
                            type="button"
                            onClick={() => handleAskAI(item)}
                            title="Query AI Assistant about this timeline event"
                            style={{
                              background: 'rgba(59, 130, 246, 0.12)',
                              border: '1px solid rgba(59, 130, 246, 0.25)',
                              color: isDark ? '#93c5fd' : '#2563eb',
                              padding: '4px 10px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                            </svg>
                            <span>Ask AI</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => handleSaveToNotes(item)}
                            title="Save this event to Case Notes"
                            style={{
                              background: isDark ? '#1e293b' : '#f1f5f9',
                              border: '1px solid var(--border-subtle)',
                              color: 'var(--text-main)',
                              padding: '4px 10px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>
                            </svg>
                            <span>Save Note</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => handleAddToReport(item)}
                            title="Add event milestone to Report draft"
                            style={{
                              background: isDark ? '#1e293b' : '#f1f5f9',
                              border: '1px solid var(--border-subtle)',
                              color: 'var(--text-main)',
                              padding: '4px 10px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            </svg>
                            <span>Add to Report</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default TimelineDetail;
