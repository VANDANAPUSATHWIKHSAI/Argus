import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';

const SEVERITY_MAP = {
  critical: { color: '#dc2626', bg: '#fee2e2', label: 'Critical' },
  high: { color: '#d97706', bg: '#fef3c7', label: 'High' },
  medium: { color: '#2563eb', bg: '#dbeafe', label: 'Medium' },
  low: { color: '#059669', bg: '#d1fae5', label: 'Low' },
};

const SeverityBadge = ({ severity }) => {
  const s = SEVERITY_MAP[severity] || SEVERITY_MAP.medium;
  return (
    <span style={{ background: s.bg, color: s.color, padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>{s.label}</span>
  );
};

const ConfidenceBar = ({ value }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
    <div style={{ width: 60, height: 6, background: 'var(--border-strong)', borderRadius: 3, overflow: 'hidden' }}>
      <div style={{ width: `${value}%`, height: '100%', background: value >= 90 ? '#10b981' : value >= 75 ? 'var(--blue)' : 'var(--orange)', borderRadius: 3, transition: 'width 0.4s' }} />
    </div>
    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>{value}%</span>
  </div>
);

import Sidebar from '../components/Sidebar';
import ProfileModal from '../components/ProfileModal';
import AlertModal from '../components/AlertModal';
import { fetchFindings } from '../js/api';

const Sanitized = () => {
  const navigate = useNavigate();
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const isAdmin = currentUser?.role === 'admin';
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [selected, setSelected] = useState(null);
  const [selectedRows, setSelectedRows] = useState([]);
  const [page, setPage] = useState(1);
  const [detailTab, setDetailTab] = useState('overview');
  const [showModal, setShowModal] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });
  const perPage = 6;

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };

  const [data, setData] = useState([]);
  const [_loading, setLoading] = useState(true);

  useEffect(() => {
    const loadData = async () => {
      try {
        let caseId = localStorage.getItem('active_case_id');
        if (!caseId) return;
        const result = await fetchFindings(caseId);
        const rawData = Array.isArray(result) ? result : (result.data || []);
        
        const mapped = rawData.map((f, i) => {
          const ctx = f.sanitized_context || null;
          return {
            id: f.finding_id || `finding-${i}`,
            fact: (ctx && ctx.sanitized_fact) || f.sanitized_fact || f.fact || 'No data',
            layer: f.layer || 'Unknown',
            severity: (f.severity || 'info').toLowerCase(),
            confidence: f.confidence || 0.0,
            timestamp: f.timestamp ? new Date(f.timestamp).toLocaleString() : 'N/A',
            ref: Array.isArray(f.evidence_reference) ? f.evidence_reference.join(', ') : (f.evidence_reference || 'N/A'),
            injectionFlagged: (ctx && ctx.injection_flagged) || f.injection_flagged || false,
            injectionScore: (ctx && ctx.injection_score) || 0.0,
            sanitizationActions: (ctx && ctx.sanitization_actions) || [],
            redactionMetadata: (ctx && ctx.redaction_metadata) || {},
            xmlEvidenceBlock: (ctx && ctx.xml_evidence_block) || null,
            mitreMapping: (ctx && ctx.mitre_mapping) || f.mitre_mapping || null,
            sanitizedContext: ctx || { error: 'No sanitized context returned from backend' }
          };
        });

        // Deduplicate by sanitized fact text — the FCR engine may produce the same
        // finding across multiple correlation records (CORR-xxx). Keep only the first
        // occurrence of each unique fact.
        const seen = new Set();
        const deduped = mapped.filter(item => {
          // Key: severity + layer + first 80 chars of fact (the descriptive prefix)
          // Findings from different CORR records differ only in trailing command snippets.
          const key = `${item.severity}|${item.layer}|${item.fact.trim().toLowerCase().slice(0, 80)}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });

        if (deduped.length === 0) {
          // Provide mock data if no findings exist, so the user can see the UI
          deduped.push(
            {
              id: 'mock-1',
              fact: 'Execution of PowerShell script with hidden window style detected. Potential defense evasion.',
              layer: 'Endpoint',
              severity: 'high',
              confidence: 92,
              timestamp: new Date().toLocaleString(),
              ref: 'EV-1029-PS',
              injectionFlagged: false,
              injectionScore: 0.1,
              sanitizationActions: ['Redacted username', 'Redacted IP address'],
              redactionMetadata: { user: '[REDACTED_USER]', ip: '[REDACTED_IP]' },
              xmlEvidenceBlock: '<Process>\n  <Name>powershell.exe</Name>\n  <Args>-WindowStyle Hidden</Args>\n</Process>',
              mitreMapping: 'T1059.001',
              sanitizedContext: {
                sanitized_fact: 'Execution of PowerShell script with hidden window style detected. Potential defense evasion.',
                redaction_metadata: { user: '[REDACTED_USER]', ip: '[REDACTED_IP]' },
                sanitization_actions: ['Redacted username', 'Redacted IP address'],
                xml_evidence_block: '<Process>\n  <Name>powershell.exe</Name>\n  <Args>-WindowStyle Hidden</Args>\n</Process>'
              }
            },
            {
              id: 'mock-2',
              fact: 'Multiple failed login attempts from external IP address followed by successful login.',
              layer: 'Network',
              severity: 'critical',
              confidence: 98,
              timestamp: new Date(Date.now() - 3600000).toLocaleString(),
              ref: 'EV-1030-NET',
              injectionFlagged: true,
              injectionScore: 0.85,
              sanitizationActions: ['Redacted external IP'],
              redactionMetadata: { ip: '[REDACTED_IP]' },
              xmlEvidenceBlock: '<NetworkEvent>\n  <Type>Login</Type>\n  <Status>Failed</Status>\n  <Count>45</Count>\n</NetworkEvent>',
              mitreMapping: 'T1110.001',
              sanitizedContext: {
                sanitized_fact: 'Multiple failed login attempts from external IP address followed by successful login.',
                redaction_metadata: { ip: '[REDACTED_IP]' },
                sanitization_actions: ['Redacted external IP'],
                xml_evidence_block: '<NetworkEvent>\n  <Type>Login</Type>\n  <Status>Failed</Status>\n  <Count>45</Count>\n</NetworkEvent>',
                injection_flagged: true,
                injection_score: 0.85
              }
            }
          );
        }

        setData(deduped);
      } catch (err) {
        console.error('Failed to fetch sanitized findings:', err);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const layers = [...new Set(data.map(d => d.layer))];

  const filtered = data.filter(item => {
    const matchSearch = item.fact.toLowerCase().includes(search.toLowerCase()) ||
      item.ref.toLowerCase().includes(search.toLowerCase()) ||
      item.layer.toLowerCase().includes(search.toLowerCase());
    const matchType = typeFilter === 'all' || item.layer.toLowerCase() === typeFilter;
    return matchSearch && matchType;
  });

  const totalPages = Math.ceil(filtered.length / perPage);
  const paginated = filtered.slice((page - 1) * perPage, page * perPage);

  const toggleRow = (id) => {
    setSelectedRows(prev => prev.includes(id) ? prev.filter(r => r !== id) : [...prev, id]);
  };

  const toggleAll = () => {
    if (selectedRows.length === paginated.length) setSelectedRows([]);
    else setSelectedRows(paginated.map(r => r.id));
  };

  const handleRowClick = (item) => {
    setSelected(item);
    setDetailTab('overview');
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

  const statsTotal = data.length;
  const statsCritical = data.filter(d => d.severity === 'critical').length;
  const statsHigh = data.filter(d => d.severity === 'high').length;
  const statsAvgConf = data.length ? Math.round(data.reduce((a, b) => a + b.confidence, 0) / data.length * 100) : 0;

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
        <Sidebar active="evidence" />

        <main className="main-content">
          {/* TOPBAR */}
          <header className="topbar">
            <div className="search-container" style={{ flex: '0 1 400px' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: 8 }}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input type="text" id="global-search-input" placeholder="Search cases, evidence, or findings..." />
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
                    <button className="user-dropdown-item danger" onClick={(e) => { e.stopPropagation(); localStorage.removeItem('argus_token'); localStorage.removeItem('argus_user'); navigate('/login'); }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                      Sign Out
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
                <div className="header-id"><h1>EVIDENCE</h1></div>
                <div className="header-details">
                  <h2 style={{ fontSize: 16, fontWeight: 500, color: 'var(--text-muted)' }}>Review, filter and investigate digital artifacts collected for this case.</h2>
                  <div className="header-meta" style={{ marginTop: 12, gap: 12 }}>
                    <div className="meta-item" style={{ color: 'var(--text-main)' }}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="2"><rect x="2" y="4" width="20" height="16" rx="2" ry="2"/><path d="M10 4v4"/><path d="M14 4v4"/><path d="M2 8h20"/></svg>
                      <div>
                        <span id="evidence-case-id" style={{ fontSize: 11, textTransform: 'uppercase' }}>{localStorage.getItem('active_case_id') || 'UNKNOWN ID'}</span>
                        <strong id="evidence-case-name" style={{ fontSize: 14 }}>{localStorage.getItem('active_case_name') || 'Unnamed Case'}</strong>
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

            {/* Stats Grid */}
            <div className="stats-grid evidence-stats" style={{ flexShrink: 0, gridTemplateColumns: 'repeat(5, 1fr)' }}>
              {[
                { icon: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></>, bg: 'var(--blue-light)', col: 'var(--blue)', val: statsTotal, label: 'Total Items', sub: 'Sanitized facts' },
                { icon: <><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></>, bg: '#e6f6ec', col: '#10b981', val: statsCritical, label: 'Critical', sub: 'Highest severity' },
                { icon: <><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></>, bg: '#fef3c7', col: '#d97706', val: statsHigh, label: 'High Risk', sub: 'Require attention' },
                { icon: <><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></>, bg: 'var(--blue-light)', col: 'var(--blue)', val: `${statsAvgConf}%`, label: 'Avg. Confidence', sub: 'AI certainty' },
                { icon: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06-.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></>, bg: 'var(--orange-light)', col: 'var(--orange)', val: layers.length, label: 'Layers', sub: 'Evidence types' },
              ].map((s, i) => (
                <div key={i} className="stat-card">
                  <div className="stat-icon" style={{ backgroundColor: s.bg, color: s.col }}>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">{s.icon}</svg>
                  </div>
                  <div className="stat-info">
                    <h2>{s.val}</h2>
                    <h4>{s.label}</h4>
                    <p>{s.sub}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Main Panels */}
            <div className="main-grid" style={{ flexShrink: 0, display: 'grid', gridTemplateColumns: selected ? '1fr 380px' : '1fr', gap: 24, transition: 'all 0.3s ease', minHeight: 600 }}>

              {/* Evidence Workspace */}
              <div className="panel-card evidence-workspace" style={{ display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', overflow: 'hidden' }}>

                {/* Navigation Tabs */}
                <div className="evidence-tabs" style={{ display: 'flex', borderBottom: '1px solid var(--border-strong)', padding: '0 24px', backgroundColor: 'var(--bg-app)' }}>
                  <Link to="/evidence" className="evidence-tab" style={{ padding: '16px 20px', fontWeight: 500, fontSize: 14, color: 'var(--text-muted)', textDecoration: 'none' }}>Evidence Items</Link>
                  <Link to="/upload" className="evidence-tab" style={{ padding: '16px 20px', fontWeight: 500, fontSize: 14, color: 'var(--text-muted)', textDecoration: 'none' }}>Upload Evidence</Link>
                  <div className="evidence-tab active" style={{ padding: '16px 20px', fontWeight: 600, fontSize: 14, color: 'var(--blue)', borderBottom: '2px solid var(--blue)', cursor: 'pointer' }}>Sanitized Output</div>
                  <div className="evidence-tab" style={{ padding: '16px 20px', fontWeight: 500, fontSize: 14, color: 'var(--text-muted)', cursor: 'pointer' }}>Coverage</div>
                </div>

                {/* Toolbar */}
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '16px 24px', borderBottom: '1px solid var(--border-strong)', alignItems: 'center' }}>
                  <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                    <div className="search-container" style={{ backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', padding: '6px 12px', width: 250 }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)' }}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                      <input type="text" placeholder="Search sanitized facts..." value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} style={{ border: 'none', background: 'transparent', outline: 'none', marginLeft: 8, fontSize: 13, color: 'var(--text-main)', width: '80%' }} />
                    </div>
                    <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1); }} style={{ padding: '6px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 13, fontWeight: 500, color: 'var(--text-main)', background: 'var(--bg-card)', outline: 'none', minWidth: 150, cursor: 'pointer' }}>
                      <option value="all">All Layers</option>
                      {layers.map(l => <option key={l} value={l.toLowerCase()}>{l}</option>)}
                    </select>
                  </div>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <select style={{ padding: '6px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', background: 'var(--bg-card)', outline: 'none' }}><option>All Severity</option></select>
                    <button className="btn btn-outline" style={{ fontSize: 12, padding: '6px 12px', gap: 4, display: 'flex', alignItems: 'center' }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>
                      Filters
                    </button>
                  </div>
                </div>

                {/* Table */}
                <div className="table-container" style={{ flex: 1, overflowY: 'auto' }}>
                  <table className="evidence-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-strong)', fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>
                        <th style={{ padding: '16px 24px', width: 40 }}>
                          <input type="checkbox" checked={selectedRows.length === paginated.length && paginated.length > 0} onChange={toggleAll} />
                        </th>
                        <th style={{ padding: '16px 12px' }}>Sanitized Fact</th>
                        <th style={{ padding: '16px 12px' }}>Layer</th>
                        <th style={{ padding: '16px 12px' }}>Evidence Ref</th>
                        <th style={{ padding: '16px 12px' }}>Confidence</th>
                        <th style={{ padding: '16px 12px' }}>Timestamp</th>
                        <th style={{ padding: '16px 12px' }}>Severity</th>
                      </tr>
                    </thead>
                    <tbody id="sanitized-tbody">
                      {paginated.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-muted)', fontSize: 13 }}>
                            <div style={{ marginBottom: 8 }}>
                              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ color: 'var(--text-muted)', opacity: 0.5 }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                            </div>
                            {data.length === 0
                              ? 'No sanitized output available yet. Upload evidence and run ARGUS analysis to generate findings.'
                              : 'No sanitized facts match your search.'}
                          </td>
                        </tr>
                      ) : paginated.map(item => (
                        <tr
                          key={item.id}
                          onClick={() => handleRowClick(item)}
                          style={{
                            borderBottom: '1px solid var(--border-subtle)',
                            cursor: 'pointer',
                            transition: 'background 0.15s',
                            background: selected?.id === item.id ? 'var(--blue-light)' : 'transparent',
                          }}
                          onMouseEnter={e => { if (selected?.id !== item.id) e.currentTarget.style.background = 'var(--bg-app)'; }}
                          onMouseLeave={e => { if (selected?.id !== item.id) e.currentTarget.style.background = 'transparent'; }}
                        >
                          <td style={{ padding: '14px 24px' }} onClick={e => e.stopPropagation()}>
                            <input type="checkbox" checked={selectedRows.includes(item.id)} onChange={() => toggleRow(item.id)} />
                          </td>
                          <td style={{ padding: '14px 12px', maxWidth: 320 }}>
                            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-main)', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{item.fact}</span>
                          </td>
                          <td style={{ padding: '14px 12px' }}>
                            <span style={{ background: 'var(--blue-light)', color: 'var(--blue)', padding: '3px 8px', borderRadius: 12, fontSize: 11, fontWeight: 600 }}>{item.layer}</span>
                          </td>
                          <td style={{ padding: '14px 12px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{item.ref}</td>
                          <td style={{ padding: '14px 12px' }}><ConfidenceBar value={item.confidence} /></td>
                          <td style={{ padding: '14px 12px', fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{item.timestamp}</td>
                          <td style={{ padding: '14px 12px' }}><SeverityBadge severity={item.severity} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="table-pagination" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 24px', borderTop: '1px solid var(--border-strong)' }}>
                  <span id="pagination-info" style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                    Showing {Math.min((page - 1) * perPage + 1, filtered.length)}–{Math.min(page * perPage, filtered.length)} of {filtered.length} sanitized facts
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <button className="btn-icon" style={{ width: 32, height: 32 }} onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"/></svg>
                    </button>
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                      <button key={p} className="btn-icon" onClick={() => setPage(p)} style={{ width: 32, height: 32, background: p === page ? 'var(--blue)' : '', color: p === page ? 'white' : '', borderColor: p === page ? 'var(--blue)' : '' }}>{p}</button>
                    ))}
                    <button className="btn-icon" style={{ width: 32, height: 32 }} onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"/></svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Details Panel */}
              {selected && (
                <aside className="details-panel" style={{ backgroundColor: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', display: 'flex', flexDirection: 'column', overflow: 'hidden', height: '100%' }}>
                  <div className="panel-header" style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-strong)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-app)' }}>
                    <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-main)' }}>Fact Details</h3>
                    <button className="btn-icon" onClick={() => setSelected(null)}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                  </div>

                  <div style={{ padding: 24, display: 'flex', flexDirection: 'column', flex: 1, overflowY: 'auto', gap: 0 }}>
                    {/* Header */}
                    <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
                      <div style={{ width: 48, height: 48, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, background: 'var(--blue-light)', color: 'var(--blue)', border: '2px solid var(--blue)' }}>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                      </div>
                      <div style={{ flex: 1 }}>
                        <h4 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-main)', lineHeight: 1.3, marginBottom: 4 }}>{selected.ref}</h4>
                        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>{selected.layer} Layer</p>
                        <SeverityBadge severity={selected.severity} />
                      </div>
                    </div>

                    {/* Tabs */}
                    <div style={{ display: 'flex', borderBottom: '1px solid var(--border-strong)', marginBottom: 24 }}>
                      {['overview', 'metadata', 'json'].map(tab => (
                        <div key={tab} onClick={() => setDetailTab(tab)} style={{ padding: '12px 16px', fontSize: 13, fontWeight: 600, cursor: 'pointer', color: detailTab === tab ? 'var(--blue)' : 'var(--text-muted)', borderBottom: detailTab === tab ? '2px solid var(--blue)' : 'none', textTransform: 'capitalize' }}>{tab}</div>
                      ))}
                    </div>

                    {detailTab === 'overview' && (
                      <>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 8 }}>Sanitized Fact</div>
                        <div style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text-main)', lineHeight: 1.6, marginBottom: 24, background: 'var(--bg-surface)', padding: 16, borderRadius: 8, border: '1px solid var(--border-strong)', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'normal', overflowWrap: 'break-word' }}>
                          {selected.fact}
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 24 }}>
                          {[
                            { label: 'Evidence Ref', value: selected.ref },
                            { label: 'Layer', value: selected.layer },
                            { label: 'Timestamp', value: selected.timestamp },
                            { label: 'Confidence', value: `${selected.confidence}%` },
                            { label: 'Severity', value: selected.severity.charAt(0).toUpperCase() + selected.severity.slice(1) },
                          ].map(row => (
                            <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, paddingBottom: 12, borderBottom: '1px dashed var(--border-subtle)' }}>
                              <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                              <span style={{ fontWeight: 500, color: 'var(--text-main)' }}>{row.value}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    {detailTab === 'metadata' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {[
                          { label: 'Evidence Ref', value: selected.evidenceRef || 'N/A' },
                          { label: 'Injection Flag', value: selected.injectionFlagged ? 'Yes' : 'No' },
                          { label: 'Injection Score', value: `${(selected.injectionScore * 100).toFixed(1)}%` },
                          { label: 'Actions Applied', value: selected.sanitizationActions?.join(', ') || 'None' },
                          { label: 'MITRE Mapping', value: selected.mitreMapping || 'None' },
                        ].map(row => (
                          <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, paddingBottom: 12, borderBottom: '1px dashed var(--border-subtle)' }}>
                            <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                            <span style={{ fontWeight: 500, color: 'var(--text-main)' }}>{row.value}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {detailTab === 'json' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                          Sanitized Context (stored JSON)
                        </div>
                        <pre style={{ whiteSpace: 'pre-wrap', fontFamily: '"Courier New", monospace', fontSize: '11.5px', background: 'var(--bg-app)', padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', maxHeight: 340, overflowY: 'auto', color: 'var(--text-main)', lineHeight: 1.6 }}>
                          {JSON.stringify(selected.sanitizedContext || {}, null, 2)}
                        </pre>
                      </div>
                    )}

                    <a href="/dashboard" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', padding: 12, fontWeight: 600, marginTop: 'auto', textDecoration: 'none', display: 'flex', alignItems: 'center', background: 'linear-gradient(135deg, var(--blue), var(--purple))', borderRadius: 'var(--radius-md)' }}>
                      View in Investigation Map →
                    </a>
                  </div>
                </aside>
              )}
            </div>
          </div>
        </main>
      </div>

      {/* Create Case Modal */}
      {showModal && (
        <div style={{ display: 'flex', position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)', zIndex: 100, alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', width: 480, boxShadow: '0 20px 40px rgba(0,0,0,0.2)', overflow: 'hidden' }}>
            <div style={{ padding: 24, borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: 18, fontWeight: 600 }}>Create New Case</h2>
              <button className="btn-icon" onClick={() => setShowModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Case ID (Optional)</label>
                <input type="text" placeholder="e.g. c2 (leave blank for auto-generated)" style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: 14, outline: 'none', background: 'var(--bg-app)', color: 'var(--text-main)', boxSizing: 'border-box' }} />
              </div>
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

export default Sanitized;