import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import ProfileModal from '../components/ProfileModal';
import NotificationMenu from '../components/NotificationMenu';
import GeneratedReportModal from '../components/GeneratedReportModal';
import { fetchCases, fetchEmployees, fetchReport, closeCase } from '../js/api';
import { safeFormatDateOnly } from '../js/dateUtils';
import { getActiveCaseId, setActiveCase, subscribeToActiveCase } from '../js/caseEvents';

const Cases = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });
  const [loadingReportId, setLoadingReportId] = useState(null);
  const [reportModal, setReportModal] = useState({ isOpen: false, caseId: '', reportHtml: '', reportData: null });
  const [selectedCaseForDetails, setSelectedCaseForDetails] = useState(null);
  const [showCloseReasonModal, setShowCloseReasonModal] = useState(false);
  const [caseToClose, setCaseToClose] = useState(null);
  const [caseCloseReasonInput, setCaseCloseReasonInput] = useState('');
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);

  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const [activeCaseId, setActiveCaseId] = useState(getActiveCaseId());

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter]);

  useEffect(() => {
    if (currentUser && (currentUser.role === 'analyst' || currentUser.role === 'senior_analyst')) {
      navigate('/dashboard');
    }
  }, [currentUser, navigate]);

  const closeAlert = () => setCustomAlert({ ...customAlert, isOpen: false });

  const handleViewReport = async (caseItem) => {
    try {
      setLoadingReportId(caseItem.case_id);
      let html;
      try {
        html = await fetchReport(caseItem.case_id, 'html', false);
      } catch (err) {
        // Fall back to draft / unreviewed dossier if findings are pending review or case has no findings
        html = await fetchReport(caseItem.case_id, 'html', true);
      }
      const content = typeof html === 'string' ? html : JSON.stringify(html, null, 2);
      setReportModal({
        isOpen: true,
        caseId: caseItem.case_id,
        reportHtml: content,
        reportData: { case_id: caseItem.case_id }
      });
    } catch (err) {
      setCustomAlert({
        isOpen: true,
        title: 'Report Unavailable',
        message: err.message || `No forensic report available for case ${caseItem.name || caseItem.case_id}.`,
        type: 'warning'
      });
    } finally {
      setLoadingReportId(null);
    }
  };

  const fetchCasesData = async () => {
    try {
      // 1. Fetch employees map
      let employeeMap = {};
      try {
        const empData = await fetchEmployees();
        if (Array.isArray(empData)) {
          empData.forEach(emp => {
            employeeMap[String(emp.id)] = emp;
          });
        }
      } catch (e) {
        console.warn('Could not load employee names map:', e);
      }

      // 2. Fetch cases
      const caseData = await fetchCases();
      const rawCases = caseData.data || [];

      // Enrich cases with employee names
      const enriched = rawCases.map(c => ({
        ...c,
        analyst_name: c.analyst_id ? (employeeMap[String(c.analyst_id)]?.name || c.analyst_id) : null,
        senior_analyst_name: c.senior_analyst_id ? (employeeMap[String(c.senior_analyst_id)]?.name || c.senior_analyst_id) : null,
      }));

      // Sort newest first: prioritize ARGUS_ sequence number, then created_at
      const sorted = [...enriched].sort((a, b) => {
        const seqA = a.case_id?.startsWith('ARGUS_') ? parseInt(a.case_id.split('_')[1], 10) : -1;
        const seqB = b.case_id?.startsWith('ARGUS_') ? parseInt(b.case_id.split('_')[1], 10) : -1;
        if (seqA > 0 && seqB > 0 && seqA !== seqB) {
          return seqB - seqA;
        }
        if (seqA > 0 && seqB <= 0) return -1;
        if (seqB > 0 && seqA <= 0) return 1;

        const timeA = a.created_at ? new Date(a.created_at).getTime() : 0;
        const timeB = b.created_at ? new Date(b.created_at).getTime() : 0;
        return timeB - timeA;
      });
      setCases(sorted);
    } catch (err) {
      console.error(err);
      if (err.status === 401 || err.status === 403) {
        navigate('/login');
        return;
      }
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message, type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCasesData();
    const unsubscribe = subscribeToActiveCase(({ caseId }) => {
      setActiveCaseId(caseId);
    });
    return unsubscribe;
  }, []);

  const handleSetActiveCase = (caseItem) => {
    setActiveCase(caseItem.case_id, caseItem.name || '');
    if (caseItem.lock && caseItem.lock.is_locked && caseItem.lock.read_only) {
      setCustomAlert({
        isOpen: true,
        title: '🔒 Case In Use — Read-Only Mode',
        message: `Case ${caseItem.case_id} (${caseItem.name || 'Unnamed'}) is currently being investigated by analyst ${caseItem.lock.locked_by?.name || 'another user'}. You have been granted Read-Only access.`,
        type: 'warning'
      });
    } else {
      setCustomAlert({
        isOpen: true,
        title: 'Active Case Selected',
        message: `Case ${caseItem.case_id} (${caseItem.name || 'Unnamed'}) is now selected as your active case.`,
        type: 'success'
      });
    }
    fetchCasesData();
  };

  const handleCloseCase = (caseId, caseName) => {
    const targetCase = cases.find(c => c.case_id === caseId);
    if (targetCase?.lock?.is_locked && targetCase?.lock?.read_only) {
      setCustomAlert({
        isOpen: true,
        title: '🔒 Case Locked — Read-Only',
        message: `Cannot close case: Case is currently locked by analyst ${targetCase.lock.locked_by?.name || 'another user'}. You have Read-Only access.`,
        type: 'warning'
      });
      return;
    }
    setCaseToClose({ caseId, caseName });
    setCaseCloseReasonInput('');
    setShowCloseReasonModal(true);
  };

  const confirmCloseCaseWithReason = async () => {
    if (!caseToClose) return;
    if (!caseCloseReasonInput.trim()) {
      setCustomAlert({
        isOpen: true,
        title: 'Description Required',
        message: 'Please provide a reason / description for closing this case.',
        type: 'warning'
      });
      return;
    }
    const { caseId, caseName } = caseToClose;
    const reasonText = caseCloseReasonInput.trim();
    try {
      await closeCase(caseId, reasonText);
      localStorage.setItem(`argus_case_${caseId}_close_reason`, reasonText);
      setShowCloseReasonModal(false);
      setCaseToClose(null);
      setCaseCloseReasonInput('');
      if (activeCaseId === caseId) {
        setActiveCase('', '');
      }
      setCustomAlert({
        isOpen: true,
        title: 'Case Closed',
        message: `Case ${caseName || caseId} was closed successfully. Reason recorded: ${reasonText}`,
        type: 'success'
      });
      fetchCasesData();
    } catch (err) {
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message || 'Failed to close case', type: 'error' });
    }
  };

  const filteredCases = cases.filter(c => {
    const matchesSearch =
      !searchTerm.trim() ||
      (c.case_id && c.case_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (c.name && c.name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (c.analyst_name && c.analyst_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (c.senior_analyst_name && c.senior_analyst_name.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus =
      statusFilter === 'all' ||
      (statusFilter === 'open' && (c.status === 'open' || c.status === 'in_progress')) ||
      (statusFilter === 'closed' && (c.status === 'closed' || c.status === 'completed' || c.status === 'archived'));

    return matchesSearch && matchesStatus;
  });

  const totalCount = cases.length;
  const closedCount = cases.filter(c => c.status === 'closed' || c.status === 'completed' || c.status === 'archived').length;

  return (
    <div id="app-shell">
      <AlertModal {...customAlert} onClose={closeAlert} />
      {showProfileModal && <ProfileModal onClose={() => setShowProfileModal(false)} />}
      <GeneratedReportModal
        isOpen={reportModal.isOpen}
        onClose={() => setReportModal(prev => ({ ...prev, isOpen: false }))}
        caseId={reportModal.caseId}
        reportData={reportModal.reportData}
        reportHtml={reportModal.reportHtml}
      />
      
      <Sidebar />

      <main className="main-content">
        {/* TOPBAR */}
        <header className="glass-topbar-capsule topbar">
          <div className="search-container">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--glass-dash-text-muted)', marginRight: '8px' }}>
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input
              type="text"
              placeholder="Search previous cases..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
          </div>

          <div className="glass-topbar-right topbar-actions">
            <NotificationMenu />
            
            <div
              className="glass-profile-pill user-profile"
              onClick={() => setShowUserDropdown(!showUserDropdown)}
            >
              <div className="glass-profile-avatar-dark avatar">
                {currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'A'}
              </div>
              <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>
                {currentUser?.name || 'User'}
              </span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>

              {showUserDropdown && (
                <div className="user-dropdown" style={{ display: 'block' }}>
                  <div className="user-dropdown-header">
                    <div className="ud-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'User'}</div>
                    <div className="ud-role">{currentUser?.role?.replace('_', ' ') || 'Digital Forensics Investigator'}</div>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowUserDropdown(false); navigate('/profile'); }}
                    className="user-dropdown-item"
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
        <div className="dashboard-scroll">
          {/* HEADER */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h1 style={{ fontSize: '26px', fontWeight: 'bold', margin: '0 0 6px 0', color: 'var(--glass-dash-text-main)' }}>
                Previous Cases & Repository
              </h1>
              <p style={{ color: 'var(--glass-dash-text-muted)', margin: 0, fontSize: '14px' }}>
                Browse, search, and manage all active, completed, and archived investigation cases.
              </p>
            </div>
          </div>

          {/* STAT CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
            <div className="stat-card" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'var(--glass-dash-blue-soft)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--glass-dash-blue)' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
              </div>
              <div>
                <div style={{ fontSize: '26px', fontWeight: 'bold', color: 'var(--glass-dash-text-main)' }}>{loading ? '-' : totalCount}</div>
                <div style={{ fontSize: '13px', color: 'var(--glass-dash-text-muted)' }}>Total Cases</div>
              </div>
            </div>

            <div className="stat-card" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'var(--glass-dash-surface-nested)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--glass-dash-text-dim)' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '26px', fontWeight: 'bold', color: 'var(--glass-dash-text-main)' }}>{loading ? '-' : closedCount}</div>
                <div style={{ fontSize: '13px', color: 'var(--glass-dash-text-muted)' }}>Closed Cases</div>
              </div>
            </div>
          </div>

          {/* TABLE CONTAINER */}
          <div className="panel-card" style={{ overflow: 'hidden' }}>
            {/* TOOLBAR */}
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                Showing <strong style={{ color: 'var(--text-main)' }}>{filteredCases.length}</strong> cases
              </div>
            </div>

            {/* TABLE */}
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-card-alt)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    <th style={{ padding: '16px 24px' }}>Case ID</th>
                    <th style={{ padding: '16px 24px' }}>Case Name</th>
                    <th style={{ padding: '16px 24px' }}>Analyst</th>
                    <th style={{ padding: '16px 24px' }}>Senior Analyst</th>
                    <th style={{ padding: '16px 24px' }}>Created Date</th>
                    <th style={{ padding: '16px 24px' }}>Status</th>
                    <th style={{ padding: '16px 24px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr>
                      <td colSpan="7" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        Loading cases repository...
                      </td>
                    </tr>
                  ) : filteredCases.length > 0 ? (
                    filteredCases.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage).map(c => {
                      const isOpen = c.status === 'open' || c.status === 'in_progress';
                      const isActive = activeCaseId === c.case_id && isOpen;
                      const closeReason = c.close_reason || (typeof localStorage !== 'undefined' ? localStorage.getItem(`argus_case_${c.case_id}_close_reason`) : null);
                      const hasReport = Boolean(
                        c.submitted_to_auditor ||
                        c.submitted_to_senior ||
                        (typeof localStorage !== 'undefined' && (
                          localStorage.getItem(`argus_case_${c.case_id}_submitted_to_auditor`) ||
                          localStorage.getItem(`argus_case_${c.case_id}_submitted_to_senior`) ||
                          localStorage.getItem(`argus_case_${c.case_id}_report_generated`) === 'true'
                        ))
                      ) && !closeReason;
                      const displayName = (c.name && c.name !== c.case_id) 
                        ? c.name 
                        : (c.case_id?.startsWith('ARGUS_') ? `Investigation Case (${c.case_id})` : 'Legacy Case Investigation');
                      return (
                        <tr
                          key={c.case_id}
                          style={{
                            borderBottom: '1px solid var(--border-subtle)',
                            background: isActive ? 'rgba(59, 130, 246, 0.05)' : 'transparent',
                            transition: 'background 0.15s ease'
                          }}
                        >
                          <td style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-main)', fontSize: '14px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <span>{c.case_id}</span>
                              {isActive && (
                                <span style={{ background: '#3b82f6', color: '#fff', fontSize: '10px', padding: '2px 6px', borderRadius: '10px', fontWeight: 700 }}>
                                  ACTIVE
                                </span>
                              )}
                              {c.lock && c.lock.is_locked && (
                                <span
                                  style={{
                                    background: c.lock.read_only ? 'rgba(245, 158, 11, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                                    color: c.lock.read_only ? '#f59e0b' : '#3b82f6',
                                    border: `1px solid ${c.lock.read_only ? 'rgba(245, 158, 11, 0.35)' : 'rgba(59, 130, 246, 0.35)'}`,
                                    fontSize: '10px',
                                    padding: '2px 7px',
                                    borderRadius: '10px',
                                    fontWeight: 700,
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px'
                                  }}
                                  title={c.lock.read_only ? `Locked by analyst ${c.lock.locked_by?.name || 'another analyst'}. Read-only access.` : 'Locked by you'}
                                >
                                  🔒 {c.lock.read_only ? `In Use (${c.lock.locked_by?.name || 'Analyst'})` : 'Your Lock'}
                                </span>
                              )}
                            </div>
                          </td>
                          <td style={{ padding: '16px 24px', color: 'var(--text-main)', fontSize: '14px', fontWeight: 500 }}>
                            <div style={{ fontWeight: 600 }}>{displayName}</div>
                            {c.description && (
                              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={c.description}>
                                {c.description}
                              </div>
                            )}
                            {(c.status === 'closed' || c.status === 'completed') && (c.close_reason || localStorage.getItem(`argus_case_${c.case_id}_close_reason`)) && (
                              <div style={{ fontSize: '11px', color: '#f59e0b', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                <span style={{ fontWeight: 700 }}>⚠️ Closed Reason:</span> {c.close_reason || localStorage.getItem(`argus_case_${c.case_id}_close_reason`)}
                              </div>
                            )}
                          </td>
                          <td style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                            {c.analyst_name || c.analyst_id || c.created_by || '-'}
                          </td>
                          <td style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                            {c.senior_analyst_name || c.senior_analyst_id || '-'}
                          </td>
                          <td style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '13px' }}>
                            {safeFormatDateOnly(c.created_at)}
                          </td>
                          <td style={{ padding: '16px 24px' }}>
                            <span
                              style={{
                                background: isOpen ? 'rgba(16, 185, 129, 0.12)' : 'rgba(148, 163, 184, 0.12)',
                                color: isOpen ? '#10b981' : '#94a3b8',
                                border: `1px solid ${isOpen ? 'rgba(16, 185, 129, 0.3)' : 'rgba(148, 163, 184, 0.3)'}`,
                                padding: '4px 10px',
                                borderRadius: '12px',
                                fontSize: '12px',
                                fontWeight: 600,
                                textTransform: 'capitalize'
                              }}
                            >
                              {c.status || 'open'}
                            </span>
                          </td>
                          <td style={{ padding: '16px 24px', textAlign: 'right' }}>
                            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', flexWrap: 'wrap' }}>

                              {c.lock && c.lock.is_locked && c.lock.read_only && (
                                <button
                                  onClick={() => handleSetActiveCase(c)}
                                  style={{
                                    background: 'rgba(245, 158, 11, 0.1)',
                                    color: '#f59e0b',
                                    border: '1px solid rgba(245, 158, 11, 0.3)',
                                    padding: '6px 12px',
                                    borderRadius: '6px',
                                    fontSize: '12px',
                                    fontWeight: 600,
                                    cursor: 'pointer'
                                  }}
                                  title="Open in Read-Only mode"
                                >
                                  Investigate (Read-Only)
                                </button>
                              )}
                              {isOpen ? (
                                <>
                                  <button
                                    onClick={() => handleViewReport(c)}
                                    disabled={loadingReportId === c.case_id}
                                    style={{
                                      background: 'rgba(59, 130, 246, 0.1)',
                                      color: '#3b82f6',
                                      border: '1px solid rgba(59, 130, 246, 0.3)',
                                      padding: '6px 12px',
                                      borderRadius: '6px',
                                      fontSize: '12px',
                                      fontWeight: 600,
                                      cursor: loadingReportId === c.case_id ? 'wait' : 'pointer'
                                    }}
                                  >
                                    {loadingReportId === c.case_id ? 'Loading...' : 'View Report'}
                                  </button>
                                  <button
                                    onClick={() => handleCloseCase(c.case_id, c.name)}
                                    style={{
                                      background: 'rgba(239, 68, 68, 0.1)',
                                      color: '#ef4444',
                                      border: '1px solid rgba(239, 68, 68, 0.3)',
                                      padding: '6px 12px',
                                      borderRadius: '6px',
                                      fontSize: '12px',
                                      fontWeight: 600,
                                      cursor: 'pointer'
                                    }}
                                    title="Close this case"
                                  >
                                    Close
                                  </button>
                                  <button
                                    onClick={() => setSelectedCaseForDetails(c)}
                                    style={{
                                      background: 'rgba(56, 189, 248, 0.1)',
                                      color: '#0284c7',
                                      border: '1px solid rgba(56, 189, 248, 0.3)',
                                      padding: '6px 12px',
                                      borderRadius: '6px',
                                      fontSize: '12px',
                                      fontWeight: 600,
                                      cursor: 'pointer'
                                    }}
                                    title="View case description and details"
                                  >
                                    Description
                                  </button>
                                </>
                              ) : (
                                <>
                                  {/* Closed case: mutually exclusive Report vs Description */}
                                  {hasReport ? (
                                    <button
                                      onClick={() => handleViewReport(c)}
                                      disabled={loadingReportId === c.case_id}
                                      style={{
                                        background: 'rgba(59, 130, 246, 0.1)',
                                        color: '#3b82f6',
                                        border: '1px solid rgba(59, 130, 246, 0.3)',
                                        padding: '6px 12px',
                                        borderRadius: '6px',
                                        fontSize: '12px',
                                        fontWeight: 600,
                                        cursor: loadingReportId === c.case_id ? 'wait' : 'pointer'
                                      }}
                                    >
                                      {loadingReportId === c.case_id ? 'Loading...' : 'View Report'}
                                    </button>
                                  ) : (
                                    <button
                                      onClick={() => setSelectedCaseForDetails(c)}
                                      style={{
                                        background: 'rgba(56, 189, 248, 0.1)',
                                        color: '#0284c7',
                                        border: '1px solid rgba(56, 189, 248, 0.3)',
                                        padding: '6px 12px',
                                        borderRadius: '6px',
                                        fontSize: '12px',
                                        fontWeight: 600,
                                        cursor: 'pointer'
                                      }}
                                      title="View case description and closure reason"
                                    >
                                      Description
                                    </button>
                                  )}
                                </>
                              )}
                              <button
                                onClick={() => {
                                  setActiveCase(c.case_id, c.name || '');
                                  navigate(`/audit-logs?case_id=${encodeURIComponent(c.case_id)}`);
                                }}
                                style={{
                                  background: 'var(--bg-app)',
                                  color: 'var(--text-main)',
                                  border: '1px solid var(--border-subtle)',
                                  padding: '6px 12px',
                                  borderRadius: '6px',
                                  fontSize: '12px',
                                  fontWeight: 500,
                                  cursor: 'pointer'
                                }}
                              >
                                Audit Log
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan="7" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px' }}>
                        No cases match your search or filter criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* PAGINATION FOOTER */}
            {filteredCases.length > itemsPerPage && (
              <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '13px', color: 'var(--text-muted)' }}>
                <span>
                  Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, filteredCases.length)} of {filteredCases.length} cases
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                    disabled={currentPage === 1}
                    style={{
                      background: 'var(--bg-app)',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-main)',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                      opacity: currentPage === 1 ? 0.5 : 1
                    }}
                  >
                    Previous
                  </button>
                  <span style={{ display: 'flex', alignItems: 'center', fontWeight: 600, color: 'var(--text-main)', padding: '0 4px' }}>
                    Page {currentPage} of {Math.ceil(filteredCases.length / itemsPerPage)}
                  </span>
                  <button
                    onClick={() => setCurrentPage(prev => Math.min(Math.ceil(filteredCases.length / itemsPerPage), prev + 1))}
                    disabled={currentPage >= Math.ceil(filteredCases.length / itemsPerPage)}
                    style={{
                      background: 'var(--bg-app)',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-main)',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: currentPage >= Math.ceil(filteredCases.length / itemsPerPage) ? 'not-allowed' : 'pointer',
                      opacity: currentPage >= Math.ceil(filteredCases.length / itemsPerPage) ? 0.5 : 1
                    }}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
      {/* Modal: View Case Description & Closure Reason */}
      {selectedCaseForDetails && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1002, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={(e) => { if (e.target === e.currentTarget) setSelectedCaseForDetails(null); }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '520px', borderRadius: '22px', padding: '28px', background: 'var(--bg-card, #ffffff)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '20px' }}>📋</span>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-main, #0f172a)' }}>Case Overview & Description</h2>
              </div>
              <button onClick={() => setSelectedCaseForDetails(null)} className="icon-btn" style={{ width: '32px', height: '32px', cursor: 'pointer', background: 'none', border: 'none', fontSize: '18px' }}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '13px' }}>
              <div style={{ background: 'var(--bg-subtle, #f8fafc)', padding: '14px', borderRadius: '12px', border: '1px solid var(--border-subtle, #e2e8f0)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Case Identifier & Name</div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-main)', marginTop: '2px' }}>
                  {selectedCaseForDetails.name || 'Unnamed Case'} <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 400 }}>({selectedCaseForDetails.case_id})</span>
                </div>
              </div>

              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>Initial Case Description</div>
                <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'var(--bg-subtle, #f8fafc)', border: '1px solid var(--border-subtle, #e2e8f0)', color: 'var(--text-main)', lineHeight: '1.5' }}>
                  {selectedCaseForDetails.description || 'No initial description provided when creating the case.'}
                </div>
              </div>

              {(selectedCaseForDetails.status === 'closed' || selectedCaseForDetails.status === 'completed') && (
                <div style={{ background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '12px', padding: '16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f59e0b', fontWeight: 800, fontSize: '13px', marginBottom: '8px' }}>
                    <span>⚠️</span>
                    <span>Reason for Closing Case</span>
                  </div>
                  <div style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text-main)', fontWeight: 500 }}>
                    {selectedCaseForDetails.close_reason || localStorage.getItem(`argus_case_${selectedCaseForDetails.case_id}_close_reason`) || 'No specific closure reason recorded.'}
                  </div>
                  {selectedCaseForDetails.closed_at && (
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px' }}>
                      Closed at: {selectedCaseForDetails.closed_at}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '24px' }}>
              <button onClick={() => setSelectedCaseForDetails(null)} className="btn-primary" style={{ padding: '8px 20px', borderRadius: '10px' }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Ask for description when closing a case from Cases table */}
      {showCloseReasonModal && caseToClose && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1002, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={(e) => { if (e.target === e.currentTarget) setShowCloseReasonModal(false); }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '480px', borderRadius: '22px', padding: '28px', background: 'var(--bg-card, #ffffff)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '12px', background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px' }}>
                ⚠️
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-main, #0f172a)' }}>Close Case: Reason Required</h2>
                <div style={{ fontSize: '12px', color: '#f59e0b', fontWeight: 700 }}>Record Administrative Closure Reason</div>
              </div>
            </div>

            <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text-secondary, #475569)', marginBottom: '16px' }}>
              Please provide a description / reason for closing case <strong>{caseToClose.caseName || caseToClose.caseId}</strong>. This description will be saved and displayed in Case Overview.
            </p>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-main, #0f172a)' }}>
                Closure Reason / Description <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <textarea
                rows={3}
                value={caseCloseReasonInput}
                onChange={(e) => setCaseCloseReasonInput(e.target.value)}
                placeholder="e.g. Investigation completed externally, test case, false positive, or closed by administrator..."
                style={{
                  width: '100%',
                  padding: '12px 14px',
                  borderRadius: '12px',
                  border: '1px solid var(--border-light, #cbd5e1)',
                  background: 'var(--bg-subtle, #f8fafc)',
                  color: 'var(--text-main, #0f172a)',
                  fontSize: '13px',
                  lineHeight: '1.5',
                  boxSizing: 'border-box',
                  resize: 'vertical'
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setShowCloseReasonModal(false)}
                className="btn-outline"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmCloseCaseWithReason}
                className="btn-primary"
                style={{ background: '#ef4444', borderColor: '#ef4444' }}
              >
                Confirm Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Cases;
