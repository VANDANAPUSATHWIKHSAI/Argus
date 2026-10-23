import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import ProfileModal from '../components/ProfileModal';
import NotificationMenu from '../components/NotificationMenu';
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
      // Fetch report adhering to backend review gating (allowUnreviewed = false)
      const html = await fetchReport(caseItem.case_id, 'html', false);
      const content = typeof html === 'string' ? html : JSON.stringify(html, null, 2);
      const blob = new Blob([content], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
    } catch (err) {
      setCustomAlert({
        isOpen: true,
        title: 'Report Unavailable',
        message: err.message || `No finalized forensic report available for case ${caseItem.name || caseItem.case_id}. Review findings must be completed before report finalization.`,
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

      // Sort newest first
      setCases([...enriched].reverse());
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
    setCustomAlert({
      isOpen: true,
      title: 'Active Case Selected',
      message: `Case ${caseItem.case_id} (${caseItem.name || 'Unnamed'}) is now selected as your active case.`,
      type: 'success'
    });
    fetchCasesData();
  };

  const handleCloseCase = async (caseId, caseName) => {
    try {
      await closeCase(caseId);
      if (activeCaseId === caseId) {
        setActiveCase('', '');
      }
      setCustomAlert({
        isOpen: true,
        title: 'Success',
        message: `Case ${caseName || caseId} was closed successfully.`,
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
  const openCount = cases.filter(c => c.status === 'open' || c.status === 'in_progress').length;
  const closedCount = cases.filter(c => c.status === 'closed' || c.status === 'completed' || c.status === 'archived').length;

  return (
    <div id="app-shell">
      <AlertModal {...customAlert} onClose={closeAlert} />
      {showProfileModal && <ProfileModal onClose={() => setShowProfileModal(false)} />}
      
      <Sidebar />

      <main className="main-content">
        {/* TOPBAR */}
        <header className="topbar">
          <div className="search-container">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: '8px' }}>
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

          <div className="topbar-actions" style={{ position: 'relative' }}>
            <NotificationMenu />
            
            <div
              className="user-profile"
              onClick={() => setShowUserDropdown(!showUserDropdown)}
              style={{ cursor: 'pointer', position: 'relative' }}
            >
              <div className="avatar">
                {currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'A'}
              </div>
              <span style={{ fontWeight: 500, textTransform: 'capitalize' }}>
                {currentUser?.name || 'User'}
              </span>

              {showUserDropdown && (
                <div
                  style={{
                    position: 'absolute',
                    top: '120%',
                    right: 0,
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '8px',
                    boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
                    padding: '8px 0',
                    zIndex: 100,
                    minWidth: '160px'
                  }}
                >
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowUserDropdown(false); setShowProfileModal(true); }}
                    style={{ width: '100%', padding: '8px 16px', background: 'transparent', border: 'none', color: 'var(--text-main)', textAlign: 'left', cursor: 'pointer', fontSize: '13px' }}
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
          {/* HEADER */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h1 style={{ fontSize: '26px', fontWeight: 'bold', margin: '0 0 6px 0', color: 'var(--text-main)' }}>
                Previous Cases & Repository
              </h1>
              <p style={{ color: 'var(--text-muted)', margin: 0, fontSize: '14px' }}>
                Browse, search, and manage all active, completed, and archived investigation cases.
              </p>
            </div>
          </div>

          {/* STAT CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px' }}>
            <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
              </div>
              <div>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--text-main)' }}>{loading ? '-' : totalCount}</div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Total Cases</div>
              </div>
            </div>

            <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--text-main)' }}>{loading ? '-' : openCount}</div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Open Cases</div>
              </div>
            </div>

            <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '20px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: 'rgba(148, 163, 184, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--text-main)' }}>{loading ? '-' : closedCount}</div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Closed Cases</div>
              </div>
            </div>
          </div>

          {/* TABLE CONTAINER */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
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
                      const isActive = activeCaseId === c.case_id;
                      const isOpen = c.status === 'open' || c.status === 'in_progress';
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
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span>{c.case_id}</span>
                              {isActive && (
                                <span style={{ background: '#3b82f6', color: '#fff', fontSize: '10px', padding: '2px 6px', borderRadius: '10px', fontWeight: 700 }}>
                                  ACTIVE
                                </span>
                              )}
                            </div>
                          </td>
                          <td style={{ padding: '16px 24px', color: 'var(--text-main)', fontSize: '14px', fontWeight: 500 }}>
                            {c.name || 'Unnamed Case'}
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
                            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
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
                                onClick={() => navigate(`/audit-logs?case_id=${c.case_id}`)}
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
    </div>
  );
};

export default Cases;
