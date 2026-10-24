import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import SearchableSelect from '../components/SearchableSelect';
import '../css/style.css';
import AlertModal from '../components/AlertModal';
import { safeFormatDateOnly, safeFormatDateTime, safeFormatTime } from '../js/dateUtils';

const AdminDashboard = () => {
  const navigate = useNavigate();
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };

  const [totalEmployees, setTotalEmployees] = useState(0);
  const [employees, setEmployees] = useState([]);
  const [casesSolved, setCasesSolved] = useState(0);
  const [currentCase, setCurrentCase] = useState(null);
  const [recentActivity, setRecentActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hasOpenCase, setHasOpenCase] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [allCasesList, setAllCasesList] = useState([]);
  const [caseSearchTerm, setCaseSearchTerm] = useState('');
  const [caseStatusFilter, setCaseStatusFilter] = useState('all');

  const handleSetActiveCase = (caseItem) => {
    localStorage.setItem('active_case_id', caseItem.case_id);
    if (caseItem.name) localStorage.setItem('active_case_name', caseItem.name);
    setCurrentCase(caseItem);
    setCustomAlert({
      isOpen: true,
      title: 'Active Case Switched',
      message: `Case ${caseItem.case_id} (${caseItem.name || 'Unnamed'}) is now selected as the active case.`,
      type: 'success'
    });
  };

  const filteredCases = allCasesList.filter(c => {
    const matchesSearch = 
      !caseSearchTerm.trim() ||
      (c.case_id && c.case_id.toLowerCase().includes(caseSearchTerm.toLowerCase())) ||
      (c.name && c.name.toLowerCase().includes(caseSearchTerm.toLowerCase())) ||
      (c.analyst_name && c.analyst_name.toLowerCase().includes(caseSearchTerm.toLowerCase())) ||
      (c.senior_analyst_name && c.senior_analyst_name.toLowerCase().includes(caseSearchTerm.toLowerCase()));

    const matchesStatus = 
      caseStatusFilter === 'all' ||
      (caseStatusFilter === 'open' && (c.status === 'open' || c.status === 'in_progress')) ||
      (caseStatusFilter === 'closed' && (c.status === 'closed' || c.status === 'completed' || c.status === 'archived'));

    return matchesSearch && matchesStatus;
  });

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseAnalyst, setNewCaseAnalyst] = useState('');
  const [newCaseSeniorAnalyst, setNewCaseSeniorAnalyst] = useState('');
  const [creating, setCreating] = useState(false);
  const [showAssignSeniorModal, setShowAssignSeniorModal] = useState(false);
  const [assigningSenior, setAssigningSenior] = useState('');
  const [assigningLoading, setAssigningLoading] = useState(false);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;
    if (!newCaseAnalyst) {
      setCustomAlert({ isOpen: true, title: 'Validation Error', message: 'Please assign an Analyst to the case.', type: 'warning' });
      return;
    }

    setCreating(true);
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/cases/`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': DEFAULT_TENANT_ID
        },
        body: JSON.stringify({ 
          name: newCaseName, 
          analyst: 'Admin', 
          analyst_id: newCaseAnalyst || null,
          senior_analyst_id: newCaseSeniorAnalyst || null,
        }),
      });
      if (!res.ok) {
        let errMsg = 'Failed to create case';
        try {
          const errJson = await res.json();
          errMsg = errJson.detail || errMsg;
        } catch {
          errMsg = await res.text() || errMsg;
        }
        throw new Error(errMsg);
      }
      const data = await res.json();
      const createdId = data.case_id || data.id;
      localStorage.setItem('active_case_id', createdId);
      localStorage.setItem('active_case_name', newCaseName);
      
      setShowCreateModal(false);
      setNewCaseName('');
      setNewCaseAnalyst('');
      setRefreshTrigger(prev => prev + 1);
      setCustomAlert({
        isOpen: true,
        title: 'Success',
        message: 'Case created and analyst assigned. You can assign a Senior Analyst later from the dashboard.',
        type: 'success',
        onClose: null
      });
    } catch (err) {
      console.error(err);
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message || 'Failed to create case', type: 'error' });
    } finally {
      setCreating(false);
    }
  };

  const handleAssignSenior = async () => {
    if (!assigningSenior || !currentCase) return;
    setAssigningLoading(true);
    try {
      const token = localStorage.getItem('argus_token');
      // Update via PATCH — send senior_analyst_id
      const res = await fetch(`${API_BASE_URL}/cases/${currentCase.case_id}/assign-senior`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, 'X-Tenant-ID': DEFAULT_TENANT_ID },
        body: JSON.stringify({ senior_analyst_id: assigningSenior })
      });
      if (!res.ok) throw new Error(await res.text());
      setShowAssignSeniorModal(false);
      setAssigningSenior('');
      setRefreshTrigger(prev => prev + 1);
      setCustomAlert({ isOpen: true, title: 'Success', message: 'Senior Analyst assigned successfully.', type: 'success' });
    } catch (err) {
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message, type: 'warning' });
    } finally {
      setAssigningLoading(false);
    }
  };

  const handleCloseCase = async () => {
    if (!currentCase) return;
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/cases/${currentCase.case_id}/close`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': DEFAULT_TENANT_ID
        }
      });
      if (res.ok) {
        const closedId = currentCase.case_id;
        const closedName = currentCase.name || closedId;
        localStorage.removeItem('active_case_id');
        localStorage.removeItem('active_case_name');
        localStorage.removeItem('active_case_desc');
        setCurrentCase(null);
        setHasOpenCase(false);
        setRefreshTrigger(prev => prev + 1);
        setCustomAlert({
          isOpen: true,
          title: 'Success',
          message: `Case ${closedId} (${closedName}) closed successfully.`,
          type: 'success',
          onClose: null
        });
      } else {
        let errMsg = 'Failed to close case.';
        try {
          const errData = await res.json();
          errMsg = errData.detail || errMsg;
        } catch (_) {}
        setCustomAlert({
          isOpen: true,
          title: 'Error',
          message: errMsg,
          type: 'error'
        });
      }
    } catch (e) {
      console.error(e);
      setCustomAlert({
        isOpen: true,
        title: 'Error',
        message: 'An error occurred.',
        type: 'error'
      });
    }
  };

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const token = localStorage.getItem('argus_token');
        const headers = {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': DEFAULT_TENANT_ID
        };

        // Fetch Employees first, build a lookup map by id
        let employeeMap = {};
        const empRes = await fetch(`${API_BASE_URL}/auth/employees`, { headers });
        if (empRes.ok) {
          const empData = await empRes.json();
          setTotalEmployees(empData.length || 0);
          setEmployees(empData || []);
          // Build a fast id -> employee lookup (handle both string and int ids)
          empData.forEach(emp => {
            employeeMap[String(emp.id)] = emp;
          });
        }

        // Fetch Cases
        const caseRes = await fetch(`${API_BASE_URL}/cases/`, { headers });
        if (caseRes.ok) {
          const caseData = await caseRes.json();
          const cases = caseData.data || [];
          setCasesSolved(cases.length || 0);
          
          if (cases.length > 0) {
            // Enrich each case with resolved analyst and senior analyst names
            const enriched = cases.map(c => ({
              ...c,
              analyst_name: c.analyst_id ? (employeeMap[String(c.analyst_id)]?.name || c.analyst_id) : null,
              senior_analyst_name: c.senior_analyst_id ? (employeeMap[String(c.senior_analyst_id)]?.name || c.senior_analyst_id) : null,
            }));

            // Sort newest first (reverse for created_at ascending)
            const sorted = enriched.reverse();
            setAllCasesList(sorted);
            
            // Only keep active case if explicitly selected in localStorage and still open
            const activeId = localStorage.getItem('active_case_id');
            const active = activeId ? sorted.find(c => c.case_id === activeId && (c.status === 'open' || c.status === 'in_progress')) : null;
            if (!active && activeId) {
              localStorage.removeItem('active_case_id');
              localStorage.removeItem('active_case_name');
              localStorage.removeItem('active_case_desc');
            }
            setCurrentCase(active || null);
            setHasOpenCase(!!active);
          } else {
            setAllCasesList([]);
            setCurrentCase(null);
            setHasOpenCase(false);
          }
        }
        
        // Fetch Recent Activity (Cases & Evidence Uploads)
        const actRes = await fetch(`${API_BASE_URL}/cases/activity`, { headers });
        if (actRes.ok) {
          const actData = await actRes.json();
          setRecentActivity(actData.data || []);
        }
      } catch (e) {
        console.error('Error fetching admin dashboard data:', e);
      } finally {
        setLoading(false);
      }
    };
    
    fetchDashboardData();
    
    const handleInterval = () => {
      if (document.visibilityState === 'visible') {
        fetchDashboardData();
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        fetchDashboardData();
      }
    };

    const intervalId = setInterval(handleInterval, 10000);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [refreshTrigger]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      <AlertModal 
        isOpen={customAlert.isOpen} 
        title={customAlert.title} 
        message={customAlert.message} 
        type={customAlert.type} 
        onClose={closeAlert} 
      />
      
      {/* HEADER */}
      <div className="glass-stage-header">
        <div>
          <h1 className="glass-stage-title">Dashboard</h1>
          <p className="glass-stage-desc">Overview of your organization and current case.</p>
        </div>
        <div className="glass-stage-actions">
          <div className="glass-datetime-badge">
            <span>{new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })}</span>
            <span>&middot;</span>
            <span>{new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: 'numeric' })}</span>
          </div>
          <button
            onClick={() => {
              if (currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress')) {
                setCustomAlert({
                  isOpen: true,
                  title: 'Notice',
                  message: `Active case "${currentCase.name || currentCase.case_id}" is currently open. Please close it before creating a new case.`,
                  type: 'warning'
                });
              } else {
                setShowCreateModal(true);
              }
            }}
            className="btn-glass-primary"
            style={{ cursor: (currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress')) ? 'not-allowed' : 'pointer', opacity: (currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress')) ? 0.6 : 1 }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Create Case
          </button>
        </div>
      </div>

      {/* STATS ROW */}
      <div className="glass-stats-grid">
        {/* Total Employees */}
        <div className="glass-stat-card">
          <div className="glass-stat-icon-wrap blue">
            <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
          </div>
          <div className="glass-stat-body">
            <div className="glass-stat-number">{loading ? '-' : totalEmployees}</div>
            <div className="glass-stat-title">Total Employees</div>
            <div className="glass-stat-subtitle">Active team members</div>
          </div>
        </div>

        {/* Cases Solved */}
        <div className="glass-stat-card">
          <div className="glass-stat-icon-wrap green">
            <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          </div>
          <div className="glass-stat-body">
            <div className="glass-stat-number">{loading ? '-' : casesSolved}</div>
            <div className="glass-stat-title">Cases Solved</div>
            <div className="glass-stat-subtitle">Completed successfully</div>
          </div>
        </div>
      </div>

      {/* ROW 2: Current Case & Recent Activity */}
      <div className="glass-split-cards-grid">
        
        {/* Current Case Dossier Card */}
        <div className="glass-dossier-card">
          <div className="glass-card-header-row">
            <div className="glass-case-brand-group">
              <div className="glass-case-icon-box">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
              </div>
              <div>
                <h2 className="glass-case-id-text">{currentCase ? currentCase.case_id : 'No Active Case'}</h2>
                <p className="glass-case-desc-text">{currentCase ? currentCase.name : 'Create a case to get started'}</p>
              </div>
            </div>
            
            <div className="glass-header-badge-group">
              <span className="glass-status-pill review">
                &bull; {currentCase ? (currentCase.status === 'open' || currentCase.status === 'in_progress' ? 'Under Review' : 'Closed') : 'No Active Cases'}
              </span>
              {currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress') && (
                <button 
                  onClick={handleCloseCase}
                  className="btn-glass-outline-danger"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"></path></svg>
                  Close
                </button>
              )}
            </div>
          </div>

          {/* Progress Timeline Pipeline */}
          <div className="glass-pipeline-container">
            <div className="glass-pipeline-track" />
            <div 
              className="glass-pipeline-progress" 
              style={{ width: currentCase?.status === 'closed' ? '100%' : '33%' }} 
            />
            
            <div className="glass-pipeline-nodes">
              <div className="glass-pipeline-node">
                <span className="glass-pipeline-dot active" />
                <span className="glass-pipeline-label">Investigation</span>
                <span className="glass-pipeline-role">(Analyst)</span>
              </div>
              <div className="glass-pipeline-node">
                <span className={`glass-pipeline-dot ${currentCase?.status !== 'closed' ? 'active' : 'pending'}`} />
                <span className="glass-pipeline-label">Review</span>
                <span className="glass-pipeline-role">(Senior Analyst)</span>
              </div>
              <div className="glass-pipeline-node">
                <span className="glass-pipeline-dot pending" />
                <span className="glass-pipeline-label">Audit</span>
                <span className="glass-pipeline-role">(Not Assigned)</span>
              </div>
              <div className="glass-pipeline-node">
                <span className={`glass-pipeline-dot ${currentCase?.status === 'closed' ? 'active' : 'pending'}`} />
                <span className="glass-pipeline-label">Closed</span>
              </div>
            </div>
          </div>

          {/* Personnel Tray */}
          <div className="glass-personnel-tray">
            <div className="glass-staff-column">
              <div className="glass-staff-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
              </div>
              <div className="glass-staff-meta">
                <span className="glass-staff-role-tag">Analyst</span>
                <span className="glass-staff-name-val">
                  {currentCase ? (currentCase.analyst_name || currentCase.analyst_id || currentCase.created_by || '-') : '-'}
                </span>
              </div>
            </div>
            
            <div className="glass-staff-column">
              <div className="glass-staff-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="8.5" cy="7" r="4" /><polyline points="17 11 19 13 23 9" /></svg>
              </div>
              <div className="glass-staff-meta">
                <span className="glass-staff-role-tag">Senior Analyst</span>
                {currentCase && !currentCase.senior_analyst_id ? (
                  <button
                    onClick={() => setShowAssignSeniorModal(true)}
                    className="btn-glass-primary"
                    style={{ padding: '4px 10px', fontSize: '11px', width: 'fit-content' }}
                  >
                    + Assign
                  </button>
                ) : (
                  <span className="glass-staff-name-val">
                    {currentCase ? (currentCase.senior_analyst_name || currentCase.senior_analyst_id) : '-'}
                  </span>
                )}
              </div>
            </div>

            <div className="glass-staff-column">
              <div className="glass-staff-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <div className="glass-staff-meta">
                <span className="glass-staff-role-tag">Auditor</span>
                <span className={`glass-staff-name-val ${currentCase && (currentCase.auditor_name || currentCase.auditor_id) ? '' : 'dim'}`}>
                  {currentCase ? (currentCase.auditor_name || currentCase.auditor_id || 'Not Assigned') : '-'}
                </span>
              </div>
            </div>
          </div>

          {/* Dates Footer Strip */}
          <div className="glass-dossier-footer">
            <div className="glass-date-metric">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <div>
                <div className="glass-date-label">Created On</div>
                <div className="glass-date-val">{safeFormatDateOnly(currentCase?.created_at)}</div>
              </div>
            </div>
            <div className="glass-date-metric">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              <div>
                <div className="glass-date-label">Last Updated</div>
                <div className="glass-date-val">{safeFormatDateTime(currentCase?.created_at)}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Activity Card */}
        <div className="glass-activity-card">
          <div className="glass-activity-header">
            <h2 className="glass-activity-title">Recent Activity</h2>
            <span 
              onClick={() => navigate(currentCase ? `/audit-logs?case_id=${currentCase.case_id}` : '/audit-logs')} 
              className="glass-view-all-link"
            >
              View All &rsaquo;
            </span>
          </div>

          <table className="glass-activity-table">
            <thead>
              <tr>
                <th style={{ width: '130px', whiteSpace: 'nowrap' }}>Date &amp; Time</th>
                <th style={{ width: '170px' }}>User</th>
                <th style={{ width: '120px' }}>Action</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {recentActivity.length > 0 ? recentActivity.slice(0, 5).map((activity, idx) => (
                <tr key={idx} className="glass-activity-row">
                  <td className="glass-cell-timestamp" style={{ whiteSpace: 'nowrap' }}>
                    {safeFormatDateOnly(activity.created_at)}<br/>
                    {safeFormatTime(activity.created_at, '')}
                  </td>
                  <td>
                    <div className="glass-user-cell">
                      <div className={`glass-user-bubble ${activity.created_by === 'admin' ? 'admin' : 'analyst'}`}>
                        {activity.created_by ? activity.created_by.charAt(0).toUpperCase() : 'U'}
                      </div>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--glass-dash-text-main)', textTransform: 'capitalize' }}>
                        {activity.created_by || 'Unknown'}
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className={`glass-action-badge ${activity.action === 'Created Case' ? 'created' : 'closed'}`}>
                      {activity.action || 'Unknown Action'}
                    </span>
                  </td>
                  <td>
                    <div className="glass-details-text" title={activity.details}>
                      {activity.details || '-'}
                    </div>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="4" style={{ padding: '24px 0', fontSize: '13px', color: 'var(--glass-dash-text-muted)', textAlign: 'center' }}>
                    No recent activity
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Admin Create Case Modal */}
      {showCreateModal && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '420px', borderRadius: '22px', overflow: 'visible' }}>
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--glass-dash-border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
               <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--glass-dash-text-main)' }}>Create New Case</h2>
              <button onClick={() => setShowCreateModal(false)} className="icon-btn" style={{ width: '32px', height: '32px' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleCreateCase} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--glass-dash-text-main)' }}>Case Name</label>
                <input type="text" value={newCaseName} onChange={e => setNewCaseName(e.target.value)} style={{ width: '100%' }} placeholder="e.g., Operation Dark Web" required />
              </div>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--glass-dash-text-main)' }}>Assign Analyst <span style={{ color: 'var(--glass-dash-red, #ef4444)' }}>*</span></label>
                <SearchableSelect 
                  value={newCaseAnalyst} 
                  onChange={setNewCaseAnalyst} 
                  placeholder="Select Analyst"
                  options={employees.filter(e => e.role === 'analyst' || e.role === 'forensic_analyst').map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }))}
                />
              </div>

              <div style={{ marginBottom: '28px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--glass-dash-text-main)' }}>Assign Senior Analyst</label>
                <SearchableSelect 
                  value={newCaseSeniorAnalyst} 
                  onChange={setNewCaseSeniorAnalyst} 
                  placeholder="Select Senior Analyst"
                  options={employees.filter(e => e.role === 'senior_analyst' || e.role === 'senior').map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }))}
                />
              </div>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid var(--glass-dash-border-subtle)' }}>
                <button type="button" onClick={() => setShowCreateModal(false)} className="btn-outline">Cancel</button>
                <button type="submit" disabled={!newCaseName || !newCaseAnalyst} className="btn-primary" style={{ cursor: (!newCaseName || !newCaseAnalyst) ? 'not-allowed' : 'pointer', opacity: (!newCaseName || !newCaseAnalyst) ? 0.6 : 1 }}>Create Case</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assign Senior Analyst Modal */}
      {showAssignSeniorModal && currentCase && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1001, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '380px', borderRadius: '22px', overflow: 'visible', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--glass-dash-text-main)' }}>Assign Senior Analyst</h2>
              <button onClick={() => setShowAssignSeniorModal(false)} className="icon-btn" style={{ width: '32px', height: '32px' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--glass-dash-text-muted)', marginBottom: '16px' }}>Assigning to case <strong style={{ color: 'var(--glass-dash-text-main)' }}>{currentCase.case_id}</strong></div>
            <SearchableSelect
              value={assigningSenior}
              onChange={setAssigningSenior}
              placeholder="Select Senior Analyst"
              options={employees.filter(e => e.role === 'senior_analyst' || e.role === 'senior').map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }))}
            />
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '24px' }}>
              <button onClick={() => setShowAssignSeniorModal(false)} className="btn-outline">Cancel</button>
              <button onClick={handleAssignSenior} disabled={!assigningSenior || assigningLoading} className="btn-primary" style={{ opacity: (!assigningSenior || assigningLoading) ? 0.6 : 1 }}>
                {assigningLoading ? 'Assigning...' : 'Assign'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
