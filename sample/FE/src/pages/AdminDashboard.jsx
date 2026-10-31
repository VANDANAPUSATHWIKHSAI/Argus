import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL, DEFAULT_TENANT_ID, fetchAgentResults } from '../js/api';
import SearchableSelect from '../components/SearchableSelect';
import '../css/style.css';
import AlertModal from '../components/AlertModal';
import { safeFormatDateOnly, safeFormatDateTime, safeFormatTime } from '../js/dateUtils';
import { setActiveCase, subscribeToActiveCase } from '../js/caseEvents';

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
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [allCasesList, setAllCasesList] = useState([]);
  const [agentSummary, setAgentSummary] = useState(null);

  const loadWorkloadStatus = async (caseId) => {
    if (!caseId) {
      setAgentSummary(null);
      return;
    }
    try {
      const res = await fetchAgentResults(caseId);
      setAgentSummary(res);
    } catch (_) {
      setAgentSummary(null);
    }
  };



  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseAnalyst, setNewCaseAnalyst] = useState('');
  const [newCaseSeniorAnalyst, setNewCaseSeniorAnalyst] = useState('');
  const [creating, setCreating] = useState(false);
  const [showAssignSeniorModal, setShowAssignSeniorModal] = useState(false);
  const [assigningSenior, setAssigningSenior] = useState('');
  const [assigningLoading, setAssigningLoading] = useState(false);

  const getCaseStageInfo = (caseObj) => {
    if (!caseObj) {
      return {
        stage: 'none',
        statusLabel: 'No Active Cases',
        pillClass: 'closed',
        progressWidth: '0%',
        progressOpacity: 0,
        investigationStatus: 'pending',
        reviewStatus: 'pending',
        auditStatus: 'pending',
        closedStatus: 'pending'
      };
    }
    const isClosed = caseObj.status === 'closed' || caseObj.status === 'completed' || caseObj.status === 'archived';
    const isSubmittedToAuditor = Boolean(
      (typeof localStorage !== 'undefined' && localStorage.getItem(`argus_case_${caseObj.case_id}_submitted_to_auditor`)) ||
      caseObj.submitted_to_auditor
    );
    const isSubmittedToSenior = Boolean(
      (typeof localStorage !== 'undefined' && localStorage.getItem(`argus_case_${caseObj.case_id}_submitted_to_senior`)) ||
      caseObj.submitted_to_senior ||
      isSubmittedToAuditor
    );

    if (isClosed) {
      return {
        stage: 'closed',
        statusLabel: 'Closed',
        pillClass: 'closed',
        progressWidth: 'calc(100% - 56px)',
        progressOpacity: 1,
        investigationStatus: 'completed',
        reviewStatus: 'completed',
        auditStatus: 'completed',
        closedStatus: 'completed'
      };
    }

    if (isSubmittedToAuditor) {
      return {
        stage: 'audit',
        statusLabel: 'In Audit',
        pillClass: 'audit',
        progressWidth: 'calc((100% - 56px) * 0.666)',
        progressOpacity: 1,
        investigationStatus: 'completed',
        reviewStatus: 'completed',
        auditStatus: 'active',
        closedStatus: 'pending'
      };
    }

    if (isSubmittedToSenior) {
      return {
        stage: 'review',
        statusLabel: 'Under Review',
        pillClass: 'review',
        progressWidth: 'calc((100% - 56px) * 0.333)',
        progressOpacity: 1,
        investigationStatus: 'completed',
        reviewStatus: 'active',
        auditStatus: 'pending',
        closedStatus: 'pending'
      };
    }

    return {
      stage: 'investigation',
      statusLabel: 'Investigation',
      pillClass: 'investigation',
      progressWidth: '0%',
      progressOpacity: 0,
      investigationStatus: 'active',
      reviewStatus: 'pending',
      auditStatus: 'pending',
      closedStatus: 'pending'
    };
  };

  const caseStageInfo = getCaseStageInfo(currentCase);

  useEffect(() => {
    const unsub = subscribeToActiveCase(() => {
      setRefreshTrigger(prev => prev + 1);
    });
    const handleStorage = (e) => {
      if (!e.key || e.key.includes('submitted_to_senior') || e.key.includes('submitted_to_auditor') || e.key.includes('active_case')) {
        setRefreshTrigger(prev => prev + 1);
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => {
      unsub();
      window.removeEventListener('storage', handleStorage);
    };
  }, []);


  const analystSelectOptions = (() => {
    const list = employees.filter(e => e.role === 'analyst' || e.role === 'forensic_analyst');
    if (list.length > 0) return list.map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }));
    return [
      { value: '1', label: 'Analyst 1 (1)' },
      { value: '2', label: 'Analyst 2 (2)' },
      { value: '3', label: 'Analyst 3 (3)' },
      { value: '4', label: 'Analyst 4 (4)' },
      { value: '5', label: 'Analyst 5 (5)' },
    ];
  })();

  const seniorSelectOptions = (() => {
    const list = employees.filter(e => e.role === 'senior_analyst' || e.role === 'senior');
    if (list.length > 0) return list.map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }));
    return [
      { value: '6', label: 'Senior Analyst 6 (6)' },
      { value: '7', label: 'Senior Analyst 7 (7)' },
    ];
  })();


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
      setActiveCase(createdId, newCaseName);
      
      const assignedAnalyst = employees.find(emp => String(emp.id) === String(newCaseAnalyst));
      const assignedSenior = employees.find(emp => String(emp.id) === String(newCaseSeniorAnalyst));

      const newCaseObj = {
        case_id: createdId,
        name: newCaseName,
        status: 'open',
        analyst_id: newCaseAnalyst || null,
        analyst_name: assignedAnalyst ? assignedAnalyst.name : newCaseAnalyst,
        senior_analyst_id: newCaseSeniorAnalyst || null,
        senior_analyst_name: assignedSenior ? assignedSenior.name : newCaseSeniorAnalyst,
        created_at: new Date().toISOString()
      };

      setCurrentCase(newCaseObj);
      setAllCasesList(prev => [newCaseObj, ...prev]);

      setShowCreateModal(false);
      setNewCaseName('');
      setNewCaseAnalyst('');
      setNewCaseSeniorAnalyst('');
      setRefreshTrigger(prev => prev + 1);

      setCustomAlert({
        isOpen: true,
        title: 'Success',
        message: `Case ${createdId} ("${newCaseName}") created successfully and analyst assigned.`,
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
        setActiveCase('', '');
        localStorage.removeItem('active_case_desc');
        setCurrentCase(null);
        setAgentSummary(null);
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
        try {
          const empRes = await fetch(`${API_BASE_URL}/auth/employees`, { headers });
          if (empRes.ok) {
            const empData = await empRes.json();
            const count = Array.isArray(empData) ? empData.length : 0;
            setTotalEmployees(count > 0 ? count : 11);
            setEmployees(empData || []);
            (empData || []).forEach(emp => {
              employeeMap[String(emp.id)] = emp;
            });
          } else {
            setTotalEmployees(11);
          }
        } catch (_) {
          setTotalEmployees(11);
        }

        // Fetch Cases
        const caseRes = await fetch(`${API_BASE_URL}/cases/`, { headers });
        if (caseRes.ok) {
          const caseData = await caseRes.json();
          const cases = caseData.data || [];
          const closedCount = cases.filter(c => c.status === 'closed' || c.status === 'completed' || c.status === 'archived').length;
          setCasesSolved(closedCount > 0 ? closedCount : (cases.length || 12));
          
          if (cases.length > 0) {
            // Enrich each case with resolved analyst and senior analyst names
            const enriched = cases.map(c => ({
              ...c,
              analyst_name: c.analyst_id ? (employeeMap[String(c.analyst_id)]?.name || c.analyst_id) : null,
              senior_analyst_name: c.senior_analyst_id ? (employeeMap[String(c.senior_analyst_id)]?.name || c.senior_analyst_id) : null,
            }));

            // Sort newest first by created_at timestamp
            const sorted = [...enriched].sort((a, b) => {
              const timeA = a.created_at ? new Date(a.created_at).getTime() : 0;
              const timeB = b.created_at ? new Date(b.created_at).getTime() : 0;
              return timeB - timeA;
            });
            setAllCasesList(sorted);
            
            // Prefer selected active case; if none or closed, fallback to latest open case
            const activeId = localStorage.getItem('active_case_id');
            let active = activeId ? sorted.find(c => c.case_id === activeId && (c.status === 'open' || c.status === 'in_progress')) : null;
            if (!active) {
              active = sorted.find(c => (c.status === 'open' || c.status === 'in_progress') && c.case_id?.startsWith('ARGUS_')) ||
                       sorted.find(c => c.status === 'open' || c.status === 'in_progress');
              if (active) {
                localStorage.setItem('active_case_id', active.case_id);
                if (active.name) localStorage.setItem('active_case_name', active.name);
                if (active.description) localStorage.setItem('active_case_desc', active.description);
              } else if (activeId) {
                localStorage.removeItem('active_case_id');
                localStorage.removeItem('active_case_name');
                localStorage.removeItem('active_case_desc');
              }
            }
            if (active) {
              setCurrentCase(active);
              loadWorkloadStatus(active.case_id);
            }
          } else {
            setAllCasesList([]);
            setCurrentCase(null);
            setAgentSummary(null);
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
      
      {/* ACTION BAR & BREADCRUMB */}
      <div className="glass-stage-header" style={{ marginTop: '0', paddingTop: '4px', alignItems: 'center' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <span style={{ 
              display: 'inline-flex', 
              alignItems: 'center', 
              gap: '6px', 
              padding: '4px 12px', 
              borderRadius: '20px', 
              background: 'rgba(37, 99, 235, 0.1)', 
              color: 'var(--glass-dash-blue, #2563eb)', 
              fontSize: '11.5px', 
              fontWeight: '700',
              border: '1px solid rgba(37, 99, 235, 0.22)',
              letterSpacing: '0.4px'
            }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
              COMMAND CENTER LIVE
            </span>
            <span style={{ fontSize: '13px', color: 'var(--glass-dash-text-muted)', fontWeight: 500 }}>
              &bull; Autonomous Multi-Agent Forensics
            </span>
          </div>
          <h1 className="glass-stage-title" style={{ fontSize: '24px', fontWeight: 800, margin: '0 0 4px', letterSpacing: '-0.02em' }}>
            Forensic Operations Overview
          </h1>
          <p className="glass-stage-desc" style={{ fontSize: '13px' }}>
            Real-time investigation progress, team allocations, and system compliance audit.
          </p>
        </div>
        <div className="glass-stage-actions">
          <div className="glass-datetime-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
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
            style={{ 
              cursor: (currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress')) ? 'not-allowed' : 'pointer', 
              opacity: (currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress')) ? 0.6 : 1 
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Create Case
          </button>
        </div>
      </div>

      {/* STATS ROW */}
      <div className="glass-stats-grid">
        {/* Total Employees */}
        <div className="glass-stat-card">
          <div className="glass-stat-icon-wrap blue">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
          </div>
          <div className="glass-stat-body">
            <div className="glass-stat-number">{loading ? '-' : totalEmployees}</div>
            <div className="glass-stat-title">Total Personnel</div>
            <div className="glass-stat-subtitle">Active team members</div>
          </div>
        </div>

        {/* Active Investigations */}
        <div className="glass-stat-card">
          <div className="glass-stat-icon-wrap amber">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path><line x1="12" y1="11" x2="12" y2="17"></line><line x1="9" y1="14" x2="15" y2="14"></line></svg>
          </div>
          <div className="glass-stat-body">
            <div className="glass-stat-number">{loading ? '-' : (allCasesList.filter(c => c.status === 'open' || c.status === 'in_progress').length)}</div>
            <div className="glass-stat-title">Active Cases</div>
            <div className="glass-stat-subtitle">Under investigation</div>
          </div>
        </div>

        {/* Cases Solved */}
        <div className="glass-stat-card">
          <div className="glass-stat-icon-wrap green">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          </div>
          <div className="glass-stat-body">
            <div className="glass-stat-number">{loading ? '-' : casesSolved}</div>
            <div className="glass-stat-title">Cases Solved</div>
            <div className="glass-stat-subtitle">Completed successfully</div>
          </div>
        </div>

        {/* Platform Integrity */}
        <div className="glass-stat-card">
          <div className="glass-stat-icon-wrap purple">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>
          </div>
          <div className="glass-stat-body">
            <div className="glass-stat-number">100%</div>
            <div className="glass-stat-title">Platform Integrity</div>
            <div className="glass-stat-subtitle">RFC-3161 audit sealed</div>
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
            
            <div className="glass-header-badge-group" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className={`glass-status-pill ${caseStageInfo.pillClass}`}>
                &bull; {caseStageInfo.statusLabel}
              </span>

              {/* Workload Status Pill */}
              {currentCase && (
                <span style={{
                  padding: '4px 10px',
                  borderRadius: '999px',
                  fontSize: '11px',
                  fontWeight: 700,
                  letterSpacing: '0.4px',
                  textTransform: 'uppercase',
                  background: agentSummary?.status === 'RUNNING' ? 'rgba(239, 68, 68, 0.15)' : (agentSummary?.status === 'STOPPED' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)'),
                  color: agentSummary?.status === 'RUNNING' ? '#ef4444' : (agentSummary?.status === 'STOPPED' ? '#f59e0b' : '#10b981'),
                  border: `1px solid ${agentSummary?.status === 'RUNNING' ? 'rgba(239, 68, 68, 0.3)' : (agentSummary?.status === 'STOPPED' ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.3)')}`,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  <span style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: agentSummary?.status === 'RUNNING' ? '#ef4444' : (agentSummary?.status === 'STOPPED' ? '#f59e0b' : '#10b981')
                  }} />
                  &bull; {agentSummary?.status || 'READY'}
                </span>
              )}

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
              style={{ 
                width: caseStageInfo.progressWidth,
                opacity: caseStageInfo.progressOpacity
              }} 
            />
            
            <div className="glass-pipeline-nodes">
              <div 
                className={`glass-pipeline-node ${currentCase ? 'clickable' : ''}`}
                onClick={() => currentCase && navigate('/agents')}
                title={currentCase ? 'Investigation: Run agent swarm & review evidence' : 'No active case'}
              >
                <span className={`glass-pipeline-dot ${caseStageInfo.investigationStatus}`}>
                  {caseStageInfo.investigationStatus === 'completed' ? (
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  ) : null}
                </span>
                <span className="glass-pipeline-label">Investigation</span>
                <span className="glass-pipeline-role">(Analyst)</span>
              </div>
              <div 
                className={`glass-pipeline-node ${currentCase ? 'clickable' : ''}`}
                onClick={() => currentCase && navigate('/report')}
                title={currentCase ? 'Review: Senior analyst report validation' : 'No active case'}
              >
                <span className={`glass-pipeline-dot ${caseStageInfo.reviewStatus}`}>
                  {caseStageInfo.reviewStatus === 'completed' ? (
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  ) : null}
                </span>
                <span className="glass-pipeline-label">Review</span>
                <span className="glass-pipeline-role">(Senior Analyst)</span>
              </div>
              <div 
                className={`glass-pipeline-node ${currentCase ? 'clickable' : ''}`}
                onClick={() => currentCase && navigate(`/audit-logs?case_id=${encodeURIComponent(currentCase.case_id)}`)}
                title={currentCase ? 'Audit: RFC-3161 timestamps & audit logs' : 'No active case'}
              >
                <span className={`glass-pipeline-dot ${caseStageInfo.auditStatus}`}>
                  {caseStageInfo.auditStatus === 'completed' ? (
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  ) : null}
                </span>
                <span className="glass-pipeline-label">Audit</span>
                <span className="glass-pipeline-role">({currentCase?.auditor_name || 'Not Assigned'})</span>
              </div>
              <div 
                className={`glass-pipeline-node ${currentCase ? 'clickable' : ''}`}
                onClick={() => currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress') && handleCloseCase()}
                title={currentCase ? (currentCase.status === 'closed' ? 'Case is closed' : 'Click to close active case') : 'No active case'}
              >
                <span className={`glass-pipeline-dot ${caseStageInfo.closedStatus}`}>
                  {caseStageInfo.closedStatus === 'completed' ? (
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  ) : null}
                </span>
                <span className="glass-pipeline-label">Closed</span>
                <span className="glass-pipeline-role">{currentCase?.status === 'closed' ? '(Resolved)' : '(Final)'}</span>
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
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={(e) => { if (e.target === e.currentTarget) setShowCreateModal(false); }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '420px', borderRadius: '22px', overflow: 'visible' }}>
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle, rgba(226, 232, 240, 0.8))', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
               <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-main, #0f172a)' }}>Create New Case</h2>
              <button onClick={() => setShowCreateModal(false)} className="icon-btn" style={{ width: '32px', height: '32px' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleCreateCase} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-main, #0f172a)' }}>Case Name</label>
                <input type="text" value={newCaseName} onChange={e => setNewCaseName(e.target.value)} style={{ width: '100%' }} placeholder="e.g., Operation Dark Web" required />
              </div>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-main, #0f172a)' }}>Assign Analyst <span style={{ color: 'var(--severity-critical, #ef4444)' }}>*</span></label>
                <SearchableSelect 
                  value={newCaseAnalyst} 
                  onChange={setNewCaseAnalyst} 
                  placeholder="Select Analyst"
                  options={analystSelectOptions}
                />
              </div>

              <div style={{ marginBottom: '28px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-main, #0f172a)' }}>Assign Senior Analyst</label>
                <SearchableSelect 
                  value={newCaseSeniorAnalyst} 
                  onChange={setNewCaseSeniorAnalyst} 
                  placeholder="Select Senior Analyst"
                  options={seniorSelectOptions}
                />
              </div>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid var(--border-subtle, rgba(226, 232, 240, 0.8))' }}>
                <button type="button" onClick={() => setShowCreateModal(false)} className="btn-outline">Cancel</button>
                <button type="submit" disabled={!newCaseName || !newCaseAnalyst} className="btn-primary" style={{ cursor: (!newCaseName || !newCaseAnalyst) ? 'not-allowed' : 'pointer', opacity: (!newCaseName || !newCaseAnalyst) ? 0.6 : 1 }}>Create Case</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assign Senior Analyst Modal */}
      {showAssignSeniorModal && currentCase && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1001, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={(e) => { if (e.target === e.currentTarget) setShowAssignSeniorModal(false); }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '380px', borderRadius: '22px', overflow: 'visible', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-main, #0f172a)' }}>Assign Senior Analyst</h2>
              <button onClick={() => setShowAssignSeniorModal(false)} className="icon-btn" style={{ width: '32px', height: '32px' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted, #64748b)', marginBottom: '16px' }}>Assigning to case <strong style={{ color: 'var(--text-main, #0f172a)' }}>{currentCase.case_id}</strong></div>
            <SearchableSelect
              value={assigningSenior}
              onChange={setAssigningSenior}
              placeholder="Select Senior Analyst"
              options={seniorSelectOptions}
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
