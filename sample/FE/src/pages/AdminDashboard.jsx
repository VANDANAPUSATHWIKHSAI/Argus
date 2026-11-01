import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL, DEFAULT_TENANT_ID, fetchAgentResults, fetchCaseSummary } from '../js/api';
import SearchableSelect from '../components/SearchableSelect';
import '../css/style.css';
import '../templates/GlassDashboardTemplate.css';
import AlertModal from '../components/AlertModal';
import { safeFormatDateOnly, safeFormatDateTime, safeFormatTime } from '../js/dateUtils';
import { setActiveCase } from '../js/caseEvents';

const DEFAULT_ANALYSTS = [
  { value: 'analyst', label: 'Junior Analyst (analyst)' },
  { value: 'EMP-002', label: 'Lead Analyst (EMP-002)' },
  { value: '4', label: 'sathwik (4)' },
  { value: '5', label: 'Analyst 5 (5)' }
];

const DEFAULT_SENIORS = [
  { value: 'senior_analyst', label: 'Senior Analyst (senior_analyst)' },
  { value: 'EMP-003', label: 'Senior Analyst (EMP-003)' },
  { value: '6', label: 'Senior Analyst 6 (6)' },
  { value: '7', label: 'Senior Analyst 7 (7)' }
];

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
  const [caseSummary, setCaseSummary] = useState(null);
  const [showCloseWithoutReportModal, setShowCloseWithoutReportModal] = useState(false);
  const [closeReason, setCloseReason] = useState('');
  const [closingCase, setClosingCase] = useState(false);

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

  const loadCaseSummary = async (caseId) => {
    if (!caseId) {
      setCaseSummary(null);
      return;
    }
    try {
      const summary = await fetchCaseSummary(caseId);
      setCaseSummary(summary);
    } catch (_) {
      setCaseSummary(null);
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

  const analystOptions = employees
    .filter(e => {
      const r = (e.role || '').toLowerCase();
      return (r.includes('analyst') || r.includes('investigator')) && !r.includes('senior');
    })
    .map(emp => ({ value: String(emp.id), label: `${emp.name || emp.id} (${emp.id})` }));

  const seniorOptions = employees
    .filter(e => {
      const r = (e.role || '').toLowerCase();
      return r.includes('senior');
    })
    .map(emp => ({ value: String(emp.id), label: `${emp.name || emp.id} (${emp.id})` }));

  const availableAnalystOptions = analystOptions.length > 0 ? analystOptions : DEFAULT_ANALYSTS;
  const availableSeniorOptions = seniorOptions.length > 0 ? seniorOptions : DEFAULT_SENIORS;

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
          name: newCaseName.trim(), 
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

      setActiveCase(createdId, newCaseName.trim());
      
      const assignedAnalyst = employees.find(emp => String(emp.id) === String(newCaseAnalyst)) ||
        availableAnalystOptions.find(opt => String(opt.value) === String(newCaseAnalyst));
      const assignedSenior = employees.find(emp => String(emp.id) === String(newCaseSeniorAnalyst)) ||
        availableSeniorOptions.find(opt => String(opt.value) === String(newCaseSeniorAnalyst));

      const newCaseObj = {
        case_id: createdId,
        name: newCaseName.trim(),
        status: 'open',
        analyst_id: newCaseAnalyst || null,
        analyst_name: assignedAnalyst ? (assignedAnalyst.name || assignedAnalyst.label) : newCaseAnalyst,
        senior_analyst_id: newCaseSeniorAnalyst || null,
        senior_analyst_name: assignedSenior ? (assignedSenior.name || assignedSenior.label) : newCaseSeniorAnalyst,
        created_at: new Date().toISOString()
      };

      setCurrentCase(newCaseObj);
      setAllCasesList(prev => [newCaseObj, ...prev.filter(c => c.case_id !== createdId)]);

      setShowCreateModal(false);
      setNewCaseName('');
      setNewCaseAnalyst('');
      setNewCaseSeniorAnalyst('');
      setRefreshTrigger(prev => prev + 1);

      loadWorkloadStatus(createdId);
      loadCaseSummary(createdId);

      setCustomAlert({
        isOpen: true,
        title: 'Success',
        message: `Case ${createdId} ("${newCaseName.trim()}") created successfully and analyst assigned.`,
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
      const res = await fetch(`${API_BASE_URL}/cases/${currentCase.case_id}/assign-senior`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, 'X-Tenant-ID': DEFAULT_TENANT_ID },
        body: JSON.stringify({ senior_analyst_id: assigningSenior })
      });
      if (!res.ok) throw new Error(await res.text());

      const assignedSeniorObj = employees.find(emp => String(emp.id) === String(assigningSenior)) ||
        availableSeniorOptions.find(opt => String(opt.value) === String(assigningSenior));

      setCurrentCase(prev => prev ? ({
        ...prev,
        senior_analyst_id: assigningSenior,
        senior_analyst_name: assignedSeniorObj ? (assignedSeniorObj.name || assignedSeniorObj.label) : assigningSenior
      }) : null);

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

  const handleCloseCase = () => {
    if (!currentCase) return;
    const isSubmittedToAuditor = Boolean(
      (typeof localStorage !== 'undefined' && localStorage.getItem(`argus_case_${currentCase.case_id}_submitted_to_auditor`)) ||
      currentCase.submitted_to_auditor
    );
    const isSubmittedToSenior = Boolean(
      (typeof localStorage !== 'undefined' && localStorage.getItem(`argus_case_${currentCase.case_id}_submitted_to_senior`)) ||
      currentCase.submitted_to_senior ||
      isSubmittedToAuditor
    );
    const evidenceCount = Number(currentCase.total_evidence_files ?? currentCase.evidence_count ?? 0);
    const findingsCount = Number(currentCase.total_findings ?? currentCase.findings_count ?? 0);
    const reportGenerated = isSubmittedToSenior || isSubmittedToAuditor || (evidenceCount > 0 && findingsCount > 0 && agentSummary?.status === 'COMPLETED');

    if (!reportGenerated) {
      setCloseReason('');
      setShowCloseWithoutReportModal(true);
      return;
    }

    executeCloseCase('');
  };

  const executeCloseCase = async (reason = '') => {
    if (!currentCase) return;
    setClosingCase(true);
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/cases/${currentCase.case_id}/close`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': DEFAULT_TENANT_ID,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ close_reason: reason })
      });
      if (res.ok) {
        const closedId = currentCase.case_id;
        const closedName = currentCase.name || closedId;
        setShowCloseWithoutReportModal(false);
        setCloseReason('');
        setActiveCase('', '');
        setCurrentCase(prev => prev ? ({ ...prev, status: 'closed' }) : null);
        setAgentSummary(null);
        setRefreshTrigger(prev => prev + 1);
        setCustomAlert({
          isOpen: true,
          title: 'Case Closed',
          message: `Case ${closedId} (${closedName}) closed successfully.${reason ? ' Reason recorded: ' + reason : ''}`,
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
        message: 'An error occurred while closing the case.',
        type: 'error'
      });
    } finally {
      setClosingCase(false);
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
            setTotalEmployees(count);
            setEmployees(empData || []);
            (empData || []).forEach(emp => {
              employeeMap[String(emp.id)] = emp;
            });
          } else {
            setTotalEmployees(0);
          }
        } catch (_) {
          setTotalEmployees(0);
        }

        // Fetch Cases
        const caseRes = await fetch(`${API_BASE_URL}/cases/`, { headers });
        if (caseRes.ok) {
          const caseData = await caseRes.json();
          const cases = caseData.data || [];
          const closedCount = cases.filter(c => c.status === 'closed' || c.status === 'completed' || c.status === 'archived').length;
          setCasesSolved(closedCount);
          
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
            let active = activeId ? sorted.find(c => c.case_id === activeId) : null;
            if (!active) {
              active = sorted.find(c => (c.status === 'open' || c.status === 'in_progress') && c.case_id?.startsWith('ARGUS_')) ||
                       sorted.find(c => c.status === 'open' || c.status === 'in_progress') ||
                       sorted[0];
              if (active) {
                setActiveCase(active.case_id, active.name || '');
              } else if (activeId) {
                setActiveCase('', '');
              }
            }
            if (active) {
              setCurrentCase(active);
              loadWorkloadStatus(active.case_id);
              loadCaseSummary(active.case_id);
            } else {
              setCurrentCase(null);
              setAgentSummary(null);
              setCaseSummary(null);
            }
          } else {
            setAllCasesList([]);
            setCurrentCase(null);
            setAgentSummary(null);
            setCaseSummary(null);
            setActiveCase('', '');
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

  // Dynamic Case Progress & Completion Calculations
  const isCaseClosed = Boolean(
    currentCase && (currentCase.status === 'closed' || currentCase.status === 'completed' || currentCase.status === 'archived')
  );

  const isSubmittedToSenior = Boolean(
    currentCase && (
      localStorage.getItem(`argus_case_${currentCase.case_id}_submitted_to_senior`) === 'true' ||
      caseSummary?.investigation_progress?.report === 'completed' ||
      isCaseClosed
    )
  );

  const isSubmittedToAuditor = Boolean(
    currentCase && (
      localStorage.getItem(`argus_case_${currentCase.case_id}_submitted_to_auditor`) === 'true' ||
      isCaseClosed
    )
  );

  const evidenceCount = caseSummary?.total_evidence_files || 0;
  const findingsCount = caseSummary?.total_findings || 0;
  const hasStartedInvestigation = evidenceCount > 0 || findingsCount > 0 || agentSummary?.status === 'RUNNING' || agentSummary?.status === 'COMPLETED';

  let stage1Status = 'pending';
  let stage2Status = 'pending';
  let stage3Status = 'pending';
  let stage4Status = 'pending';
  let progressPercent = 0;
  let stageStatusText = 'No Active Case';

  if (!currentCase) {
    stage1Status = 'pending';
    stage2Status = 'pending';
    stage3Status = 'pending';
    stage4Status = 'pending';
    progressPercent = 0;
    stageStatusText = 'No Active Case · 0% Complete';
  } else if (isCaseClosed) {
    stage1Status = 'completed';
    stage2Status = 'completed';
    stage3Status = 'completed';
    stage4Status = 'completed';
    progressPercent = 100;
    stageStatusText = '4 of 4 stages complete (100%) · Investigation Closed & Sealed';
  } else if (isSubmittedToAuditor) {
    stage1Status = 'completed';
    stage2Status = 'completed';
    stage3Status = 'active';
    stage4Status = 'pending';
    progressPercent = 75;
    stageStatusText = '2 of 4 stages complete (75%) · In Compliance Audit';
  } else if (isSubmittedToSenior) {
    stage1Status = 'completed';
    stage2Status = 'active';
    stage3Status = 'pending';
    stage4Status = 'pending';
    progressPercent = 50;
    stageStatusText = '1 of 4 stages complete (50%) · In Senior Analyst Review';
  } else if (hasStartedInvestigation) {
    stage1Status = 'active';
    stage2Status = 'pending';
    stage3Status = 'pending';
    stage4Status = 'pending';
    progressPercent = 25;
    stageStatusText = '0 of 4 stages complete (25%) · Investigation In Progress';
  } else {
    // Brand-new case with 0 evidence uploaded
    stage1Status = 'active';
    stage2Status = 'pending';
    stage3Status = 'pending';
    stage4Status = 'pending';
    progressPercent = 0;
    stageStatusText = '0 of 4 stages complete (0%) · Case Initialized, Awaiting Evidence';
  }

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
            onClick={() => setShowCreateModal(true)}
            className="btn-glass-primary"
            style={{ cursor: 'pointer', opacity: 1 }}
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
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h2 className="glass-case-id-text" style={{ margin: 0 }}>{currentCase ? currentCase.case_id : 'No Active Case'}</h2>
                  {allCasesList.length > 1 && (
                    <select
                      value={currentCase?.case_id || ''}
                      onChange={(e) => {
                        const sel = allCasesList.find(c => c.case_id === e.target.value);
                        if (sel) {
                          setCurrentCase(sel);
                          setActiveCase(sel.case_id, sel.name || '');
                          loadWorkloadStatus(sel.case_id);
                          loadCaseSummary(sel.case_id);
                        }
                      }}
                      style={{
                        padding: '3px 8px',
                        fontSize: '11.5px',
                        fontWeight: 600,
                        borderRadius: '8px',
                        background: 'var(--glass-dash-surface-nested)',
                        border: '1px solid var(--glass-dash-border-subtle)',
                        color: 'var(--glass-dash-text-main)',
                        cursor: 'pointer'
                      }}
                      title="Switch active case"
                    >
                      {allCasesList.map(c => (
                        <option key={c.case_id} value={c.case_id}>
                          {c.case_id}: {c.name || 'Unnamed'} ({c.status})
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <p className="glass-case-desc-text">{currentCase ? currentCase.name : 'Create a case to get started'}</p>
              </div>
            </div>
            
            <div className="glass-header-badge-group" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className={`glass-status-pill ${isCaseClosed ? 'closed' : isSubmittedToAuditor ? 'audit' : isSubmittedToSenior ? 'review' : currentCase ? 'active' : 'inactive'}`}>
                &bull; {
                  !currentCase 
                    ? 'No Active Cases'
                    : isCaseClosed
                    ? 'Closed'
                    : isSubmittedToAuditor
                    ? 'Compliance Audit'
                    : isSubmittedToSenior
                    ? 'Senior Review'
                    : 'Investigation Active'
                }
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
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontWeight: 600, padding: '6px 14px', cursor: 'pointer' }}
                  title="Close this case"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"></path></svg>
                  Close Case
                </button>
              )}
            </div>
          </div>

          {/* Progress Header with Accurate How Much Completed Metric */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '14px 0 6px 0', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--glass-dash-text-dim)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Lifecycle Pipeline
              </span>
              <span style={{ 
                fontSize: '11px', 
                fontWeight: 700, 
                padding: '2px 8px', 
                borderRadius: '12px',
                background: progressPercent === 100 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(37, 99, 235, 0.12)',
                color: progressPercent === 100 ? '#10b981' : 'var(--glass-dash-blue, #38bdf8)',
                border: `1px solid ${progressPercent === 100 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(37, 99, 235, 0.25)'}`
              }}>
                {progressPercent}% Complete
              </span>
            </div>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--glass-dash-text-muted)' }}>
              {stageStatusText}
            </span>
          </div>

          {/* Progress Timeline Pipeline */}
          <div className="glass-pipeline-container">
            <div className="glass-pipeline-track" />
            <div 
              className="glass-pipeline-progress" 
              style={{ width: `${progressPercent}%`, transition: 'width 0.4s ease' }} 
            />
            
            <div className="glass-pipeline-nodes">
              <div className="glass-pipeline-node">
                <span className={`glass-pipeline-dot ${stage1Status}`} />
                <span className="glass-pipeline-label">Investigation</span>
                <span className="glass-pipeline-role">({currentCase ? (currentCase.analyst_name || currentCase.analyst_id || 'Analyst') : 'Analyst'})</span>
              </div>
              <div className="glass-pipeline-node">
                <span className={`glass-pipeline-dot ${stage2Status}`} />
                <span className="glass-pipeline-label">Review</span>
                <span className="glass-pipeline-role">({currentCase ? (currentCase.senior_analyst_name || currentCase.senior_analyst_id || 'Senior Analyst') : 'Senior Analyst'})</span>
              </div>
              <div className="glass-pipeline-node">
                <span className={`glass-pipeline-dot ${stage3Status}`} />
                <span className="glass-pipeline-label">Audit</span>
                <span className="glass-pipeline-role">({currentCase ? (currentCase.auditor_name || currentCase.auditor_id || 'Compliance Auditor') : 'Compliance Auditor'})</span>
              </div>
              <div className="glass-pipeline-node">
                <span className={`glass-pipeline-dot ${stage4Status}`} />
                <span className="glass-pipeline-label">Closed</span>
                <span className="glass-pipeline-role">({isCaseClosed ? 'Archived' : 'Final'})</span>
              </div>
            </div>
          </div>

          {/* Real-time Case Telemetry Chips */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginTop: '14px', marginBottom: '4px' }}>
            <div style={{ padding: '8px 12px', borderRadius: '10px', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--glass-dash-border-subtle)', textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)', fontWeight: 600 }}>Evidence Files</div>
              <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--glass-dash-text-main)', marginTop: '2px' }}>{currentCase ? evidenceCount : 0}</div>
            </div>
            <div style={{ padding: '8px 12px', borderRadius: '10px', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--glass-dash-border-subtle)', textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)', fontWeight: 600 }}>Artifacts</div>
              <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--glass-dash-text-main)', marginTop: '2px' }}>{currentCase ? (caseSummary?.total_artifacts || 0) : 0}</div>
            </div>
            <div style={{ padding: '8px 12px', borderRadius: '10px', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--glass-dash-border-subtle)', textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)', fontWeight: 600 }}>Findings</div>
              <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--glass-dash-text-main)', marginTop: '2px' }}>{currentCase ? findingsCount : 0}</div>
            </div>
            <div style={{ padding: '8px 12px', borderRadius: '10px', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--glass-dash-border-subtle)', textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)', fontWeight: 600 }}>Completion</div>
              <div style={{ fontSize: '15px', fontWeight: 700, color: progressPercent === 100 ? '#10b981' : 'var(--glass-dash-blue, #38bdf8)', marginTop: '2px' }}>{progressPercent}%</div>
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
                  options={availableAnalystOptions}
                />
              </div>

              <div style={{ marginBottom: '28px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-main, #0f172a)' }}>Assign Senior Analyst</label>
                <SearchableSelect 
                  value={newCaseSeniorAnalyst} 
                  onChange={setNewCaseSeniorAnalyst} 
                  placeholder="Select Senior Analyst"
                  options={availableSeniorOptions}
                />
              </div>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid var(--border-subtle, rgba(226, 232, 240, 0.8))' }}>
                <button type="button" onClick={() => setShowCreateModal(false)} className="btn-outline">Cancel</button>
                <button type="submit" disabled={!newCaseName.trim() || !newCaseAnalyst || creating} className="btn-primary" style={{ cursor: (!newCaseName.trim() || !newCaseAnalyst || creating) ? 'not-allowed' : 'pointer', opacity: (!newCaseName.trim() || !newCaseAnalyst || creating) ? 0.6 : 1 }}>
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
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
              options={availableSeniorOptions}
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
      {/* Modal: Close Case Without Report (Admin Description Required) */}
      {showCloseWithoutReportModal && currentCase && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, zIndex: 1002, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={(e) => { if (e.target === e.currentTarget && !closingCase) setShowCloseWithoutReportModal(false); }}>
          <div className="modal-content" style={{ width: '100%', maxWidth: '480px', borderRadius: '22px', padding: '28px', background: 'var(--bg-card, #ffffff)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '12px', background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px' }}>
                ⚠️
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: 'var(--text-main, #0f172a)' }}>Close Case Without Report</h2>
                <div style={{ fontSize: '12px', color: '#f59e0b', fontWeight: 700 }}>Investigation Report Not Generated</div>
              </div>
            </div>

            <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text-secondary, #475569)', marginBottom: '16px' }}>
              The investigation report has not been generated for case <strong>{currentCase.name || currentCase.case_id}</strong>.
              To close this case early without waiting for the report, please provide a mandatory description / reason for administrative audit records.
            </p>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-main, #0f172a)' }}>
                Closure Reason / Description <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <textarea
                rows={3}
                value={closeReason}
                onChange={(e) => setCloseReason(e.target.value)}
                placeholder="e.g. Test case created in error, duplicate incident, or closed without waiting for report..."
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
                onClick={() => setShowCloseWithoutReportModal(false)}
                disabled={closingCase}
                className="btn-outline"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  if (!closeReason.trim()) {
                    setCustomAlert({
                      isOpen: true,
                      title: 'Description Required',
                      message: 'Please provide a description / reason for closing this case without waiting for the report.',
                      type: 'warning'
                    });
                    return;
                  }
                  executeCloseCase(closeReason.trim());
                }}
                disabled={closingCase}
                className="btn-primary"
                style={{ background: '#ef4444', borderColor: '#ef4444' }}
              >
                {closingCase ? 'Closing...' : 'Confirm Early Close'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
