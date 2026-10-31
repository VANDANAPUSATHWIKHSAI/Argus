import React, { useState, useEffect } from 'react';

import { useNavigate, Link, Navigate } from 'react-router-dom';

import '../css/style.css';

import Sidebar from '../components/Sidebar';

import ProfileModal from '../components/ProfileModal';

import AlertModal from '../components/AlertModal';

import NotificationMenu from '../components/NotificationMenu';

import AdminDashboard from './AdminDashboard';

import SeniorDashboard from './SeniorDashboard';

import AuditorDashboard from './AuditorDashboard';

import ForensicGraph from '../components/ForensicGraph';

import AnalystSubmitReportModal from '../components/AnalystSubmitReportModal';

import CaseNotAssigned from '../components/CaseNotAssigned';

import { fetchCases, fetchCaseSummary, fetchAgentResults, stopWorkload, restartWorkload, API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';

import { safeFormatDateTime } from '../js/dateUtils';

import { setActiveCase } from '../js/caseEvents';



const Dashboard = () => {

  const [cases, setCases] = useState([]);

  const navigate = useNavigate();

  const [activeSummary, setActiveSummary] = useState(null);

  const [agentSummary, setAgentSummary] = useState(null);

  const [loading, setLoading] = useState(true);

  

  const currentUserStr = localStorage.getItem('argus_user');

  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;

  const isAdmin = currentUser?.role === 'admin';

  const isSeniorAnalyst = currentUser?.role === 'senior_analyst';

  const isAuditor = currentUser?.role === 'auditor';

  const [showCreateModal, setShowCreateModal] = useState(false);

  const [showUserDropdown, setShowUserDropdown] = useState(false);

  const [showProfileModal, setShowProfileModal] = useState(false);

  const [newCaseName, setNewCaseName] = useState('');

  const [newCaseDesc, setNewCaseDesc] = useState('');

  const [creating, setCreating] = useState(false);

  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });

  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');

  const [submitModalOpen, setSubmitModalOpen] = useState(false);

  const [isReportSubmitted, setIsReportSubmitted] = useState(false);

  const [stoppingWorkload, setStoppingWorkload] = useState(false);

  const [restartingWorkload, setRestartingWorkload] = useState(false);

  const handleDashboardStopWorkload = async () => {
    const targetCaseId = activeSummary?.case_id || (cases && cases[0]?.id);
    if (!targetCaseId || stoppingWorkload) return;
    setStoppingWorkload(true);
    try {
      const res = await stopWorkload(targetCaseId);
      setCustomAlert({
        isOpen: true,
        title: '⏹ Workload Stopped',
        message: res.message || 'Workload was stopped. All captured evidence is safely retained. You can upload missing evidence and restart anytime.',
        type: 'info'
      });
      const [summaryData, agentData] = await Promise.all([
        fetchCaseSummary(targetCaseId).catch(() => null),
        fetchAgentResults(targetCaseId).catch(() => null)
      ]);
      if (summaryData) setActiveSummary(summaryData);
      if (agentData) setAgentSummary(agentData);
    } catch (err) {
      setCustomAlert({
        isOpen: true,
        title: 'Error Stopping Workload',
        message: err.message || 'Could not stop the workload.',
        type: 'error'
      });
    } finally {
      setStoppingWorkload(false);
    }
  };

  const handleDashboardRestartWorkload = async () => {
    const targetCaseId = activeSummary?.case_id || (cases && cases[0]?.id);
    if (!targetCaseId || restartingWorkload) return;
    setRestartingWorkload(true);
    try {
      const res = await restartWorkload(targetCaseId);
      setCustomAlert({
        isOpen: true,
        title: '🔄 Workload Restarted',
        message: res.message || 'Multi-agent analysis restarted with all captured evidence.',
        type: 'success'
      });
      const [summaryData, agentData] = await Promise.all([
        fetchCaseSummary(targetCaseId).catch(() => null),
        fetchAgentResults(targetCaseId).catch(() => null)
      ]);
      if (summaryData) setActiveSummary(summaryData);
      if (agentData) setAgentSummary(agentData);
    } catch (err) {
      setCustomAlert({
        isOpen: true,
        title: 'Error Restarting Workload',
        message: err.message || 'Could not restart the workload.',
        type: 'error'
      });
    } finally {
      setRestartingWorkload(false);
    }
  };



  const toggleTheme = () => {

    const nextTheme = theme === 'dark' ? 'light' : 'dark';

    setTheme(nextTheme);

    document.documentElement.setAttribute('data-theme', nextTheme);

    localStorage.setItem('argus_theme', nextTheme);

  };



  useEffect(() => {

    const syncReportSubmission = () => {

      const cId = activeSummary?.case_id || localStorage.getItem('active_case_id');

      if (cId) {

        const subRecord = localStorage.getItem(`argus_case_${cId}_submitted_to_senior`);

        setIsReportSubmitted(Boolean(subRecord));

      } else {

        setIsReportSubmitted(false);

      }

    };

    syncReportSubmission();

    window.addEventListener('storage', syncReportSubmission);

    return () => window.removeEventListener('storage', syncReportSubmission);

  }, [activeSummary]);



  const closeAlert = () => {

    if (customAlert.onClose) customAlert.onClose();

    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));

  };





  async function loadDashboard() {

    setLoading(true);

    try {

      const res = await fetchCases();

      const caseList = res.data || [];

      setCases(caseList);



      // Single assigned case enforcement: only OPEN or IN_PROGRESS cases can be active
      let currentActiveId = null;
      const openCases = caseList.filter(c => c.status === 'open' || c.status === 'in_progress');
      if (openCases.length > 0) {
        const storedActiveId = localStorage.getItem('active_case_id');
        const matched = storedActiveId ? openCases.find(c => c.case_id === storedActiveId) : null;
        const targetCase = matched || openCases[0];
        if (targetCase) {
          currentActiveId = targetCase.case_id;
          localStorage.setItem('active_case_id', targetCase.case_id);
          if (targetCase.name) localStorage.setItem('active_case_name', targetCase.name);
          if (targetCase.description) localStorage.setItem('active_case_desc', targetCase.description);
        }
      } else {
        localStorage.removeItem('active_case_id');
        localStorage.removeItem('active_case_name');
        localStorage.removeItem('active_case_desc');
        currentActiveId = null;
      }



      const activeCaseId = localStorage.getItem('active_case_id');

      if (activeCaseId) {

        const [summaryData, agentData] = await Promise.all([

          fetchCaseSummary(activeCaseId).catch(() => null),

          fetchAgentResults(activeCaseId).catch(() => null)

        ]);

        if (summaryData) {

          setActiveSummary(summaryData);

          if (summaryData.name) localStorage.setItem('active_case_name', summaryData.name);

          if (summaryData.description) localStorage.setItem('active_case_desc', summaryData.description);

        } else {

          setActiveSummary(null);

        }

        setAgentSummary(agentData);

      } else {

        setActiveSummary(null);

        setAgentSummary(null);

      }

    } catch (e) {

      console.error(e);

    } finally {

      setLoading(false);

    }

  }



  const activeCaseId = localStorage.getItem('active_case_id');



  // eslint-disable-next-line react-hooks/exhaustive-deps

  useEffect(() => { loadDashboard(); }, []);



  async function handleCreateCase(e) {

    e.preventDefault();

    const dateStr = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    const finalCaseName = newCaseName.trim() || `Investigation Case (${dateStr})`;

    if (newCaseName.trim() && cases.some(c => c.name && c.name.toLowerCase() === newCaseName.trim().toLowerCase())) {

      setCustomAlert({ isOpen: true, title: 'Notice', message: 'This case name is already in use. Please choose another.', type: 'warning' });

      return;

    }



    setCreating(true);

    try {

      const token = localStorage.getItem('argus_token');

      const res = await fetch(`${API_BASE_URL}/cases/`, {

        method: 'POST',

        headers: { 

          'Content-Type': 'application/json', 

          'X-Tenant-ID': DEFAULT_TENANT_ID,

          'Authorization': `Bearer ${token}` 

        },

        body: JSON.stringify({ name: finalCaseName, description: newCaseDesc, analyst: 'Admin' }),

      });

      if (!res.ok) throw new Error(await res.text());

      const data = await res.json();

      const createdId = data.case_id || data.id;

      setActiveCase(createdId, finalCaseName);

      if (newCaseDesc) localStorage.setItem('active_case_desc', newCaseDesc);



      setShowCreateModal(false);

      setNewCaseName('');

      setNewCaseDesc('');

      await loadDashboard();

    } catch (err) {

      setCustomAlert({ isOpen: true, title: 'Error', message: 'Failed to create case: ' + err.message, type: 'warning' });

    } finally {

      setCreating(false);

    }

  }



  const handleOpenCreateCase = () => {

    const activeCaseId = localStorage.getItem('active_case_id');

    const activeCaseName = localStorage.getItem('active_case_name');

    if (activeCaseId && activeCaseId !== '00000000-0000-0000-0000-000000000001' && activeCaseName && activeCaseName !== 'Case 00000000') {

      setCustomAlert({ isOpen: true, title: 'Notice', message: `An active case "${activeCaseName}" is currently open. You cannot create a new case until the active case is closed.`, type: 'warning' });

      return;

    }

    setShowCreateModal(true);

  };



  const handleCloseCase = async () => {

    const activeCaseName = localStorage.getItem('active_case_name') || 'Current case';

    const activeCaseId = localStorage.getItem('active_case_id');

    if (!activeCaseId && !localStorage.getItem('active_case_name')) {

      setCustomAlert({ isOpen: true, title: 'Notice', message: "There is no active case currently open.", type: 'warning' });

      return;

    }

    

    try {

      if (activeCaseId) {

        const token = localStorage.getItem('argus_token');

        await fetch(`${API_BASE_URL}/cases/${activeCaseId}/close`, {

          method: 'PUT',

          headers: { 

            'X-Tenant-ID': DEFAULT_TENANT_ID,

            'Authorization': `Bearer ${token}`

          }

        });

      }

    } catch (e) {

      console.error("Failed to close case globally:", e);

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



  const criticalHigh = (activeSummary?.severity_breakdown?.critical ?? 0) + (activeSummary?.severity_breakdown?.high ?? 0);



  const STAGE_DEFINITIONS = [

    {

      key: 'evidence_collection',

      label: 'Evidence\nCollection',

      shortLabel: 'Evidence',

      path: '/evidence',

      actionText: 'View Evidence'

    },

    {

      key: 'analysis',

      label: 'File\nAnalysis',

      shortLabel: 'File Analysis',

      path: '/evidence',

      actionText: 'Inspect Files'

    },

    {

      key: 'agent_analysis',

      label: 'Agent\nAnalysis',

      shortLabel: 'Agent Analysis',

      path: '/agents',

      actionText: 'Run Agent Swarm'

    },

    {

      key: 'report',

      label: 'Case\nReport',

      shortLabel: 'Report',

      path: '/report',

      actionText: 'View Report'

    }

  ];



  const evidenceCount = activeSummary

    ? (activeSummary.total_evidence_files || activeSummary.evidence_count || activeSummary.formatted_evidence?.length || 0)

    : 0;

  const findingsCount = activeSummary

    ? (activeSummary.total_findings ?? activeSummary.findings_count ?? 0)

    : 0;

  const artifactsCount = activeSummary

    ? (activeSummary.total_artifacts ?? 0)

    : 0;

  const isCaseClosed = activeSummary?.status === 'closed';



  const currentCaseId = activeSummary?.case_id || localStorage.getItem('active_case_id');

  const isSubmittedToSenior = isReportSubmitted || Boolean(currentCaseId && localStorage.getItem(`argus_case_${currentCaseId}_submitted_to_senior`));

  const isSubmittedToAuditor = Boolean(currentCaseId && localStorage.getItem(`argus_case_${currentCaseId}_submitted_to_auditor`));

  const isReportCompleted = isSubmittedToAuditor || isSubmittedToSenior || isCaseClosed;



  let rawStageStatuses = ['not_started', 'not_started', 'not_started', 'not_started'];



  if (activeSummary?.investigation_progress) {

    const prog = activeSummary.investigation_progress;

    const evVal = prog.evidence_collection;

    rawStageStatuses[0] = (typeof evVal === 'object' ? evVal?.status : evVal) || 'not_started';



    const anVal = prog.analysis;

    rawStageStatuses[1] = (typeof anVal === 'object' ? anVal?.status : anVal) || 'not_started';



    const agVal = prog.agent_analysis || prog.findings || prog.correlation;

    rawStageStatuses[2] = (typeof agVal === 'object' ? agVal?.status : agVal) || 'not_started';



    const repVal = prog.report;

    rawStageStatuses[3] = (typeof repVal === 'object' ? repVal?.status : repVal) || 'not_started';

  }



  // Comprehensive forensic stage integration:

  if (evidenceCount > 0) {

    rawStageStatuses[0] = 'completed';

    // Stage 2 (File Analysis) is dynamic: completed when artifacts extracted, in-progress when files uploaded but parsing

    rawStageStatuses[1] = artifactsCount > 0 ? 'completed' : 'in_progress';

    rawStageStatuses[2] = findingsCount > 0 ? 'completed' : (artifactsCount > 0 ? 'in_progress' : 'not_started');

    rawStageStatuses[3] = isReportCompleted ? 'completed' : (findingsCount > 0 ? 'in_progress' : 'not_started');

  } else {

    rawStageStatuses[0] = 'not_started';

    rawStageStatuses[1] = 'not_started';

    rawStageStatuses[2] = 'not_started';

    rawStageStatuses[3] = 'not_started';

  }



  if (artifactsCount > 0) {

    rawStageStatuses[0] = 'completed';

    rawStageStatuses[1] = 'completed';

    if (rawStageStatuses[2] === 'not_started') {

      rawStageStatuses[2] = 'in_progress';

    }

  }



  if (findingsCount > 0) {

    rawStageStatuses[0] = 'completed';

    rawStageStatuses[1] = 'completed';

    rawStageStatuses[2] = 'completed';

    rawStageStatuses[3] = isReportCompleted ? 'completed' : 'in_progress';

  }



  if (isReportCompleted) {

    rawStageStatuses[0] = 'completed';

    rawStageStatuses[1] = 'completed';

    rawStageStatuses[2] = 'completed';

    rawStageStatuses[3] = 'completed';

  }



  // Contextual telemetry metrics under each stage

  const stageTelemetry = [

    evidenceCount > 0 ? `${evidenceCount} file${evidenceCount > 1 ? 's' : ''}` : 'No files',

    artifactsCount > 0

      ? `${artifactsCount} parsed`

      : (evidenceCount > 0 ? 'Parsing...' : 'Pending'),

    findingsCount > 0

      ? `${findingsCount} finding${findingsCount > 1 ? 's' : ''}`

      : (artifactsCount > 0 ? 'Ready to run' : 'Pending'),

    isSubmittedToAuditor

      ? 'Escalated to Auditor'

      : isSubmittedToSenior

      ? 'Submitted to Senior'

      : isCaseClosed

      ? 'Case Closed'

      : (findingsCount > 0 ? 'Ready for Senior' : 'Pending')

  ];



  const stages = STAGE_DEFINITIONS.map((def, idx) => {

    const status = rawStageStatuses[idx];

    const isDone = status === 'completed';

    const isActive = status === 'in_progress';

    const isPending = status === 'not_started';

    return {

      ...def,

      status,

      isDone,

      isActive,

      isPending,

      metric: stageTelemetry[idx]

    };

  });



  const completedSteps = stages.filter(s => s.isDone).length;

  const inProgIdx = stages.findIndex(s => s.isActive);

  const activeStep = inProgIdx !== -1 ? inProgIdx : (completedSteps >= stages.length ? stages.length - 1 : completedSteps);

  const progressBarWidth = `${(completedSteps / stages.length) * 100}%`;



  const totalIntervals = Math.max(1, stages.length - 1);

  const highestDoneStep = stages.map(s => s.isDone).lastIndexOf(true);

  const targetStep = inProgIdx !== -1 ? inProgIdx : Math.max(0, highestDoneStep);

  const fillRatio = highestDoneStep === -1 && inProgIdx <= 0 ? 0 : Math.min(1, targetStep / totalIntervals);

  const activeTrackWidth = `calc((100% - 90px) * ${fillRatio})`;





  return (

    <>

      <div id="app-shell">

        <AlertModal 

          {...customAlert} 

          onClose={closeAlert} 

        />



        {/* ── SIDEBAR ── */}

        <Sidebar />



        {/* ── MAIN CONTENT ── */}

        <main className="main-content">

          {isAuditor ? (

            <AuditorDashboard />

          ) : isSeniorAnalyst ? (

            <SeniorDashboard />

          ) : isAdmin ? (

            <>

              {/* ADMIN TOPBAR */}

              <header className="glass-topbar-capsule topbar">

                <div className="glass-topbar-left">

                  <h2 className="glass-welcome-title">Welcome, {currentUser?.name || 'Admin'}</h2>

                  <p className="glass-welcome-sub">Manage people, cases, and ensure compliance.</p>

                </div>

                <div className="glass-topbar-right topbar-actions">

                  <button

                    id="btn-admin-topbar-create-case"

                    className="btn btn-primary"

                    onClick={() => {

                      const activeId = localStorage.getItem('active_case_id');

                      const activeName = localStorage.getItem('active_case_name');

                      if (activeId && activeName && activeId !== '00000000-0000-0000-0000-000000000001') {

                        setCustomAlert({

                          isOpen: true,

                          title: 'Notice',

                          message: `Active case "${activeName}" is currently open. You cannot create a new case until the active case is closed.`,

                          type: 'warning'

                        });

                        return;

                      }

                      setShowCreateModal(true);

                    }}

                    style={{

                      display: 'flex',

                      alignItems: 'center',

                      gap: '6px',

                      padding: '7px 16px',

                      fontSize: '13px',

                      fontWeight: 600,

                      borderRadius: '10px',

                      background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',

                      color: '#ffffff',

                      boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)',

                      border: 'none',

                      cursor: 'pointer'

                    }}

                  >

                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>

                    Create Case

                  </button>

                  <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Theme">

                    {theme === 'dark' ? (

                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>

                    ) : (

                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>

                    )}

                  </button>

                  <NotificationMenu />

                  <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>

                    <div className="glass-profile-avatar-dark avatar">A</div>

                    <span className="glass-profile-name">{currentUser?.name || 'Admin'}</span>

                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>

                    {showUserDropdown && (

                      <div className="user-dropdown" style={{ display: 'block' }}>

                        <div className="user-dropdown-header">

                          <div className="ud-name">{currentUser?.name || 'Admin'}</div>

                          <div className="ud-role">System Administrator</div>

                        </div>

                        <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); navigate('/profile'); setShowUserDropdown(false); }}>

                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>

                          My Profile

                        </button>

                      </div>

                    )}

                  </div>

                </div>

              </header>

              <div className="dashboard-scroll">

                <AdminDashboard />

              </div>

            </>

          ) : (

            <>

              {/* ANALYST TOPBAR */}

              <header className="glass-topbar-capsule topbar">

                <div className="glass-topbar-left">

                  <h2 className="glass-welcome-title">Welcome, {currentUser?.name || 'Investigator'}</h2>

                  <p className="glass-welcome-sub">Autonomous AI Forensic Investigation Workstation</p>

                </div>



                <div className="glass-topbar-right topbar-actions">

                  {/* Live Analysis badge */}

                  {localStorage.getItem('active_case_id') && (

                    <div className="badge-live">

                      <div className="live-dot"></div>

                      Live Analysis

                    </div>

                  )}







                  {/* Theme Toggle */}

                  <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Theme">

                    {theme === 'dark' ? (

                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>

                    ) : (

                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>

                    )}

                  </button>



                  {/* Bell */}

                  <NotificationMenu />



                  {/* User profile */}

                  <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>

                    <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'S'}</div>

                    <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'sathwik'}</span>

                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>

                    {showUserDropdown && (

                      <div className="user-dropdown" style={{ display: 'block' }}>

                        <div className="user-dropdown-header">

                          <div className="ud-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'sathwik'}</div>

                          <div className="ud-role">{currentUser?.role?.replace('_', ' ') || 'Digital Forensics Investigator'}</div>

                        </div>

                        <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); navigate('/profile'); setShowUserDropdown(false); }}>

                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>

                          My Profile

                        </button>

                      </div>

                    )}

                  </div>

                </div>

              </header>



          {/* DASHBOARD SCROLL */}

          <div className="dashboard-scroll">



            {loading && (

              <div style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>Loading...</div>

            )}



            {!loading && (

              <>

                {/* EMPTY / RESTRICTED STATE */}

                {!activeSummary && (

                  isAdmin ? (

                    <div id="dashboard-empty-state" style={{ display: 'block', textAlign: 'center', padding: '100px 20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', marginBottom: '24px', border: '1px dashed var(--border-strong)' }}>

                      <div style={{ width: '64px', height: '64px', background: 'var(--blue-light)', color: 'var(--blue)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>

                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>

                      </div>

                      <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>

                        No Active Case Selected

                      </h2>

                      <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>

                        Select an existing case or create a new one to begin your investigation.

                      </p>

                    </div>

                  ) : (

                    <CaseNotAssigned />

                  )

                )}



                {/* ACTIVE CONTENT */}

                {activeSummary && (

                  <div id="dashboard-active-content">



                    {/* Case Header */}

                    <div className="header-card" style={{ flexShrink: 0 }}>

                      <div className="header-info-wrap">

                        <div className="header-id">

                          <p>Active Case</p>

                          <h1 id="dashboard-case-name">{activeSummary.name || localStorage.getItem('active_case_name') || 'Unnamed Case'}</h1>

                        </div>

                        <div className="header-details">

                          <h2 id="dashboard-case-id" style={{ fontSize: '14px', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{activeSummary.case_id}</h2>

                          <p id="dashboard-case-desc">{activeSummary.description || localStorage.getItem('active_case_desc') || 'No description provided.'}</p>

                          <div className="header-meta">

                            <div className="badge-danger">

                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>

                              {criticalHigh > 0 ? 'High Risk' : 'Under Review'}

                            </div>

                            <div className="meta-item">

                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>

                              <div>

                                <span>Last Updated</span>

                                <strong>{safeFormatDateTime(activeSummary.latest_timestamp, '—')}</strong>

                              </div>

                            </div>

                          </div>

                        </div>

                      </div>



                      {/* Analyst Report Generation Option */}

                      {!isAdmin && (

                        <div className="header-actions-wrap" style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0, marginTop: '8px' }}>

                          <button

                            type="button"

                            onClick={() => setSubmitModalOpen(true)}

                            id="btn-analyst-generate-report"

                            className="btn btn-primary"

                            style={{

                              display: 'flex',

                              alignItems: 'center',

                              gap: '8px',

                              padding: '10px 18px',

                              borderRadius: '12px',

                              background: isReportSubmitted

                                ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'

                                : 'linear-gradient(135deg, #2563eb 0%, #7c3aed 100%)',

                              color: '#ffffff',

                              fontSize: '13px',

                              fontWeight: 700,

                              border: 'none',

                              cursor: 'pointer',

                              boxShadow: isReportSubmitted

                                ? '0 4px 14px rgba(16, 185, 129, 0.35)'

                                : '0 4px 14px rgba(37, 99, 235, 0.35)',

                              transition: 'all 0.2s ease',

                              whiteSpace: 'nowrap'

                            }}

                            title="Compile multi-agent findings and hand off report to Senior Analyst for validation"

                          >

                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">

                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

                              <polyline points="14 2 14 8 20 8"></polyline>

                              <line x1="16" y1="13" x2="8" y2="13"></line>

                              <line x1="16" y1="17" x2="8" y2="17"></line>

                            </svg>

                            <span>{isReportSubmitted ? '✓ Report Submitted to Senior' : '📑 Generate Report for Senior'}</span>

                          </button>

                        </div>

                      )}



                    </div>



                    {/* Stats Grid */}

                    <div className="stats-grid" style={{ flexShrink: 0 }}>

                      <div className="stat-card">

                        <div className="stat-icon" style={{ backgroundColor: 'var(--blue-light)', color: 'var(--blue)' }}>

                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>

                        </div>

                        <div className="stat-info">

                          <h2>{activeSummary.total_evidence_files ?? 0}</h2>

                          <h4>Evidence Files</h4>

                          <p>Uploaded to this case</p>

                        </div>

                        <div className="trend-badge">Total</div>

                      </div>

                      <div className="stat-card">

                        <div className="stat-icon" style={{ backgroundColor: 'var(--purple-light)', color: 'var(--purple)' }}>

                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>

                        </div>

                        <div className="stat-info">

                          <h2>{activeSummary.total_artifacts ?? 0}</h2>

                          <h4>Artifacts</h4>

                          <p>Parsed from evidence</p>

                        </div>

                        <div className="trend-badge">↑ New</div>

                      </div>

                      <div className="stat-card">

                        <div className="stat-icon" style={{ backgroundColor: 'var(--cyan-light)', color: 'var(--cyan)' }}>

                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>

                        </div>

                        <div className="stat-info">

                          <h2>{activeSummary.total_findings ?? 0}</h2>

                          <h4>Total Findings</h4>

                          <p>Across all layers</p>

                        </div>

                        <div className="trend-badge">↑ +{activeSummary.total_findings ?? 0}</div>

                      </div>

                      <div className="stat-card">

                        <div className="stat-icon" style={{ backgroundColor: 'var(--red-light)', color: 'var(--red)' }}>

                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>

                        </div>

                        <div className="stat-info">

                          <h2>{criticalHigh}</h2>

                          <h4>Critical / High</h4>

                          <p>Require analyst review</p>

                        </div>

                        <div className="trend-badge trend-danger">↑ Risk</div>

                      </div>

                    </div>





                    {/* ARGUS Multi-Agent Swarm Intelligence Card */}

                    <div style={{

                      background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.08), rgba(99, 102, 241, 0.12))',

                      border: '1px solid rgba(99, 102, 241, 0.35)',

                      borderRadius: 10,

                      padding: '18px 24px',

                      display: 'flex',

                      justifyContent: 'space-between',

                      alignItems: 'center',

                      flexWrap: 'wrap',

                      gap: 16,

                      flexShrink: 0

                    }}>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>

                        <div style={{

                          width: 44,

                          height: 44,

                          borderRadius: 8,

                          background: 'rgba(99, 102, 241, 0.2)',

                          color: '#818cf8',

                          display: 'flex',

                          alignItems: 'center',

                          justifyContent: 'center',

                          flexShrink: 0

                        }}>

                          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>

                        </div>

                        <div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>

                            <span style={{ fontSize: 11, fontWeight: 900, background: '#6366f1', color: '#fff', padding: '2px 8px', borderRadius: 4, letterSpacing: '0.05em' }}>

                              MULTI-AGENT SWARM

                            </span>

                            <span style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-main)' }}>

                              7-Agent Forensic Reasoning Engine

                            </span>

                            <span style={{
                              fontSize: 11,
                              fontWeight: 800,
                              background: agentSummary?.status === 'COMPLETED' ? 'rgba(16, 185, 129, 0.15)' : agentSummary?.status === 'STOPPED' ? 'rgba(245, 158, 11, 0.18)' : agentSummary?.status === 'RUNNING' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                              color: agentSummary?.status === 'COMPLETED' ? '#10b981' : agentSummary?.status === 'STOPPED' ? '#f59e0b' : agentSummary?.status === 'RUNNING' ? '#ef4444' : 'var(--blue)',
                              padding: '2px 8px',
                              borderRadius: 4,
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 5
                            }}>
                              {agentSummary?.status === 'RUNNING' && <span className="live-dot" style={{ background: '#ef4444', width: 6, height: 6 }}></span>}
                              {agentSummary?.status || 'READY'}
                            </span>
                          </div>
                          <p style={{ margin: 0, fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                            Qwen3-8B Evidence Intelligence, Neo4j Graph Correlation, MITRE ATT&amp;CK Kill-Chain, YARA Heuristics, Threat Intel, and DeBERTa-v3 NLI Verification.
                          </p>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        {agentSummary?.status === 'RUNNING' && (
                          <button
                            onClick={handleDashboardStopWorkload}
                            disabled={stoppingWorkload}
                            style={{
                              background: 'rgba(239, 68, 68, 0.15)',
                              border: '1px solid rgba(239, 68, 68, 0.4)',
                              color: '#ef4444',
                              padding: '9px 16px',
                              borderRadius: 6,
                              fontSize: 12,
                              fontWeight: 700,
                              cursor: stoppingWorkload ? 'not-allowed' : 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 6
                            }}
                            title="Stop workload to upload missing evidence or review current findings"
                          >
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16" rx="2" /></svg>
                            <span>{stoppingWorkload ? 'Stopping...' : 'Stop Workload'}</span>
                          </button>
                        )}

                        {agentSummary?.status !== 'RUNNING' && (
                          <button
                            onClick={handleDashboardRestartWorkload}
                            disabled={restartingWorkload}
                            style={{
                              background: agentSummary?.status === 'STOPPED' ? '#10b981' : 'linear-gradient(135deg, #10b981, #059669)',
                              border: 'none',
                              color: '#fff',
                              padding: '9px 16px',
                              borderRadius: 6,
                              fontSize: 12,
                              fontWeight: 700,
                              cursor: restartingWorkload ? 'not-allowed' : 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 6,
                              boxShadow: '0 2px 8px rgba(16, 185, 129, 0.3)'
                            }}
                            title="Restart workload from scratch with all captured and newly uploaded evidence"
                          >
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                            <span>{restartingWorkload ? 'Restarting...' : 'Restart Workload'}</span>
                          </button>
                        )}

                        <Link
                          to="/agents"
                          style={{
                            background: 'linear-gradient(135deg, #3b82f6, #6366f1)',
                            color: '#fff',
                            padding: '10px 20px',
                            borderRadius: 6,
                            fontSize: 12.5,
                            fontWeight: 800,
                            textDecoration: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 8,
                            boxShadow: '0 4px 14px rgba(99, 102, 241, 0.35)',
                            whiteSpace: 'nowrap'
                          }}
                        >
                          OPEN AGENT SWARM →
                        </Link>
                      </div>

                    </div>



                    {/* Interactive Investigation Map */}

                    <ForensicGraph caseId={activeCaseId} />



                    {/* Investigation Progress */}

                    <div className="timeline-card" style={{ flexShrink: 0 }}>

                      <div className="timeline-header">

                        <div>

                          <h3 style={{ margin: 0 }}>Investigation Progress</h3>

                          <p style={{ margin: '4px 0 0 0' }}>Track the lifecycle of the active case.</p>

                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>

                          <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)' }}>{completedSteps} of {stages.length} stages complete</span>

                          <div style={{ width: '120px', height: '5px', backgroundColor: 'var(--border-strong)', borderRadius: '99px', overflow: 'hidden' }}>

                            <div style={{ width: progressBarWidth, height: '100%', background: '#10b981', borderRadius: '99px', transition: 'width 0.6s ease' }}></div>

                          </div>

                        </div>

                      </div>



                      {/* Continuous Stepper Container */}

                      <div style={{ position: 'relative', padding: '16px 0 8px 0' }}>

                        {/* Background Track Line spanning across all circle centers */}

                        <div style={{

                          position: 'absolute',

                          top: '33px',

                          left: '45px',

                          right: '45px',

                          height: '3px',

                          backgroundColor: 'var(--border-strong)',

                          borderRadius: '99px',

                          zIndex: 0

                        }} />

                        {/* Dynamic Active Fill Track Line */}

                        <div style={{

                          position: 'absolute',

                          top: '33px',

                          left: '45px',

                          width: activeTrackWidth,

                          height: '3px',

                          background: 'linear-gradient(90deg, #10b981, #3b82f6)',

                          borderRadius: '99px',

                          zIndex: 0,

                          transition: 'width 0.6s cubic-bezier(0.4, 0, 0.2, 1)'

                        }} />



                        {/* Interactive Stage Nodes */}

                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', position: 'relative', zIndex: 1 }}>

                          {stages.map((stage, i) => {

                            const isAnalystRole = !isAdmin && !isSeniorAnalyst && !isAuditor;

                            const isReportStep = stage.key === 'report';



                            const nodeContent = (

                              <>

                                <div style={{

                                  width: '34px',

                                  height: '34px',

                                  borderRadius: '50%',

                                  background: stage.isDone

                                    ? '#10b981'

                                    : stage.isActive

                                    ? 'var(--blue)'

                                    : 'var(--bg-card)',

                                  border: stage.isDone

                                    ? '2.5px solid #10b981'

                                    : stage.isActive

                                    ? '2.5px solid var(--blue)'

                                    : '2.5px solid var(--border-strong)',

                                  display: 'flex',

                                  alignItems: 'center',

                                  justifyContent: 'center',

                                  transition: 'all 0.3s ease',

                                  flexShrink: 0,

                                  zIndex: 2,

                                  boxShadow: stage.isActive

                                    ? '0 0 12px rgba(59, 130, 246, 0.5)'

                                    : stage.isDone

                                    ? '0 0 8px rgba(16, 185, 129, 0.3)'

                                    : 'none'

                                }}>

                                  {stage.isDone && (

                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">

                                      <polyline points="20 6 9 17 4 12" />

                                    </svg>

                                  )}

                                  {stage.isActive && (

                                    <div style={{

                                      width: '10px',

                                      height: '10px',

                                      borderRadius: '50%',

                                      background: 'white',

                                      boxShadow: '0 0 4px white'

                                    }} />

                                  )}

                                  {stage.isPending && (

                                    <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)' }}>

                                      {i + 1}

                                    </span>

                                  )}

                                </div>



                                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px', width: '100%' }}>

                                  <span style={{

                                    fontSize: '12px',

                                    fontWeight: stage.isActive ? 700 : stage.isDone ? 600 : 500,

                                    color: stage.isActive ? 'var(--blue)' : stage.isDone ? 'var(--text-main)' : 'var(--text-muted)',

                                    textAlign: 'center',

                                    lineHeight: '1.25',

                                    whiteSpace: 'pre-line'

                                  }}>

                                    {stage.label}

                                  </span>

                                  <span style={{

                                    fontSize: '10.5px',

                                    fontWeight: 600,

                                    color: stage.isDone ? '#10b981' : stage.isActive ? 'var(--blue)' : 'var(--text-muted)',

                                    background: stage.isDone ? 'rgba(16, 185, 129, 0.12)' : stage.isActive ? 'rgba(59, 130, 246, 0.12)' : 'rgba(255, 255, 255, 0.04)',

                                    border: stage.isDone ? '1px solid rgba(16, 185, 129, 0.25)' : stage.isActive ? '1px solid rgba(59, 130, 246, 0.25)' : '1px solid var(--border-subtle)',

                                    padding: '1px 6px',

                                    borderRadius: '4px',

                                    letterSpacing: '0.2px',

                                    whiteSpace: 'nowrap'

                                  }}>

                                    {stage.metric}

                                  </span>

                                </div>

                              </>

                            );



                            if (isReportStep && isAnalystRole) {

                              return (

                                <div

                                  key={stage.key}

                                  onClick={() => setSubmitModalOpen(true)}

                                  title="Click to generate and submit report to Senior Analyst"

                                  style={{

                                    display: 'flex',

                                    flexDirection: 'column',

                                    alignItems: 'center',

                                    gap: '8px',

                                    cursor: 'pointer',

                                    width: '90px',

                                    flexShrink: 0

                                  }}

                                >

                                  {nodeContent}

                                </div>

                              );

                            }



                            return (

                              <Link

                                key={stage.key}

                                to={stage.path}

                                title={`${stage.shortLabel} — Click to ${stage.actionText}`}

                                style={{

                                  display: 'flex',

                                  flexDirection: 'column',

                                  alignItems: 'center',

                                  gap: '8px',

                                  textDecoration: 'none',

                                  cursor: 'pointer',

                                  width: '90px',

                                  flexShrink: 0

                                }}

                              >

                                {nodeContent}

                              </Link>

                            );

                          })}

                        </div>

                      </div>

                    </div>





                  </div>

                )}

              </>

            )}

          </div>

            </>

          )}

        </main>

      </div>



      {/* CREATE CASE MODAL — matches HTML exactly */}

      {showCreateModal && (

        <div style={{ display: 'flex', position: 'fixed', inset: 0, background: 'transparent', zIndex: 100, alignItems: 'center', justifyContent: 'center' }}>

          <div style={{ background: 'var(--bg-card)', padding: '30px', borderRadius: 'var(--radius-lg)', width: '400px', border: '1px solid var(--border-strong)', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}>

            <div style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

              <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-main)' }}>Create New Case</h2>

              <button onClick={() => setShowCreateModal(false)} style={{ background: 'none', border: '1px solid var(--border-strong)', borderRadius: '8px', width: '32px', height: '32px', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: 'var(--text-muted)' }}>

                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>

              </button>

            </div>

            <form onSubmit={handleCreateCase}>

              <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>

                <div>

                  <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Case Name</label>

                  <input

                    type="text"

                    value={newCaseName}

                    onChange={e => setNewCaseName(e.target.value)}

                    placeholder="e.g. Ransomware Incident - Alpha Corp (or auto-generated)"

                    style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: '14px', outline: 'none', boxSizing: 'border-box', background: 'var(--bg-app)', color: 'var(--text-main)' }}

                  />

                </div>

                <div>

                  <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Description</label>

                  <textarea

                    value={newCaseDesc}

                    onChange={e => setNewCaseDesc(e.target.value)}

                    rows={3}

                    placeholder="Brief details about the investigation..."

                    style={{ width: '100%', padding: '10px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', fontSize: '14px', outline: 'none', resize: 'none', boxSizing: 'border-box', background: 'var(--bg-app)', color: 'var(--text-main)' }}

                  />

                </div>

              </div>

              <div style={{ padding: '16px 24px', background: 'var(--bg-card-modal)', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>

                <button type="button" onClick={() => setShowCreateModal(false)} style={{ padding: '8px 16px', borderRadius: 'var(--radius-full)', border: '1px solid var(--border-strong)', background: 'transparent', color: 'var(--text-main)', fontWeight: 600, cursor: 'pointer', fontSize: '13px' }}>Cancel</button>

                <button type="submit" disabled={creating} style={{ padding: '8px 16px', borderRadius: 'var(--radius-full)', border: 'none', background: 'var(--blue)', color: '#fff', fontWeight: 600, cursor: creating ? 'not-allowed' : 'pointer', opacity: creating ? 0.7 : 1, fontSize: '13px' }}>

                  {creating ? 'Creating...' : 'Create Case'}

                </button>

              </div>

            </form>

          </div>

        </div>

      )}



      <ProfileModal isOpen={showProfileModal} onClose={() => setShowProfileModal(false)} />



      {/* Analyst Report Generation and Senior Submission Modal */}

      <AnalystSubmitReportModal

        isOpen={submitModalOpen}

        onClose={() => setSubmitModalOpen(false)}

        caseId={activeSummary?.case_id || localStorage.getItem('active_case_id') || ''}

        caseName={activeSummary?.name || localStorage.getItem('active_case_name') || ''}

        activeSummary={activeSummary}

        onSuccess={() => {

          setIsReportSubmitted(true);

          setCustomAlert({

            isOpen: true,

            title: 'Report Submitted',

            message: `Forensic report for Case ${activeSummary?.case_id || ''} has been compiled and submitted to the Senior Analyst for review.`,

            type: 'success',

            onClose: null

          });

        }}

      />

    </>

  );

};



export default Dashboard;