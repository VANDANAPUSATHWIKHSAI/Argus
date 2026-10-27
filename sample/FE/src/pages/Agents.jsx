import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import CaseLockBanner from '../components/CaseLockBanner';
import { fetchAgentResults, triggerAgentAnalysis, fetchCases } from '../js/api';
import { formatEvidenceId } from '../js/dateUtils';
import { getActiveCaseId, getActiveCaseName, subscribeToActiveCase, setActiveCase } from '../js/caseEvents';
import { syncCaseLock, subscribeToCaseLock } from '../js/caseLockService';
import '../css/style.css';

const AGENT_METADATA = {
  agent1: {
    id: 'agent1',
    number: '01',
    name: 'Evidence Intelligence',
    subtitle: 'Triage, Lineage & Confidence Verification',
    badge: 'LLM Reasoning (Qwen3-8B)',
    color: '#3b82f6',
    bg: 'rgba(59, 130, 246, 0.12)',
    border: 'rgba(59, 130, 246, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
        <polyline points="14 2 14 8 20 8"></polyline>
        <line x1="16" y1="13" x2="8" y2="13"></line>
        <line x1="16" y1="17" x2="8" y2="17"></line>
        <polyline points="10 9 9 9 8 9"></polyline>
      </svg>
    )
  },
  agent2: {
    id: 'agent2',
    number: '02',
    name: 'Evidence Correlation',
    subtitle: 'Graph Topology & GDS WCC Clustering',
    badge: 'Neo4j GDS Engine',
    color: '#8b5cf6',
    bg: 'rgba(139, 92, 246, 0.12)',
    border: 'rgba(139, 92, 246, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="18" cy="5" r="3"></circle>
        <circle cx="6" cy="12" r="3"></circle>
        <circle cx="18" cy="19" r="3"></circle>
        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
      </svg>
    )
  },
  agent3: {
    id: 'agent3',
    number: '03',
    name: 'Attack Reconstruction',
    subtitle: 'Kill-Chain Scoping & Attack Path Builder',
    badge: 'MITRE ATT&CK Matrix',
    color: '#06b6d4',
    bg: 'rgba(6, 182, 212, 0.12)',
    border: 'rgba(6, 182, 212, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
      </svg>
    )
  },
  agent4: {
    id: 'agent4',
    number: '04',
    name: 'Malware Behaviour',
    subtitle: 'Deterministic YARA, Sigma & Novel Anomaly',
    badge: 'YARA / Sigma Heuristics',
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.12)',
    border: 'rgba(245, 158, 11, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2a4 4 0 0 0-4 4v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2h-2V6a4 4 0 0 0-4-4z"></path>
        <circle cx="12" cy="14" r="2"></circle>
      </svg>
    )
  },
  agent5a: {
    id: 'agent5a',
    number: '05a',
    name: 'Threat Intelligence',
    subtitle: 'STIX/TAXII Threat Feeds & CVE/NVD Enrichment',
    badge: 'TAXII 2.1 Feeds',
    color: '#ec4899',
    bg: 'rgba(236, 72, 153, 0.12)',
    border: 'rgba(236, 72, 153, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="2" y1="12" x2="22" y2="12"></line>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
      </svg>
    )
  },
  agent5b: {
    id: 'agent5b',
    number: '05b',
    name: 'Campaign Similarity',
    subtitle: 'Vector Store RAG & Historical Incident Attribution',
    badge: 'Qdrant Vector RAG',
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
        <polyline points="2 17 12 22 22 17"></polyline>
        <polyline points="2 12 12 17 22 12"></polyline>
      </svg>
    )
  },
  agent6: {
    id: 'agent6',
    number: '06',
    name: 'Impact Assessment',
    subtitle: 'CVSS v3.1 Quantitative Math & Remediation',
    badge: 'ISS Severity Engine',
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.12)',
    border: 'rgba(239, 68, 68, 0.3)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
      </svg>
    )
  },
  agent7: {
    id: 'agent7',
    number: '07',
    name: 'Supervisor & NLI Gate',
    subtitle: 'Cross-Agent Synthesis & DeBERTa Verification',
    badge: 'DeBERTa-v3 MNLI Gate',
    color: '#6366f1',
    bg: 'rgba(99, 102, 241, 0.15)',
    border: 'rgba(99, 102, 241, 0.4)',
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
      </svg>
    )
  }
};

const AGENT_WORKFLOW_META = {
  agent1: {
    stageNumber: 1,
    stageCode: '01',
    roleLabel: 'Evidence Ingestion & Triage',
    inputs: 'Raw forensic artifacts & logs (PCAP, EVTX, RAM)',
    outputs: 'Normalized timeline, verified claims & trust score',
    nextAgent: 'Agent 02 (Evidence Correlation)'
  },
  agent2: {
    stageNumber: 2,
    stageCode: '02',
    roleLabel: 'Graph Topology & Clustering',
    inputs: 'Normalized evidence items from Agent 01',
    outputs: 'Neo4j GDS WCC graph clusters & entity links',
    nextAgent: 'Agent 03 (Attack Reconstruction)'
  },
  agent3: {
    stageNumber: 3,
    stageCode: '03',
    roleLabel: 'Kill-Chain Scoping & ATT&CK',
    inputs: 'Correlated entity clusters from Agent 02',
    outputs: 'MITRE ATT&CK progression & infection entry point',
    nextAgent: 'Agent 04 (Malware Behaviour)'
  },
  agent4: {
    stageNumber: 4,
    stageCode: '04',
    roleLabel: 'Malware Behavioral Profiling',
    inputs: 'Extracted binaries & suspicious execution paths',
    outputs: 'YARA/Sigma signatures & novel threat scores',
    nextAgent: 'Agents 05a & 05b (Threat Intel & Vector RAG)'
  },
  agent5a: {
    stageNumber: 5,
    stageCode: '05a',
    roleLabel: 'Threat Intelligence Feeds',
    inputs: 'IOC hashes, domains, IPs & CVE indicators',
    outputs: 'TAXII 2.1 threat actor & campaign enrichment',
    nextAgent: 'Agent 06 (Impact Assessment)'
  },
  agent5b: {
    stageNumber: 5,
    stageCode: '05b',
    roleLabel: 'Historical Vector RAG',
    inputs: 'Extracted TTPs & behavioral feature vectors',
    outputs: 'Qdrant vector similarity & campaign attribution',
    nextAgent: 'Agent 06 (Impact Assessment)'
  },
  agent6: {
    stageNumber: 6,
    stageCode: '06',
    roleLabel: 'CVSS Impact & Remediation',
    inputs: 'Attributed attack paths & affected asset lists',
    outputs: 'CVSS v3.1 base score, ISS index & recovery playbook',
    nextAgent: 'Agent 07 (Supervisor & NLI Gate)'
  },
  agent7: {
    stageNumber: 7,
    stageCode: '07',
    roleLabel: 'Supervisor Synthesis & NLI Gate',
    inputs: 'All accumulated claims & findings (Agents 01–06)',
    outputs: 'Executive incident synthesis & DeBERTa NLI verification',
    nextAgent: 'Final Executive FIR Report'
  }
};

const Agents = () => {
  const navigate = useNavigate();
  const [activeCaseId, setActiveCaseId] = useState(getActiveCaseId());
  const [activeCaseName, setActiveCaseName] = useState(getActiveCaseName());
  const [agentData, setAgentData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [runningAgents, setRunningAgents] = useState(false);
  const [selectedAgentTab, setSelectedAgentTab] = useState('agent7'); // default to supervisor
  const [activeViewMode, setActiveViewMode] = useState('pipeline'); // 'pipeline' | 'claims' | 'raw_json'
  const [claimsFilter, setClaimsFilter] = useState('all');
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem('argus_theme') || 'dark');
  const [caseDetails, setCaseDetails] = useState(null);
  const [availableCases, setAvailableCases] = useState([]);
  const [showCaseSelector, setShowCaseSelector] = useState(false);
  const [caseLock, setCaseLock] = useState(null);

  const currentUser = (() => {
    try {
      return JSON.parse(localStorage.getItem('argus_user'));
    } catch (_e) {
      return null;
    }
  })();

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
  };

  // Synchronize active case across tabs and components
  useEffect(() => {
    return subscribeToActiveCase(({ caseId, caseName }) => {
      setActiveCaseId(caseId);
      setActiveCaseName(caseName || caseId);
      setRunningAgents(false); // Cleanly terminate in-progress polling when case changes
      if (!caseId) {
        setAgentData(null);
        setCaseDetails(null);
        setLoading(false);
      }
    });
  }, []);

  // Synchronize case locking: ensure single active investigator and read-only mode for others
  useEffect(() => {
    if (activeCaseId) {
      syncCaseLock(activeCaseId).then(lock => {
        setCaseLock(lock);
      });
    } else {
      setCaseLock(null);
    }
  }, [activeCaseId]);

  useEffect(() => {
    return subscribeToCaseLock((updatedLock) => {
      setCaseLock(updatedLock);
    });
  }, []);

  // Fetch agent results safely, ensuring responses for an old case cannot overwrite newly selected case
  const loadAgentResults = async (caseId) => {
    if (!caseId) {
      setAgentData(null);
      setRunningAgents(false);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await fetchAgentResults(caseId);
      // Guard against race conditions: if active case changed while request was in flight, discard response
      if (getActiveCaseId() !== caseId) return;
      setAgentData(data);
      if (data && data.status === 'RUNNING') {
        setRunningAgents(true);
      } else {
        setRunningAgents(false);
      }
    } catch (err) {
      if (getActiveCaseId() !== caseId) return;
      console.error('Failed to fetch agent results:', err);
      setCustomAlert({
        isOpen: true,
        title: 'Error Fetching Agent Telemetry',
        message: err.message || 'Could not load multi-agent results for this case.',
        type: 'error'
      });
    } finally {
      if (getActiveCaseId() === caseId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchCases().then(res => {
      const list = res.data || (Array.isArray(res) ? res : []);
      setAvailableCases(list);
      if (activeCaseId) {
        const match = list.find(c => String(c.case_id) === String(activeCaseId) || String(c.id) === String(activeCaseId));
        if (match) setCaseDetails(match);
      }
    }).catch(() => {});
  }, [activeCaseId]);

  useEffect(() => {
    if (activeCaseId) {
      loadAgentResults(activeCaseId);
    } else {
      setCaseDetails(null);
    }
  }, [activeCaseId]);

  // Polling when analysis is running with bounded errors, visible user feedback, and overlap prevention
  useEffect(() => {
    let interval = null;
    let consecutiveErrors = 0;
    let isPolling = false; // Prevent overlapping polling cycles
    const MAX_CONSECUTIVE_ERRORS = 5;

    if (runningAgents && activeCaseId) {
      interval = setInterval(async () => {
        if (isPolling) return; // Skip cycle if previous request is still in-flight
        isPolling = true;
        try {
          const data = await fetchAgentResults(activeCaseId);
          // Discard if case changed or unmounted while in flight
          if (getActiveCaseId() !== activeCaseId) return;

          consecutiveErrors = 0;
          setAgentData(data);
          if (data.status !== 'RUNNING') {
            setRunningAgents(false);
            if (data.status === 'FAILED' || data.status === 'ERROR') {
              setCustomAlert({
                isOpen: true,
                title: '❌ Multi-Agent Analysis Failed',
                message: (typeof data.agent_errors === 'string' ? data.agent_errors : data.error_message) || `Multi-agent reasoning execution failed for Case ${activeCaseId}. Inspect error telemetry for details.`,
                type: 'error'
              });
            } else if (data.status === 'PARTIAL_SUCCESS') {
              setCustomAlert({
                isOpen: true,
                title: '⚠️ Multi-Agent Analysis Partial Success',
                message: `Analysis completed with warnings or degraded stages for Case ${activeCaseId}. Some agent outputs may be partial or require review.`,
                type: 'warning'
              });
            } else if (data.status === 'COMPLETED' || data.status === 'SUCCESS') {
              setCustomAlert({
                isOpen: true,
                title: '✅ Multi-Agent Analysis Complete',
                message: `Agents 1 through 7 finished processing Case ${activeCaseId}. Full findings, attack paths, and supervisor synthesis are now ready.`,
                type: 'success'
              });
            }
          }
        } catch (e) {
          if (getActiveCaseId() !== activeCaseId) return;
          consecutiveErrors += 1;
          console.error(`Polling error (${consecutiveErrors}/${MAX_CONSECUTIVE_ERRORS}):`, e);
          if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
            setRunningAgents(false);
            setCustomAlert({
              isOpen: true,
              title: '📡 Backend Polling Paused',
              message: `Lost connection to agent service after multiple attempts for Case ${activeCaseId}. Polling stopped to avoid unconstrained retries.`,
              type: 'error'
            });
          }
        } finally {
          isPolling = false;
        }
      }, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [runningAgents, activeCaseId]);

  const handleRunAnalysis = async () => {
    if (runningAgents || loading) return; // Prevent duplicate execution
    if (!activeCaseId) {
      setCustomAlert({
        isOpen: true,
        title: 'No Active Case',
        message: 'Please select an active case first before running the Multi-Agent Swarm.',
        type: 'warning'
      });
      return;
    }

    if (caseLock?.readOnly) {
      setCustomAlert({
        isOpen: true,
        title: '🔒 Case Locked (Read-Only Mode)',
        message: `Cannot launch multi-agent analysis. Case is currently being investigated by analyst ${caseLock.lockedBy?.name || 'another user'}. You have Read-Only access.`,
        type: 'warning'
      });
      return;
    }

    setRunningAgents(true);
    try {
      const res = await triggerAgentAnalysis(activeCaseId);
      setCustomAlert({
        isOpen: true,
        title: '🚀 Swarm Analysis Launched',
        message: res.message || 'Multi-agent reasoning swarm started in the background.',
        type: 'success'
      });
      // reload status
      loadAgentResults(activeCaseId);
    } catch (err) {
      console.error('Failed to run agents:', err);
      setRunningAgents(false);
      setCustomAlert({
        isOpen: true,
        title: 'Execution Failed',
        message: err.message || 'Could not launch multi-agent analysis.',
        type: 'error'
      });
    }
  };


  const closeAlert = () => setCustomAlert(prev => ({ ...prev, isOpen: false }));

  const stageStatuses = agentData?.stage_statuses || {};
  const currentAgent = AGENT_METADATA[selectedAgentTab] || AGENT_METADATA.agent7;
  const currentAgentData = agentData?.[selectedAgentTab] || {};

  // Swarm execution telemetry calculations
  const agentOrder = ['agent1', 'agent2', 'agent3', 'agent4', 'agent5a', 'agent5b', 'agent6', 'agent7'];
  const totalAgents = agentOrder.length;

  let completedCount = 0;
  let runningCount = 0;
  let failedCount = 0;
  let activeRunningAgent = null;

  agentOrder.forEach(key => {
    const st = (stageStatuses[key] || '').toUpperCase();
    if (st === 'COMPLETED' || st === 'SUCCESS') {
      completedCount += 1;
    } else if (st === 'RUNNING' || st === 'PROCESSING') {
      runningCount += 1;
      if (!activeRunningAgent) activeRunningAgent = AGENT_METADATA[key];
    } else if (st === 'FAILED') {
      failedCount += 1;
    }
  });

  let progressPercentage = 0;
  if (agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS' || completedCount === totalAgents) {
    progressPercentage = 100;
  } else if (runningAgents || runningCount > 0) {
    progressPercentage = Math.max(12, Math.round(((completedCount + 0.5) / totalAgents) * 100));
  } else if (completedCount > 0) {
    progressPercentage = Math.round((completedCount / totalAgents) * 100);
  }

  // Enhanced Status Pill with high-visibility icon & crystal glass style
  const renderStatusPill = (agentId) => {
    const st = (stageStatuses[agentId] || 'PENDING').toUpperCase();
    if (st === 'COMPLETED' || st === 'SUCCESS') {
      return (
        <span className="swarm-badge-pill swarm-badge-ready" title="Execution Completed & Verified">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
          <span>READY</span>
        </span>
      );
    }
    if (st === 'RUNNING' || st === 'PROCESSING') {
      return (
        <span className="swarm-badge-pill swarm-badge-running" title="Reasoning Engine In-Flight">
          <span className="swarm-radar-dot"></span>
          <span>RUNNING</span>
        </span>
      );
    }
    if (st === 'FAILED') {
      return (
        <span className="swarm-badge-pill swarm-badge-failed" title="Execution Failed">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          <span>FAILED</span>
        </span>
      );
    }
    return (
      <span className="swarm-badge-pill swarm-badge-pending" title="Awaiting upstream pipeline execution">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        <span>PENDING</span>
      </span>
    );
  };

  // Status helper (for test & sidebar backwards compatibility)
  const getAgentStatusBadge = (agentId) => {
    return renderStatusPill(agentId);
  };

  // Stage node renderer in workflow pipeline
  const renderStageNode = (agentId) => {
    const agent = AGENT_METADATA[agentId];
    if (!agent) return null;
    const isSelected = selectedAgentTab === agentId;
    const st = (stageStatuses[agentId] || 'PENDING').toUpperCase();
    const isCompleted = st === 'COMPLETED' || st === 'SUCCESS';
    const isRunning = st === 'RUNNING' || st === 'PROCESSING';
    const isFailed = st === 'FAILED';

    let statusClass = 'status-pending';
    if (isCompleted) statusClass = 'status-completed';
    else if (isRunning) statusClass = 'status-running';
    else if (isFailed) statusClass = 'status-failed';

    return (
      <div
        key={agentId}
        className={`swarm-stage-node ${isSelected ? 'is-active-tab' : ''} ${statusClass}`}
        onClick={() => setSelectedAgentTab(agentId)}
        title={`Stage ${agent.number}: ${agent.name} - Click to inspect live telemetry`}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setSelectedAgentTab(agentId);
          }
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{
            fontSize: 10,
            fontWeight: 900,
            color: agent.color,
            background: agent.bg,
            border: `1px solid ${agent.border}`,
            padding: '1px 6px',
            borderRadius: 6
          }}>
            {agent.number}
          </span>
          {renderStatusPill(agentId)}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ color: agent.color, flexShrink: 0, display: 'flex', alignItems: 'center' }}>
            {agent.icon}
          </div>
          <div style={{ overflow: 'hidden' }}>
            <div style={{ fontSize: 11.5, fontWeight: 800, color: 'var(--text-main)', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
              {agent.name}
            </div>
            <div style={{ fontSize: 9.5, color: 'var(--text-muted)', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
              {agent.badge}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Split node renderer for parallel stages 05a / 05b
  const renderSplitNode = (agentId) => {
    const agent = AGENT_METADATA[agentId];
    if (!agent) return null;
    const isSelected = selectedAgentTab === agentId;
    const st = (stageStatuses[agentId] || 'PENDING').toUpperCase();
    const isCompleted = st === 'COMPLETED' || st === 'SUCCESS';
    const isRunning = st === 'RUNNING' || st === 'PROCESSING';

    return (
      <div
        key={agentId}
        className={`swarm-split-node ${isSelected ? 'is-active-tab' : ''}`}
        style={{
          borderLeft: `3px solid ${agent.color}`,
          background: isSelected ? 'var(--glass-dash-surface-nested)' : 'var(--glass-dash-surface)'
        }}
        onClick={() => setSelectedAgentTab(agentId)}
        title={`Stage ${agent.number}: ${agent.name} - Click to inspect live telemetry`}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setSelectedAgentTab(agentId);
          }
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
          <span style={{ fontSize: 9.5, fontWeight: 900, color: agent.color }}>{agent.number}</span>
          <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {agent.name}
          </span>
        </div>
        <div>
          {renderStatusPill(agentId)}
        </div>
      </div>
    );
  };

  // Flow connector arrow renderer
  const renderConnector = (fromAgentId, toAgentId) => {
    const fromStatus = (stageStatuses[fromAgentId] || 'PENDING').toUpperCase();
    const toStatus = (stageStatuses[toAgentId] || 'PENDING').toUpperCase();
    const isPassed = fromStatus === 'COMPLETED' || fromStatus === 'SUCCESS';
    const isActive = toStatus === 'RUNNING' || toStatus === 'PROCESSING';

    let connClass = 'swarm-flow-connector';
    if (isActive) connClass += ' is-active';
    else if (isPassed) connClass += ' is-passed';

    return (
      <div className={connClass} title={`Data flow: ${fromAgentId} ➔ ${toAgentId}`}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <polyline points="9 18 15 12 9 6"></polyline>
        </svg>
      </div>
    );
  };

  const claimsList = agentData?.claims || [];
  const filteredClaims = claimsList.filter(c => {
    if (claimsFilter === 'all') return true;
    return c.agent_id === claimsFilter;
  });

  return (
    <div id="app-shell">
      <AlertModal
        isOpen={customAlert.isOpen}
        title={customAlert.title}
        message={customAlert.message}
        type={customAlert.type}
        onClose={closeAlert}
      />
      <Sidebar />

      <main className="main-content">
        {/* TOPBAR */}
        <header className="glass-topbar-capsule topbar">
          <div className="glass-topbar-left" style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', gap: '14px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ 
                  background: 'var(--glass-dash-blue-soft)', 
                  color: 'var(--glass-dash-blue)', 
                  border: '1px solid var(--glass-dash-blue-border)', 
                  padding: '2px 8px', 
                  borderRadius: '6px', 
                  fontSize: '10.5px', 
                  fontWeight: 800, 
                  letterSpacing: '0.05em' 
                }}>
                  ARGUS SWARM
                </span>
                <h2 className="glass-welcome-title" style={{ margin: 0, fontSize: '15px', fontWeight: 700 }}>
                  Multi-Agent Forensic Intelligence
                </h2>
              </div>
              <p className="glass-welcome-sub" style={{ margin: 0, fontSize: '11px', opacity: 0.75 }}>
                Autonomous reasoning pipeline, threat intelligence &amp; evidence verification
              </p>
            </div>

            {/* Active Case Badge with Dropdown Switcher */}
            <div style={{ position: 'relative' }}>
              <button
                type="button"
                onClick={() => setShowCaseSelector(!showCaseSelector)}
                style={{
                  background: 'var(--glass-dash-surface-nested)',
                  border: '1px solid var(--glass-dash-border-subtle)',
                  padding: '5px 14px',
                  borderRadius: '9999px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginLeft: '4px',
                  cursor: 'pointer',
                  color: 'inherit'
                }}
                title="Click to switch active investigation case"
              >
                <span style={{ fontSize: '11px', color: 'var(--glass-dash-blue)', textTransform: 'uppercase', fontWeight: 800 }}>Active Case:</span>
                <span style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--glass-dash-text-main)' }}>
                  {activeCaseId ? `${caseDetails?.name || activeCaseName} (${activeCaseId})` : 'Select Case ▾'}
                </span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
              </button>

              {showCaseSelector && (
                <>
                  <div
                    style={{ position: 'fixed', inset: 0, zIndex: 99 }}
                    onClick={() => setShowCaseSelector(false)}
                  />
                  <div className="swarm-case-select-dropdown" style={{ zIndex: 100 }}>
                    <div style={{ padding: '6px 8px', fontSize: 11, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Switch Active Investigation
                    </div>
                  {availableCases.length > 0 ? (
                    availableCases.map((c) => {
                      const cid = c.case_id || c.id;
                      const isCur = String(cid) === String(activeCaseId);
                      return (
                        <div
                          key={cid}
                          className={`swarm-case-item ${isCur ? 'is-selected' : ''}`}
                          onClick={() => {
                            setActiveCase(cid, c.name);
                            setShowCaseSelector(false);
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: 12.5, fontWeight: 700, color: isCur ? 'var(--blue)' : 'var(--text-main)' }}>
                              {c.name || 'Unnamed Case'}
                            </span>
                            <span style={{ fontSize: 10.5, fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                              {cid}
                            </span>
                          </div>
                          {c.description && (
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {c.description}
                            </div>
                          )}
                        </div>
                      );
                    })
                  ) : (
                    <div style={{ padding: '12px', textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
                      No cases found in workspace.
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>

          <div className="glass-topbar-right topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              onClick={handleRunAnalysis}
              disabled={runningAgents || loading || !activeCaseId}
              className="btn-primary"
              style={{
                fontSize: '12.5px',
                padding: '7px 16px',
                borderRadius: '10px',
                cursor: (runningAgents || loading || !activeCaseId || caseLock?.readOnly) ? 'not-allowed' : 'pointer',
                opacity: (runningAgents || loading || !activeCaseId || caseLock?.readOnly) ? 0.6 : 1,
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
              title={caseLock?.readOnly ? `Read-Only: Case is locked by ${caseLock.lockedBy?.name || 'another analyst'}` : 'Launch multi-agent analysis'}
            >
              {runningAgents ? (
                <>
                  <div className="live-dot" style={{ background: '#38bdf8' }}></div>
                  <span>Swarm Analyzing...</span>
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                  <span>{caseLock?.readOnly ? 'Read-Only Mode' : 'Run Multi-Agent Analysis'}</span>
                </>
              )}
            </button>

            {/* Theme Toggle */}
            <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Theme">
              {theme === 'dark' ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
              )}
            </button>

            <NotificationMenu />

            {/* User Profile Pill */}
            <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
              <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'U'}</div>
              <span className="glass-profile-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'Investigator'}</span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
              {showUserDropdown && (
                <div className="user-dropdown" style={{ display: 'block' }}>
                  <div className="user-dropdown-header">
                    <div className="ud-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'Investigator'}</div>
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

        {/* WORKSPACE CONTENT */}
        <div className="dashboard-scroll">
          {/* Case Lock Warning Banner */}
          <CaseLockBanner lockState={caseLock} caseId={activeCaseId} onLockRefreshed={setCaseLock} />

          {/* Active Case Details Header Card */}
          {activeCaseId ? (
            <div className="header-card" style={{ flexShrink: 0, padding: '24px 28px', borderRadius: '18px' }}>
              <div className="header-info-wrap" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
                <div className="header-id">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--glass-dash-blue)', fontWeight: 800 }}>ACTIVE INVESTIGATION CASE</span>
                    <span style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#38bdf8', padding: '2px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: 700, fontFamily: 'monospace' }}>
                      {activeCaseId}
                    </span>
                  </div>
                  <h1 id="dashboard-case-name" style={{ fontSize: '22px', fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                    {caseDetails?.name || activeCaseName || 'Unnamed Forensic Case'}
                  </h1>
                  <p id="dashboard-case-desc" style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '6px', marginBottom: 0, maxWidth: '750px' }}>
                    {caseDetails?.description || 'Active digital forensic case undergoing automated agent correlation, threat modeling, and evidence extraction.'}
                  </p>
                </div>

                <div className="header-meta" style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                  <div className="badge-danger" style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 14px', borderRadius: '9999px', fontSize: '12px', fontWeight: 700 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                    <span>{caseDetails?.severity ? `${caseDetails.severity.toUpperCase()} RISK` : 'ACTIVE ANALYSIS'}</span>
                  </div>
                  <div className="meta-item" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--glass-dash-blue)' }}><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                    <div>
                      <div style={{ fontSize: '10.5px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>Status</div>
                      <strong style={{ fontSize: '13px', color: 'var(--text-main)' }}>{caseDetails?.status ? caseDetails.status.toUpperCase() : 'IN PROGRESS'}</strong>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* Prompt to select a case when none is active */
            <div className="header-card" style={{ flexShrink: 0, padding: '24px 28px', borderRadius: '18px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                    <span style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', padding: '2px 8px', borderRadius: 6, fontSize: 11, fontWeight: 800 }}>
                      CASE SELECTION REQUIRED
                    </span>
                    <h2 style={{ fontSize: 18, fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                      Select an Active Investigation Case
                    </h2>
                  </div>
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--text-muted)', maxWidth: 640 }}>
                    Choose an active forensic case to run or view the autonomous multi-agent reasoning swarm, threat intelligence correlation, and DeBERTa verification matrix.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  {availableCases.length > 0 ? (
                    <select
                      style={{
                        background: 'var(--glass-dash-surface-nested)',
                        border: '1px solid var(--glass-dash-blue-border)',
                        color: 'var(--text-main)',
                        padding: '8px 14px',
                        borderRadius: 10,
                        fontSize: 12.5,
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                      onChange={(e) => {
                        const selected = availableCases.find(c => String(c.case_id || c.id) === e.target.value);
                        if (selected) {
                          setActiveCase(selected.case_id || selected.id, selected.name);
                        }
                      }}
                      defaultValue=""
                    >
                      <option value="" disabled>Choose a Case to Load...</option>
                      {availableCases.map(c => (
                        <option key={c.case_id || c.id} value={c.case_id || c.id}>
                          {c.name} ({c.case_id || c.id})
                        </option>
                      ))}
                    </select>
                  ) : (
                    <button className="btn-primary" onClick={() => navigate('/cases')}>
                      Browse Cases
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* MASTER AUTONOMOUS FORENSIC REASONING SWARM & WORKFLOW CONSOLE */}
          <div className="swarm-workflow-card" style={{ marginBottom: 18 }}>
            {/* Top Row: Title, Status, Description & Live Telemetry Metrics */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              flexWrap: 'wrap',
              gap: 16,
              marginBottom: 16
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                  <span style={{
                    background: 'var(--glass-dash-blue-soft)',
                    color: 'var(--glass-dash-blue)',
                    border: '1px solid var(--glass-dash-blue-border)',
                    padding: '2.5px 8.5px',
                    borderRadius: 6,
                    fontSize: 10.5,
                    fontWeight: 800,
                    letterSpacing: '0.06em'
                  }}>
                    SWARM PIPELINE DAG
                  </span>
                  <h1 style={{ fontSize: 19, fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                    Autonomous Forensic Reasoning Swarm
                  </h1>
                  <span style={{
                    background: (agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS') ? 'rgba(16, 185, 129, 0.16)' :
                                agentData?.status === 'PARTIAL_SUCCESS' ? 'rgba(245, 158, 11, 0.16)' :
                                (agentData?.status === 'FAILED' || agentData?.status === 'ERROR') ? 'rgba(239, 68, 68, 0.16)' :
                                'rgba(59, 130, 246, 0.16)',
                    color: (agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS') ? '#10b981' :
                           agentData?.status === 'PARTIAL_SUCCESS' ? '#f59e0b' :
                           (agentData?.status === 'FAILED' || agentData?.status === 'ERROR') ? '#ef4444' :
                           'var(--blue)',
                    border: `1px solid ${(agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS') ? '#10b981' :
                                        agentData?.status === 'PARTIAL_SUCCESS' ? '#f59e0b' :
                                        (agentData?.status === 'FAILED' || agentData?.status === 'ERROR') ? '#ef4444' :
                                        'var(--blue)'}`,
                    padding: '2.5px 10px',
                    borderRadius: 20,
                    fontSize: 10.5,
                    fontWeight: 800
                  }}>
                    {agentData?.status || 'READY'}
                  </span>
                  <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                    Case: <strong>{activeCaseId || 'None Selected'}</strong>
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-muted)', maxWidth: 760 }}>
                  Seven specialized AI agents continuously correlate artifact lineage, reconstruct MITRE ATT&amp;CK kill-chains, profile novel malware behaviors, query vector threat intelligence, and gate forensic claims through DeBERTa-v3 NLI verification.
                </p>
                {agentData?.agent_errors && (
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: 6,
                    padding: '6px 12px',
                    marginTop: 8,
                    fontSize: 12,
                    color: '#ef4444',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8
                  }}>
                    <span style={{ fontWeight: 800 }}>ANALYSIS NOTICE:</span>
                    <span>{typeof agentData.agent_errors === 'string' ? agentData.agent_errors : JSON.stringify(agentData.agent_errors)}</span>
                  </div>
                )}
              </div>

              {/* Quick Telemetry Capsule */}
              <div style={{
                display: 'flex',
                gap: 14,
                alignItems: 'center',
                background: 'var(--glass-dash-surface)',
                border: '1px solid var(--glass-dash-border-subtle)',
                padding: '8px 18px',
                borderRadius: 14
              }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Review Gate</div>
                  <div style={{ fontSize: 12.5, fontWeight: 800, color: agentData?.review_level === 'ROUTINE_ANALYST_REVIEW' ? '#10b981' : '#f59e0b', marginTop: 1 }}>
                    {agentData?.review_level || 'ROUTINE REVIEW'}
                  </div>
                </div>
                <div style={{ width: 1, height: 26, background: 'var(--border-strong)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>FIR Findings</div>
                  <div style={{ fontSize: 15, fontWeight: 900, color: 'var(--blue)', marginTop: 1 }}>
                    {agentData?.findings_count ?? 0}
                  </div>
                </div>
                <div style={{ width: 1, height: 26, background: 'var(--border-strong)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Claims</div>
                  <div style={{ fontSize: 15, fontWeight: 900, color: '#10b981', marginTop: 1 }}>
                    {claimsList.length}
                  </div>
                </div>
                <div style={{ width: 1, height: 26, background: 'var(--border-strong)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Progress</div>
                  <div style={{ fontSize: 15, fontWeight: 900, color: progressPercentage === 100 ? '#10b981' : 'var(--blue)', marginTop: 1 }}>
                    {progressPercentage}%
                  </div>
                </div>
              </div>
            </div>

            {/* Swarm Execution Progress Bar & Frontier Callout */}
            <div style={{ marginBottom: 16 }}>
              <div className="swarm-progress-bar-wrap">
                <div
                  className={`swarm-progress-bar-fill ${runningAgents ? 'is-running' : ''}`}
                  style={{
                    width: `${progressPercentage}%`,
                    background: progressPercentage === 100
                      ? 'linear-gradient(90deg, #10b981, #059669)'
                      : failedCount > 0
                      ? 'linear-gradient(90deg, #3b82f6, #ef4444)'
                      : 'linear-gradient(90deg, #3b82f6 0%, #06b6d4 40%, #10b981 100%)'
                  }}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8, fontSize: 11.5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 800, color: 'var(--text-muted)' }}>STATUS:</span>
                  {runningAgents ? (
                    <span style={{ color: '#0284c7', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span className="swarm-radar-dot"></span>
                      {activeRunningAgent ? `Reasoning In-Flight: Agent ${activeRunningAgent.number} (${activeRunningAgent.name})` : 'Swarm Reasoning In-Flight...'}
                    </span>
                  ) : progressPercentage === 100 ? (
                    <span style={{ color: '#10b981', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                      All 8 Agents Completed &amp; Verified
                    </span>
                  ) : failedCount > 0 ? (
                    <span style={{ color: '#ef4444', fontWeight: 800 }}>
                      Pipeline Degraded ({failedCount} Failed)
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>
                      Idle &amp; Ready for Execution ({completedCount} / {totalAgents} Agents Ready)
                    </span>
                  )}
                </div>

                <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                  Inspecting: <strong style={{ color: currentAgent.color }}>Agent {currentAgent.number} ({currentAgent.name})</strong>
                </div>
              </div>
            </div>

            {/* VISUAL WORKFLOW PIPELINE FLOWCHART */}
            <div className="swarm-pipeline-flow">
              {/* Stage 01: Evidence Intelligence */}
              {renderStageNode('agent1')}

              {/* Flow Connector */}
              {renderConnector('agent1', 'agent2')}

              {/* Stage 02: Evidence Correlation */}
              {renderStageNode('agent2')}

              {/* Flow Connector */}
              {renderConnector('agent2', 'agent3')}

              {/* Stage 03: Attack Reconstruction */}
              {renderStageNode('agent3')}

              {/* Flow Connector */}
              {renderConnector('agent3', 'agent4')}

              {/* Stage 04: Malware Behaviour */}
              {renderStageNode('agent4')}

              {/* Flow Connector into Fork */}
              {renderConnector('agent4', 'agent5a')}

              {/* Stage 05: Parallel Dual Branches (05a Threat Intel & 05b Vector RAG) */}
              <div className="swarm-split-stage">
                <div style={{ fontSize: 9.5, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', textAlign: 'center', marginBottom: 2 }}>
                  Stage 05 (Parallel)
                </div>
                {renderSplitNode('agent5a')}
                {renderSplitNode('agent5b')}
              </div>

              {/* Flow Connector from Fork */}
              {renderConnector('agent5a', 'agent6')}

              {/* Stage 06: Impact Assessment */}
              {renderStageNode('agent6')}

              {/* Flow Connector */}
              {renderConnector('agent6', 'agent7')}

              {/* Stage 07: Supervisor & NLI Gate */}
              {renderStageNode('agent7')}
            </div>
          </div>

          {/* VIEW MODE SELECTOR */}
          <div style={{ display: 'flex', gap: 10, borderBottom: '1px solid var(--glass-dash-border-subtle)', paddingBottom: 14 }}>
            <button
              onClick={() => setActiveViewMode('pipeline')}
              style={{
                background: activeViewMode === 'pipeline' ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.22) 0%, rgba(37, 99, 235, 0.12) 100%)' : 'var(--glass-dash-surface-nested)',
                color: activeViewMode === 'pipeline' ? 'var(--glass-dash-blue)' : 'var(--glass-dash-text-muted)',
                border: `1px solid ${activeViewMode === 'pipeline' ? 'var(--glass-dash-blue-border)' : 'var(--glass-dash-border-subtle)'}`,
                padding: '8px 18px',
                borderRadius: '9999px',
                fontSize: 12.5,
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
              }}
            >
              Swarm Architecture &amp; Deep-Dive
            </button>
            <button
              onClick={() => setActiveViewMode('claims')}
              style={{
                background: activeViewMode === 'claims' ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.22) 0%, rgba(37, 99, 235, 0.12) 100%)' : 'var(--glass-dash-surface-nested)',
                color: activeViewMode === 'claims' ? 'var(--glass-dash-blue)' : 'var(--glass-dash-text-muted)',
                border: `1px solid ${activeViewMode === 'claims' ? 'var(--glass-dash-blue-border)' : 'var(--glass-dash-border-subtle)'}`,
                padding: '8px 18px',
                borderRadius: '9999px',
                fontSize: 12.5,
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
              }}
            >
              Claims &amp; Evidence Ledger ({claimsList.length})
            </button>
            <button
              onClick={() => setActiveViewMode('raw_json')}
              style={{
                background: activeViewMode === 'raw_json' ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.22) 0%, rgba(37, 99, 235, 0.12) 100%)' : 'var(--glass-dash-surface-nested)',
                color: activeViewMode === 'raw_json' ? 'var(--glass-dash-blue)' : 'var(--glass-dash-text-muted)',
                border: `1px solid ${activeViewMode === 'raw_json' ? 'var(--glass-dash-blue-border)' : 'var(--glass-dash-border-subtle)'}`,
                padding: '8px 18px',
                borderRadius: '9999px',
                fontSize: 12.5,
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)'
              }}
            >
              Raw Swarm Telemetry (JSON)
            </button>
          </div>

          {/* VIEW 1: PIPELINE ARCHITECTURE TRACKER & AGENT DEEP DIVE */}
          {activeViewMode === 'pipeline' && (
            <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 20, alignItems: 'start' }}>

              {/* 7-AGENT SIDEBAR SELECTION */}
              <div role="tablist" aria-label="Agent Pipeline Hierarchy" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                  Agent Pipeline Hierarchy
                </div>

                {Object.values(AGENT_METADATA).map(agent => {
                  const isSelected = selectedAgentTab === agent.id;
                  return (
                    <div
                      key={agent.id}
                      id={`agent-tab-${agent.id}`}
                      role="tab"
                      tabIndex={0}
                      aria-selected={isSelected}
                      aria-controls={`agent-panel-${agent.id}`}
                      onClick={() => setSelectedAgentTab(agent.id)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          setSelectedAgentTab(agent.id);
                        }
                      }}
                      style={{
                        background: isSelected ? agent.bg : 'var(--glass-dash-surface-nested)',
                        border: `1px solid ${isSelected ? agent.color : 'var(--glass-dash-border-subtle)'}`,
                        borderRadius: 14,
                        padding: '12px 16px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        transition: 'all 0.2s ease',
                        boxShadow: isSelected ? `0 4px 12px ${agent.bg}` : 'none'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{
                          width: 32,
                          height: 32,
                          borderRadius: 10,
                          background: isSelected ? agent.color : 'var(--glass-dash-surface)',
                          color: isSelected ? '#fff' : agent.color,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: 12,
                          fontWeight: 900
                        }}>
                          {agent.number}
                        </div>
                        <div>
                          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)' }}>
                            {agent.name}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {agent.badge}
                          </div>
                        </div>
                      </div>

                      <div>{getAgentStatusBadge(agent.id)}</div>
                    </div>
                  );
                })}
              </div>

              {/* SELECTED AGENT DEEP DIVE CARD */}
              <div 
                role="tabpanel"
                id={`agent-panel-${selectedAgentTab}`}
                aria-labelledby={`agent-tab-${selectedAgentTab}`}
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 10,
                  padding: '24px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 20
                }}
              >
                {/* Workflow Step Context Breadcrumb */}
                <div className="swarm-breadcrumb-banner">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      background: currentAgent.bg,
                      color: currentAgent.color,
                      fontWeight: 900,
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 6
                    }}>
                      STAGE {currentAgent.number} OF 07
                    </span>
                    <span style={{ fontWeight: 700, color: 'var(--text-main)' }}>
                      {AGENT_WORKFLOW_META[selectedAgentTab]?.roleLabel || currentAgent.name}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)', fontSize: 11.5 }}>
                    <span><strong>Inputs:</strong> {AGENT_WORKFLOW_META[selectedAgentTab]?.inputs || 'Case Artifacts'}</span>
                    <span>➔</span>
                    <span><strong>Outputs to:</strong> {AGENT_WORKFLOW_META[selectedAgentTab]?.nextAgent || 'Supervisor'}</span>
                  </div>
                </div>

                {/* Agent Header Banner */}
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  borderBottom: '1px solid var(--border-subtle)',
                  paddingBottom: 16
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    <div style={{
                      width: 44,
                      height: 44,
                      borderRadius: 8,
                      background: currentAgent.bg,
                      color: currentAgent.color,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      {currentAgent.icon}
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <h2 style={{ fontSize: 18, fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                          Agent {currentAgent.number}: {currentAgent.name}
                        </h2>
                        <span style={{ background: currentAgent.bg, color: currentAgent.color, padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800 }}>
                          {currentAgent.badge}
                        </span>
                      </div>
                      <p style={{ margin: '4px 0 0 0', fontSize: 12.5, color: 'var(--text-muted)' }}>
                        {currentAgent.subtitle}
                      </p>
                    </div>
                  </div>

                  <div>{getAgentStatusBadge(currentAgent.id)}</div>
                </div>

                {/* Agent Error / Diagnostic Banner */}
                {(currentAgentData?.execution_status === 'FAILED' ||
                  stageStatuses[currentAgent.id] === 'FAILED' ||
                  currentAgentData?.error_message ||
                  currentAgentData?.error ||
                  (typeof agentData?.agent_errors === 'object' && agentData?.agent_errors?.[currentAgent.id])) && (
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.12)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    borderRadius: 8,
                    padding: '14px 18px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 6
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#ef4444', fontWeight: 800, fontSize: 13 }}>
                      <span>⚠️ AGENT EXECUTION FAILURE</span>
                      {currentAgentData?.failure_type && (
                        <span style={{ background: 'rgba(239, 68, 68, 0.25)', padding: '2px 6px', borderRadius: 4, fontSize: 11 }}>
                          {currentAgentData.failure_type}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 12.5, color: 'var(--text-main)', lineHeight: 1.5 }}>
                      {currentAgentData?.error_message ||
                       currentAgentData?.error ||
                       (typeof agentData?.agent_errors === 'object' ? agentData?.agent_errors?.[currentAgent.id] : agentData?.agent_errors) ||
                       `Agent ${currentAgent.number} experienced an execution failure during processing.`}
                    </div>
                  </div>
                )}

                {/* AGENT 7: SUPERVISOR & NLI VERIFICATION DEEP DIVE */}
                {selectedAgentTab === 'agent7' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                    {/* Synthesis Narrative Box */}
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--blue)', textTransform: 'uppercase', marginBottom: 8 }}>
                        Executive Incident Synthesis (Call 1)
                      </div>
                      <p style={{ fontSize: 14, lineHeight: 1.6, color: 'var(--text-main)', margin: 0 }}>
                        {currentAgentData.synthesis?.executive_summary ||
                          currentAgentData.synthesis?.summary ||
                          agentData?.supervisor_synthesis?.summary ||
                          'The multi-agent reasoning swarm synthesizes cross-source evidence across memory, filesystem, event logs, and network pcaps into an immutable executive report validated against ground truth.'}
                      </p>
                    </div>

                    {/* Confidence Gate & Calibrated Thresholds */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
                      <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 14 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Confidence Gate Rating</div>
                        <div style={{ fontSize: 22, fontWeight: 800, color: '#10b981', marginTop: 4 }}>
                          {(() => {
                            const score = currentAgentData.confidence_gate?.investigation_confidence_score ??
                                          agentData?.confidence_gate?.investigation_confidence_score ??
                                          currentAgentData.synthesis?.confidence_score;
                            return score !== undefined && score !== null ? `${Math.round(score * 100)}%` : 'N/A';
                          })()}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Calculated across verified premise pairs</div>
                      </div>

                      <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 14 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Verification Engine</div>
                        <div style={{ fontSize: 14, fontWeight: 800, color: 'var(--purple)', marginTop: 4 }}>
                          DeBERTa-v3-large-MNLI
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Independent verification call 2</div>
                      </div>

                      <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 14 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Analyst Action Level</div>
                        <div style={{ fontSize: 14, fontWeight: 800, color: '#38bdf8', marginTop: 4 }}>
                          {currentAgentData.review_level || agentData?.review_level || 'ROUTINE_ANALYST_REVIEW'}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Gated by automated threshold check</div>
                      </div>
                    </div>

                    {/* Verification Matrix Table */}
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                        DeBERTa NLI Entailment Verification Matrix
                      </div>
                      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                          <thead>
                            <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                              <th style={{ padding: '10px 14px' }}>Claim / Hypothesis</th>
                              <th style={{ padding: '10px 14px' }}>Source Agent</th>
                              <th style={{ padding: '10px 14px' }}>NLI Verification Status</th>
                              <th style={{ padding: '10px 14px' }}>Score</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(currentAgentData.verification || agentData?.verification_results || []).length > 0 ? (
                              (currentAgentData.verification || agentData?.verification_results || []).map((v, idx) => {
                                const isEntailed = (v.verdict || v.status || '').toLowerCase().includes('entail') || v.verified === true;
                                const isContradicted = (v.verdict || v.status || '').toLowerCase().includes('contradict');
                                const badgeBg = isEntailed ? 'rgba(16,185,129,0.15)' : (isContradicted ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)');
                                const badgeColor = isEntailed ? '#10b981' : (isContradicted ? '#ef4444' : '#f59e0b');
                                const badgeText = isEntailed ? (v.verdict || 'VERIFIED') : (isContradicted ? 'CONTRADICTED' : (v.verdict || v.verification_status || 'UNVERIFIED'));
                                return (
                                  <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                    <td style={{ padding: '10px 14px', color: 'var(--text-main)', maxWidth: 380 }}>{v.hypothesis || v.claim_text || v.claim || JSON.stringify(v)}</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--blue)', fontWeight: 700 }}>{v.agent_id || v.claim_id || 'N/A'}</td>
                                    <td style={{ padding: '10px 14px' }}>
                                      <span style={{
                                        background: badgeBg,
                                        color: badgeColor,
                                        padding: '2px 8px', borderRadius: 4, fontWeight: 700, fontSize: 11
                                      }}>
                                        {badgeText}
                                      </span>
                                    </td>
                                    <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--text-main)' }}>
                                      {(() => {
                                        const sc = v.support_score ?? v.confidence;
                                        return sc !== undefined && sc !== null ? `${Math.round(sc * 100)}%` : 'N/A';
                                      })()}
                                    </td>
                                  </tr>
                                );
                              })
                            ) : (
                              <tr>
                                <td colSpan="4" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                  No verification pairs recorded yet. Click &quot;Run Multi-Agent Analysis&quot; to execute DeBERTa NLI cross-verification.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* AGENT 1: EVIDENCE INTELLIGENCE */}
                {selectedAgentTab === 'agent1' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--blue)', textTransform: 'uppercase' }}>
                          Investigation Readiness &amp; Triage Assessment
                        </div>
                        {currentAgentData.investigation_readiness?.status && (
                          <span style={{
                            background: currentAgentData.investigation_readiness.status === 'READY' ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.15)',
                            color: currentAgentData.investigation_readiness.status === 'READY' ? '#10b981' : '#f59e0b',
                            padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800
                          }}>
                            {currentAgentData.investigation_readiness.status}
                          </span>
                        )}
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.investigation_readiness?.reason || currentAgentData.summary || 'Agent 1 analyzes evidence integrity, normalizes timeline timestamps, filters low-fidelity noise, and computes initial confidence weights across all ingested artifacts.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>TRIAGED FINDINGS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {currentAgentData.evidence_summary?.total_findings ?? currentAgentData.findings_ingested ?? currentAgentData.total_findings_processed ?? agentData?.findings_count ?? 0}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>EVIDENCE TRUST SCORE</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#10b981', marginTop: 4 }}>
                          {currentAgentData.evidence_trust_score !== undefined && currentAgentData.evidence_trust_score !== null ? `${Math.round(currentAgentData.evidence_trust_score * 100)}%` : 'N/A'}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>REASONING ENGINE</div>
                        <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-main)', marginTop: 4 }}>
                          {currentAgentData.model_used || 'Qwen3-8B Instruct'}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* AGENT 2: CORRELATION GRAPH */}
                {selectedAgentTab === 'agent2' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--purple)', textTransform: 'uppercase', marginBottom: 6 }}>
                        Cross-Source Correlation &amp; Neo4j Topology
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.summary || 'Constructs topological property graphs linking network sessions, registry run-keys, and EVTX authentication logs into correlated clusters using Graph Data Science Weakly Connected Components (WCC).'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>CORRELATION CLUSTERS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--purple)', marginTop: 4 }}>
                          {currentAgentData.graph?.components?.length ?? currentAgentData.correlation_signals?.temporal_clusters?.length ?? currentAgentData.clusters_preview ?? 0} Detected
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>CONNECTED ENTITIES</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {currentAgentData.graph?.node_count ?? currentAgentData.graph_nodes ?? 0} Nodes
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>RELATIONSHIPS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-main)', marginTop: 4 }}>
                          {currentAgentData.graph?.relationship_count ?? currentAgentData.relationships?.length ?? 0} Edges
                        </div>
                      </div>
                    </div>

                    {(currentAgentData.conflicts || []).length > 0 && (
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 800, color: '#ef4444', marginBottom: 8 }}>
                          Forensic Contradictions &amp; Timestamp Conflicts ({currentAgentData.conflicts.length})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                          {currentAgentData.conflicts.map((conf, i) => (
                            <div key={i} style={{ background: 'var(--bg-app)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, padding: '10px 14px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span style={{ fontWeight: 700, color: '#ef4444', fontSize: 13 }}>{conf.conflict_type}</span>
                                <span style={{ background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 800 }}>{conf.severity?.toUpperCase()}</span>
                              </div>
                              <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-main)' }}>{conf.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* AGENT 3: ATTACK RECONSTRUCTION */}
                {selectedAgentTab === 'agent3' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--teal)', textTransform: 'uppercase', marginBottom: 6 }}>
                        MITRE ATT&CK Kill-Chain Reconstruction
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.reconstruction_summary || currentAgentData.summary || currentAgentData.investigator_report || 'Rebuilds chronological attacker tradecraft progression from Initial Access to Defense Evasion and Impact.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>TACTIC PHASES DETECTED</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#06b6d4', marginTop: 4 }}>
                          {currentAgentData.attack_chain?.length ?? (currentAgentData.mitre_tactics || []).length ?? 0} Tactics
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>ATTACK STEPS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-main)', marginTop: 4 }}>
                          {currentAgentData.attack_path?.length ?? currentAgentData.attack_steps_projected ?? 0} Steps
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>RECONSTRUCTION CONFIDENCE</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#10b981', marginTop: 4 }}>
                          {currentAgentData.overall_confidence !== undefined && currentAgentData.overall_confidence !== null ? `${Math.round(currentAgentData.overall_confidence * 100)}%` : 'N/A'}
                        </div>
                      </div>
                    </div>

                    {currentAgentData.infection_path?.entry_point && (
                      <div style={{ background: 'rgba(6, 182, 212, 0.08)', border: '1px solid rgba(6, 182, 212, 0.25)', borderRadius: 6, padding: '10px 14px' }}>
                        <div style={{ fontSize: 11, fontWeight: 800, color: '#06b6d4', textTransform: 'uppercase' }}>Infection Entry Point</div>
                        <div style={{ fontSize: 13, color: 'var(--text-main)', marginTop: 2 }}>{currentAgentData.infection_path.entry_point}</div>
                      </div>
                    )}

                    {(currentAgentData.attack_path || []).length > 0 && (
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                          Step-by-Step Attack Path
                        </div>
                        <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                            <thead>
                              <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                                <th style={{ padding: '8px 12px' }}>Step</th>
                                <th style={{ padding: '8px 12px' }}>Kill-Chain Stage</th>
                                <th style={{ padding: '8px 12px' }}>Description</th>
                                <th style={{ padding: '8px 12px' }}>Evidence IDs</th>
                              </tr>
                            </thead>
                            <tbody>
                              {currentAgentData.attack_path.map((step, idx) => (
                                <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                  <td style={{ padding: '8px 12px', fontWeight: 800, color: '#06b6d4' }}>{step.step_number || idx + 1}</td>
                                  <td style={{ padding: '8px 12px', fontWeight: 700, color: 'var(--text-main)' }}>{step.stage}</td>
                                  <td style={{ padding: '8px 12px', color: 'var(--text-main)' }}>{step.description}</td>
                                  <td style={{ padding: '8px 12px', color: 'var(--blue)', fontFamily: 'monospace', fontSize: 11 }}>
                                    {(step.evidence_ids && step.evidence_ids.length > 0) ? step.evidence_ids.map(id => formatEvidenceId(id)).join(', ') : 'None'}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* AGENT 4: MALWARE BEHAVIOUR */}
                {selectedAgentTab === 'agent4' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                    <div style={{
                      background: 'var(--bg-app)',
                      border: '1px solid var(--border-strong)',
                      borderRadius: 8,
                      padding: 18,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 12
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                        <div style={{ fontSize: 12, fontWeight: 800, color: '#f59e0b', textTransform: 'uppercase' }}>
                          Malware Behavioral Profile &amp; Classification
                        </div>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                          {currentAgentData.novel_threat_detected && (
                            <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '1px solid #ef4444', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800 }}>
                              NOVEL THREAT DETECTED (Score: {currentAgentData.novelty_score || 'N/A'})
                            </span>
                          )}
                          <span style={{
                            background: (currentAgentData.threat_classification?.classification || '').toLowerCase() === 'malicious' ? 'rgba(239, 68, 68, 0.2)' :
                                        (currentAgentData.threat_classification?.classification || '').toLowerCase() === 'suspicious' ? 'rgba(245, 158, 11, 0.2)' :
                                        (currentAgentData.threat_classification?.classification || '').toLowerCase() === 'benign' ? 'rgba(16, 185, 129, 0.2)' :
                                        'rgba(59, 130, 246, 0.2)',
                            color: (currentAgentData.threat_classification?.classification || '').toLowerCase() === 'malicious' ? '#ef4444' :
                                   (currentAgentData.threat_classification?.classification || '').toLowerCase() === 'suspicious' ? '#f59e0b' :
                                   (currentAgentData.threat_classification?.classification || '').toLowerCase() === 'benign' ? '#10b981' :
                                   'var(--blue)',
                            padding: '3px 10px',
                            borderRadius: 4,
                            fontSize: 11.5,
                            fontWeight: 800,
                            textTransform: 'uppercase'
                          }}>
                            {currentAgentData.threat_classification?.classification || 'UNCLASSIFIED'}
                          </span>
                        </div>
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.threat_classification?.reason ||
                         currentAgentData.threat_classification?.classification_reason ||
                         currentAgentData.summary ||
                         'Analyzes observed process execution, memory injections, registry modifications, and YARA signatures to construct behavioral capability profiles.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>BEHAVIOR OBSERVATIONS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#f59e0b', marginTop: 4 }}>
                          {currentAgentData.behavior_observations?.length ?? 0}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>YARA MATCHES</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {currentAgentData.yara_matches?.length ?? currentAgentData.deterministic_findings?.length ?? 0}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>PERSISTENCE STATUS</div>
                        <div style={{ fontSize: 14, fontWeight: 800, color: 'var(--text-main)', marginTop: 4 }}>
                          {currentAgentData.persistence_status || 'NOT_PERSISTED'}
                        </div>
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                        Observed Forensic Behaviors
                      </div>
                      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                          <thead>
                            <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                              <th style={{ padding: '10px 14px' }}>Category</th>
                              <th style={{ padding: '10px 14px' }}>Action</th>
                              <th style={{ padding: '10px 14px' }}>Target / Subject</th>
                              <th style={{ padding: '10px 14px' }}>Cited Evidence</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(currentAgentData.behavior_observations || []).length > 0 ? (
                              currentAgentData.behavior_observations.map((obs, idx) => (
                                <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                  <td style={{ padding: '10px 14px', fontWeight: 700, color: '#f59e0b' }}>{obs.category || 'Behavior'}</td>
                                  <td style={{ padding: '10px 14px', color: 'var(--text-main)' }}>{obs.action || 'Observed action'}</td>
                                  <td style={{ padding: '10px 14px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{obs.subject || obs.target || 'N/A'}</td>
                                  <td style={{ padding: '10px 14px', color: 'var(--blue)', fontFamily: 'monospace', fontSize: 11 }}>
                                    {(obs.evidence_ids && obs.evidence_ids.length > 0) ? obs.evidence_ids.map(id => formatEvidenceId(id)).join(', ') : 'None'}
                                  </td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan="4" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                  No behavioral observations recorded for this case.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {(currentAgentData.yara_matches?.length > 0 || currentAgentData.deterministic_findings?.length > 0) && (
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                          YARA &amp; Deterministic Signatures
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                          {(currentAgentData.yara_matches || currentAgentData.deterministic_findings || []).map((ym, i) => (
                            <div key={i} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div>
                                <span style={{ fontWeight: 700, color: 'var(--text-main)', fontSize: 13 }}>{ym.rule_name || ym.rule || ym.finding_id || `Signature #${i+1}`}</span>
                                <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>{ym.description || ym.namespace || ''}</span>
                              </div>
                              <span style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>
                                MATCHED
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* AGENT 5A: THREAT INTELLIGENCE */}
                {selectedAgentTab === 'agent5a' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#ec4899', textTransform: 'uppercase', marginBottom: 6 }}>
                        STIX / TAXII Global Threat Intelligence Enrichment
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.reasoning_summary || currentAgentData.claim || 'Correlates observed IOCs, CVEs, and MITRE techniques against TAXII feeds, CISA Known Exploited Vulnerabilities (KEV), and global threat feeds.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>IOC MATCHES</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#ec4899', marginTop: 4 }}>
                          {currentAgentData.ioc_matches?.length ?? 0}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>CVE / VULN MATCHES</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {(currentAgentData.cve_references?.length ?? 0) + (currentAgentData.vulnerability_matches?.length ?? 0)}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>INTELLIGENCE CONFIDENCE</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#10b981', marginTop: 4 }}>
                          {currentAgentData.confidence !== undefined && currentAgentData.confidence !== null ? `${Math.round(currentAgentData.confidence * 100)}%` : 'N/A'}
                        </div>
                      </div>
                    </div>

                    {(currentAgentData.candidate_malware_families?.length > 0) && (
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                          Candidate Malware Families Identified
                        </div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          {currentAgentData.candidate_malware_families.map((fam, i) => (
                            <span key={i} style={{ background: 'rgba(236, 72, 153, 0.15)', color: '#ec4899', border: '1px solid rgba(236, 72, 153, 0.3)', padding: '4px 10px', borderRadius: 4, fontSize: 12, fontWeight: 700 }}>
                              {fam}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                        Threat Intel Enriched Matches (IOC / MITRE / CVE)
                      </div>
                      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                          <thead>
                            <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                              <th style={{ padding: '10px 14px' }}>Indicator / Reference</th>
                              <th style={{ padding: '10px 14px' }}>Threat Actor / Family</th>
                              <th style={{ padding: '10px 14px' }}>Severity</th>
                              <th style={{ padding: '10px 14px' }}>Cited Evidence</th>
                            </tr>
                          </thead>
                          <tbody>
                            {((currentAgentData.ioc_matches || []).concat(currentAgentData.mitre_mappings || []).concat(currentAgentData.cve_references || [])).length > 0 ? (
                              (currentAgentData.ioc_matches || []).concat(currentAgentData.mitre_mappings || []).concat(currentAgentData.cve_references || []).map((m, idx) => (
                                <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                  <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--text-main)', fontFamily: 'monospace' }}>
                                    {m.indicator_value || m.technique_id || m.cve_id || m.name || m.value || 'N/A'}
                                  </td>
                                  <td style={{ padding: '10px 14px', color: '#ec4899' }}>{m.threat_actor || m.malware_family || 'N/A'}</td>
                                  <td style={{ padding: '10px 14px' }}>
                                    <span style={{
                                      background: (m.severity || '').toLowerCase() === 'high' || (m.severity || '').toLowerCase() === 'critical' ? 'rgba(239,68,68,0.15)' : 'rgba(59,130,246,0.15)',
                                      color: (m.severity || '').toLowerCase() === 'high' || (m.severity || '').toLowerCase() === 'critical' ? '#ef4444' : 'var(--blue)',
                                      padding: '2px 8px', borderRadius: 4, fontWeight: 700, fontSize: 11
                                    }}>
                                      {m.severity || 'INFORMATIONAL'}
                                    </span>
                                  </td>
                                  <td style={{ padding: '10px 14px', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: 11 }}>
                                    {(m.evidence_ids && m.evidence_ids.length > 0) ? m.evidence_ids.map(id => formatEvidenceId(id)).join(', ') : 'None Cited'}
                                  </td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan="4" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                  No enriched threat intelligence matches found for current indicators.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* AGENT 5B: CAMPAIGN SIMILARITY */}
                {selectedAgentTab === 'agent5b' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#10b981', textTransform: 'uppercase', marginBottom: 6 }}>
                        Historical Incident Vector RAG &amp; Campaign Attribution
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.claim || 'Retrieves nearest-neighbor historical forensic incidents using dense vector embeddings and computes multi-factor similarity across behaviors, attack paths, and threat actor TTPs.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>COMPOSITE SIMILARITY</div>
                        <div style={{ fontSize: 22, fontWeight: 800, color: '#10b981', marginTop: 4 }}>
                          {currentAgentData.historical_similarity?.composite_similarity !== undefined && currentAgentData.historical_similarity?.composite_similarity !== null ?
                            `${Math.round(currentAgentData.historical_similarity.composite_similarity * 100)}%` : 'N/A'}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Multi-factor weighted score</div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>BEHAVIOR SIMILARITY</div>
                        <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {currentAgentData.historical_similarity?.behavior_similarity !== undefined && currentAgentData.historical_similarity?.behavior_similarity !== null ?
                            `${Math.round(currentAgentData.historical_similarity.behavior_similarity * 100)}%` : 'N/A'}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>ATTACK PATH SIMILARITY</div>
                        <div style={{ fontSize: 18, fontWeight: 800, color: 'var(--purple)', marginTop: 4 }}>
                          {currentAgentData.historical_similarity?.attack_similarity !== undefined && currentAgentData.historical_similarity?.attack_similarity !== null ?
                            `${Math.round(currentAgentData.historical_similarity.attack_similarity * 100)}%` : 'N/A'}
                        </div>
                      </div>
                    </div>

                    <div style={{
                      background: 'rgba(59, 130, 246, 0.08)',
                      border: '1px solid rgba(59, 130, 246, 0.25)',
                      borderRadius: 6,
                      padding: '10px 14px',
                      fontSize: 12,
                      color: 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10
                    }}>
                      <span style={{ fontWeight: 800, color: 'var(--blue)' }}>ATTRIBUTION SAFEGUARD:</span>
                      <span>
                        {currentAgentData.historical_similarity?.possible_actor_context?.[0]?.attribution_caveat ||
                         'Contextual profiling only. Historical similarity provides reference intelligence and does not assert definitive legal or forensic actor attribution.'}
                      </span>
                    </div>

                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                        Correlated Historical Campaigns &amp; Families
                      </div>
                      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                          <thead>
                            <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                              <th style={{ padding: '10px 14px' }}>Campaign / Family Name</th>
                              <th style={{ padding: '10px 14px' }}>Historical Case ID</th>
                              <th style={{ padding: '10px 14px' }}>Similarity Score</th>
                              <th style={{ padding: '10px 14px' }}>Overlapping Characteristics</th>
                            </tr>
                          </thead>
                          <tbody>
                            {((currentAgentData.historical_similarity?.similar_campaigns || []).length > 0 || (currentAgentData.historical_similarity?.similar_malware_families || []).length > 0) ? (
                              <>
                                {(currentAgentData.historical_similarity?.similar_campaigns || []).map((sc, idx) => (
                                  <tr key={`camp-${idx}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                    <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--text-main)' }}>{sc.campaign_name}</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--blue)', fontFamily: 'monospace' }}>{sc.historical_case_id}</td>
                                    <td style={{ padding: '10px 14px', fontWeight: 700, color: '#10b981' }}>{Math.round(sc.similarity_score * 100)}%</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>{(sc.overlapping_techniques || []).join(', ') || 'TTP Alignment'}</td>
                                  </tr>
                                ))}
                                {(currentAgentData.historical_similarity?.similar_malware_families || []).map((mf, idx) => (
                                  <tr key={`fam-${idx}`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                    <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--text-main)' }}>{mf.family_name}</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--blue)', fontFamily: 'monospace' }}>{mf.historical_case_id}</td>
                                    <td style={{ padding: '10px 14px', fontWeight: 700, color: '#10b981' }}>{Math.round(mf.similarity_score * 100)}%</td>
                                    <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>{(mf.supporting_behaviors || []).join(', ') || 'Behavioral Match'}</td>
                                  </tr>
                                ))}
                              </>
                            ) : (
                              <tr>
                                <td colSpan="4" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                  No historical campaigns matched above similarity threshold.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* AGENT 6: IMPACT ASSESSMENT */}
                {selectedAgentTab === 'agent6' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#ef4444', textTransform: 'uppercase', marginBottom: 6 }}>
                        Quantitative Impact &amp; Severity Assessment
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.iss_assessment?.executive_summary ||
                         currentAgentData.explanation ||
                         currentAgentData.claim ||
                         'Computes deterministic CVSS v3.1 technical vulnerability scores alongside the multidimensional ARGUS Investigation Severity Score (ISS) and generates prioritized operational recovery checklists.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 14 }}>
                      <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>CVSS v3.1 Base Score</div>
                          <span style={{
                            background: (currentAgentData.cvss_assessment?.severity || '').toLowerCase() === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                                        (currentAgentData.cvss_assessment?.severity || '').toLowerCase() === 'high' ? 'rgba(245, 158, 11, 0.2)' :
                                        'rgba(59, 130, 246, 0.2)',
                            color: (currentAgentData.cvss_assessment?.severity || '').toLowerCase() === 'critical' ? '#ef4444' :
                                   (currentAgentData.cvss_assessment?.severity || '').toLowerCase() === 'high' ? '#f59e0b' :
                                   'var(--blue)',
                            padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800
                          }}>
                            {currentAgentData.cvss_assessment?.severity || 'UNDETERMINED'}
                          </span>
                        </div>
                        <div style={{ fontSize: 26, fontWeight: 900, color: '#ef4444', marginTop: 6 }}>
                          {currentAgentData.cvss_assessment?.base_score !== undefined && currentAgentData.cvss_assessment?.base_score !== null ? currentAgentData.cvss_assessment.base_score : 'N/A'}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: 4, wordBreak: 'break-all' }}>
                          {currentAgentData.cvss_assessment?.vector_string || 'No CVSS Vector Computed'}
                        </div>
                      </div>

                      <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>ARGUS ISS Severity</div>
                          <span style={{
                            background: (currentAgentData.iss_assessment?.severity || '').toLowerCase() === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                                        (currentAgentData.iss_assessment?.severity || '').toLowerCase() === 'high' ? 'rgba(245, 158, 11, 0.2)' :
                                        'rgba(16, 185, 129, 0.2)',
                            color: (currentAgentData.iss_assessment?.severity || '').toLowerCase() === 'critical' ? '#ef4444' :
                                   (currentAgentData.iss_assessment?.severity || '').toLowerCase() === 'high' ? '#f59e0b' :
                                   '#10b981',
                            padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 800
                          }}>
                            {currentAgentData.iss_assessment?.severity || 'MEDIUM'}
                          </span>
                        </div>
                        <div style={{ fontSize: 26, fontWeight: 900, color: '#f59e0b', marginTop: 6 }}>
                          {currentAgentData.iss_assessment?.iss_score !== undefined && currentAgentData.iss_assessment?.iss_score !== null ? currentAgentData.iss_assessment.iss_score : 'N/A'}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                          Compromised Assets: {currentAgentData.total_assets_affected || currentAgentData.affected_assets?.length || 0}
                        </div>
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                        Affected Assets &amp; Compromise State Inventory
                      </div>
                      <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                          <thead>
                            <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                              <th style={{ padding: '10px 14px' }}>Asset ID / Name</th>
                              <th style={{ padding: '10px 14px' }}>Type</th>
                              <th style={{ padding: '10px 14px' }}>Criticality</th>
                              <th style={{ padding: '10px 14px' }}>Compromise State</th>
                              <th style={{ padding: '10px 14px' }}>Cited Evidence</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(currentAgentData.affected_assets || []).length > 0 ? (
                              currentAgentData.affected_assets.map((asset, idx) => (
                                <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                  <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--text-main)', fontFamily: 'monospace' }}>
                                    {asset.asset_id}
                                  </td>
                                  <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>{asset.asset_type || 'UNKNOWN'}</td>
                                  <td style={{ padding: '10px 14px', fontWeight: 700, color: asset.criticality === 'CRITICAL' ? '#ef4444' : 'var(--blue)' }}>
                                    {asset.criticality || 'MEDIUM'}
                                  </td>
                                  <td style={{ padding: '10px 14px' }}>
                                    <span style={{
                                      background: (asset.compromise_state || '').includes('CONFIRMED') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                                      color: (asset.compromise_state || '').includes('CONFIRMED') ? '#ef4444' : '#f59e0b',
                                      padding: '2px 8px', borderRadius: 4, fontWeight: 700, fontSize: 11
                                    }}>
                                      {asset.compromise_state || 'SUSPECTED'}
                                    </span>
                                  </td>
                                  <td style={{ padding: '10px 14px', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: 11 }}>
                                    {(asset.evidence_ids && asset.evidence_ids.length > 0) ? asset.evidence_ids.map(id => formatEvidenceId(id)).join(', ') : 'None'}
                                  </td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan="5" style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                                  No compromised or targeted assets recorded.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {((currentAgentData.recovery_checklist?.containment_steps || []).length > 0 ||
                      (currentAgentData.recovery_checklist?.eradication_steps || []).length > 0 ||
                      (currentAgentData.recovery_actions || []).length > 0) && (
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-main)', marginBottom: 8 }}>
                          Prioritized Operational Recovery Checklist
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                          {((currentAgentData.recovery_checklist?.containment_steps || [])
                            .concat(currentAgentData.recovery_checklist?.eradication_steps || [])
                            .concat(currentAgentData.recovery_checklist?.recovery_steps || [])
                            .concat(currentAgentData.recovery_actions || [])
                          ).map((action, i) => (
                            <div key={i} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <div>
                                <span style={{ background: action.priority === 'P1_IMMEDIATE' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)', color: action.priority === 'P1_IMMEDIATE' ? '#ef4444' : 'var(--blue)', padding: '2px 6px', borderRadius: 4, fontSize: 10, fontWeight: 800, marginRight: 8 }}>
                                  {action.priority || 'P2_HIGH'}
                                </span>
                                <span style={{ fontWeight: 700, color: 'var(--text-main)', fontSize: 13 }}>{action.title}</span>
                                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{action.description || ''}</div>
                              </div>
                              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>
                                Role: {action.responsible_role || 'SOC_L2'}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

              </div>
            </div>
          )}

          {/* VIEW 2: ALL VERIFIED CLAIMS LEDGER */}
          {activeViewMode === 'claims' && (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 24 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
                <div>
                  <h3 style={{ fontSize: 16, fontWeight: 800, margin: '0 0 4px 0', color: 'var(--text-main)' }}>
                    Claims &amp; Evidence Provenance Ledger
                  </h3>
                  <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-muted)' }}>
                    Atomic claims verified by Agent 1-7 reasoning engines with cited source evidence hashes.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {['all', 'agent1', 'agent2', 'agent3', 'agent4', 'agent5a', 'agent5b', 'agent6', 'agent7'].map(aKey => (
                    <button
                      key={aKey}
                      onClick={() => setClaimsFilter(aKey)}
                      style={{
                        background: claimsFilter === aKey ? 'var(--blue)' : 'var(--bg-app)',
                        color: claimsFilter === aKey ? '#fff' : 'var(--text-muted)',
                        border: '1px solid var(--border-strong)',
                        padding: '4px 12px',
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        cursor: 'pointer',
                        textTransform: 'uppercase'
                      }}
                    >
                      {aKey}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ overflowX: 'auto', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, textAlign: 'left' }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-app)', borderBottom: '1px solid var(--border-strong)', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '10px 14px' }}>Agent</th>
                      <th style={{ padding: '10px 14px' }}>Claim / Reasoning Deduction</th>
                      <th style={{ padding: '10px 14px' }}>Evidence References</th>
                      <th style={{ padding: '10px 14px' }}>Confidence</th>
                      <th style={{ padding: '10px 14px' }}>Verification</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredClaims.length > 0 ? (
                      filteredClaims.map((c, i) => (
                        <tr key={c.id || i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '12px 14px', fontWeight: 800, color: 'var(--blue)', whiteSpace: 'nowrap' }}>
                            {c.agent_id}
                          </td>
                          <td style={{ padding: '12px 14px', color: 'var(--text-main)', maxWidth: 420 }}>
                            {c.claim}
                          </td>
                          <td style={{ padding: '12px 14px', color: 'var(--text-muted)', fontSize: 11, fontFamily: 'monospace' }}>
                            {(c.evidence_ids && c.evidence_ids.length > 0) ? c.evidence_ids.slice(0, 3).map(id => formatEvidenceId(id)).join(', ') : 'None Cited'}
                          </td>
                          <td style={{ padding: '12px 14px', fontWeight: 700, color: 'var(--text-main)' }}>
                            {c.confidence !== undefined && c.confidence !== null ? `${Math.round(c.confidence * 100)}%` : 'N/A'}
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            <span style={{
                              background: c.verified ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                              color: c.verified ? '#10b981' : '#f59e0b',
                              padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700
                            }}>
                              {c.verified ? 'VERIFIED' : 'UNVERIFIED'}
                            </span>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5" style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          No claims recorded yet for this filter. Run the swarm analysis to populate the ledger.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* VIEW 3: RAW JSON */}
          {activeViewMode === 'raw_json' && (
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 24 }}>
              <pre style={{
                margin: 0,
                fontSize: 12,
                fontFamily: 'var(--argus-mono, monospace)',
                color: '#38bdf8',
                background: 'var(--bg-app)',
                padding: 16,
                borderRadius: 8,
                overflowX: 'auto',
                maxHeight: 520
              }}>
                {JSON.stringify(agentData, null, 2)}
              </pre>
            </div>
          )}

        </div>
      </main>
    </div>
  );
};

export default Agents;
