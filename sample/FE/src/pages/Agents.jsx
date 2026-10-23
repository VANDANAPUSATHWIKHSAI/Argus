import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { fetchAgentResults, triggerAgentAnalysis } from '../js/api';
import { formatEvidenceId } from '../js/dateUtils';
import { getActiveCaseId, getActiveCaseName, subscribeToActiveCase } from '../js/caseEvents';
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

const Agents = () => {
  const [activeCaseId, setActiveCaseId] = useState(getActiveCaseId());
  const [activeCaseName, setActiveCaseName] = useState(getActiveCaseName());
  const [agentData, setAgentData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [runningAgents, setRunningAgents] = useState(false);
  const [selectedAgentTab, setSelectedAgentTab] = useState('agent7'); // default to supervisor
  const [activeViewMode, setActiveViewMode] = useState('pipeline'); // 'pipeline' | 'claims' | 'raw_json'
  const [claimsFilter, setClaimsFilter] = useState('all');
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });

  // Synchronize active case across tabs and components
  useEffect(() => {
    return subscribeToActiveCase(({ caseId, caseName }) => {
      setActiveCaseId(caseId);
      setActiveCaseName(caseName || caseId);
      setRunningAgents(false); // Cleanly terminate in-progress polling when case changes
      if (!caseId) {
        setAgentData(null);
        setLoading(false);
      }
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
    if (activeCaseId) {
      loadAgentResults(activeCaseId);
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

  // Status helper
  const getAgentStatusBadge = (agentId) => {
    const st = (stageStatuses[agentId] || 'PENDING').toUpperCase();
    if (st === 'COMPLETED' || st === 'SUCCESS') {
      return <span style={{ background: '#10b981', color: '#090d16', padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 800 }}>READY</span>;
    }
    if (st === 'RUNNING' || st === 'PROCESSING') {
      return <span style={{ background: '#38bdf8', color: '#090d16', padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 800 }}>RUNNING</span>;
    }
    if (st === 'FAILED') {
      return <span style={{ background: '#ef4444', color: '#ffffff', padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 800 }}>FAILED</span>;
    }
    return <span style={{ background: 'var(--border-strong)', color: 'var(--text-muted)', padding: '3px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700 }}>PENDING</span>;
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

      <main className="main-content" style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
        {/* TOPBAR */}
        <header className="topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.2))',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              borderRadius: 8,
              padding: '6px 12px',
              display: 'flex',
              alignItems: 'center',
              gap: 8
            }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: 'var(--blue)', letterSpacing: '0.05em' }}>ARGUS SWARM</span>
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)' }}>Multi-Agent Forensic Intelligence</span>
            </div>

            {/* Active Case Badge */}
            <div style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-strong)',
              padding: '6px 14px',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              gap: 8
            }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Active Case:</span>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)' }}>
                {activeCaseId ? `${activeCaseName} (${activeCaseId})` : 'No Active Case'}
              </span>
            </div>
          </div>

          <div className="topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button
              onClick={handleRunAnalysis}
              disabled={runningAgents || loading || !activeCaseId}
              style={{
                background: (runningAgents || loading || !activeCaseId) ? 'var(--border-strong)' : 'linear-gradient(135deg, #3b82f6, #6366f1)',
                color: '#fff',
                border: 'none',
                padding: '8px 18px',
                borderRadius: 6,
                fontSize: 12.5,
                fontWeight: 700,
                cursor: (runningAgents || loading || !activeCaseId) ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                boxShadow: (runningAgents || loading || !activeCaseId) ? 'none' : '0 4px 14px rgba(59, 130, 246, 0.35)'
              }}
            >
              {runningAgents ? (
                <>
                  <div className="live-dot" style={{ background: '#38bdf8' }}></div>
                  Swarm Analyzing...
                </>
              ) : (
                <>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                  Run Multi-Agent Analysis
                </>
              )}
            </button>
            <NotificationMenu />
          </div>
        </header>

        {/* WORKSPACE CONTENT */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* SWARM SUMMARY HEADER */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 10,
            padding: '20px 24px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 16
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <h1 style={{ fontSize: 20, fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                  Autonomous Forensic Reasoning Swarm
                </h1>
                <span style={{
                  background: (agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS') ? 'rgba(16, 185, 129, 0.15)' :
                              agentData?.status === 'PARTIAL_SUCCESS' ? 'rgba(245, 158, 11, 0.15)' :
                              (agentData?.status === 'FAILED' || agentData?.status === 'ERROR') ? 'rgba(239, 68, 68, 0.15)' :
                              'rgba(59, 130, 246, 0.15)',
                  color: (agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS') ? '#10b981' :
                         agentData?.status === 'PARTIAL_SUCCESS' ? '#f59e0b' :
                         (agentData?.status === 'FAILED' || agentData?.status === 'ERROR') ? '#ef4444' :
                         'var(--blue)',
                  border: `1px solid ${(agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS') ? '#10b981' :
                                      agentData?.status === 'PARTIAL_SUCCESS' ? '#f59e0b' :
                                      (agentData?.status === 'FAILED' || agentData?.status === 'ERROR') ? '#ef4444' :
                                      'var(--blue)'}`,
                  padding: '2px 10px',
                  borderRadius: 20,
                  fontSize: 11,
                  fontWeight: 800
                }}>
                  {agentData?.status || 'READY'}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Case ID: <strong>{activeCaseId}</strong>
                </span>
              </div>
              <p style={{ margin: 0, fontSize: 13, color: 'var(--text-muted)', maxWidth: 780 }}>
                Seven specialized AI agents continuously correlate artifact lineage, reconstruct MITRE ATT&CK kill-chains, profile novel malware behaviors, query vector threat intelligence, and gate forensic claims through DeBERTa-v3 NLI verification.
              </p>
              {agentData?.agent_errors && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: 6,
                  padding: '8px 12px',
                  marginTop: 10,
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

            {/* Quick Metrics */}
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Review Gate</div>
                <div style={{ fontSize: 13, fontWeight: 800, color: agentData?.review_level === 'ROUTINE_ANALYST_REVIEW' ? '#10b981' : '#f59e0b' }}>
                  {agentData?.review_level || 'ROUTINE REVIEW'}
                </div>
              </div>
              <div style={{ width: 1, height: 32, background: 'var(--border-strong)' }}></div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>FIR Findings</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--blue)' }}>
                  {agentData?.findings_count ?? 0}
                </div>
              </div>
              <div style={{ width: 1, height: 32, background: 'var(--border-strong)' }}></div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Verified Claims</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: '#10b981' }}>
                  {claimsList.length}
                </div>
              </div>
            </div>
          </div>

          {/* VIEW MODE SELECTOR */}
          <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
            <button
              onClick={() => setActiveViewMode('pipeline')}
              style={{
                background: activeViewMode === 'pipeline' ? 'var(--blue)' : 'var(--bg-card)',
                color: activeViewMode === 'pipeline' ? '#fff' : 'var(--text-main)',
                border: '1px solid var(--border-strong)',
                padding: '8px 16px',
                borderRadius: 6,
                fontSize: 12.5,
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Swarm Architecture &amp; Deep-Dive
            </button>
            <button
              onClick={() => setActiveViewMode('claims')}
              style={{
                background: activeViewMode === 'claims' ? 'var(--blue)' : 'var(--bg-card)',
                color: activeViewMode === 'claims' ? '#fff' : 'var(--text-main)',
                border: '1px solid var(--border-strong)',
                padding: '8px 16px',
                borderRadius: 6,
                fontSize: 12.5,
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Claims &amp; Evidence Ledger ({claimsList.length})
            </button>
            <button
              onClick={() => setActiveViewMode('raw_json')}
              style={{
                background: activeViewMode === 'raw_json' ? 'var(--blue)' : 'var(--bg-card)',
                color: activeViewMode === 'raw_json' ? '#fff' : 'var(--text-main)',
                border: '1px solid var(--border-strong)',
                padding: '8px 16px',
                borderRadius: 6,
                fontSize: 12.5,
                fontWeight: 700,
                cursor: 'pointer'
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
                        background: isSelected ? agent.bg : 'var(--bg-card)',
                        border: `1px solid ${isSelected ? agent.color : 'var(--border-subtle)'}`,
                        borderRadius: 8,
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
                          borderRadius: 6,
                          background: isSelected ? agent.color : 'var(--bg-app)',
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
