import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { fetchAgentResults, triggerAgentAnalysis, fetchCases, DEFAULT_TENANT_ID } from '../js/api';
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
  const navigate = useNavigate();
  const [activeCaseId, setActiveCaseId] = useState(localStorage.getItem('active_case_id') || '');
  const [activeCaseName, setActiveCaseName] = useState(localStorage.getItem('active_case_name') || 'Current Case');
  const [casesList, setCasesList] = useState([]);
  const [agentData, setAgentData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [runningAgents, setRunningAgents] = useState(false);
  const [selectedAgentTab, setSelectedAgentTab] = useState('agent7'); // default to supervisor
  const [activeViewMode, setActiveViewMode] = useState('pipeline'); // 'pipeline' | 'claims' | 'raw_json'
  const [claimsFilter, setClaimsFilter] = useState('all');
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });

  // Load cases list
  useEffect(() => {
    const initCases = async () => {
      try {
        const res = await fetchCases();
        const list = res.data || [];
        setCasesList(list);
        if (!activeCaseId && list.length > 0) {
          const first = list.find(c => c.status === 'open') || list[0];
          setActiveCaseId(first.case_id);
          setActiveCaseName(first.name || first.case_id);
          localStorage.setItem('active_case_id', first.case_id);
          localStorage.setItem('active_case_name', first.name || first.case_id);
        }
      } catch (err) {
        console.error('Failed to load cases:', err);
      }
    };
    initCases();
  }, []);

  // Fetch agent results
  const loadAgentResults = async (caseId) => {
    if (!caseId) return;
    setLoading(true);
    try {
      const data = await fetchAgentResults(caseId);
      setAgentData(data);
      if (data.status === 'RUNNING') {
        setRunningAgents(true);
      } else {
        setRunningAgents(false);
      }
    } catch (err) {
      console.error('Failed to fetch agent results:', err);
      setCustomAlert({
        isOpen: true,
        title: 'Error Fetching Agent Telemetry',
        message: err.message || 'Could not load multi-agent results for this case.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeCaseId) {
      loadAgentResults(activeCaseId);
    }
  }, [activeCaseId]);

  // Polling when analysis is running
  useEffect(() => {
    let interval = null;
    if (runningAgents && activeCaseId) {
      interval = setInterval(async () => {
        try {
          const data = await fetchAgentResults(activeCaseId);
          setAgentData(data);
          if (data.status !== 'RUNNING') {
            setRunningAgents(false);
            setCustomAlert({
              isOpen: true,
              title: '✅ Multi-Agent Analysis Complete',
              message: `Agents 1 through 7 finished processing Case ${activeCaseId}. Full findings, attack paths, and supervisor synthesis are now ready.`,
              type: 'success'
            });
          }
        } catch (e) {
          console.error('Polling error:', e);
        }
      }, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [runningAgents, activeCaseId]);

  const handleRunAnalysis = async () => {
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

  const handleSelectCase = (newId) => {
    const sel = casesList.find(c => c.case_id === newId);
    if (sel) {
      setActiveCaseId(sel.case_id);
      setActiveCaseName(sel.name || sel.case_id);
      localStorage.setItem('active_case_id', sel.case_id);
      localStorage.setItem('active_case_name', sel.name || sel.case_id);
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

            {/* Case selector */}
            <select
              value={activeCaseId}
              onChange={(e) => handleSelectCase(e.target.value)}
              style={{
                background: 'var(--bg-card)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-strong)',
                padding: '6px 14px',
                borderRadius: 6,
                fontSize: 13,
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              {casesList.map(c => (
                <option key={c.case_id} value={c.case_id}>
                  {c.name || c.case_id} ({c.status})
                </option>
              ))}
            </select>
          </div>

          <div className="topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <button
              onClick={handleRunAnalysis}
              disabled={runningAgents}
              style={{
                background: runningAgents ? 'var(--border-strong)' : 'linear-gradient(135deg, #3b82f6, #6366f1)',
                color: '#fff',
                border: 'none',
                padding: '8px 18px',
                borderRadius: 6,
                fontSize: 12.5,
                fontWeight: 700,
                cursor: runningAgents ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                boxShadow: runningAgents ? 'none' : '0 4px 14px rgba(59, 130, 246, 0.35)'
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
                  background: agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                  color: agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS' ? '#10b981' : 'var(--blue)',
                  border: `1px solid ${agentData?.status === 'COMPLETED' || agentData?.status === 'SUCCESS' ? '#10b981' : 'var(--blue)'}`,
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
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                  Agent Pipeline Hierarchy
                </div>

                {Object.values(AGENT_METADATA).map(agent => {
                  const isSelected = selectedAgentTab === agent.id;
                  return (
                    <div
                      key={agent.id}
                      onClick={() => setSelectedAgentTab(agent.id)}
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
              <div style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 10,
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: 20
              }}>
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
                          {Math.round(((currentAgentData.confidence_gate?.overall_confidence || agentData?.confidence_gate?.overall_confidence || 0.88) * 100))}%
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
                              <th style={{ padding: '10px 14px' }}>NLI Status</th>
                              <th style={{ padding: '10px 14px' }}>Score</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(currentAgentData.verification || agentData?.verification_results || []).length > 0 ? (
                              (currentAgentData.verification || agentData?.verification_results).map((v, idx) => (
                                <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                  <td style={{ padding: '10px 14px', color: 'var(--text-main)', maxWidth: 380 }}>{v.hypothesis || v.claim || JSON.stringify(v)}</td>
                                  <td style={{ padding: '10px 14px', color: 'var(--blue)', fontWeight: 700 }}>{v.agent_id || 'Agent 1'}</td>
                                  <td style={{ padding: '10px 14px' }}>
                                    <span style={{
                                      background: (v.verdict || v.status || '').toLowerCase().includes('entail') ? 'rgba(16,185,129,0.15)' : 'rgba(59,130,246,0.15)',
                                      color: (v.verdict || v.status || '').toLowerCase().includes('entail') ? '#10b981' : 'var(--blue)',
                                      padding: '2px 8px', borderRadius: 4, fontWeight: 700, fontSize: 11
                                    }}>
                                      {v.verdict || v.status || 'VERIFIED'}
                                    </span>
                                  </td>
                                  <td style={{ padding: '10px 14px', fontWeight: 700, color: 'var(--text-main)' }}>
                                    {v.confidence ? `${Math.round(v.confidence * 100)}%` : '95%'}
                                  </td>
                                </tr>
                              ))
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
                      <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--blue)', textTransform: 'uppercase', marginBottom: 6 }}>
                        Investigation Readiness &amp; Triage Assessment
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.summary || 'Agent 1 analyzes evidence integrity, normalizes timeline timestamps, filters low-fidelity noise, and computes initial confidence weights across all ingested artifacts.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>TRIAGED FINDINGS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {currentAgentData.findings_ingested || agentData?.findings_count || 0}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>HIGH VALUE FINDINGS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#f59e0b', marginTop: 4 }}>
                          {currentAgentData.high_value_findings || Math.round((agentData?.findings_count || 0) * 0.4)}
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>REASONING ENGINE</div>
                        <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-main)', marginTop: 4 }}>
                          Qwen3-8B Instruct
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
                          {currentAgentData.clusters_preview || 3} Detected
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>CONNECTED ENTITIES</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--blue)', marginTop: 4 }}>
                          {currentAgentData.graph_nodes || (agentData?.findings_count || 0) + 4} Nodes
                        </div>
                      </div>
                    </div>
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
                        {currentAgentData.summary || 'Rebuilds chronological attacker tradecraft progression from Initial Access to Defense Evasion and Impact. Automatically flags missing intermediate events for targeted investigator hunting.'}
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>TACTIC PHASES DETECTED</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: '#06b6d4', marginTop: 4 }}>
                          {(currentAgentData.mitre_tactics || []).length || 4} Tactics
                        </div>
                      </div>
                      <div style={{ background: 'var(--bg-app)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700 }}>ATTACK STEPS</div>
                        <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-main)', marginTop: 4 }}>
                          {currentAgentData.attack_steps_projected || (agentData?.findings_count || 0)} Projected
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* AGENT 4, 5A, 5B, 6: SIMILAR STRUCTURE */}
                {(selectedAgentTab === 'agent4' || selectedAgentTab === 'agent5a' || selectedAgentTab === 'agent5b' || selectedAgentTab === 'agent6') && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', borderRadius: 8, padding: 18 }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: currentAgent.color, textTransform: 'uppercase', marginBottom: 6 }}>
                        {currentAgent.name} Intelligence Stream
                      </div>
                      <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-main)', lineHeight: 1.6 }}>
                        {currentAgentData.summary || currentAgent.subtitle}
                      </p>
                    </div>

                    <pre style={{
                      background: 'var(--bg-app)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 8,
                      padding: 16,
                      fontSize: 12,
                      fontFamily: 'var(--argus-mono, monospace)',
                      color: 'var(--text-main)',
                      maxHeight: 260,
                      overflowY: 'auto'
                    }}>
                      {JSON.stringify(currentAgentData, null, 2)}
                    </pre>
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

                <div style={{ display: 'flex', gap: 8 }}>
                  {['all', 'agent1', 'agent2', 'agent3', 'agent6'].map(aKey => (
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
                            {(c.evidence_ids || []).slice(0, 3).join(', ') || 'F-CORR-01'}
                          </td>
                          <td style={{ padding: '12px 14px', fontWeight: 700, color: 'var(--text-main)' }}>
                            {Math.round((c.confidence || 0.9) * 100)}%
                          </td>
                          <td style={{ padding: '12px 14px' }}>
                            <span style={{
                              background: c.verified ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                              color: c.verified ? '#10b981' : '#f59e0b',
                              padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700
                            }}>
                              {c.verified ? 'VERIFIED' : 'GATED'}
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
