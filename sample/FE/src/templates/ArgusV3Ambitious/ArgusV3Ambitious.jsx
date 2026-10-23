import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../../components/Sidebar';
import NotificationMenu from '../../components/NotificationMenu';
import {
  MOCK_CASES,
  MOCK_EVIDENCE_FILES,
  MOCK_FIR_FINDINGS,
  MOCK_TIMELINE_EVENTS,
  MOCK_TOPOLOGY_NODES,
  MOCK_AI_CLAIMS
} from '../../mock/investigationMockData';
import '../../css/style.css';
import './ArgusAmbitious.css';

export default function ArgusV3Ambitious() {
  const navigate = useNavigate();
  const [activeCaseId, setActiveCaseId] = useState('ARGUS_01');
  const [selectedNode, setSelectedNode] = useState(MOCK_TOPOLOGY_NODES[0]);
  const [activeNodeTab, setActiveNodeTab] = useState('overview'); // overview, diff, provenance
  const [bottomTab, setBottomTab] = useState('lifecycle'); // lifecycle, findings, nli, evidence
  const [findings, setFindings] = useState(MOCK_FIR_FINDINGS);
  const [selectedFinding, setSelectedFinding] = useState(MOCK_FIR_FINDINGS[0]);
  const [showCaseMenu, setShowCaseMenu] = useState(false);
  const [toast, setToast] = useState(null);

  const activeCase = MOCK_CASES.find(c => c.case_id === activeCaseId) || MOCK_CASES[0];
  const criticalHighCount = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;

  const timelineSteps = [
    { title: 'Evidence Ingestion', desc: '5 Files RFC 3161 Sealed' },
    { title: 'Artifact Parsing', desc: '1,420 Items Extracted' },
    { title: 'Deterministic Redaction', desc: 'PII Protected' },
    { title: 'FIR Formulation', desc: '5 Sanitized Facts' },
    { title: 'Defensible Case Report', desc: 'Maker-Checker Signoff' }
  ];

  const triggerToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const handlePromoteFinding = (id) => {
    setFindings(prev => prev.map(f => f.id === id ? {
      ...f,
      reviewStatus: 'PROMOTED',
      makerChecker: { status: 'APPROVED', promotedBy: 'Sarah Connor', approvedAt: 'Just now' }
    } : f));
    triggerToast(`Finding ${id} promoted to Defensible Report.`);
  };

  return (
    <div id="app-shell" className="argus-ambitious-shell">
      {toast && (
        <div style={{
          position: 'fixed', bottom: '24px', right: '24px',
          background: 'var(--bg-card)', border: '1px solid var(--green)',
          padding: '10px 16px', borderRadius: 'var(--radius-sm)',
          fontSize: '12px', color: 'var(--text-main)', zIndex: 9999,
          boxShadow: '0 8px 24px rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', gap: '8px'
        }}>
          <span style={{ color: 'var(--green)', fontWeight: 'bold' }}>✓</span>
          <span>{toast}</span>
        </div>
      )}

      {/* ── PRESERVED ARGUS SIDEBAR ── */}
      <Sidebar />

      {/* ── MAIN CONTENT ── */}
      <main className="main-content">
        {/* ── TOPBAR ── */}
        <header className="topbar">
          <div className="search-container">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: '8px' }}>
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input type="text" placeholder="Search observables, artifacts, findings, or MITRE TTPs..." />
            <span className="search-shortcut">⌘ K</span>
          </div>

          <div className="topbar-actions">
            <div className="badge-live">
              <div className="live-dot"></div>
              Live Analysis
            </div>

            {/* Quick Case Switcher */}
            <div style={{ position: 'relative' }}>
              <button 
                className="btn btn-outline"
                style={{ fontSize: '12px', padding: '6px 12px', background: 'var(--bg-card)' }}
                onClick={() => setShowCaseMenu(!showCaseMenu)}
              >
                <span>{activeCase.name}</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginLeft: '6px' }}><polyline points="6 9 12 15 18 9"/></svg>
              </button>
              {showCaseMenu && (
                <div style={{
                  position: 'absolute', top: '110%', right: 0, width: '280px',
                  background: 'var(--bg-card)', border: '1px solid var(--border-strong)',
                  borderRadius: 'var(--radius-md)', padding: '6px', zIndex: 1000,
                  boxShadow: '0 8px 24px rgba(0,0,0,0.5)'
                }}>
                  {MOCK_CASES.map(c => (
                    <div 
                      key={c.case_id}
                      onClick={() => { setActiveCaseId(c.case_id); setShowCaseMenu(false); triggerToast(`Switched to ${c.name}`); }}
                      style={{
                        padding: '8px 12px', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                        background: c.case_id === activeCaseId ? 'var(--blue-light)' : 'transparent',
                        color: c.case_id === activeCaseId ? 'var(--blue)' : 'var(--text-main)',
                        fontSize: '12px', fontWeight: c.case_id === activeCaseId ? 600 : 400
                      }}
                    >
                      <div style={{ fontWeight: 600 }}>{c.name}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{c.case_id} • {c.severity}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <NotificationMenu />

            <div className="user-profile">
              <div className="avatar" style={{ background: '#3b82f6' }}>SC</div>
              <span style={{ fontWeight: 500 }}>Sarah Connor</span>
            </div>
          </div>
        </header>

        {/* ── DASHBOARD SCROLL ── */}
        <div className="dashboard-scroll">
          <div id="dashboard-active-content">

            {/* 1. Header Card with Active Incident Scope & TTPs */}
            <div className="header-card" style={{ flexShrink: 0 }}>
              <div className="header-info-wrap">
                <div className="header-id">
                  <p>Active Case Workspace</p>
                  <h1 id="dashboard-case-name">{activeCase.name}</h1>
                </div>
                <div className="header-details">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h2 id="dashboard-case-id" style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--blue)', background: 'var(--blue-light)', padding: '2px 8px', borderRadius: '4px' }}>
                      {activeCase.case_id}
                    </h2>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Threat Actor: <strong style={{ color: 'var(--text-main)' }}>{activeCase.threat_actor}</strong></span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>• Target: <strong style={{ color: 'var(--text-main)' }}>{activeCase.affected_hosts.join(', ')}</strong></span>
                  </div>
                  <p id="dashboard-case-desc" style={{ marginTop: '6px', lineHeight: '1.5' }}>{activeCase.description}</p>
                  
                  <div className="header-meta" style={{ marginTop: '12px' }}>
                    <div className="badge-danger">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                      {activeCase.severity} RISK
                    </div>
                    <div className="meta-item">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                      <div>
                        <span>Lead Investigator</span>
                        <strong>{activeCase.assignedTo}</strong>
                      </div>
                    </div>
                    <div className="meta-item">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                      <div>
                        <span>Verification Status</span>
                        <strong style={{ color: 'var(--green)' }}>DeBERTa Grounded (98.2%)</strong>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Stats Grid with Defensibility Counters */}
            <div className="stats-grid" style={{ flexShrink: 0 }}>
              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--blue-light)', color: 'var(--blue)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                </div>
                <div className="stat-info">
                  <h2>{MOCK_EVIDENCE_FILES.length}</h2>
                  <h4>Evidence Files</h4>
                  <p>100% RFC 3161 Sealed</p>
                </div>
                <div className="trend-badge">5 Verified</div>
              </div>

              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--purple-light)', color: 'var(--purple)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                </div>
                <div className="stat-info">
                  <h2>1,420</h2>
                  <h4>Parsed Artifacts</h4>
                  <p>Zero Injection Alerts</p>
                </div>
                <div className="trend-badge">Clean</div>
              </div>

              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--cyan-light)', color: 'var(--cyan)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                </div>
                <div className="stat-info">
                  <h2>{findings.length}</h2>
                  <h4>FIR Findings</h4>
                  <p>2 Promoted • 3 Pending</p>
                </div>
                <div className="trend-badge">Active Triage</div>
              </div>

              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--red-light)', color: 'var(--red)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <div className="stat-info">
                  <h2>{criticalHighCount}</h2>
                  <h4>High / Critical</h4>
                  <p>Credential & C2 Vector</p>
                </div>
                <div className="trend-badge trend-danger">Review Req.</div>
              </div>
            </div>

            {/* 3. Dual-Synchronized Matrix: Topology Graph on Left + Correlated Timeline on Right */}
            <div className="main-grid" id="main-grid" style={{ flexShrink: 0 }}>
              
              {/* Map Panel */}
              <div className="panel-card map-panel">
                <div className="panel-header">
                  <div>
                    <h3>Investigation Correlation Canvas</h3>
                    <p>Select any entity to inspect cryptographic provenance and synchronized timeline telemetry.</p>
                  </div>
                </div>

                <div className="graph-container" style={{ padding: '16px', display: 'flex', flexDirection: 'column' }}>
                  <div className="graph-legend" style={{ position: 'relative', top: 'auto', left: 'auto', margin: '0 0 8px 0' }}>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#3b82f6' }}></div> Host</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#ef4444' }}></div> Process</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#a78bfa' }}></div> Memory</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#10b981' }}></div> C2 Network</div>
                  </div>

                  <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <svg viewBox="0 0 540 250" style={{ width: '100%', height: '100%' }}>
                      <line x1="100" y1="125" x2="220" y2="65" stroke="rgba(255,255,255,0.15)" strokeWidth="2" strokeDasharray="4 2" />
                      <line x1="100" y1="125" x2="220" y2="185" stroke="rgba(255,255,255,0.15)" strokeWidth="2" />
                      <line x1="220" y1="65" x2="360" y2="65" stroke="#ef4444" strokeWidth="2.5" />
                      <line x1="360" y1="65" x2="460" y2="125" stroke="#ef4444" strokeWidth="2" strokeDasharray="3 3" />
                      <line x1="220" y1="185" x2="460" y2="125" stroke="#f59e0b" strokeWidth="2" />

                      {MOCK_TOPOLOGY_NODES.map((n, i) => {
                        const coords = [
                          { x: 220, y: 65 },
                          { x: 360, y: 65 },
                          { x: 220, y: 185 },
                          { x: 460, y: 125 },
                          { x: 100, y: 125 }
                        ][i] || { x: 100, y: 100 };

                        const isSelected = selectedNode.id === n.id;
                        const nodeColor = n.type === 'process' ? '#ef4444' : n.type === 'host' ? '#3b82f6' : n.type === 'artifact' ? '#a78bfa' : n.type === 'network' ? '#10b981' : '#64748b';

                        return (
                          <g 
                            key={n.id}
                            transform={`translate(${coords.x}, ${coords.y})`}
                            onClick={() => setSelectedNode(n)}
                            style={{ cursor: 'pointer' }}
                          >
                            <circle 
                              r={isSelected ? 26 : 22} 
                              fill="#1e1e1e" 
                              stroke={nodeColor} 
                              strokeWidth={isSelected ? 3.5 : 2}
                              style={{ filter: isSelected ? `drop-shadow(0 0 8px ${nodeColor})` : 'none' }}
                            />
                            <text textAnchor="middle" dy="4" fill="#ffffff" fontSize="9" fontWeight="bold">
                              {n.type.toUpperCase().substring(0, 4)}
                            </text>
                            <text textAnchor="middle" dy={isSelected ? 38 : 34} fill="#cbd5e1" fontSize="10" fontWeight={isSelected ? 'bold' : 'normal'}>
                              {n.label}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                </div>
              </div>

              {/* Node Details Panel with Raw vs. Sanitized Diff */}
              <aside className="details-panel" id="details-panel">
                <div className="panel-header">
                  <h3>Forensic Node Inspector</h3>
                </div>
                <div className="details-content" id="details-content">
                  <div className="details-header">
                    <div className="details-icon" style={{ background: 'var(--blue-light)', color: 'var(--blue)' }}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/></svg>
                    </div>
                    <div className="details-title-wrap">
                      <h4 id="details-title">{selectedNode.label}</h4>
                      <p id="details-subtitle">{selectedNode.id} • {selectedNode.type.toUpperCase()}</p>
                    </div>
                    <div className={`badge-${selectedNode.riskLevel === 'CRITICAL' ? 'danger' : 'live'}`}>
                      {selectedNode.riskLevel}
                    </div>
                  </div>

                  <div className="details-tabs">
                    <div className={`tab ${activeNodeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveNodeTab('overview')}>Overview</div>
                    <div className={`tab ${activeNodeTab === 'diff' ? 'active' : ''}`} onClick={() => setActiveNodeTab('diff')}>Redaction Diff</div>
                    <div className={`tab ${activeNodeTab === 'provenance' ? 'active' : ''}`} onClick={() => setActiveNodeTab('provenance')}>RFC 3161 Proof</div>
                  </div>

                  {activeNodeTab === 'overview' && (
                    <>
                      <p className="details-desc" id="details-desc">
                        {selectedNode.metadata}. Correlated with initial execution and C2 beaconing.
                      </p>
                      <div className="details-list" style={{ display: 'flex', flexDirection: 'column', gap: '8px', margin: '12px 0' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Entity Type:</span>
                          <strong style={{ color: 'var(--text-main)' }}>{selectedNode.type}</strong>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Parent Host:</span>
                          <strong style={{ color: 'var(--text-main)' }}>WORKSTATION-412</strong>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>DeBERTa Entailment:</span>
                          <strong style={{ color: 'var(--green)' }}>✓ 98% Grounded</strong>
                        </div>
                      </div>

                      <div className="risk-score-wrap" id="details-risk-wrap">
                        <div className="risk-header">
                          <span>Calculated Risk Score</span>
                          <strong id="details-risk-val">{selectedNode.riskLevel === 'CRITICAL' ? '92 / 100' : '65 / 100'}</strong>
                        </div>
                        <div className="risk-bar-bg">
                          <div className="risk-bar-fill" id="details-risk-fill" style={{ width: selectedNode.riskLevel === 'CRITICAL' ? '92%' : '65%', backgroundColor: selectedNode.riskLevel === 'CRITICAL' ? 'var(--red)' : 'var(--blue)' }}></div>
                        </div>
                      </div>
                    </>
                  )}

                  {activeNodeTab === 'diff' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', padding: '8px', borderRadius: '4px', fontSize: '10px', fontFamily: 'monospace', color: '#fca5a5' }}>
                        <strong>RAW:</strong> powershell.exe -Enc SUVYKE5ldy1PYmplY3Q... -Host WORKSTATION-412 -User FINANCE\jsmith
                      </div>
                      <div style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', padding: '8px', borderRadius: '4px', fontSize: '10px', fontFamily: 'monospace', color: '#6ee7b7' }}>
                        <strong>SANITIZED:</strong> powershell.exe spawned with base64 encoded arguments [PAYLOAD REDACTED FOR PRIVACY]
                      </div>
                    </div>
                  )}

                  {activeNodeTab === 'provenance' && (
                    <div style={{ background: 'var(--bg-card)', padding: '10px', borderRadius: '4px', border: '1px solid var(--border-subtle)', fontSize: '11px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>RFC 3161 FreeTSA Token</div>
                      <div style={{ fontFamily: 'monospace', fontSize: '10px', color: 'var(--blue)' }}>SHA-256: 9f83a21d5c7b4e8a...</div>
                      <div style={{ color: 'var(--green)', fontSize: '10px', marginTop: '4px' }}>✓ Strict Chain-of-Custody Verified</div>
                    </div>
                  )}

                  <button className="btn btn-outline" style={{ width: '100%', justifyContent: 'center', color: 'var(--blue)', borderColor: 'var(--blue-light)', marginTop: 'auto' }} onClick={() => setBottomTab('findings')}>
                    Inspect in Findings Table →
                  </button>
                </div>
              </aside>
            </div>

            {/* 4. Integrated Lower Forensic Workbench with Multi-Tabs */}
            <div className="timeline-card" style={{ flexShrink: 0 }}>
              <div className="timeline-header" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '14px' }}>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button 
                    className={`btn ${bottomTab === 'lifecycle' ? 'btn-primary' : 'btn-outline'}`}
                    style={{ fontSize: '12px', padding: '6px 12px' }}
                    onClick={() => setBottomTab('lifecycle')}
                  >
                    Investigation Lifecycle
                  </button>
                  <button 
                    className={`btn ${bottomTab === 'findings' ? 'btn-primary' : 'btn-outline'}`}
                    style={{ fontSize: '12px', padding: '6px 12px' }}
                    onClick={() => setBottomTab('findings')}
                  >
                    Sanitized FIR Findings ({findings.length})
                  </button>
                  <button 
                    className={`btn ${bottomTab === 'nli' ? 'btn-primary' : 'btn-outline'}`}
                    style={{ fontSize: '12px', padding: '6px 12px' }}
                    onClick={() => setBottomTab('nli')}
                  >
                    DeBERTa NLI Grounding ({MOCK_AI_CLAIMS.length})
                  </button>
                </div>
              </div>

              {/* TAB 1: LIFECYCLE */}
              {bottomTab === 'lifecycle' && (
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', position: 'relative', padding: '6px 0' }}>
                  {timelineSteps.map((step, i) => {
                    const isDone = i < 3;
                    const isActive = i === 3;

                    return (
                      <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px', flex: 1 }}>
                        <div style={{
                          width: '32px', height: '32px', borderRadius: '50%',
                          background: isDone ? 'var(--blue)' : isActive ? 'var(--blue)' : 'var(--bg-app)',
                          border: isDone ? '2px solid var(--blue)' : '2px solid var(--border-strong)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center'
                        }}>
                          {isDone ? (
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3"><polyline points="20 6 9 17 4 12" /></svg>
                          ) : (
                            <span style={{ fontSize: '11px', fontWeight: 'bold', color: isActive ? '#fff' : 'var(--text-muted)' }}>{i + 1}</span>
                          )}
                        </div>
                        <span style={{ fontSize: '12px', fontWeight: isActive ? 700 : 500, color: isActive ? 'var(--blue)' : 'var(--text-main)', textAlign: 'center' }}>
                          {step.title}
                        </span>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', textAlign: 'center' }}>
                          {step.desc}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* TAB 2: FINDINGS TABLE */}
              {bottomTab === 'findings' && (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--bg-card)', color: 'var(--text-muted)', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>
                        <th style={{ padding: '8px 12px' }}>ID</th>
                        <th>SEVERITY</th>
                        <th>SANITIZED OBSERVATION</th>
                        <th>MITRE TTP</th>
                        <th>CONFIDENCE</th>
                        <th>STATUS</th>
                        <th>MAKER-CHECKER</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map(f => (
                        <tr key={f.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', fontWeight: 'bold', color: 'var(--blue)' }}>{f.id}</td>
                          <td><span className={`badge-${f.severity === 'CRITICAL' ? 'danger' : 'live'}`}>{f.severity}</span></td>
                          <td style={{ color: 'var(--text-main)' }}>{f.sanitizedFact}</td>
                          <td style={{ fontFamily: 'monospace', color: 'var(--blue)', fontSize: '11px' }}>{f.mitreTechnique}</td>
                          <td><strong>{f.confidence}%</strong></td>
                          <td>
                            <span style={{ fontSize: '10px', fontWeight: 'bold', color: f.reviewStatus === 'PROMOTED' ? 'var(--green)' : 'var(--orange)' }}>
                              {f.reviewStatus}
                            </span>
                          </td>
                          <td>
                            {f.reviewStatus !== 'PROMOTED' ? (
                              <button 
                                className="btn btn-primary"
                                style={{ padding: '3px 8px', fontSize: '10px' }}
                                onClick={() => handlePromoteFinding(f.id)}
                              >
                                Approve & Promote
                              </button>
                            ) : (
                              <span style={{ color: 'var(--green)', fontSize: '11px', fontWeight: 600 }}>✓ Approved by Sarah Connor</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* TAB 3: NLI GROUNDING */}
              {bottomTab === 'nli' && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  {MOCK_AI_CLAIMS.map(claim => (
                    <div key={claim.id} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', padding: '12px', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ fontFamily: 'monospace', fontWeight: 'bold', color: 'var(--blue)', fontSize: '11px' }}>{claim.id}</span>
                        <span style={{ color: 'var(--green)', fontSize: '10px', fontWeight: 'bold' }}>Score: {(claim.entailmentScore * 100).toFixed(0)}%</span>
                      </div>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>"{claim.claimText}"</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', background: 'var(--bg-app)', padding: '6px', borderRadius: '4px' }}>
                        {claim.groundedPassage}
                      </div>
                    </div>
                  ))}
                </div>
              )}

            </div>

          </div>
        </div>
      </main>
    </div>
  );
}
