import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../../components/Sidebar';
import NotificationMenu from '../../components/NotificationMenu';
import {
  MOCK_CASES,
  MOCK_EVIDENCE_FILES,
  MOCK_FIR_FINDINGS,
  MOCK_TIMELINE_EVENTS,
  MOCK_TOPOLOGY_NODES
} from '../../mock/investigationMockData';
import '../../css/style.css';
import './ArgusConservative.css';

export default function ArgusV1Conservative() {
  const navigate = useNavigate();
  const [activeCaseId, setActiveCaseId] = useState('ARGUS_01');
  const [selectedNode, setSelectedNode] = useState(MOCK_TOPOLOGY_NODES[0]);
  const [activeNodeTab, setActiveNodeTab] = useState('overview'); // overview, related, connections
  const [viewMode, setViewMode] = useState('graph'); // graph, timeline
  const [showCaseMenu, setShowCaseMenu] = useState(false);

  const activeCase = MOCK_CASES.find(c => c.case_id === activeCaseId) || MOCK_CASES[0];
  const criticalHighCount = MOCK_FIR_FINDINGS.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;

  const timelineSteps = ['Evidence\nCollection', 'Analysis', 'Correlation', 'Findings', 'Report'];
  const completedSteps = 3;
  const activeStep = 3;
  const progressBarWidth = `${(completedSteps / timelineSteps.length) * 100}%`;

  return (
    <div id="app-shell" className="argus-conservative-shell">
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
            <input type="text" placeholder="Search cases, evidence, or findings..." />
            <span className="search-shortcut">⌘ K</span>
          </div>

          <div className="topbar-actions">
            {/* Live Analysis Badge */}
            <div className="badge-live">
              <div className="live-dot"></div>
              Live Analysis
            </div>

            {/* Case Selector Dropdown */}
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
                      onClick={() => { setActiveCaseId(c.case_id); setShowCaseMenu(false); }}
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

            {/* User Profile */}
            <div className="user-profile">
              <div className="avatar" style={{ background: '#3b82f6' }}>SC</div>
              <span style={{ fontWeight: 500 }}>Sarah Connor</span>
            </div>
          </div>
        </header>

        {/* ── DASHBOARD SCROLL ── */}
        <div className="dashboard-scroll">
          <div id="dashboard-active-content">

            {/* 1. Header Card (Preserved structure with improved typography & spacing) */}
            <div className="header-card" style={{ flexShrink: 0 }}>
              <div className="header-info-wrap">
                <div className="header-id">
                  <p>Active Case</p>
                  <h1 id="dashboard-case-name">{activeCase.name}</h1>
                </div>
                <div className="header-details">
                  <h2 id="dashboard-case-id" style={{ fontSize: '13px', fontFamily: 'monospace', color: 'var(--blue)', background: 'var(--blue-light)', padding: '2px 8px', borderRadius: '4px', display: 'inline-block' }}>
                    {activeCase.case_id}
                  </h2>
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
                        <span>Integrity Proof</span>
                        <strong>RFC 3161 Sealed</strong>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* 2. Stats Grid (Preserved 4-card structure with cleaner baseline) */}
            <div className="stats-grid" style={{ flexShrink: 0 }}>
              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--blue-light)', color: 'var(--blue)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                </div>
                <div className="stat-info">
                  <h2>{MOCK_EVIDENCE_FILES.length}</h2>
                  <h4>Evidence Files</h4>
                  <p>100% SHA-256 verified</p>
                </div>
                <div className="trend-badge">Total</div>
              </div>

              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--purple-light)', color: 'var(--purple)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                </div>
                <div className="stat-info">
                  <h2>1,420</h2>
                  <h4>Artifacts</h4>
                  <p>Parsed from evidence</p>
                </div>
                <div className="trend-badge">Parsed</div>
              </div>

              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--cyan-light)', color: 'var(--cyan)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                </div>
                <div className="stat-info">
                  <h2>{MOCK_FIR_FINDINGS.length}</h2>
                  <h4>Sanitized Findings</h4>
                  <p>Fact-checked observations</p>
                </div>
                <div className="trend-badge">FIR Active</div>
              </div>

              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: 'var(--red-light)', color: 'var(--red)' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <div className="stat-info">
                  <h2>{criticalHighCount}</h2>
                  <h4>Critical / High</h4>
                  <p>Require analyst sign-off</p>
                </div>
                <div className="trend-badge trend-danger">Action Req.</div>
              </div>
            </div>

            {/* 3. Interactive Investigation Map & Details Panel (Preserved layout, fully interactive) */}
            <div className="main-grid" id="main-grid" style={{ flexShrink: 0 }}>
              
              {/* Map Panel */}
              <div className="panel-card map-panel">
                <div className="panel-header">
                  <div>
                    <h3>Investigation Map</h3>
                    <p>Explore the relationships between evidence, users, devices, and network activity.</p>
                  </div>
                  <div className="panel-actions">
                    <button 
                      className={`btn ${viewMode === 'graph' ? 'btn-primary' : 'btn-outline'}`}
                      onClick={() => setViewMode('graph')}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                      Graph View
                    </button>
                    <button 
                      className={`btn ${viewMode === 'timeline' ? 'btn-primary' : 'btn-outline'}`}
                      onClick={() => setViewMode('timeline')}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                      Timeline View
                    </button>
                  </div>
                </div>

                <div className="graph-container" id="graph-container">
                  {/* Legend */}
                  <div className="graph-legend">
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#3b82f6' }}></div> Host</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#ef4444' }}></div> Process</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#a78bfa' }}></div> Memory</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#10b981' }}></div> C2 Network</div>
                    <div className="legend-item"><div className="legend-dot" style={{ background: '#64748b' }}></div> Evidence</div>
                  </div>

                  {viewMode === 'graph' ? (
                    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
                      <svg viewBox="0 0 540 280" style={{ width: '100%', height: '100%' }}>
                        {/* Edges */}
                        <line x1="100" y1="140" x2="220" y2="80" stroke="rgba(255,255,255,0.15)" strokeWidth="2" strokeDasharray="4 2" />
                        <line x1="100" y1="140" x2="220" y2="200" stroke="rgba(255,255,255,0.15)" strokeWidth="2" />
                        <line x1="220" y1="80" x2="360" y2="80" stroke="#ef4444" strokeWidth="2" />
                        <line x1="360" y1="80" x2="460" y2="140" stroke="#ef4444" strokeWidth="2" strokeDasharray="3 3" />
                        <line x1="220" y1="200" x2="460" y2="140" stroke="#f59e0b" strokeWidth="2" />

                        {/* Interactive Nodes */}
                        {MOCK_TOPOLOGY_NODES.map((n, i) => {
                          const coords = [
                            { x: 220, y: 80 },
                            { x: 360, y: 80 },
                            { x: 220, y: 200 },
                            { x: 460, y: 140 },
                            { x: 100, y: 140 }
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
                  ) : (
                    /* Timeline View Mode in Panel */
                    <div style={{ padding: '16px', overflowY: 'auto', height: '100%' }}>
                      {MOCK_TIMELINE_EVENTS.map(t => (
                        <div key={t.id} style={{ display: 'flex', gap: '12px', marginBottom: '12px', background: 'var(--bg-surface)', padding: '10px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                          <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--blue)', width: '70px', flexShrink: 0 }}>{t.timestamp.split(' ')[1]}</span>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>{t.event}</div>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{t.details}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Node Details Panel (Preserved layout, fully interactive) */}
              <aside className="details-panel" id="details-panel">
                <div className="panel-header">
                  <h3>Node Details</h3>
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
                    <div className={`tab ${activeNodeTab === 'related' ? 'active' : ''}`} onClick={() => setActiveNodeTab('related')}>Related (4)</div>
                    <div className={`tab ${activeNodeTab === 'connections' ? 'active' : ''}`} onClick={() => setActiveNodeTab('connections')}>Connections</div>
                  </div>

                  {activeNodeTab === 'overview' && (
                    <>
                      <p className="details-desc" id="details-desc">
                        {selectedNode.metadata}. Actively correlated with initial intrusion and C2 exfiltration pathway.
                      </p>
                      <div className="details-list" id="details-list">
                        <div className="detail-row"><span>Entity Type</span><strong>{selectedNode.type}</strong></div>
                        <div className="detail-row"><span>RFC 3161 Stamp</span><strong style={{ color: 'var(--green)' }}>✓ Verified</strong></div>
                        <div className="detail-row"><span>Source Case</span><strong>{activeCase.case_id}</strong></div>
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

                  {activeNodeTab === 'related' && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ background: 'var(--bg-app)', padding: '8px', borderRadius: '4px' }}>Finding: F-101 (PowerShell Cradle)</div>
                      <div style={{ background: 'var(--bg-app)', padding: '8px', borderRadius: '4px' }}>Evidence: Sysmon-Operational.evtx</div>
                    </div>
                  )}

                  {activeNodeTab === 'connections' && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ background: 'var(--bg-app)', padding: '8px', borderRadius: '4px' }}>➔ C2 IP: 198.51.100.42:443</div>
                      <div style={{ background: 'var(--bg-app)', padding: '8px', borderRadius: '4px' }}>➔ Process: powershell.exe (PID 4892)</div>
                    </div>
                  )}

                  <button className="btn btn-outline" style={{ width: '100%', justifyContent: 'center', color: 'var(--blue)', borderColor: 'var(--blue-light)', marginTop: 'auto' }} onClick={() => setViewMode('timeline')}>
                    View in Timeline →
                  </button>
                </div>
              </aside>
            </div>

            {/* 4. Investigation Progress Stepper (Preserved single-track timeline) */}
            <div className="timeline-card" style={{ flexShrink: 0 }}>
              <div className="timeline-header">
                <div>
                  <h3>Investigation Progress</h3>
                  <p>Track the lifecycle of the active case.</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)' }}>{completedSteps} of {timelineSteps.length} stages complete</span>
                  <div style={{ width: '120px', height: '5px', backgroundColor: 'var(--border-strong)', borderRadius: '99px', overflow: 'hidden' }}>
                    <div style={{ width: progressBarWidth, height: '100%', background: 'var(--blue)', borderRadius: '99px', transition: 'width 0.6s ease' }}></div>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', position: 'relative', padding: '8px 0' }}>
                {timelineSteps.map((label, i) => {
                  const isDone = i < completedSteps;
                  const isActive = i === activeStep;
                  const isPending = !isDone && !isActive;

                  return (
                    <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', zIndex: 2 }}>
                      <div style={{
                        width: '32px', height: '32px', borderRadius: '50%',
                        background: isDone ? 'var(--blue)' : isActive ? 'var(--blue)' : 'var(--bg-app)',
                        border: isPending ? '2.5px solid var(--border-strong)' : '2.5px solid var(--blue)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        transition: 'all 0.3s ease', flexShrink: 0
                      }}>
                        {isDone && (
                          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="20 6 9 17 4 12" />
                          </svg>
                        )}
                        {isActive && (
                          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'white' }} />
                        )}
                      </div>
                      <span style={{
                        fontSize: '12px', fontWeight: isActive ? 700 : isDone ? 600 : 500,
                        color: isActive ? 'var(--blue)' : isDone ? 'var(--text-main)' : 'var(--text-muted)',
                        textAlign: 'center', lineHeight: '1.3', whiteSpace: 'pre-line'
                      }}>
                        {label}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

          </div>
        </div>
      </main>
    </div>
  );
}
