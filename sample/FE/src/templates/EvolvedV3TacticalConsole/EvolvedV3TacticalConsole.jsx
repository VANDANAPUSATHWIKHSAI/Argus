import React, { useState } from 'react';
import {
  MOCK_CASES,
  MOCK_EVIDENCE_FILES,
  MOCK_FINDINGS,
  MOCK_TIMELINE_EVENTS,
  MOCK_TOPOLOGY_NODES,
  MOCK_AI_CLAIMS
} from '../../mock/investigationMockData';
import './EvolvedV3.css';

export default function EvolvedV3TacticalConsole() {
  const [activeCaseId, setActiveCaseId] = useState('ARGUS-2026-0892');
  const [selectedNodeId, setSelectedNodeId] = useState('N-HOST-01');
  const [bottomTab, setBottomTab] = useState('findings'); // findings, entailment, evidence
  const [selectedFindingId, setSelectedFindingId] = useState('F-101');
  const [findings, setFindings] = useState(MOCK_FINDINGS);
  const [toast, setToast] = useState(null);

  const currentCase = MOCK_CASES.find(c => c.id === activeCaseId) || MOCK_CASES[0];
  const selectedNode = MOCK_TOPOLOGY_NODES.find(n => n.id === selectedNodeId) || MOCK_TOPOLOGY_NODES[0];

  const triggerToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const handlePromote = (id) => {
    setFindings(prev => prev.map(f => f.id === id ? {
      ...f,
      reviewStatus: 'PROMOTED',
      makerChecker: { status: 'APPROVED', promotedBy: 'Senior Lead Analyst', approvedAt: new Date().toLocaleTimeString() }
    } : f));
    triggerToast(`Finding ${id} approved & promoted.`);
  };

  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');

  return (
    <div className="v3-app-shell">
      {toast && (
        <div className="v3-toast">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          <span>{toast}</span>
        </div>
      )}

      {/* ── TOP TACTICAL TELEMETRY HUD ── */}
      <header className="v3-top-hud">
        <div className="v3-hud-brand">
          <div className="v3-brand-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2.2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="4.93" y1="4.93" x2="9.17" y2="9.17"/><line x1="14.83" y1="14.83" x2="19.07" y2="19.07"/></svg>
          </div>
          <div>
            <div className="v3-brand-title">ARGUS FORENSIC CONSOLE</div>
            <div className="v3-brand-sub">TACTICAL DUAL-PANE MATRIX</div>
          </div>
        </div>

        {/* Case Switcher in HUD */}
        <div className="v3-case-pill">
          <span className="v3-cp-tag">ACTIVE CASE</span>
          <select 
            className="v3-cp-select"
            value={activeCaseId}
            onChange={(e) => { setActiveCaseId(e.target.value); triggerToast(`Loaded case: ${e.target.value}`); }}
          >
            {MOCK_CASES.map(c => (
              <option key={c.id} value={c.id}>{c.id} — {c.name}</option>
            ))}
          </select>
        </div>

        {/* HUD Quick Metrics */}
        <div className="v3-hud-metrics">
          <div className="v3-hm-item">
            <span className="v3-hm-label">EVIDENCE INTEGRITY</span>
            <span className="v3-hm-val text-success">100% RFC 3161</span>
          </div>
          <div className="v3-hm-item">
            <span className="v3-hm-label">EVALUATED TTPs</span>
            <span className="v3-hm-val">4 MITRE Techniques</span>
          </div>
          <div className="v3-hm-item">
            <span className="v3-hm-label">HIGH/CRITICAL RISK</span>
            <span className="v3-hm-val text-danger">{criticalFindings.length} Entities</span>
          </div>
          <div className="v3-hm-item">
            <span className="v3-hm-label">AI VERIFICATION</span>
            <span className="v3-hm-val text-primary">DeBERTa Verified</span>
          </div>
        </div>

        <div className="v3-hud-user">
          <div className="v3-user-avatar">SC</div>
          <span>Sarah Connor</span>
        </div>
      </header>

      {/* ── DUAL-PANE INVESTIGATION MATRIX (UPPER 60%) ── */}
      <div className="v3-matrix-container">

        {/* ── LEFT PANE: INTERACTIVE TOPOLOGY GRAPH ── */}
        <div className="v3-matrix-pane v3-graph-pane">
          <div className="v3-pane-bar">
            <div className="v3-pb-left">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><line x1="8.59" y1="8.59" x2="15.42" y2="15.42"/></svg>
              <span className="v3-pb-title">Investigation Entity Relationship Graph</span>
            </div>
            <div className="v3-graph-legend">
              <span className="v3-leg-dot host"></span> Host
              <span className="v3-leg-dot process"></span> Process
              <span className="v3-leg-dot finding"></span> Malicious Finding
              <span className="v3-leg-dot network"></span> C2 IP
            </div>
          </div>

          <div className="v3-graph-viewport">
            {/* Interactive SVG Diagram */}
            <svg className="v3-svg-canvas" viewBox="0 0 540 280">
              <defs>
                <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.8"/>
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0.8"/>
                </linearGradient>
              </defs>

              {/* Edge Connections */}
              <line x1="90" y1="140" x2="220" y2="80" stroke="#3b82f6" strokeWidth="2" strokeDasharray="4 2" />
              <line x1="90" y1="140" x2="220" y2="200" stroke="#3b82f6" strokeWidth="2" />
              <line x1="220" y1="80" x2="360" y2="80" stroke="url(#edgeGrad)" strokeWidth="2.5" />
              <line x1="360" y1="80" x2="470" y2="140" stroke="#ef4444" strokeWidth="2.5" strokeDasharray="3 3" />
              <line x1="220" y1="200" x2="470" y2="140" stroke="#f59e0b" strokeWidth="2" />

              {/* Node 1: Evidence Disk Image */}
              <g 
                className={`v3-svg-node ${selectedNodeId === 'N-EVID-01' ? 'active' : ''}`}
                onClick={() => setSelectedNodeId('N-EVID-01')}
                transform="translate(90, 140)"
              >
                <circle r="22" fill="#1e1e1e" stroke="#3b82f6" strokeWidth="2.5"/>
                <text textAnchor="middle" dy="4" fill="#60a5fa" fontSize="10" fontWeight="bold">EVID</text>
                <text textAnchor="middle" dy="36" fill="#94a3b8" fontSize="10">E01 Disk</text>
              </g>

              {/* Node 2: Compromised Host */}
              <g 
                className={`v3-svg-node ${selectedNodeId === 'N-HOST-01' ? 'active' : ''}`}
                onClick={() => setSelectedNodeId('N-HOST-01')}
                transform="translate(220, 80)"
              >
                <circle r="24" fill="#1e1e1e" stroke="#3b82f6" strokeWidth="3"/>
                <text textAnchor="middle" dy="4" fill="#ffffff" fontSize="10" fontWeight="bold">HOST</text>
                <text textAnchor="middle" dy="38" fill="#cbd5e1" fontSize="10">WS-FIN-09</text>
              </g>

              {/* Node 3: Memory Dump */}
              <g 
                className={`v3-svg-node ${selectedNodeId === 'N-MEM-01' ? 'active' : ''}`}
                onClick={() => setSelectedNodeId('N-MEM-01')}
                transform="translate(220, 200)"
              >
                <circle r="20" fill="#1e1e1e" stroke="#a78bfa" strokeWidth="2"/>
                <text textAnchor="middle" dy="4" fill="#a78bfa" fontSize="9" fontWeight="bold">MEM</text>
                <text textAnchor="middle" dy="34" fill="#94a3b8" fontSize="10">LSASS Dump</text>
              </g>

              {/* Node 4: Malicious Process */}
              <g 
                className={`v3-svg-node ${selectedNodeId === 'N-PROC-01' ? 'active' : ''}`}
                onClick={() => setSelectedNodeId('N-PROC-01')}
                transform="translate(360, 80)"
              >
                <circle r="24" fill="#1e1e1e" stroke="#ef4444" strokeWidth="3"/>
                <text textAnchor="middle" dy="4" fill="#ef4444" fontSize="10" fontWeight="bold">PROC</text>
                <text textAnchor="middle" dy="38" fill="#fca5a5" fontSize="10">powershell.exe</text>
              </g>

              {/* Node 5: C2 Exfiltration IP */}
              <g 
                className={`v3-svg-node ${selectedNodeId === 'N-NET-01' ? 'active' : ''}`}
                onClick={() => setSelectedNodeId('N-NET-01')}
                transform="translate(470, 140)"
              >
                <circle r="22" fill="#1e1e1e" stroke="#f59e0b" strokeWidth="2.5"/>
                <text textAnchor="middle" dy="4" fill="#f59e0b" fontSize="10" fontWeight="bold">C2</text>
                <text textAnchor="middle" dy="36" fill="#fbbf24" fontSize="10">198.51.100.42</text>
              </g>
            </svg>

            {/* Selected Node Telemetry Callout */}
            <div className="v3-node-hud-card">
              <div className="v3-nh-head">
                <span className="v3-nh-id font-mono">{selectedNode.id}</span>
                <span className={`v3-nh-status ${selectedNode.riskLevel.toLowerCase()}`}>{selectedNode.riskLevel} RISK</span>
              </div>
              <div className="v3-nh-label font-bold">{selectedNode.label}</div>
              <div className="v3-nh-meta font-mono text-xs">{selectedNode.metadata}</div>
            </div>
          </div>
        </div>

        {/* ── RIGHT PANE: SYNCHRONIZED RECONSTRUCTED TIMELINE ── */}
        <div className="v3-matrix-pane v3-timeline-pane">
          <div className="v3-pane-bar">
            <div className="v3-pb-left">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              <span className="v3-pb-title">Synchronized Incident Chronology</span>
            </div>
            <span className="v3-pb-count">{MOCK_TIMELINE_EVENTS.length} Correlated Events</span>
          </div>

          <div className="v3-timeline-list">
            {MOCK_TIMELINE_EVENTS.map((event, idx) => (
              <div key={event.id} className="v3-tl-row">
                <div className="v3-tl-time font-mono">{event.timestamp.split(' ')[1]}</div>
                <div className="v3-tl-indicator">
                  <div className={`v3-tl-dot ${event.severity.toLowerCase()}`}></div>
                  {idx < MOCK_TIMELINE_EVENTS.length - 1 && <div className="v3-tl-line"></div>}
                </div>
                <div className="v3-tl-content">
                  <div className="v3-tl-head">
                    <span className="v3-tl-actor">{event.actor}</span>
                    <span className={`v3-sev-badge ${event.severity.toLowerCase()}`}>{event.severity}</span>
                  </div>
                  <div className="v3-tl-event">{event.event}</div>
                  <div className="v3-tl-obs font-mono text-xs">{event.observable}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* ── BOTTOM DOCK: FORENSIC DATA & ENTAILMENT TABLE (LOWER 40%) ── */}
      <div className="v3-bottom-dock">
        <div className="v3-dock-tabs">
          <button className={`v3-dock-tab ${bottomTab === 'findings' ? 'active' : ''}`} onClick={() => setBottomTab('findings')}>
            <span>Sanitized FIR Findings</span>
            <span className="v3-dt-badge">{findings.length}</span>
          </button>
          <button className={`v3-dock-tab ${bottomTab === 'entailment' ? 'active' : ''}`} onClick={() => setBottomTab('entailment')}>
            <span>AI Claim Entailment (DeBERTa)</span>
            <span className="v3-dt-badge">{MOCK_AI_CLAIMS.length}</span>
          </button>
          <button className={`v3-dock-tab ${bottomTab === 'evidence' ? 'active' : ''}`} onClick={() => setBottomTab('evidence')}>
            <span>Evidence Vault & RFC 3161</span>
            <span className="v3-dt-badge">{MOCK_EVIDENCE_FILES.length}</span>
          </button>
        </div>

        <div className="v3-dock-content">
          {/* TAB 1: FINDINGS TABLE */}
          {bottomTab === 'findings' && (
            <table className="v3-dock-table">
              <thead>
                <tr>
                  <th>FINDING ID</th>
                  <th>SEVERITY</th>
                  <th>SANITIZED FORENSIC FACT</th>
                  <th>MITRE TTP</th>
                  <th>CONFIDENCE</th>
                  <th>STATUS</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(f => (
                  <tr key={f.id} className={selectedFindingId === f.id ? 'active-row' : ''} onClick={() => setSelectedFindingId(f.id)}>
                    <td className="font-mono font-bold text-primary">{f.id}</td>
                    <td><span className={`v3-sev-badge ${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                    <td className="font-medium text-main">{f.sanitizedFact}</td>
                    <td className="font-mono text-primary text-xs">{f.mitreTechnique}</td>
                    <td><span className="font-bold text-success">{f.confidence}%</span></td>
                    <td><span className={`v3-status-tag ${f.reviewStatus.toLowerCase()}`}>{f.reviewStatus}</span></td>
                    <td>
                      {f.reviewStatus !== 'PROMOTED' ? (
                        <button className="v3-btn-promote" onClick={(e) => { e.stopPropagation(); handlePromote(f.id); }}>
                          Promote
                        </button>
                      ) : (
                        <span className="text-success font-bold text-xs">✓ Promoted</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* TAB 2: AI ENTAILMENT MATRIX */}
          {bottomTab === 'entailment' && (
            <div className="v3-entail-grid">
              {MOCK_AI_CLAIMS.map(c => (
                <div key={c.id} className="v3-claim-card">
                  <div className="v3-cc-head">
                    <span className="font-mono text-primary font-bold">{c.id}</span>
                    <span className="v3-nli-pill">Score: {(c.entailmentScore * 100).toFixed(0)}%</span>
                  </div>
                  <div className="v3-cc-claim">"{c.claimText}"</div>
                  <div className="v3-cc-ground font-mono text-xs">{c.groundedPassage}</div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 3: EVIDENCE VAULT */}
          {bottomTab === 'evidence' && (
            <table className="v3-dock-table">
              <thead>
                <tr>
                  <th>EVIDENCE ID</th>
                  <th>FILENAME</th>
                  <th>TYPE</th>
                  <th>SHA-256 HASH</th>
                  <th>RFC 3161 TIMESTAMP</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_EVIDENCE_FILES.map(e => (
                  <tr key={e.id}>
                    <td className="font-mono font-bold text-primary">{e.id}</td>
                    <td className="font-bold">{e.fileName}</td>
                    <td><span className="v3-type-tag">{e.fileType}</span></td>
                    <td className="font-mono text-xs text-muted">{e.sha256}</td>
                    <td className="font-mono text-xs">{e.rfc3161Timestamp}</td>
                    <td><span className="text-success font-bold text-xs">✓ Verified</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
