import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  MOCK_CASES,
  MOCK_EVIDENCE_FILES,
  MOCK_FINDINGS,
  MOCK_TIMELINE_EVENTS,
  MOCK_AI_CLAIMS,
  MOCK_AUDIT_LOGS,
  MOCK_CASE_NOTES
} from '../../mock/investigationMockData';
import './EvolvedV1.css';

export default function EvolvedV1UnifiedWorkstation() {
  const navigate = useNavigate();
  const [activeCaseId, setActiveCaseId] = useState('ARGUS-2026-0892');
  const [activeTab, setActiveTab] = useState('overview'); // overview, findings, evidence, timeline, verification
  const [selectedFindingId, setSelectedFindingId] = useState('F-101');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('EV-001');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [inspectorTab, setInspectorTab] = useState('details'); // details, raw, audit
  const [showCaseSelector, setShowCaseSelector] = useState(false);
  const [findingsData, setFindingsData] = useState(MOCK_FINDINGS);
  const [toastMessage, setToastMessage] = useState(null);

  const currentCase = MOCK_CASES.find(c => c.id === activeCaseId) || MOCK_CASES[0];
  const selectedFinding = findingsData.find(f => f.id === selectedFindingId) || findingsData[0];
  const selectedEvidence = MOCK_EVIDENCE_FILES.find(e => e.id === selectedEvidenceId) || MOCK_EVIDENCE_FILES[0];

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handlePromoteFinding = (id) => {
    setFindingsData(prev => prev.map(f => f.id === id ? { ...f, reviewStatus: 'PROMOTED', makerChecker: { status: 'APPROVED', promotedBy: 'Sarah Connor (Senior Analyst)', approvedAt: new Date().toISOString() } } : f));
    showToast(`Finding ${id} approved & promoted to Defensible Case Report.`);
  };

  const filteredFindings = findingsData.filter(f => {
    const matchSev = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchSearch = !searchTerm || (f.id + f.title + f.sanitizedFact + f.mitreTechnique).toLowerCase().includes(searchTerm.toLowerCase());
    return matchSev && matchSearch;
  });

  const criticalHighCount = findingsData.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;

  return (
    <div className="v1-app-shell">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="v1-toast">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          <span>{toastMessage}</span>
        </div>
      )}

      {/* ── CLASSIC ARGUS SIDEBAR (ENHANCED) ── */}
      <aside className="v1-sidebar">
        <div className="v1-sidebar-brand">
          <div className="v1-logo-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2.2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
          </div>
          <div className="v1-brand-text">
            <h2>ARGUS</h2>
            <p>Digital Forensics Platform</p>
          </div>
        </div>

        {/* Case Switcher Tile */}
        <div className="v1-case-tile" onClick={() => setShowCaseSelector(!showCaseSelector)}>
          <div className="v1-case-tile-head">
            <span className="v1-tile-label">ACTIVE CASE</span>
            <span className={`v1-status-pill ${currentCase.status.toLowerCase()}`}>{currentCase.status}</span>
          </div>
          <div className="v1-case-tile-title">{currentCase.name}</div>
          <div className="v1-case-tile-meta">
            <span>{currentCase.id}</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
          </div>
        </div>

        {/* Dropdown Case Menu */}
        {showCaseSelector && (
          <div className="v1-case-dropdown">
            <div className="v1-dropdown-header">Switch Investigation Case</div>
            {MOCK_CASES.map(c => (
              <div 
                key={c.id} 
                className={`v1-dropdown-item ${c.id === activeCaseId ? 'active' : ''}`}
                onClick={() => { setActiveCaseId(c.id); setShowCaseSelector(false); showToast(`Switched to case: ${c.name}`); }}
              >
                <div className="v1-item-name">{c.name}</div>
                <div className="v1-item-id">{c.id} • {c.severity}</div>
              </div>
            ))}
          </div>
        )}

        {/* Navigation Links */}
        <nav className="v1-nav-menu">
          <button className={`v1-nav-item ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
            <span>Case Overview</span>
          </button>
          <button className={`v1-nav-item ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            <span>Forensic Findings</span>
            <span className="v1-nav-count">{findingsData.length}</span>
          </button>
          <button className={`v1-nav-item ${activeTab === 'evidence' ? 'active' : ''}`} onClick={() => setActiveTab('evidence')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
            <span>Evidence & Hashes</span>
            <span className="v1-nav-count">{MOCK_EVIDENCE_FILES.length}</span>
          </button>
          <button className={`v1-nav-item ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <span>Event Timeline</span>
          </button>
          <button className={`v1-nav-item ${activeTab === 'verification' ? 'active' : ''}`} onClick={() => setActiveTab('verification')}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            <span>AI Verification & NLI</span>
            <span className="v1-nav-badge">DeBERTa</span>
          </button>
        </nav>

        {/* Sidebar Footer / User badge */}
        <div className="v1-sidebar-user">
          <div className="v1-user-avatar">SC</div>
          <div className="v1-user-meta">
            <span className="v1-user-name">Sarah Connor</span>
            <span className="v1-user-role">Senior Lead Analyst</span>
          </div>
        </div>
      </aside>

      {/* ── MAIN WORKSPACE CANVAS ── */}
      <div className="v1-workspace-canvas">
        {/* Top App Header */}
        <header className="v1-topbar">
          <div className="v1-search-box">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input 
              type="text" 
              placeholder="Search findings, IP observables, hashes, or MITRE techniques..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <kbd className="v1-kbd">⌘K</kbd>
          </div>

          <div className="v1-topbar-actions">
            <div className="v1-badge-live">
              <span className="v1-live-pulse"></span>
              LIVE INVESTIGATION
            </div>
            <button 
              className={`v1-btn-toggle-inspector ${inspectorOpen ? 'active' : ''}`}
              onClick={() => setInspectorOpen(!inspectorOpen)}
              title="Toggle Evidence & Finding Inspector"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="15" y1="3" x2="15" y2="21"/></svg>
              <span>{inspectorOpen ? 'Hide Inspector' : 'Show Inspector'}</span>
            </button>
          </div>
        </header>

        {/* Case Context Banner */}
        <div className="v1-context-banner">
          <div className="v1-banner-main">
            <div className="v1-case-title-row">
              <span className="v1-banner-id">{currentCase.id}</span>
              <h1 className="v1-banner-heading">{currentCase.name}</h1>
              <span className="v1-banner-tag high-risk">{currentCase.severity} RISK</span>
            </div>
            <p className="v1-banner-desc">{currentCase.description}</p>
          </div>

          <div className="v1-metrics-strip">
            <div className="v1-metric-cell">
              <span className="v1-m-label">EVIDENCE FILES</span>
              <span className="v1-m-val">{MOCK_EVIDENCE_FILES.length}</span>
              <span className="v1-m-sub">100% RFC 3161 Stamped</span>
            </div>
            <div className="v1-metric-cell">
              <span className="v1-m-label">SANITIZED FINDINGS</span>
              <span className="v1-m-val">{findingsData.length}</span>
              <span className="v1-m-sub text-danger">{criticalHighCount} Critical/High</span>
            </div>
            <div className="v1-metric-cell">
              <span className="v1-m-label">AI VERIFICATION</span>
              <span className="v1-m-val">96.8%</span>
              <span className="v1-m-sub text-success">Zero Hallucinations</span>
            </div>
            <div className="v1-metric-cell">
              <span className="v1-m-label">LEAD INVESTIGATOR</span>
              <span className="v1-m-val font-normal">{currentCase.assignedTo}</span>
              <span className="v1-m-sub">Active Session</span>
            </div>
          </div>
        </div>

        {/* Interactive Workspace Body (Split view with inspector) */}
        <div className="v1-workspace-layout">
          <main className="v1-content-area">
            {/* ── TAB 1: CASE OVERVIEW ── */}
            {activeTab === 'overview' && (
              <div className="v1-view-pane">
                {/* Investigation Progress Lifecycle */}
                <div className="v1-card v1-lifecycle-card">
                  <div className="v1-card-header">
                    <div>
                      <h3>Investigation Lifecycle & Readiness</h3>
                      <p>Active progression through the 5-stage digital forensics pipeline</p>
                    </div>
                    <span className="v1-pill-status">Stage 4 of 5 (Findings Review)</span>
                  </div>
                  <div className="v1-stepper">
                    {['Evidence Acquisition', 'Artifact Parsing', 'Sanitization & Redaction', 'FIR Findings Formulation', 'Defensible Case Report'].map((step, idx) => (
                      <div key={idx} className={`v1-step-item ${idx < 3 ? 'completed' : idx === 3 ? 'active' : 'pending'}`}>
                        <div className="v1-step-circle">
                          {idx < 3 ? '✓' : idx + 1}
                        </div>
                        <span className="v1-step-name">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Grid: Attack Summary & Key Findings */}
                <div className="v1-two-col-grid">
                  <div className="v1-card">
                    <div className="v1-card-header">
                      <h3>Active Attack Vector & MITRE TTPs</h3>
                      <button className="v1-btn-link" onClick={() => setActiveTab('timeline')}>View Timeline →</button>
                    </div>
                    <div className="v1-attack-summary">
                      <div className="v1-ttp-badge-list">
                        <span className="v1-ttp-badge"><span className="v1-ttp-id">T1566.001</span> Spearphishing Attachment</span>
                        <span className="v1-ttp-badge"><span className="v1-ttp-id">T1059.001</span> PowerShell In-Memory Execution</span>
                        <span className="v1-ttp-badge"><span className="v1-ttp-id">T1003.001</span> LSASS Memory Dumping</span>
                        <span className="v1-ttp-badge"><span className="v1-ttp-id">T1041</span> C2 Exfiltration</span>
                      </div>
                      <p className="v1-summary-text">
                        Initial intrusion initiated via malicious invoice macro executing Cobalt Strike beacon in memory.
                        Attacker performed credential dumping on domain controller and staged exfiltration archive via HTTPS.
                      </p>
                    </div>
                  </div>

                  <div className="v1-card">
                    <div className="v1-card-header">
                      <h3>High-Risk Findings Summary</h3>
                      <button className="v1-btn-link" onClick={() => setActiveTab('findings')}>All Findings ({findingsData.length}) →</button>
                    </div>
                    <div className="v1-quick-findings-list">
                      {findingsData.slice(0, 3).map(f => (
                        <div 
                          key={f.id} 
                          className={`v1-quick-finding-row ${selectedFindingId === f.id ? 'selected' : ''}`}
                          onClick={() => { setSelectedFindingId(f.id); setInspectorOpen(true); }}
                        >
                          <span className={`v1-sev-tag ${f.severity.toLowerCase()}`}>{f.severity}</span>
                          <div className="v1-qf-info">
                            <div className="v1-qf-title">{f.title}</div>
                            <div className="v1-qf-sub">{f.mitreTechnique} • Confidence: {f.confidence}%</div>
                          </div>
                          <span className="v1-status-check">{f.reviewStatus}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 2: FINDINGS TABLE & TRIAGE ── */}
            {activeTab === 'findings' && (
              <div className="v1-view-pane">
                <div className="v1-card">
                  <div className="v1-card-header">
                    <div>
                      <h3>Sanitized Forensic Findings (FIR Table)</h3>
                      <p>Review fact-checked observations and promote approved items for official reporting</p>
                    </div>
                    <div className="v1-filters-row">
                      {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                        <button 
                          key={sev} 
                          className={`v1-chip-btn ${severityFilter === sev ? 'active' : ''}`}
                          onClick={() => setSeverityFilter(sev)}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="v1-table-wrapper">
                    <table className="v1-data-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>SEVERITY</th>
                          <th>FORENSIC FACT / OBSERVATION</th>
                          <th>MITRE TTP</th>
                          <th>CONFIDENCE</th>
                          <th>STATUS</th>
                          <th>ACTION</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFindings.map(f => (
                          <tr 
                            key={f.id} 
                            className={selectedFindingId === f.id ? 'row-selected' : ''}
                            onClick={() => { setSelectedFindingId(f.id); setInspectorOpen(true); }}
                          >
                            <td className="font-mono text-primary font-bold">{f.id}</td>
                            <td><span className={`v1-sev-tag ${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                            <td>
                              <div className="v1-table-fact">{f.sanitizedFact}</div>
                              <div className="v1-table-sub">Source: {f.sourceEvidence} (p. {f.sourcePage})</div>
                            </td>
                            <td><span className="v1-ttp-pill">{f.mitreTechnique}</span></td>
                            <td>
                              <div className="v1-conf-bar">
                                <div className="v1-conf-fill" style={{ width: `${f.confidence}%` }}></div>
                                <span>{f.confidence}%</span>
                              </div>
                            </td>
                            <td>
                              <span className={`v1-review-pill ${f.reviewStatus.toLowerCase()}`}>
                                {f.reviewStatus}
                              </span>
                            </td>
                            <td>
                              {f.reviewStatus !== 'PROMOTED' ? (
                                <button 
                                  className="v1-btn-action-sm"
                                  onClick={(e) => { e.stopPropagation(); handlePromoteFinding(f.id); }}
                                >
                                  Promote
                                </button>
                              ) : (
                                <span className="v1-approved-text">✓ Promoted</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 3: EVIDENCE & HASH VERIFICATION ── */}
            {activeTab === 'evidence' && (
              <div className="v1-view-pane">
                <div className="v1-card">
                  <div className="v1-card-header">
                    <div>
                      <h3>Acquired Evidence & Cryptographic Provenance</h3>
                      <p>Chain-of-custody tracking with SHA-256 integrity and RFC 3161 timestamps</p>
                    </div>
                  </div>

                  <div className="v1-table-wrapper">
                    <table className="v1-data-table">
                      <thead>
                        <tr>
                          <th>EVIDENCE ID</th>
                          <th>FILE / ARTIFACT</th>
                          <th>TYPE</th>
                          <th>FILE SIZE</th>
                          <th>SHA-256 INTEGRITY</th>
                          <th>RFC 3161 TIMESTAMP</th>
                          <th>STATUS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {MOCK_EVIDENCE_FILES.map(e => (
                          <tr 
                            key={e.id}
                            className={selectedEvidenceId === e.id ? 'row-selected' : ''}
                            onClick={() => { setSelectedEvidenceId(e.id); setInspectorOpen(true); }}
                          >
                            <td className="font-mono text-primary font-bold">{e.id}</td>
                            <td>
                              <div className="font-bold">{e.fileName}</div>
                              <div className="v1-table-sub">{e.parsedArtifacts} artifacts extracted</div>
                            </td>
                            <td><span className="v1-type-badge">{e.fileType}</span></td>
                            <td className="font-mono">{e.fileSize}</td>
                            <td className="font-mono text-xs">{e.sha256.substring(0, 18)}...</td>
                            <td className="text-xs">{e.rfc3161Timestamp}</td>
                            <td><span className="v1-status-verified">✓ {e.chainOfCustodyStatus}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 4: CHRONOLOGICAL TIMELINE ── */}
            {activeTab === 'timeline' && (
              <div className="v1-view-pane">
                <div className="v1-card">
                  <div className="v1-card-header">
                    <div>
                      <h3>Reconstructed Chronological Incident River</h3>
                      <p>Time-correlated sequence of events across endpoint, network, and memory telemetry</p>
                    </div>
                  </div>

                  <div className="v1-timeline-flow">
                    {MOCK_TIMELINE_EVENTS.map(t => (
                      <div key={t.id} className="v1-timeline-node">
                        <div className="v1-node-timestamp">{t.timestamp}</div>
                        <div className="v1-node-dot"></div>
                        <div className="v1-node-card">
                          <div className="v1-node-card-head">
                            <span className={`v1-sev-tag ${t.severity.toLowerCase()}`}>{t.severity}</span>
                            <span className="v1-node-actor">Actor: {t.actor}</span>
                            <span className="v1-node-source">{t.source}</span>
                          </div>
                          <div className="v1-node-event">{t.event}</div>
                          <div className="v1-node-details">{t.details}</div>
                          <div className="v1-node-meta font-mono">Observable: {t.observable}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── TAB 5: AI ENTAILMENT VERIFICATION ── */}
            {activeTab === 'verification' && (
              <div className="v1-view-pane">
                <div className="v1-card">
                  <div className="v1-card-header">
                    <div>
                      <h3>DeBERTa-v3 Natural Language Entailment Matrix</h3>
                      <p>Automated verification proving every generated claim is strictly entailed by source evidence</p>
                    </div>
                  </div>

                  <div className="v1-claims-grid">
                    {MOCK_AI_CLAIMS.map(claim => (
                      <div key={claim.id} className="v1-claim-card">
                        <div className="v1-claim-head">
                          <span className="font-mono font-bold text-primary">{claim.id}</span>
                          <span className={`v1-entail-badge ${claim.entailmentScore >= 0.9 ? 'verified' : 'flagged'}`}>
                            {claim.entailmentScore >= 0.9 ? '✓ STRICT ENTAILMENT' : '⚠ REQUIRES ANALYST CHECK'}
                          </span>
                        </div>
                        <div className="v1-claim-statement">"{claim.claimText}"</div>
                        <div className="v1-claim-grounding">
                          <div className="v1-grounding-label">GROUNDED CITATION:</div>
                          <div className="v1-grounding-text">{claim.groundedPassage}</div>
                        </div>
                        <div className="v1-claim-score-row">
                          <span>Confidence: <strong>{(claim.entailmentScore * 100).toFixed(1)}%</strong></span>
                          <span>Source: {claim.sourceDoc}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </main>

          {/* ── PERSISTENT CONTEXTUAL INSPECTOR (RIGHT DRAWER) ── */}
          {inspectorOpen && (
            <aside className="v1-inspector-pane">
              <div className="v1-inspector-head">
                <div>
                  <h3 className="v1-inspector-title">Contextual Inspector</h3>
                  <p className="v1-inspector-sub">Active Forensic Entity: {selectedFinding.id}</p>
                </div>
                <button className="v1-btn-close-sm" onClick={() => setInspectorOpen(false)}>✕</button>
              </div>

              {/* Inspector Sub-tabs */}
              <div className="v1-inspector-tabs">
                <button className={`v1-ins-tab ${inspectorTab === 'details' ? 'active' : ''}`} onClick={() => setInspectorTab('details')}>Finding</button>
                <button className={`v1-ins-tab ${inspectorTab === 'raw' ? 'active' : ''}`} onClick={() => setInspectorTab('raw')}>Sanitization Diff</button>
                <button className={`v1-ins-tab ${inspectorTab === 'audit' ? 'active' : ''}`} onClick={() => setInspectorTab('audit')}>Audit Trail</button>
              </div>

              <div className="v1-inspector-body">
                {inspectorTab === 'details' && (
                  <div className="v1-ins-section">
                    <div className="v1-ins-field">
                      <label>FINDING TITLE</label>
                      <div className="v1-ins-val font-bold">{selectedFinding.title}</div>
                    </div>
                    <div className="v1-ins-field">
                      <label>SANITIZED FACT</label>
                      <div className="v1-ins-val">{selectedFinding.sanitizedFact}</div>
                    </div>
                    <div className="v1-ins-field">
                      <label>MITRE ATT&CK TECHNIQUE</label>
                      <div className="v1-ins-val font-mono text-primary">{selectedFinding.mitreTechnique}</div>
                    </div>
                    <div className="v1-ins-field">
                      <label>SOURCE EVIDENCE & HASH</label>
                      <div className="v1-ins-val font-mono text-xs">{selectedEvidence.fileName}</div>
                      <div className="v1-ins-val font-mono text-muted text-xs">{selectedEvidence.sha256}</div>
                    </div>
                    <div className="v1-ins-field">
                      <label>MAKER-CHECKER APPROVAL</label>
                      <div className="v1-maker-box">
                        <div>Status: <strong>{selectedFinding.reviewStatus}</strong></div>
                        {selectedFinding.reviewStatus === 'PROMOTED' ? (
                          <div className="text-success text-xs mt-1">Approved by {selectedFinding.makerChecker.promotedBy}</div>
                        ) : (
                          <button 
                            className="v1-btn-promote-full"
                            onClick={() => handlePromoteFinding(selectedFinding.id)}
                          >
                            ✓ Approve & Promote Finding
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {inspectorTab === 'raw' && (
                  <div className="v1-ins-section">
                    <label>ORIGINAL RAW TEXT (PRE-REDACTION)</label>
                    <div className="v1-diff-block raw">{selectedFinding.rawText}</div>
                    <label className="mt-3">SANITIZED OUTPUT (POST-REDACTION)</label>
                    <div className="v1-diff-block sanitized">{selectedFinding.sanitizedFact}</div>
                    <div className="v1-redaction-meta">
                      <span>Redaction Method: Deterministic Pseudonymization</span>
                      <span>PII Protected: IP, Username, Hostname</span>
                    </div>
                  </div>
                )}

                {inspectorTab === 'audit' && (
                  <div className="v1-ins-section">
                    <label>CASE AUDIT STREAM</label>
                    <div className="v1-audit-stream">
                      {MOCK_AUDIT_LOGS.map(log => (
                        <div key={log.id} className="v1-audit-row">
                          <div className="v1-audit-time">{log.timestamp}</div>
                          <div className="v1-audit-action">{log.action}</div>
                          <div className="v1-audit-user">{log.user} ({log.role})</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </aside>
          )}
        </div>
      </div>
    </div>
  );
}
