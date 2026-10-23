import React, { useState } from 'react';
import { 
  MOCK_CASES, 
  MOCK_EVIDENCE_FILES, 
  MOCK_FIR_FINDINGS, 
  MOCK_AI_CLAIMS, 
  MOCK_TIMELINE_EVENTS,
  MOCK_CASE_NOTES,
  MOCK_AUDIT_EVENTS
} from '../../mock/investigationMockData';
import './Template1.css';

export default function Template1CommandCenter() {
  const [activeCase, setActiveCase] = useState(MOCK_CASES[0]);
  const [selectedFinding, setSelectedFinding] = useState(MOCK_FIR_FINDINGS[0]);
  const [selectedEvidence, setSelectedEvidence] = useState(MOCK_EVIDENCE_FILES[0]);
  const [activeTab, setActiveTab] = useState('findings'); // 'findings' | 'timeline' | 'ai_claims' | 'evidence' | 'notes'
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [provenanceOpen, setProvenanceOpen] = useState(false);
  const [claimsList, setClaimsList] = useState(MOCK_AI_CLAIMS);

  // Filter findings
  const filteredFindings = MOCK_FIR_FINDINGS.filter(f => {
    const matchesSev = filterSeverity === 'ALL' || f.severity.toUpperCase() === filterSeverity.toUpperCase();
    const matchesSearch = f.fact.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          f.finding_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          f.source_engine.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const handleToggleClaimApproval = (claimId) => {
    setClaimsList(prev => prev.map(c => {
      if (c.claim_id === claimId) {
        return {
          ...c,
          human_approval: c.human_approval === 'confirmed' ? 'rejected' : 'confirmed'
        };
      }
      return c;
    }));
  };

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 't1-badge-crit';
      case 'high': return 't1-badge-high';
      case 'medium': return 't1-badge-med';
      default: return 't1-badge-low';
    }
  };

  return (
    <div className="t1-container">
      {/* ── TOP TELEMETRY HUD ── */}
      <header className="t1-header">
        <div className="t1-header-brand">
          <div className="t1-logo-icon">ARGUS</div>
          <div>
            <div className="t1-title-main">FORENSIC COMMAND CENTER</div>
            <div className="t1-title-sub">Deterministic Ground Truth &bull; Multi-Agent Entailment Engine</div>
          </div>
        </div>

        {/* ACTIVE CASE HUD CARD */}
        <div className="t1-case-hud">
          <div className="t1-case-selector">
            <span className="t1-label">ACTIVE CASE:</span>
            <select 
              value={activeCase.case_id} 
              onChange={(e) => setActiveCase(MOCK_CASES.find(c => c.case_id === e.target.value))}
              className="t1-select"
            >
              {MOCK_CASES.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.name}</option>
              ))}
            </select>
          </div>

          <div className="t1-hud-metrics">
            <div className="t1-metric">
              <span className="t1-metric-label">SEVERITY</span>
              <span className="t1-metric-val t1-color-crit">{activeCase.severity.toUpperCase()}</span>
            </div>
            <div className="t1-metric">
              <span className="t1-metric-label">EVIDENCE HASH</span>
              <span className="t1-metric-val t1-color-cyan">RFC 3161 SEALED</span>
            </div>
            <div className="t1-metric">
              <span className="t1-metric-label">AI VERIFICATION</span>
              <span className="t1-metric-val t1-color-green">96.4% ENTAILED</span>
            </div>
            <div className="t1-metric">
              <span className="t1-metric-label">LEAD ANALYST</span>
              <span className="t1-metric-val">{activeCase.analyst_name}</span>
            </div>
          </div>
        </div>
      </header>

      {/* ── MAIN WORKBENCH BODY ── */}
      <div className="t1-workbench">
        
        {/* ── LEFT DOCK: EVIDENCE & INTAKE TREE ── */}
        <aside className="t1-left-dock">
          <div className="t1-dock-header">
            <span>SECURED EVIDENCE FILES ({MOCK_EVIDENCE_FILES.length})</span>
            <span className="t1-badge-count">100% PARSED</span>
          </div>

          <div className="t1-evidence-list">
            {MOCK_EVIDENCE_FILES.map(ev => (
              <div 
                key={ev.evidence_id} 
                className={`t1-ev-card ${selectedEvidence.evidence_id === ev.evidence_id ? 'active' : ''}`}
                onClick={() => setSelectedEvidence(ev)}
              >
                <div className="t1-ev-top">
                  <span className="t1-ev-type">{ev.type}</span>
                  <span className="t1-ev-size">{ev.size_formatted}</span>
                </div>
                <div className="t1-ev-name">{ev.filename}</div>
                <div className="t1-ev-meta">
                  <span>Host: {ev.source_host}</span>
                  <span className="t1-color-green">✔ {ev.findings_count} FIR Findings</span>
                </div>
              </div>
            ))}
          </div>

          <div className="t1-intake-status">
            <div className="t1-intake-title">COLLECTION COVERAGE CHECK</div>
            <div className="t1-progress-bar">
              <div className="t1-progress-fill" style={{ width: '85%' }}></div>
            </div>
            <div className="t1-intake-legend">
              <span>Host Memory ✔</span>
              <span>Sysmon ✔</span>
              <span>PCAP ✔</span>
              <span className="t1-color-crit">VPN Logs ✘</span>
            </div>
          </div>
        </aside>

        {/* ── CENTER WORKBENCH: DATA GRID & INVESTIGATION TABS ── */}
        <main className="t1-center-stage">
          {/* TAB BAR */}
          <div className="t1-tabs">
            <button className={`t1-tab ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>
              🔍 Ground-Truth FIR Findings ({filteredFindings.length})
            </button>
            <button className={`t1-tab ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>
              ⏳ Attack Timeline ({MOCK_TIMELINE_EVENTS.length})
            </button>
            <button className={`t1-tab ${activeTab === 'ai_claims' ? 'active' : ''}`} onClick={() => setActiveTab('ai_claims')}>
              🧠 AI Multi-Agent Claims ({claimsList.length})
            </button>
            <button className={`t1-tab ${activeTab === 'notes' ? 'active' : ''}`} onClick={() => setActiveTab('notes')}>
              📝 Case Notes ({MOCK_CASE_NOTES.length})
            </button>
          </div>

          {/* TAB CONTENT: FINDINGS */}
          {activeTab === 'findings' && (
            <div className="t1-panel-content">
              {/* FILTER BAR */}
              <div className="t1-filter-bar">
                <input 
                  type="text" 
                  placeholder="Filter facts, PIDs, MITRE techniques, IOCs..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="t1-search-input"
                />
                <div className="t1-sev-filters">
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                    <button 
                      key={sev} 
                      className={`t1-sev-btn ${filterSeverity === sev ? 'active' : ''}`}
                      onClick={() => setFilterSeverity(sev)}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              {/* DENSE FINDINGS TABLE */}
              <div className="t1-table-wrapper">
                <table className="t1-table">
                  <thead>
                    <tr>
                      <th style={{ width: '85px' }}>ID</th>
                      <th style={{ width: '100px' }}>SEVERITY</th>
                      <th style={{ width: '130px' }}>ENGINE</th>
                      <th>FACT & FORENSIC OBSERVATION</th>
                      <th style={{ width: '220px' }}>MITRE ATT&CK</th>
                      <th style={{ width: '90px' }}>CONF</th>
                      <th style={{ width: '100px' }}>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map(f => (
                      <tr 
                        key={f.finding_id} 
                        className={selectedFinding?.finding_id === f.finding_id ? 't1-row-selected' : ''}
                        onClick={() => setSelectedFinding(f)}
                      >
                        <td className="t1-td-id">{f.finding_id}</td>
                        <td><span className={`t1-badge ${getSeverityBadgeClass(f.severity)}`}>{f.severity.toUpperCase()}</span></td>
                        <td className="t1-td-engine">[{f.source_engine}]</td>
                        <td className="t1-td-fact">
                          <div className="t1-fact-text">{f.sanitized_fact}</div>
                          <div className="t1-fact-sources">Ref: {f.evidence_reference.join(', ')}</div>
                        </td>
                        <td className="t1-td-mitre">{f.mitre_mapping}</td>
                        <td><span className="t1-conf-score">{Math.round(f.confidence * 100)}%</span></td>
                        <td>
                          <button 
                            className="t1-btn-inspect"
                            onClick={(e) => { e.stopPropagation(); setSelectedFinding(f); setProvenanceOpen(true); }}
                          >
                            PROVENANCE
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB CONTENT: TIMELINE */}
          {activeTab === 'timeline' && (
            <div className="t1-panel-content">
              <div className="t1-timeline-stream">
                {MOCK_TIMELINE_EVENTS.map((tl, idx) => (
                  <div key={tl.id} className="t1-timeline-item">
                    <div className="t1-tl-marker">
                      <div className="t1-tl-dot"></div>
                      {idx < MOCK_TIMELINE_EVENTS.length - 1 && <div className="t1-tl-line"></div>}
                    </div>
                    <div className="t1-tl-card">
                      <div className="t1-tl-header">
                        <span className="t1-tl-time">{tl.time}</span>
                        <span className={`t1-badge ${getSeverityBadgeClass(tl.severity)}`}>{tl.category}</span>
                        <span className="t1-tl-host">Host: {tl.host}</span>
                      </div>
                      <div className="t1-tl-title">{tl.title}</div>
                      <div className="t1-tl-desc">{tl.description}</div>
                      <div className="t1-tl-source">Source: {tl.source} &bull; Linked Finding: {tl.finding_id}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB CONTENT: AI AGENT CLAIMS & VERIFICATION */}
          {activeTab === 'ai_claims' && (
            <div className="t1-panel-content">
              <div className="t1-claims-grid">
                {claimsList.map(c => (
                  <div key={c.claim_id} className="t1-claim-card">
                    <div className="t1-claim-top">
                      <span className="t1-claim-agent">{c.agent_name}</span>
                      <span className="t1-claim-conf">Confidence: {(c.confidence_score * 100).toFixed(0)}%</span>
                    </div>
                    <div className="t1-claim-title">{c.title}</div>
                    <div className="t1-claim-text">"{c.claim}"</div>

                    {/* ENTAILMENT VERIFICATION BOX */}
                    <div className="t1-verification-box">
                      <div className="t1-v-header">
                        <span>🤖 INDEPENDENT VERIFICATION (DeBERTa-v3-large-MNLI)</span>
                        <span className="t1-color-green">ENTAILMENT: {(c.verification.entailment_score * 100).toFixed(0)}%</span>
                      </div>
                      <div className="t1-v-checks">
                        <span>✔ Existence in FIR: PASS</span>
                        <span>✔ Severity Inflation: CLEAN</span>
                        <span>✔ Divergence: CLEAN</span>
                      </div>
                    </div>

                    <div className="t1-claim-footer">
                      <div className="t1-claim-citations">
                        Cited FIR Findings: {c.cited_evidence_ids.map(id => <span key={id} className="t1-cite-pill">{id}</span>)}
                      </div>
                      <button 
                        className={`t1-btn-approve ${c.human_approval === 'confirmed' ? 'approved' : ''}`}
                        onClick={() => handleToggleClaimApproval(c.claim_id)}
                      >
                        {c.human_approval === 'confirmed' ? '✔ MAKER-CHECKER APPROVED' : '⚠ PENDING REVIEW'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB CONTENT: CASE NOTES */}
          {activeTab === 'notes' && (
            <div className="t1-panel-content">
              <div className="t1-notes-feed">
                {MOCK_CASE_NOTES.map(n => (
                  <div key={n.note_id} className="t1-note-card">
                    <div className="t1-note-header">
                      <span className="t1-note-author">{n.author}</span>
                      <span className="t1-badge t1-badge-high">{n.type} &bull; {n.priority}</span>
                      <span className="t1-note-time">{new Date(n.created_at).toLocaleTimeString()}</span>
                    </div>
                    <div className="t1-note-title">{n.title}</div>
                    <div className="t1-note-body">{n.content}</div>
                    <div className="t1-note-footer">
                      Ref Evidence: {n.related_evidence} &bull; Linked Finding: {n.related_finding}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>

        {/* ── RIGHT DOCK: LIVE FORENSIC TELEMETRY ── */}
        <aside className="t1-right-dock">
          <div className="t1-dock-header">
            <span>FORENSIC TELEMETRY</span>
            <span className="t1-color-cyan">LIVE</span>
          </div>

          {/* SELECTED ITEM QUICK SUMMARY */}
          {selectedFinding && (
            <div className="t1-quick-summary">
              <div className="t1-qs-title">SELECTED FINDING: {selectedFinding.finding_id}</div>
              <div className="t1-qs-item">
                <span className="t1-label">Engine:</span>
                <span>{selectedFinding.source_engine}</span>
              </div>
              <div className="t1-qs-item">
                <span className="t1-label">Layer:</span>
                <span>{selectedFinding.layer}</span>
              </div>
              <div className="t1-qs-item">
                <span className="t1-label">Confidence:</span>
                <span>{(selectedFinding.confidence * 100).toFixed(0)}%</span>
              </div>
              <div className="t1-qs-item">
                <span className="t1-label">Injection Risk:</span>
                <span className="t1-color-green">{selectedFinding.injection_flagged ? 'FLAGGED' : '0.00 (Clean)'}</span>
              </div>
              <button className="t1-btn-full-prov" onClick={() => setProvenanceOpen(true)}>
                OPEN FULL PROVENANCE DRAWER ➔
              </button>
            </div>
          )}

          <div className="t1-audit-feed">
            <div className="t1-feed-title">AUDIT TRAIL & CUSTODY LOG</div>
            {MOCK_AUDIT_EVENTS.map(a => (
              <div key={a.id} className="t1-audit-row">
                <div className="t1-audit-top">
                  <span className="t1-color-cyan">{a.actor}</span>
                  <span className="t1-audit-time">{new Date(a.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="t1-audit-act">{a.action}: {a.resource}</div>
              </div>
            ))}
          </div>
        </aside>

      </div>

      {/* ── SLIDE-OUT EVIDENCE PROVENANCE DRAWER ── */}
      {provenanceOpen && selectedFinding && (
        <div className="t1-drawer-overlay" onClick={() => setProvenanceOpen(false)}>
          <div className="t1-drawer" onClick={(e) => e.stopPropagation()}>
            <div className="t1-drawer-header">
              <div>
                <div className="t1-drawer-tag">EVIDENTIARY PROVENANCE INSPECTOR</div>
                <div className="t1-drawer-title">{selectedFinding.finding_id} &mdash; Ground Truth Origin</div>
              </div>
              <button className="t1-btn-close" onClick={() => setProvenanceOpen(false)}>✕</button>
            </div>

            <div className="t1-drawer-body">
              <div className="t1-prov-section">
                <div className="t1-prov-heading">1. Ground-Truth FIR Record (PostgreSQL)</div>
                <div className="t1-code-block">
                  {JSON.stringify(selectedFinding, null, 2)}
                </div>
              </div>

              <div className="t1-prov-section">
                <div className="t1-prov-heading">2. Associated Raw Evidence Container</div>
                <div className="t1-prov-grid">
                  <div><strong>File:</strong> {selectedEvidence.filename}</div>
                  <div><strong>Type:</strong> {selectedEvidence.type}</div>
                  <div><strong>SHA-256:</strong> <code>{selectedEvidence.sha256}</code></div>
                  <div><strong>RFC 3161 Stamp:</strong> ✔ Validated (FreeTSA Authority)</div>
                  <div><strong>Storage Object:</strong> <code>minio://argus-raw-evidence/{activeCase.case_id}/{selectedEvidence.filename}</code></div>
                </div>
              </div>

              <div className="t1-prov-section">
                <div className="t1-prov-heading">3. Prompt-Injection & Sanitization Audit</div>
                <div className="t1-prov-status">
                  <span>Injection Score: <strong>{selectedFinding.injection_score}</strong></span>
                  <span>Classifier: <code>protectai/deberta-v3-base-prompt-injection-v2</code></span>
                  <span>PII Redacted: <strong>Yes (Credentials/SSN scrubbed)</strong></span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
