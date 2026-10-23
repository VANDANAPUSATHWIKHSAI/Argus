import React, { useState } from 'react';
import { 
  MOCK_CASES, 
  MOCK_EVIDENCE_FILES, 
  MOCK_FIR_FINDINGS, 
  MOCK_AI_CLAIMS, 
  MOCK_TIMELINE_EVENTS,
  MOCK_CASE_NOTES,
  MOCK_INCIDENT_TEMPLATES
} from '../../mock/investigationMockData';
import './Template2.css';

export default function Template2Workspace() {
  const [activeCase, setActiveCase] = useState(MOCK_CASES[0]);
  const [activeView, setActiveView] = useState('overview'); // 'overview' | 'evidence' | 'findings' | 'timeline' | 'ai_synthesis' | 'notes'
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedClaim, setSelectedClaim] = useState(MOCK_AI_CLAIMS[0]);
  const [claims, setClaims] = useState(MOCK_AI_CLAIMS);

  const handleToggleClaim = (claimId) => {
    setClaims(prev => prev.map(c => {
      if (c.claim_id === claimId) {
        return {
          ...c,
          human_approval: c.human_approval === 'confirmed' ? 'rejected' : 'confirmed'
        };
      }
      return c;
    }));
  };

  const getSeverityStyle = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return { bg: 'rgba(239, 68, 68, 0.15)', text: '#f87171', border: 'rgba(239, 68, 68, 0.4)' };
      case 'high': return { bg: 'rgba(249, 115, 22, 0.15)', text: '#fb923c', border: 'rgba(249, 115, 22, 0.4)' };
      case 'medium': return { bg: 'rgba(59, 130, 246, 0.15)', text: '#60a5fa', border: 'rgba(59, 130, 246, 0.4)' };
      default: return { bg: 'rgba(16, 185, 129, 0.15)', text: '#34d399', border: 'rgba(16, 185, 129, 0.4)' };
    }
  };

  return (
    <div className="t2-app">
      {/* ── LEFT NAVIGATION SIDEBAR ── */}
      <aside className="t2-sidebar">
        <div className="t2-brand">
          <div className="t2-brand-logo">A</div>
          <div className="t2-brand-text">
            <span className="t2-brand-name">ARGUS</span>
            <span className="t2-brand-sub">Workspace v2.4</span>
          </div>
        </div>

        <nav className="t2-nav">
          <button 
            className={`t2-nav-btn ${activeView === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveView('overview')}
          >
            <span className="t2-nav-icon">📊</span>
            <span>Case Overview</span>
          </button>
          <button 
            className={`t2-nav-btn ${activeView === 'evidence' ? 'active' : ''}`}
            onClick={() => setActiveView('evidence')}
          >
            <span className="t2-nav-icon">📁</span>
            <span>Evidence Locker</span>
            <span className="t2-nav-badge">{MOCK_EVIDENCE_FILES.length}</span>
          </button>
          <button 
            className={`t2-nav-btn ${activeView === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveView('findings')}
          >
            <span className="t2-nav-icon">🔍</span>
            <span>FIR Ground Truth</span>
            <span className="t2-nav-badge">{MOCK_FIR_FINDINGS.length}</span>
          </button>
          <button 
            className={`t2-nav-btn ${activeView === 'timeline' ? 'active' : ''}`}
            onClick={() => setActiveView('timeline')}
          >
            <span className="t2-nav-icon">⏳</span>
            <span>Attack Timeline</span>
          </button>
          <button 
            className={`t2-nav-btn ${activeView === 'ai_synthesis' ? 'active' : ''}`}
            onClick={() => setActiveView('ai_synthesis')}
          >
            <span className="t2-nav-icon">🤖</span>
            <span>AI Verification</span>
            <span className="t2-nav-badge highlight">96%</span>
          </button>
          <button 
            className={`t2-nav-btn ${activeView === 'notes' ? 'active' : ''}`}
            onClick={() => setActiveView('notes')}
          >
            <span className="t2-nav-icon">📝</span>
            <span>Case Notes</span>
            <span className="t2-nav-badge">{MOCK_CASE_NOTES.length}</span>
          </button>
        </nav>

        {/* SIDEBAR FOOTER */}
        <div className="t2-sidebar-footer">
          <div className="t2-user-pill">
            <div className="t2-avatar">S</div>
            <div>
              <div className="t2-user-name">Sathwik</div>
              <div className="t2-user-role">Lead Analyst</div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── MAIN CONTENT AREA ── */}
      <main className="t2-main">
        {/* ── TOP CONTEXTUAL BAR ── */}
        <header className="t2-topbar">
          <div className="t2-breadcrumb">
            <span>Investigations</span>
            <span className="t2-sep">/</span>
            <select 
              value={activeCase.case_id} 
              onChange={(e) => setActiveCase(MOCK_CASES.find(c => c.case_id === e.target.value))}
              className="t2-case-select"
            >
              {MOCK_CASES.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.case_id}: {c.name}</option>
              ))}
            </select>
          </div>

          <div className="t2-topbar-actions">
            <div className="t2-status-pill">
              <span className="t2-status-dot"></span>
              <span>STATUS: {activeCase.status.toUpperCase()}</span>
            </div>
            <button className="t2-btn-export">
              📄 Export Defensible Report (PDF)
            </button>
          </div>
        </header>

        {/* ── VIEW: OVERVIEW & BLAST RADIUS ── */}
        {activeView === 'overview' && (
          <div className="t2-canvas">
            <div className="t2-hero-card">
              <div className="t2-hero-header">
                <div>
                  <span className="t2-incident-tag">{activeCase.incident_type}</span>
                  <h1 className="t2-hero-title">{activeCase.name}</h1>
                </div>
                <div className="t2-hero-sev" style={getSeverityStyle(activeCase.severity)}>
                  {activeCase.severity.toUpperCase()} PRIORITY
                </div>
              </div>
              <p className="t2-hero-desc">{activeCase.description}</p>

              <div className="t2-metrics-row">
                <div className="t2-metric-card">
                  <div className="t2-mc-val">{MOCK_EVIDENCE_FILES.length} Files</div>
                  <div className="t2-mc-sub">Raw Blobs Sealed in MinIO</div>
                </div>
                <div className="t2-metric-card">
                  <div className="t2-mc-val">{MOCK_FIR_FINDINGS.length} Facts</div>
                  <div className="t2-mc-sub">Deterministic Ground Truth</div>
                </div>
                <div className="t2-metric-card">
                  <div className="t2-mc-val">96.4%</div>
                  <div className="t2-mc-sub">DeBERTa Verification Score</div>
                </div>
                <div className="t2-metric-card">
                  <div className="t2-mc-val">{activeCase.affected_hosts.length} Hosts</div>
                  <div className="t2-mc-sub">Compromise Blast Radius</div>
                </div>
              </div>
            </div>

            {/* AFFECTED ASSETS & INTAKE CHECKLIST */}
            <div className="t2-two-col">
              <div className="t2-card">
                <div className="t2-card-title">🚨 Compromised Asset Scope</div>
                <div className="t2-asset-list">
                  {activeCase.affected_hosts.map(host => (
                    <div key={host} className="t2-asset-item">
                      <span className="t2-asset-icon">💻</span>
                      <div>
                        <div className="t2-asset-name">{host}</div>
                        <div className="t2-asset-meta">Domain: AD.CORP &bull; Sysmon ID 1 Logged</div>
                      </div>
                      <span className="t2-asset-status">ISOLATION RECOMMENDED</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="t2-card">
                <div className="t2-card-title">📋 Evidence Coverage Matrix</div>
                <div className="t2-checklist">
                  {MOCK_INCIDENT_TEMPLATES['Ransomware & Credential Theft'].map((item, idx) => (
                    <div key={idx} className="t2-check-row">
                      <span className={`t2-check-icon ${item.status === 'Available' ? 'avail' : 'miss'}`}>
                        {item.status === 'Available' ? '✔' : '✘'}
                      </span>
                      <span className="t2-check-name">{item.name}</span>
                      <span className="t2-check-cat">{item.category}</span>
                      <span className={`t2-check-status ${item.status === 'Available' ? 'avail' : 'miss'}`}>
                        {item.status.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── VIEW: EVIDENCE LOCKER ── */}
        {activeView === 'evidence' && (
          <div className="t2-canvas">
            <div className="t2-section-header">
              <h2>Evidence Locker & Custody Repository</h2>
              <p>Cryptographically sealed binary evidence stored immutably with RFC 3161 timestamps.</p>
            </div>

            <div className="t2-grid-3">
              {MOCK_EVIDENCE_FILES.map(ev => (
                <div key={ev.evidence_id} className="t2-evidence-box">
                  <div className="t2-ev-box-header">
                    <span className="t2-ev-badge">{ev.type}</span>
                    <span className="t2-ev-size">{ev.size_formatted}</span>
                  </div>
                  <h3 className="t2-ev-box-name">{ev.filename}</h3>
                  <div className="t2-ev-meta-block">
                    <div><strong>SHA-256:</strong> <code className="t2-hash">{ev.sha256.slice(0, 16)}...</code></div>
                    <div><strong>Host:</strong> {ev.source_host}</div>
                    <div><strong>Timestamp Seal:</strong> ✔ FreeTSA RFC 3161</div>
                    <div><strong>Artifacts Extracted:</strong> {ev.extracted_artifacts_count} items</div>
                  </div>
                  <div className="t2-ev-actions">
                    <button className="t2-btn-ev-action">Download Verified Blob</button>
                    <button className="t2-btn-ev-action">View Raw Metadata</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── VIEW: FINDINGS & PROVENANCE ── */}
        {activeView === 'findings' && (
          <div className="t2-canvas">
            <div className="t2-section-header">
              <h2>Deterministic Forensic Intelligence Repository (FIR)</h2>
              <p>Rule-based ground truth extracted by Python forensic engines, scrubbed of prompt-injections.</p>
            </div>

            <div className="t2-findings-feed">
              {MOCK_FIR_FINDINGS.map(f => (
                <div 
                  key={f.finding_id} 
                  className={`t2-finding-card ${selectedFinding?.finding_id === f.finding_id ? 'active' : ''}`}
                  onClick={() => setSelectedFinding(selectedFinding?.finding_id === f.finding_id ? null : f)}
                >
                  <div className="t2-fc-header">
                    <span className="t2-fc-id">{f.finding_id}</span>
                    <span className="t2-fc-sev" style={getSeverityStyle(f.severity)}>{f.severity.toUpperCase()}</span>
                    <span className="t2-fc-engine">Engine: {f.source_engine}</span>
                    <span className="t2-fc-time">{new Date(f.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="t2-fc-fact">{f.sanitized_fact}</div>
                  <div className="t2-fc-mitre">🎯 MITRE ATT&CK: <strong>{f.mitre_mapping}</strong></div>

                  {/* EXPANDABLE PROVENANCE DETAIL */}
                  {selectedFinding?.finding_id === f.finding_id && (
                    <div className="t2-fc-expanded">
                      <div className="t2-exp-title">EVIDENTIARY PROVENANCE & TECHNICAL DETAILS</div>
                      <div className="t2-exp-grid">
                        <div><strong>Source Files:</strong> {f.evidence_reference.join(', ')}</div>
                        <div><strong>Confidence Score:</strong> {(f.confidence * 100).toFixed(0)}% (Deterministic)</div>
                        <div><strong>Sanitization Gate:</strong> Passed (Score: {f.injection_score})</div>
                        <div><strong>Raw Parameters:</strong> <pre className="t2-pre">{JSON.stringify(f.details, null, 2)}</pre></div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── VIEW: CHRONOLOGICAL TIMELINE ── */}
        {activeView === 'timeline' && (
          <div className="t2-canvas">
            <div className="t2-section-header">
              <h2>Chronological Attack Sequence</h2>
              <p>Correlated timeline of adversary execution across host, memory, and perimeter network.</p>
            </div>

            <div className="t2-timeline-stream">
              {MOCK_TIMELINE_EVENTS.map((item, idx) => (
                <div key={item.id} className="t2-tl-node">
                  <div className="t2-tl-timestamp">
                    <div className="t2-tl-clock">{item.time}</div>
                    <div className="t2-tl-host-tag">{item.host}</div>
                  </div>
                  <div className="t2-tl-center">
                    <div className="t2-tl-bullet"></div>
                    {idx < MOCK_TIMELINE_EVENTS.length - 1 && <div className="t2-tl-connector"></div>}
                  </div>
                  <div className="t2-tl-content-card">
                    <div className="t2-tl-card-top">
                      <span className="t2-tl-cat">{item.category}</span>
                      <span className="t2-tl-source">{item.source}</span>
                    </div>
                    <div className="t2-tl-title">{item.title}</div>
                    <div className="t2-tl-desc">{item.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── VIEW: AI SYNTHESIS & ENTAILMENT VERIFICATION ── */}
        {activeView === 'ai_synthesis' && (
          <div className="t2-canvas">
            <div className="t2-section-header">
              <h2>Multi-Agent AI Synthesis & Verification Engine</h2>
              <p>Synthesized narrative claims generated by Agents 1–7 with zero-shot DeBERTa-MNLI entailment checks.</p>
            </div>

            <div className="t2-claims-container">
              {claims.map(claim => (
                <div key={claim.claim_id} className="t2-claim-box">
                  <div className="t2-claim-header">
                    <div>
                      <span className="t2-agent-badge">{claim.agent_name}</span>
                      <h3 className="t2-claim-title">{claim.title}</h3>
                    </div>
                    <div className="t2-claim-status-group">
                      <div className="t2-entailment-badge">
                        <span>🤖 Entailment Score:</span>
                        <strong>{(claim.verification.entailment_score * 100).toFixed(0)}%</strong>
                      </div>
                      <button 
                        className={`t2-btn-approval ${claim.human_approval === 'confirmed' ? 'approved' : ''}`}
                        onClick={() => handleToggleClaim(claim.claim_id)}
                      >
                        {claim.human_approval === 'confirmed' ? '✔ Senior Approved' : '⚠ Action Required'}
                      </button>
                    </div>
                  </div>

                  <p className="t2-claim-prose">"{claim.claim}"</p>

                  <div className="t2-claim-footer">
                    <div className="t2-claim-citations">
                      <span>Cited FIR Facts:</span>
                      {claim.cited_evidence_ids.map(id => (
                        <span key={id} className="t2-cite-tag">{id}</span>
                      ))}
                    </div>
                    <div className="t2-verification-checks">
                      <span>✔ Existence: PASS</span>
                      <span>✔ No Hallucination</span>
                      <span>✔ Severity Intact</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── VIEW: CASE NOTES ── */}
        {activeView === 'notes' && (
          <div className="t2-canvas">
            <div className="t2-section-header">
              <h2>Collaborative Case Notes & Hypotheses</h2>
              <p>Real-time investigator notepad with tagged evidence references and senior review queues.</p>
            </div>

            <div className="t2-notes-grid">
              {MOCK_CASE_NOTES.map(note => (
                <div key={note.note_id} className="t2-note-card">
                  <div className="t2-note-head">
                    <span className="t2-note-author">{note.author}</span>
                    <span className="t2-note-prio">{note.priority} Priority</span>
                  </div>
                  <h3 className="t2-note-title">{note.title}</h3>
                  <p className="t2-note-text">{note.content}</p>
                  <div className="t2-note-tags">
                    <span>Evidence: {note.related_evidence}</span>
                    <span>Finding: {note.related_finding}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
