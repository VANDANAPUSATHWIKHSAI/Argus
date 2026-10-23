import React, { useState } from 'react';
import {
  MOCK_CASES,
  MOCK_EVIDENCE_FILES,
  MOCK_FINDINGS,
  MOCK_TIMELINE_EVENTS,
  MOCK_AI_CLAIMS,
  MOCK_CASE_NOTES
} from '../../mock/investigationMockData';
import './EvolvedV2.css';

export default function EvolvedV2MasterDetail() {
  const [activeCaseId, setActiveCaseId] = useState('ARGUS-2026-0892');
  const [selectedFindingId, setSelectedFindingId] = useState('F-101');
  const [selectedTreeItem, setSelectedTreeItem] = useState('all-findings');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [notes, setNotes] = useState(MOCK_CASE_NOTES);
  const [newNote, setNewNote] = useState('');
  const [findings, setFindings] = useState(MOCK_FINDINGS);
  const [toast, setToast] = useState(null);

  const currentCase = MOCK_CASES.find(c => c.id === activeCaseId) || MOCK_CASES[0];
  const selectedFinding = findings.find(f => f.id === selectedFindingId) || findings[0];
  const selectedEvidence = MOCK_EVIDENCE_FILES.find(e => e.id === selectedFinding.sourceEvidence) || MOCK_EVIDENCE_FILES[0];
  const relatedClaim = MOCK_AI_CLAIMS.find(c => c.findingId === selectedFinding.id) || MOCK_AI_CLAIMS[0];

  const triggerToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const handleApprove = (id) => {
    setFindings(prev => prev.map(f => f.id === id ? {
      ...f,
      reviewStatus: 'PROMOTED',
      makerChecker: {
        status: 'APPROVED',
        promotedBy: 'Senior Lead Analyst',
        approvedAt: new Date().toLocaleTimeString()
      }
    } : f));
    triggerToast(`Finding ${id} approved & promoted for reporting.`);
  };

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    const noteObj = {
      id: `NOTE-${Date.now()}`,
      author: 'Sarah Connor',
      role: 'Lead Analyst',
      timestamp: 'Just now',
      content: newNote.trim()
    };
    setNotes([noteObj, ...notes]);
    setNewNote('');
    triggerToast('Case note recorded.');
  };

  const filteredFindings = findings.filter(f => {
    const matchSev = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchSearch = !searchQuery || (f.id + f.title + f.sanitizedFact + f.mitreTechnique).toLowerCase().includes(searchQuery.toLowerCase());
    return matchSev && matchSearch;
  });

  return (
    <div className="v2-layout-shell">
      {toast && (
        <div className="v2-toast-notification">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          <span>{toast}</span>
        </div>
      )}

      {/* ── TOP BREADCRUMB & CONTEXT BAR ── */}
      <header className="v2-top-header">
        <div className="v2-header-left">
          <div className="v2-brand-badge">
            <span className="v2-brand-letter">Λ</span>
            <span className="v2-brand-title">ARGUS</span>
          </div>
          <div className="v2-divider-v"></div>
          <div className="v2-breadcrumb">
            <span className="v2-crumb-muted">Cases</span>
            <span className="v2-crumb-sep">/</span>
            <select 
              className="v2-case-select"
              value={activeCaseId}
              onChange={(e) => { setActiveCaseId(e.target.value); triggerToast(`Switched to ${e.target.value}`); }}
            >
              {MOCK_CASES.map(c => (
                <option key={c.id} value={c.id}>{c.id} — {c.name}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Milestone Tracker in Topbar */}
        <div className="v2-milestones">
          <div className="v2-ms-step completed">1. Ingestion</div>
          <div className="v2-ms-arrow">→</div>
          <div className="v2-ms-step completed">2. Parsing</div>
          <div className="v2-ms-arrow">→</div>
          <div className="v2-ms-step completed">3. Sanitizing</div>
          <div className="v2-ms-arrow">→</div>
          <div className="v2-ms-step active">4. Triage & NLI</div>
          <div className="v2-ms-arrow">→</div>
          <div className="v2-ms-step pending">5. Final Report</div>
        </div>

        <div className="v2-header-right">
          <div className="v2-stat-pill">
            <span className="v2-sp-label">Findings:</span>
            <span className="v2-sp-val">{findings.length}</span>
          </div>
          <div className="v2-stat-pill danger">
            <span className="v2-sp-label">Critical:</span>
            <span className="v2-sp-val">{findings.filter(f => f.severity === 'CRITICAL').length}</span>
          </div>
          <div className="v2-user-badge">
            <div className="v2-avatar">SC</div>
            <span>Sarah Connor</span>
          </div>
        </div>
      </header>

      {/* ── 3-COLUMN MASTER-DETAIL INVESTIGATION WORKBENCH ── */}
      <div className="v2-main-grid">

        {/* ── PANE 1: EVIDENCE & ARTIFACT TREE (LEFT) ── */}
        <aside className="v2-pane v2-tree-pane">
          <div className="v2-pane-header">
            <span className="v2-pane-title">CASE ARTIFACTS</span>
            <span className="v2-pane-badge">{MOCK_EVIDENCE_FILES.length} Files</span>
          </div>

          <div className="v2-tree-container">
            <div 
              className={`v2-tree-node ${selectedTreeItem === 'all-findings' ? 'active' : ''}`}
              onClick={() => setSelectedTreeItem('all-findings')}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
              <span>All Findings (FIR)</span>
              <span className="v2-tree-count">{findings.length}</span>
            </div>

            <div className="v2-tree-group-label">INGESTED EVIDENCE</div>

            {MOCK_EVIDENCE_FILES.map(file => (
              <div 
                key={file.id}
                className={`v2-tree-node ${selectedTreeItem === file.id ? 'active' : ''}`}
                onClick={() => setSelectedTreeItem(file.id)}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                <div className="v2-tree-file-info">
                  <div className="v2-tree-file-name">{file.fileName}</div>
                  <div className="v2-tree-file-sub">{file.id} • {file.fileSize}</div>
                </div>
              </div>
            ))}

            <div className="v2-tree-group-label">COLLABORATION NOTES</div>
            <div className="v2-mini-notes">
              <form onSubmit={handleAddNote} className="v2-note-form">
                <input 
                  type="text"
                  placeholder="Add case note..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                />
                <button type="submit">+</button>
              </form>
              <div className="v2-notes-list">
                {notes.slice(0, 2).map(n => (
                  <div key={n.id} className="v2-note-card">
                    <div className="v2-note-author">{n.author} • <span className="v2-note-time">{n.timestamp}</span></div>
                    <div className="v2-note-text">{n.content}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </aside>

        {/* ── PANE 2: FINDINGS TRIAGE STREAM (MIDDLE) ── */}
        <section className="v2-pane v2-list-pane">
          <div className="v2-pane-header">
            <div>
              <span className="v2-pane-title">FINDINGS QUEUE</span>
              <span className="v2-pane-sub">{filteredFindings.length} observations</span>
            </div>
          </div>

          <div className="v2-filter-bar">
            <input 
              type="text" 
              placeholder="Filter findings..."
              className="v2-filter-input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <div className="v2-sev-buttons">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(s => (
                <button 
                  key={s} 
                  className={`v2-sev-btn ${severityFilter === s ? 'active' : ''}`}
                  onClick={() => setSeverityFilter(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="v2-findings-scroll">
            {filteredFindings.map(f => (
              <div 
                key={f.id}
                className={`v2-finding-card ${selectedFindingId === f.id ? 'selected' : ''}`}
                onClick={() => setSelectedFindingId(f.id)}
              >
                <div className="v2-fc-top">
                  <span className={`v2-badge-sev ${f.severity.toLowerCase()}`}>{f.severity}</span>
                  <span className="v2-fc-id">{f.id}</span>
                  <span className="v2-fc-conf">{f.confidence}% Conf</span>
                </div>
                <div className="v2-fc-title">{f.title}</div>
                <div className="v2-fc-fact">{f.sanitizedFact}</div>
                <div className="v2-fc-footer">
                  <span className="v2-fc-ttp">{f.mitreTechnique}</span>
                  <span className={`v2-fc-status ${f.reviewStatus.toLowerCase()}`}>{f.reviewStatus}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── PANE 3: DEEP INVESTIGATION CANVAS (RIGHT) ── */}
        <main className="v2-pane v2-canvas-pane">
          <div className="v2-canvas-header">
            <div>
              <div className="v2-ch-id-row">
                <span className="v2-ch-id font-mono">{selectedFinding.id}</span>
                <span className={`v2-badge-sev ${selectedFinding.severity.toLowerCase()}`}>{selectedFinding.severity} RISK</span>
                <span className="v2-ch-layer">Layer: {selectedFinding.layer}</span>
              </div>
              <h2 className="v2-ch-heading">{selectedFinding.title}</h2>
            </div>

            <div className="v2-canvas-actions">
              {selectedFinding.reviewStatus !== 'PROMOTED' ? (
                <button 
                  className="v2-btn-primary"
                  onClick={() => handleApprove(selectedFinding.id)}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  Approve & Promote Finding
                </button>
              ) : (
                <div className="v2-promoted-tag">
                  ✓ Promoted for Defensible Report
                </div>
              )}
            </div>
          </div>

          <div className="v2-canvas-body">
            {/* Section 1: Sanitized Forensic Statement */}
            <div className="v2-section-card">
              <div className="v2-sec-title">1. FORENSIC ASSERTION & FACT</div>
              <div className="v2-assertion-box">
                {selectedFinding.sanitizedFact}
              </div>
            </div>

            {/* Section 2: Side-by-Side Raw vs. Sanitized Provenance */}
            <div className="v2-section-card">
              <div className="v2-sec-title">2. REDACTION & PRIVACY PRESERVATION PROVENANCE</div>
              <div className="v2-diff-grid">
                <div className="v2-diff-box raw">
                  <div className="v2-diff-head">PRE-REDACTION RAW LOG (EVIDENCE VAULT)</div>
                  <code>{selectedFinding.rawText}</code>
                </div>
                <div className="v2-diff-box sanitized">
                  <div className="v2-diff-head">SANITIZED FIR TEXT (COURT-DEFENSIBLE)</div>
                  <code>{selectedFinding.sanitizedFact}</code>
                </div>
              </div>
            </div>

            {/* Section 3: DeBERTa Natural Language Entailment Verification */}
            <div className="v2-section-card">
              <div className="v2-sec-title">3. DEBERTA-V3 AI ENTAILMENT VERIFICATION</div>
              <div className="v2-nli-box">
                <div className="v2-nli-head">
                  <span className="v2-nli-badge verified">✓ STRICT FACTUAL ENTAILMENT</span>
                  <span className="v2-nli-score">Score: <strong>{(relatedClaim.entailmentScore * 100).toFixed(1)}%</strong></span>
                </div>
                <div className="v2-nli-claim">
                  <strong>AI Generated Claim:</strong> "{relatedClaim.claimText}"
                </div>
                <div className="v2-nli-grounding">
                  <strong>Source Evidence Passage:</strong> {relatedClaim.groundedPassage}
                </div>
              </div>
            </div>

            {/* Section 4: Evidence Integrity & RFC 3161 Timestamp */}
            <div className="v2-section-card">
              <div className="v2-sec-title">4. CHAIN OF CUSTODY & CRYPTOGRAPHIC PROOF</div>
              <div className="v2-crypto-grid">
                <div className="v2-crypto-cell">
                  <label>SOURCE FILE</label>
                  <span className="font-mono font-bold">{selectedEvidence.fileName}</span>
                </div>
                <div className="v2-crypto-cell">
                  <label>SHA-256 HASH</label>
                  <span className="font-mono text-xs text-primary">{selectedEvidence.sha256}</span>
                </div>
                <div className="v2-crypto-cell">
                  <label>RFC 3161 TIMESTAMP</label>
                  <span className="font-mono">{selectedEvidence.rfc3161Timestamp}</span>
                </div>
                <div className="v2-crypto-cell">
                  <label>CUSTODY STATUS</label>
                  <span className="text-success font-bold">✓ {selectedEvidence.chainOfCustodyStatus}</span>
                </div>
              </div>
            </div>

          </div>
        </main>

      </div>
    </div>
  );
}
