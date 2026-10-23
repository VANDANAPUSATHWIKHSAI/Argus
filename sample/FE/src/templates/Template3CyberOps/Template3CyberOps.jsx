import React, { useState } from 'react';
import { 
  MOCK_CASES, 
  MOCK_EVIDENCE_FILES, 
  MOCK_FIR_FINDINGS, 
  MOCK_AI_CLAIMS, 
  MOCK_TIMELINE_EVENTS,
  MOCK_MALWARE_PROFILE,
  MOCK_AUDIT_EVENTS
} from '../../mock/investigationMockData';
import './Template3.css';

export default function Template3CyberOps() {
  const [activeCase, setActiveCase] = useState(MOCK_CASES[0]);
  const [selectedKillStage, setSelectedKillStage] = useState('Execution');
  const [selectedFinding, setSelectedFinding] = useState(MOCK_FIR_FINDINGS[0]);
  const [verifiedFilter, setVerifiedFilter] = useState('ALL');

  const killChainStages = [
    { name: 'Initial Access', technique: 'T1566.001', findingId: 'F-101', icon: '🎯', status: 'CONFIRMED' },
    { name: 'Execution', technique: 'T1059.001', findingId: 'F-101', icon: '⚡', status: 'CONFIRMED' },
    { name: 'Command & Control', technique: 'T1071.001', findingId: 'F-102', icon: '📡', status: 'ACTIVE' },
    { name: 'Credential Access', technique: 'T1003.001', findingId: 'F-103', icon: '🔑', status: 'CONFIRMED' },
    { name: 'Persistence', technique: 'T1547.001', findingId: 'F-104', icon: '⚓', status: 'DETECTED' },
    { name: 'Impact Staging', technique: 'T1490', findingId: 'F-105', icon: '💣', status: 'BLOCKED' }
  ];

  const currentStageFinding = MOCK_FIR_FINDINGS.find(f => {
    const stage = killChainStages.find(s => s.name === selectedKillStage);
    return f.finding_id === stage?.findingId;
  }) || MOCK_FIR_FINDINGS[0];

  return (
    <div className="t3-container">
      {/* ── TOP TACTICAL HUD ── */}
      <header className="t3-hud-header">
        <div className="t3-hud-left">
          <div className="t3-hex-badge">⚡ SOC</div>
          <div>
            <div className="t3-hud-title">ARGUS CYBERSECURITY OPERATIONS CONSOLE</div>
            <div className="t3-hud-sub">TACTICAL FORENSIC INTELLIGENCE &bull; THREAT RECONSTRUCTION</div>
          </div>
        </div>

        <div className="t3-hud-center">
          <span className="t3-hud-label">ACTIVE ENGAGEMENT:</span>
          <select 
            value={activeCase.case_id} 
            onChange={(e) => setActiveCase(MOCK_CASES.find(c => c.case_id === e.target.value))}
            className="t3-case-select"
          >
            {MOCK_CASES.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.case_id} // {c.name.toUpperCase()}</option>
            ))}
          </select>
        </div>

        <div className="t3-hud-right">
          <div className="t3-threat-level">
            <span className="t3-tl-dot"></span>
            <span>THREAT POSTURE: <strong>CRITICAL LEVEL 4</strong></span>
          </div>
        </div>
      </header>

      {/* ── MAIN TACTICAL GRID ── */}
      <div className="t3-grid">

        {/* ── LEFT COLUMN: THREAT ACTOR & MALWARE TELEMETRY ── */}
        <section className="t3-col-left">
          {/* MALWARE PROFILE CARD */}
          <div className="t3-panel">
            <div className="t3-panel-head">
              <span className="t3-panel-icon">☣</span>
              <span>MALWARE & THREAT ATTRIBUTION</span>
              <span className="t3-pill-red">{MOCK_MALWARE_PROFILE.threat_family}</span>
            </div>
            
            <div className="t3-malware-body">
              <div className="t3-mb-row">
                <span className="t3-text-muted">Classification:</span>
                <span className="t3-text-bright">{MOCK_MALWARE_PROFILE.malware_type}</span>
              </div>
              <div className="t3-mb-row">
                <span className="t3-text-muted">Attribution Confidence:</span>
                <span className="t3-text-green">{MOCK_MALWARE_PROFILE.confidence}</span>
              </div>
              <div className="t3-mb-row">
                <span className="t3-text-muted">Campaign Similarity:</span>
                <span className="t3-text-cyan">{MOCK_MALWARE_PROFILE.campaign_similarity.matched_campaign} (89%)</span>
              </div>

              <div className="t3-yara-box">
                <div className="t3-yara-head">YARA SIGNATURES TRIGGERED ({MOCK_MALWARE_PROFILE.yara_rules_fired.length})</div>
                {MOCK_MALWARE_PROFILE.yara_rules_fired.map(y => (
                  <div key={y} className="t3-yara-tag">⚡ {y}</div>
                ))}
              </div>

              <div className="t3-behaviors-list">
                <div className="t3-yara-head">BEHAVIORAL CATEGORIES</div>
                {MOCK_MALWARE_PROFILE.behavior_categories.map(b => (
                  <div key={b.name} className="t3-beh-item">
                    <span className="t3-beh-name">{b.name}</span>
                    <span className="t3-beh-tag">{b.tag}</span>
                    <span className="t3-beh-count">{b.count} events</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* TELEMETRY GAUGES */}
          <div className="t3-panel">
            <div className="t3-panel-head">
              <span className="t3-panel-icon">⚙</span>
              <span>PIPELINE VERIFICATION GAUGES</span>
            </div>
            <div className="t3-gauges-grid">
              <div className="t3-gauge-box">
                <div className="t3-gauge-circle green">
                  <span>100%</span>
                </div>
                <div className="t3-gauge-label">PARSER INTEGRITY</div>
              </div>
              <div className="t3-gauge-box">
                <div className="t3-gauge-circle cyan">
                  <span>0.02</span>
                </div>
                <div className="t3-gauge-label">INJECTION RISK</div>
              </div>
              <div className="t3-gauge-box">
                <div className="t3-gauge-circle purple">
                  <span>96%</span>
                </div>
                <div className="t3-gauge-label">MNLI ENTAILMENT</div>
              </div>
              <div className="t3-gauge-box">
                <div className="t3-gauge-circle amber">
                  <span>4/4</span>
                </div>
                <div className="t3-gauge-label">CLAIMS VERIFIED</div>
              </div>
            </div>
          </div>
        </section>

        {/* ── CENTER COLUMN: ATTACK SEQUENCE & TOPOLOGY ── */}
        <section className="t3-col-center">
          {/* MITRE ATT&CK KILL CHAIN STEPPER */}
          <div className="t3-panel">
            <div className="t3-panel-head">
              <span className="t3-panel-icon">🎯</span>
              <span>MITRE ATT&CK RECONSTRUCTED KILL CHAIN</span>
              <span className="t3-pill-cyan">AGENT 3 RECONSTRUCTION</span>
            </div>

            <div className="t3-stepper">
              {killChainStages.map(stage => (
                <div 
                  key={stage.name} 
                  className={`t3-step-node ${selectedKillStage === stage.name ? 'active' : ''}`}
                  onClick={() => setSelectedKillStage(stage.name)}
                >
                  <div className="t3-step-icon">{stage.icon}</div>
                  <div className="t3-step-name">{stage.name}</div>
                  <div className="t3-step-tech">{stage.technique}</div>
                  <div className={`t3-step-status ${stage.status.toLowerCase()}`}>{stage.status}</div>
                </div>
              ))}
            </div>

            {/* STAGE INSPECTION CARD */}
            <div className="t3-stage-detail">
              <div className="t3-sd-header">
                <div>
                  <span className="t3-sd-tag">ACTIVE STAGE INSPECTION // {selectedKillStage.toUpperCase()}</span>
                  <div className="t3-sd-title">{currentStageFinding.sanitized_fact}</div>
                </div>
                <span className="t3-badge-crit">{currentStageFinding.severity.toUpperCase()}</span>
              </div>

              <div className="t3-sd-meta">
                <div><strong>Engine:</strong> {currentStageFinding.source_engine}</div>
                <div><strong>Finding ID:</strong> {currentStageFinding.finding_id}</div>
                <div><strong>Timestamp:</strong> {new Date(currentStageFinding.timestamp).toUTCString()}</div>
                <div><strong>Evidence Reference:</strong> {currentStageFinding.evidence_reference.join(', ')}</div>
              </div>
            </div>
          </div>

          {/* ATTACK TOPOLOGY NODE MAP */}
          <div className="t3-panel">
            <div className="t3-panel-head">
              <span className="t3-panel-icon">🌐</span>
              <span>INCIDENT NETWORK TOPOLOGY & HOST LINKAGE</span>
            </div>

            <div className="t3-topology-canvas">
              <div className="t3-topo-node red">
                <div className="t3-tn-icon">☠</div>
                <div className="t3-tn-name">C2 SERVER</div>
                <div className="t3-tn-sub">198.51.100.4:443</div>
              </div>

              <div className="t3-topo-link pulse">
                <span>TLS 1.3 C2 Tunnel (45s Beacon)</span>
              </div>

              <div className="t3-topo-node amber active">
                <div className="t3-tn-icon">💻</div>
                <div className="t3-tn-name">WORKSTATION-412</div>
                <div className="t3-tn-sub">192.168.4.12 &bull; jsmith</div>
              </div>

              <div className="t3-topo-link">
                <span>LSASS Dumped ➔ Credential Reuse</span>
              </div>

              <div className="t3-topo-node cyan">
                <div className="t3-tn-icon">🏛</div>
                <div className="t3-tn-name">DOMAIN CONTROLLER</div>
                <div className="t3-tn-sub">WIN-SRV-AD01</div>
              </div>
            </div>
          </div>
        </section>

        {/* ── RIGHT COLUMN: MULTI-AGENT CLAIMS & LIVE TELEMETRY STREAM ── */}
        <section className="t3-col-right">
          {/* SYNTHESIZED CLAIMS FEED */}
          <div className="t3-panel t3-flex-1">
            <div className="t3-panel-head">
              <span className="t3-panel-icon">🤖</span>
              <span>SYNTHESIZED AI CLAIMS</span>
              <span className="t3-pill-purple">ENTAILMENT CHECKED</span>
            </div>

            <div className="t3-claims-feed">
              {MOCK_AI_CLAIMS.map(c => (
                <div key={c.claim_id} className="t3-claim-node">
                  <div className="t3-cn-header">
                    <span className="t3-cn-id">{c.claim_id}</span>
                    <span className="t3-cn-agent">{c.agent_name.split(' ')[1]}</span>
                    <span className="t3-cn-score">Entailment: {(c.verification.entailment_score * 100).toFixed(0)}%</span>
                  </div>
                  <div className="t3-cn-title">{c.title}</div>
                  <div className="t3-cn-claim">"{c.claim}"</div>
                  <div className="t3-cn-footer">
                    <span>Cited FIR: {c.cited_evidence_ids.join(', ')}</span>
                    <span className="t3-cn-status">✔ VERIFIED</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* LIVE SOC AUDIT STREAM */}
          <div className="t3-panel" style={{ maxHeight: '240px' }}>
            <div className="t3-panel-head">
              <span className="t3-panel-icon">⚡</span>
              <span>LIVE INVESTIGATION TELEMETRY</span>
            </div>
            <div className="t3-telemetry-feed">
              {MOCK_AUDIT_EVENTS.map(a => (
                <div key={a.id} className="t3-telemetry-line">
                  <span className="t3-tel-time">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  <span className="t3-tel-actor">{a.actor}</span>
                  <span className="t3-tel-act">{a.action}: {a.resource}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}
