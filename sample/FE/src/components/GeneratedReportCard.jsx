import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { MITRE_TECHNIQUE_NAMES, handleDownloadHtml, handleDownloadJson } from '../js/reportUtils';

export default function GeneratedReportCard({
  caseId,
  caseName,
  reportData,
  reportHtml,
  loading,
  onOpenReportModal,
  role = 'senior_analyst',
  onSubmitToAuditor = null,
  isSubmittedToAuditor = false
}) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('findings'); // 'findings' | 'evidence' | 'timeline' | 'mitre'

  const auditorEscalationRecord = (() => {
    try {
      const raw = localStorage.getItem(`argus_case_${caseId}_submitted_to_auditor`);
      return raw ? JSON.parse(raw) : null;
    } catch (_e) {
      return null;
    }
  })();
  const effectiveSubmittedToAuditor = isSubmittedToAuditor || Boolean(auditorEscalationRecord?.submitted);

  const currentTheme = document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  const isDark = currentTheme === 'dark';

  const findings = Array.isArray(reportData?.findings) ? reportData.findings : [];
  const evidence = Array.isArray(reportData?.evidence_files) ? reportData.evidence_files : [];
  const timeline = Array.isArray(reportData?.timeline) ? reportData.timeline : [];

  const critCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
  const highCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;
  const medCount = findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const lowCount = findings.filter(f => (f.severity || '').toLowerCase() === 'low' || (f.severity || '').toLowerCase() === 'info').length;

  // Extract unique MITRE techniques
  const mitreMap = new Map();
  findings.forEach(f => {
    const raw = f.mitre_mapping || f.mitre_technique || (f.sanitized_context && f.sanitized_context.mitre_mapping);
    if (raw) {
      const match = raw.match(/T\d{4}(?:\.\d{3})?/i);
      const techId = match ? match[0].toUpperCase() : raw;
      const count = mitreMap.get(techId) || 0;
      mitreMap.set(techId, count + 1);
    }
  });
  if (Array.isArray(reportData?.mitre_techniques)) {
    reportData.mitre_techniques.forEach(t => {
      const id = typeof t === 'string' ? t : (t.id || t.technique_id);
      if (id && !mitreMap.has(id)) mitreMap.set(id, 1);
    });
  }
  const mitreList = Array.from(mitreMap.entries()).map(([id, count]) => ({
    id,
    name: MITRE_TECHNIQUE_NAMES[id] || 'Adversary Technique',
    count
  }));

  const genAt = reportData?.generated_at 
    ? (String(reportData.generated_at).includes('IST') 
        ? String(reportData.generated_at) 
        : new Date(reportData.generated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST') 
    : new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST';

  const execSummary = reportData?.executive_summary || (
    findings.length > 0
      ? `Forensic investigation package compiled for Case ${caseId}. Triaged ${findings.length} finding(s) with ${critCount + highCount} prioritized critical/high-severity indicator(s) across ${evidence.length} ingested evidence file(s).`
      : `Forensic case baseline compiled for Case ${caseId}. Contains ${evidence.length} cataloged evidence artifact(s). Multi-agent analysis ready for review.`
  );

  return (
    <div className="panel-card" style={{ padding: '28px 32px', borderRadius: '22px', marginBottom: '24px' }}>
      {/* Header Banner */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: '16px',
        borderBottom: '1px solid var(--glass-dash-border-subtle)',
        paddingBottom: '20px',
        marginBottom: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '14px',
            background: 'linear-gradient(135deg, #2563eb 0%, #7c3aed 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#ffffff',
            boxShadow: '0 4px 16px rgba(37, 99, 235, 0.4)',
            flexShrink: 0
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line>
              <line x1="16" y1="17" x2="8" y2="17"></line>
              <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{
                fontSize: '11px',
                fontWeight: 800,
                color: 'var(--glass-dash-blue, #38bdf8)',
                letterSpacing: '1px',
                textTransform: 'uppercase'
              }}>
                Generated Forensic Dossier
              </span>
              <span style={{
                fontSize: '11px',
                fontWeight: 700,
                background: effectiveSubmittedToAuditor ? 'rgba(16, 185, 129, 0.2)' : 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                padding: '2px 10px',
                borderRadius: '9999px',
                border: '1px solid rgba(16, 185, 129, 0.3)'
              }}>
                {role === 'auditor' 
                  ? (effectiveSubmittedToAuditor ? 'AUDITOR VERIFICATION READY' : 'AUDIT-READY DOSSIER')
                  : (effectiveSubmittedToAuditor ? 'ESCALATED TO AUDITOR' : 'READY FOR SENIOR REVIEW')}
              </span>
              {effectiveSubmittedToAuditor && (
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: '#10b981',
                  padding: '2px 10px',
                  borderRadius: '9999px',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px'
                }}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  Validated by Senior Analyst {auditorEscalationRecord?.senior_analyst_name ? `(${auditorEscalationRecord.senior_analyst_name})` : ''}
                </span>
              )}
            </div>
            <h2 style={{ margin: '4px 0 2px 0', fontSize: '20px', fontWeight: 800, color: 'var(--text-main)' }}>
              Case #{caseId} &mdash; Official Forensic Report
            </h2>
            <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
              Compiled: <span style={{ fontFamily: 'monospace', color: 'var(--text-main)' }}>{genAt}</span> &middot; Classification: <strong style={{ color: '#ef4444' }}>CONFIDENTIAL</strong>
            </div>
          </div>
        </div>

        {/* Primary Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {role === 'senior_analyst' && onSubmitToAuditor && (
            <button
              type="button"
              onClick={onSubmitToAuditor}
              className="btn btn-primary"
              style={{
                padding: '9px 18px',
                fontSize: '13px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                borderRadius: '10px',
                background: effectiveSubmittedToAuditor
                  ? 'rgba(37, 99, 235, 0.15)'
                  : 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
                color: effectiveSubmittedToAuditor ? 'var(--glass-dash-blue, #60a5fa)' : '#ffffff',
                border: effectiveSubmittedToAuditor ? '1px solid rgba(37, 99, 235, 0.4)' : '1px solid rgba(255, 255, 255, 0.2)',
                boxShadow: effectiveSubmittedToAuditor ? '0 2px 8px rgba(37, 99, 235, 0.15)' : '0 4px 12px rgba(37, 99, 235, 0.35)',
                cursor: 'pointer'
              }}
              title={effectiveSubmittedToAuditor ? 'Report already escalated to Auditor' : 'Approve findings and escalate to Auditor'}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                {effectiveSubmittedToAuditor ? (
                  <polyline points="20 6 9 17 4 12"></polyline>
                ) : (
                  <>
                    <line x1="22" y1="2" x2="11" y2="13"></line>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                  </>
                )}
              </svg>
              <span>{effectiveSubmittedToAuditor ? '✓ Escalated to Auditor' : 'Submit to Auditor'}</span>
            </button>
          )}

          <button
            type="button"
            onClick={onOpenReportModal}
            className="btn btn-primary"
            style={{
              padding: '9px 18px',
              fontSize: '13px',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
              color: '#ffffff',
              border: 'none',
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.35)',
              cursor: 'pointer'
            }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
            <span>Inspect Full Report</span>
          </button>

          <button
            type="button"
            onClick={() => navigate('/report')}
            className="btn btn-outline"
            style={{
              padding: '9px 16px',
              fontSize: '13px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              borderRadius: '10px',
              background: 'var(--glass-dash-surface-nested)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-main)',
              cursor: 'pointer'
            }}
            title="Open interactive side-by-side review workspace"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
              <polyline points="15 3 21 3 21 9"></polyline>
              <line x1="10" y1="14" x2="21" y2="3"></line>
            </svg>
            <span>Open Workspace</span>
          </button>

          <button
            type="button"
            onClick={() => handleDownloadHtml(reportData, reportHtml, caseId)}
            className="btn btn-outline"
            style={{
              padding: '9px 14px',
              fontSize: '12.5px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              borderRadius: '10px',
              background: 'var(--glass-dash-surface-nested)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-main)',
              cursor: 'pointer'
            }}
            title="Download official HTML dossier"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            <span>HTML</span>
          </button>

          <button
            type="button"
            onClick={() => handleDownloadJson(reportData, caseId)}
            className="btn btn-outline"
            style={{
              padding: '9px 14px',
              fontSize: '12.5px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              borderRadius: '10px',
              background: 'var(--glass-dash-surface-nested)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-main)',
              cursor: 'pointer'
            }}
            title="Download structured JSON report"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <polyline points="16 18 22 12 16 6"></polyline>
              <polyline points="8 6 2 12 8 18"></polyline>
            </svg>
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Telemetry Metrics Row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '14px',
        marginBottom: '20px'
      }}>
        <div style={{
          background: 'var(--glass-dash-surface-nested)',
          border: '1px solid var(--glass-dash-border-subtle)',
          borderRadius: '14px',
          padding: '14px 18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px'
        }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Triaged Findings
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-main)' }}>
            {findings.length}
          </div>
          <div style={{ display: 'flex', gap: '8px', fontSize: '11px', fontWeight: 600 }}>
            <span style={{ color: '#ef4444' }}>{critCount + highCount} High/Crit</span>
            <span style={{ color: '#f59e0b' }}>{medCount} Med</span>
            <span style={{ color: '#3b82f6' }}>{lowCount} Low</span>
          </div>
        </div>

        <div style={{
          background: 'var(--glass-dash-surface-nested)',
          border: '1px solid var(--glass-dash-border-subtle)',
          borderRadius: '14px',
          padding: '14px 18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px'
        }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Evidence Artifacts
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#10b981' }}>
            {evidence.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {evidence.length > 0 ? 'Cryptographically Cataloged' : 'Awaiting Ingestion'}
          </div>
        </div>

        <div style={{
          background: 'var(--glass-dash-surface-nested)',
          border: '1px solid var(--glass-dash-border-subtle)',
          borderRadius: '14px',
          padding: '14px 18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px'
        }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Attack Timeline Events
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#f59e0b' }}>
            {timeline.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Sequential Kill-Chain Rebuilt
          </div>
        </div>

        <div style={{
          background: 'var(--glass-dash-surface-nested)',
          border: '1px solid var(--glass-dash-border-subtle)',
          borderRadius: '14px',
          padding: '14px 18px',
          display: 'flex',
          flexDirection: 'column',
          gap: '4px'
        }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            MITRE ATT&CK Matrix
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#8b5cf6' }}>
            {mitreList.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Adversary TTPs Mapped
          </div>
        </div>
      </div>

      {/* Executive Assessment Box */}
      <div style={{
        background: 'var(--glass-dash-surface-nested)',
        border: '1px solid var(--glass-dash-border-subtle)',
        borderLeft: '4px solid var(--glass-dash-blue, #38bdf8)',
        borderRadius: '14px',
        padding: '16px 20px',
        marginBottom: '20px'
      }}>
        <div style={{ fontSize: '11.5px', fontWeight: 800, color: 'var(--glass-dash-blue, #38bdf8)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
          Executive Forensic Assessment
        </div>
        <div style={{ fontSize: '13.5px', lineHeight: '1.65', color: 'var(--text-main)' }}>
          {execSummary}
        </div>
      </div>

      {/* Report Breakdown Tabs */}
      <div style={{
        display: 'flex',
        gap: '8px',
        borderBottom: '1px solid var(--glass-dash-border-subtle)',
        paddingBottom: '10px',
        marginBottom: '16px',
        overflowX: 'auto'
      }}>
        <button
          type="button"
          onClick={() => setActiveTab('findings')}
          style={{
            padding: '7px 16px',
            fontSize: '12.5px',
            fontWeight: 600,
            borderRadius: '8px',
            border: activeTab === 'findings' ? '1px solid var(--glass-dash-blue)' : '1px solid transparent',
            background: activeTab === 'findings' ? 'var(--glass-dash-blue-soft, rgba(56,189,248,0.15))' : 'transparent',
            color: activeTab === 'findings' ? 'var(--glass-dash-blue, #38bdf8)' : 'var(--text-muted)',
            cursor: 'pointer',
            transition: 'all 0.2s'
          }}
        >
          🔍 Key Findings ({findings.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('evidence')}
          style={{
            padding: '7px 16px',
            fontSize: '12.5px',
            fontWeight: 600,
            borderRadius: '8px',
            border: activeTab === 'evidence' ? '1px solid var(--glass-dash-blue)' : '1px solid transparent',
            background: activeTab === 'evidence' ? 'var(--glass-dash-blue-soft, rgba(56,189,248,0.15))' : 'transparent',
            color: activeTab === 'evidence' ? 'var(--glass-dash-blue, #38bdf8)' : 'var(--text-muted)',
            cursor: 'pointer',
            transition: 'all 0.2s'
          }}
        >
          📁 Evidence Ledger ({evidence.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('timeline')}
          style={{
            padding: '7px 16px',
            fontSize: '12.5px',
            fontWeight: 600,
            borderRadius: '8px',
            border: activeTab === 'timeline' ? '1px solid var(--glass-dash-blue)' : '1px solid transparent',
            background: activeTab === 'timeline' ? 'var(--glass-dash-blue-soft, rgba(56,189,248,0.15))' : 'transparent',
            color: activeTab === 'timeline' ? 'var(--glass-dash-blue, #38bdf8)' : 'var(--text-muted)',
            cursor: 'pointer',
            transition: 'all 0.2s'
          }}
        >
          ⏱️ Chronology ({timeline.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('mitre')}
          style={{
            padding: '7px 16px',
            fontSize: '12.5px',
            fontWeight: 600,
            borderRadius: '8px',
            border: activeTab === 'mitre' ? '1px solid var(--glass-dash-blue)' : '1px solid transparent',
            background: activeTab === 'mitre' ? 'var(--glass-dash-blue-soft, rgba(56,189,248,0.15))' : 'transparent',
            color: activeTab === 'mitre' ? 'var(--glass-dash-blue, #38bdf8)' : 'var(--text-muted)',
            cursor: 'pointer',
            transition: 'all 0.2s'
          }}
        >
          🛡️ ATT&CK Mapping ({mitreList.length})
        </button>
      </div>

      {/* Tab Panels */}
      <div>
        {/* TAB 1: Findings */}
        {activeTab === 'findings' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {findings.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--glass-dash-surface-nested)', borderRadius: '12px' }}>
                No findings currently reported for this case.
              </div>
            ) : (
              findings.slice(0, 5).map((f, idx) => {
                const sev = (f.severity || 'medium').toLowerCase();
                const isCrit = sev === 'critical' || sev === 'high';
                return (
                  <div key={idx} style={{
                    padding: '12px 16px',
                    borderRadius: '12px',
                    background: 'var(--glass-dash-surface-nested)',
                    border: '1px solid var(--glass-dash-border-subtle)',
                    borderLeft: `4px solid ${isCrit ? (sev === 'critical' ? '#ef4444' : '#f97316') : '#3b82f6'}`
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{
                          fontSize: '10px',
                          fontWeight: 800,
                          padding: '2px 8px',
                          borderRadius: '6px',
                          background: sev === 'critical' ? 'rgba(239, 68, 68, 0.2)' : sev === 'high' ? 'rgba(249, 115, 22, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                          color: sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f97316' : '#3b82f6',
                          textTransform: 'uppercase'
                        }}>
                          {f.severity || 'Medium'}
                        </span>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          {f.finding_id || `#${idx + 1}`}
                        </span>
                      </div>
                      {f.confidence !== undefined && (
                        <span style={{ fontSize: '11.5px', color: '#10b981', fontWeight: 600 }}>
                          {(f.confidence > 1 ? f.confidence : f.confidence * 100).toFixed(0)}% Confidence
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: '1.5' }}>
                      {f.sanitized_fact || f.fact || 'Documented intrusion finding'}
                    </div>
                  </div>
                );
              })
            )}
            {findings.length > 5 && (
              <div style={{ textAlign: 'center', paddingTop: '6px' }}>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  + {findings.length - 5} more finding(s) cataloged in official dossier.
                </span>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Evidence */}
        {activeTab === 'evidence' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {evidence.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--glass-dash-surface-nested)', borderRadius: '12px' }}>
                No evidence artifacts uploaded for this case yet.
              </div>
            ) : (
              evidence.slice(0, 5).map((ev, idx) => (
                <div key={idx} style={{
                  padding: '10px 14px',
                  borderRadius: '10px',
                  background: 'var(--glass-dash-surface-nested)',
                  border: '1px solid var(--glass-dash-border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px'
                }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {ev.filename || 'Evidence File'}
                    </div>
                    {ev.sha256_hash && (
                      <div style={{ fontSize: '11px', fontFamily: 'monospace', color: 'var(--glass-dash-blue, #38bdf8)' }}>
                        SHA-256: {ev.sha256_hash.slice(0, 32)}...
                      </div>
                    )}
                  </div>
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    background: 'rgba(16, 185, 129, 0.15)',
                    color: '#10b981',
                    padding: '2px 8px',
                    borderRadius: '6px',
                    textTransform: 'uppercase',
                    flexShrink: 0
                  }}>
                    {ev.status || 'stored'}
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {/* TAB 3: Timeline */}
        {activeTab === 'timeline' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {timeline.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--glass-dash-surface-nested)', borderRadius: '12px' }}>
                No chronological attack events recorded in report yet.
              </div>
            ) : (
              timeline.slice(0, 5).map((t, idx) => (
                <div key={idx} style={{
                  padding: '10px 14px',
                  borderRadius: '10px',
                  background: 'var(--glass-dash-surface-nested)',
                  border: '1px solid var(--glass-dash-border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px'
                }}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b', flexShrink: 0 }}></div>
                  <div style={{ fontSize: '11.5px', fontFamily: 'monospace', color: 'var(--glass-dash-blue, #38bdf8)', minWidth: '80px', flexShrink: 0 }}>
                    {t.timestamp ? new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--'}
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.summary || t.event_type || 'Event observed'}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* TAB 4: MITRE */}
        {activeTab === 'mitre' && (
          <div>
            {mitreList.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--glass-dash-surface-nested)', borderRadius: '12px' }}>
                No MITRE ATT&CK techniques mapped to current report findings.
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px' }}>
                {mitreList.map(t => (
                  <div key={t.id} style={{
                    padding: '10px 12px',
                    borderRadius: '10px',
                    background: 'var(--glass-dash-surface-nested)',
                    border: '1px solid var(--glass-dash-border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <strong style={{ fontSize: '12px', color: 'var(--glass-dash-blue, #38bdf8)', fontFamily: 'monospace' }}>{t.id}</strong>
                      {t.count > 1 && (
                        <span style={{ background: 'var(--glass-dash-blue, #38bdf8)', color: '#0f172a', fontSize: '9px', padding: '1px 5px', borderRadius: '999px', fontWeight: 800 }}>
                          {t.count}x
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '11.5px', color: 'var(--text-main)' }}>{t.name}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

