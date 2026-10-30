import React, { useState } from 'react';
import { createCaseNote } from '../js/api';
import GeneratedReportModal from './GeneratedReportModal';

export default function SeniorSubmitToAuditorModal({
  isOpen,
  onClose,
  caseId,
  caseName,
  reportData,
  reportHtml,
  onSuccess
}) {
  const [seniorMemo, setSeniorMemo] = useState(
    'All triaged findings and cross-source evidence artifacts have been validated against forensic ground truth. Entailment scores verified. Case report is promoted to Auditor for formal compliance audit and attestation.'
  );
  const [submitting, setSubmitting] = useState(false);
  const [showFullPreview, setShowFullPreview] = useState(false);
  const [submittedSuccess, setSubmittedSuccess] = useState(false);

  const currentUser = JSON.parse(localStorage.getItem('argus_user') || '{}');
  const currentTheme = document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  const isDark = currentTheme === 'dark';

  if (!isOpen) return null;

  const findings = Array.isArray(reportData?.findings) ? reportData.findings : [];
  const evidence = Array.isArray(reportData?.evidence_files) ? reportData.evidence_files : [];
  const timeline = Array.isArray(reportData?.timeline) ? reportData.timeline : [];

  const critCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
  const highCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;

  const handleApproveAndSubmit = async () => {
    setSubmitting(true);
    const seniorName = currentUser.name || 'Senior Analyst';
    const memoText = seniorMemo.trim() || 'Validated by Senior Analyst. Ready for independent compliance audit.';

    try {
      // 1. Create durable Case Note for complete audit trail
      const notePayload = {
        title: `🛡️ Senior Analyst Approval & Escalation to Auditor`,
        content: `[SENIOR ANALYST APPROVAL & AUDITOR PROMOTION]\n\nValidated By: ${seniorName} (${currentUser.email || 'senior@argus.local'})\nTimestamp: ${new Date().toLocaleString()}\nCase ID: ${caseId} (${caseName || caseId})\n\n[SENIOR VALIDATION MEMO]\n${memoText}\n\n[VERIFIED METRICS]\n• Confirmed Findings: ${findings.length} (${critCount + highCount} Critical/High)\n• Evidence Ledger: ${evidence.length} files cryptographically logged\n• Chronological Attack Events: ${timeline.length}\n\nStatus: Promoted to Compliance Auditor for evidentiary certification.`,
        type: 'finding',
        priority: 'HIGH',
        related_evidence_id: null,
        related_finding_id: null
      };

      await createCaseNote(caseId, notePayload).catch(e => console.warn('Case note save warning:', e));

      // 2. Persist escalation record in localStorage for multi-view synchronization
      const escalationRecord = {
        case_id: caseId,
        submitted: true,
        submitted_at: new Date().toISOString(),
        senior_analyst_id: currentUser.id || 'senior_analyst',
        senior_analyst_name: seniorName,
        memo: memoText,
        findings_count: findings.length,
        evidence_count: evidence.length
      };

      localStorage.setItem(`argus_case_${caseId}_submitted_to_auditor`, JSON.stringify(escalationRecord));
      window.dispatchEvent(new Event('storage'));

      setSubmittedSuccess(true);
      if (onSuccess) onSuccess(escalationRecord);

      setTimeout(() => {
        onClose();
      }, 1400);
    } catch (err) {
      console.error('Failed to submit report to auditor:', err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div 
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 99998,
          background: 'transparent',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '20px'
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget && !submitting) onClose();
        }}
      >
        <div 
          style={{
            width: '95vw',
            maxWidth: '780px',
            maxHeight: '90vh',
            background: isDark ? '#0f172a' : '#ffffff',
            borderRadius: '20px',
            border: `1px solid ${isDark ? 'rgba(16, 185, 129, 0.35)' : '#cbd5e1'}`,
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.65)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}
        >
          {/* Header */}
          <div style={{
            padding: '20px 26px',
            borderBottom: `1px solid ${isDark ? '#1e293b' : '#e2e8f0'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: isDark ? '#1e293b' : '#f8fafc'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '12px',
                background: 'linear-gradient(135deg, #059669 0%, #10b981 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: '0 4px 14px rgba(16, 185, 129, 0.4)',
                flexShrink: 0
              }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: '#10b981', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
                    Senior Analyst Escalation
                  </span>
                  <span style={{
                    fontSize: '10.5px',
                    fontWeight: 700,
                    background: 'rgba(16, 185, 129, 0.15)',
                    color: '#10b981',
                    padding: '1px 8px',
                    borderRadius: '999px',
                    border: '1px solid rgba(16, 185, 129, 0.3)'
                  }}>
                    READY FOR AUDIT
                  </span>
                </div>
                <h2 style={{ margin: '2px 0 0 0', fontSize: '18px', fontWeight: 800, color: isDark ? '#f8fafc' : '#0f172a' }}>
                  Submit Case Report to Auditor
                </h2>
              </div>
            </div>

            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              style={{
                background: 'none',
                border: 'none',
                color: isDark ? '#94a3b8' : '#64748b',
                cursor: 'pointer',
                fontSize: '20px',
                padding: '4px 8px',
                borderRadius: '8px'
              }}
              title="Close"
            >
              ✕
            </button>
          </div>

          {/* Modal Body */}
          <div style={{ padding: '24px 26px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {submittedSuccess ? (
              <div style={{ textAlign: 'center', padding: '40px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
                <div style={{
                  width: '64px',
                  height: '64px',
                  borderRadius: '50%',
                  background: 'rgba(16, 185, 129, 0.2)',
                  color: '#10b981',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 20px rgba(16, 185, 129, 0.4)'
                }}>
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </div>
                <h3 style={{ margin: 0, fontSize: '20px', fontWeight: 800, color: '#10b981' }}>
                  Case Report Successfully Promoted to Auditor!
                </h3>
                <p style={{ margin: 0, fontSize: '14px', color: isDark ? '#cbd5e1' : '#475569', maxWidth: '480px', lineHeight: '1.6' }}>
                  Case #{caseId} has been submitted to the Compliance Auditor workspace for final verification, evidentiary compliance, and certification.
                </p>
              </div>
            ) : (
              <>
                {/* Workflow Participants Bar */}
                <div style={{
                  background: isDark ? 'rgba(255, 255, 255, 0.03)' : '#f8fafc',
                  border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : '#e2e8f0'}`,
                  borderRadius: '12px',
                  padding: '14px 18px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Active Case</div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', marginTop: '2px' }}>
                      {caseName ? `${caseName} (${caseId})` : caseId}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Validating Senior Analyst</div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: '#8b5cf6', marginTop: '2px' }}>
                        {currentUser.name || 'Senior Analyst'}
                      </div>
                    </div>
                    <div style={{ color: 'var(--border-strong)' }}>&rarr;</div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Receiving Role</div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: '#10b981', marginTop: '2px' }}>
                        Compliance Auditor
                      </div>
                    </div>
                  </div>
                </div>

                {/* Telemetry Highlights */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: '#10b981' }}>{findings.length}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Validated Findings</div>
                  </div>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: '#3b82f6' }}>{evidence.length}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Evidence Files</div>
                  </div>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: '#f59e0b' }}>{timeline.length}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Timeline Events</div>
                  </div>
                </div>

                {/* Senior Analyst Memo for Auditor */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <label style={{ fontSize: '12px', fontWeight: 700, color: isDark ? '#f8fafc' : '#0f172a' }}>
                      Senior Analyst Approval Memo &amp; Auditor Guidelines
                    </label>
                    <button
                      type="button"
                      onClick={() => setShowFullPreview(true)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--glass-dash-blue, #38bdf8)',
                        fontSize: '11.5px',
                        fontWeight: 700,
                        cursor: 'pointer',
                        padding: 0
                      }}
                    >
                      Inspect Dossier &rarr;
                    </button>
                  </div>
                  <textarea
                    rows={4}
                    value={seniorMemo}
                    onChange={(e) => setSeniorMemo(e.target.value)}
                    placeholder="Enter compliance validation observations, chain of custody review confirmation, and guidelines for the independent auditor..."
                    style={{
                      width: '100%',
                      padding: '12px 14px',
                      borderRadius: '10px',
                      border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.15)' : '#cbd5e1'}`,
                      background: isDark ? '#1e293b' : '#ffffff',
                      color: isDark ? '#f8fafc' : '#0f172a',
                      fontSize: '13px',
                      lineHeight: '1.5',
                      boxSizing: 'border-box',
                      resize: 'vertical'
                    }}
                  />
                </div>
              </>
            )}
          </div>

          {/* Modal Footer */}
          {!submittedSuccess && (
            <div style={{
              padding: '16px 26px',
              borderTop: `1px solid ${isDark ? '#1e293b' : '#e2e8f0'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: isDark ? '#1e293b' : '#f8fafc',
              flexWrap: 'wrap',
              gap: '10px'
            }}>
              <button
                type="button"
                onClick={() => setShowFullPreview(true)}
                disabled={submitting}
                className="btn btn-outline"
                style={{ fontSize: '12.5px', padding: '7px 14px' }}
              >
                Inspect Full Dossier
              </button>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  onClick={onClose}
                  disabled={submitting}
                  className="btn btn-outline"
                  style={{ fontSize: '12.5px', padding: '7px 16px' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleApproveAndSubmit}
                  disabled={submitting}
                  className="btn btn-primary"
                  style={{
                    fontSize: '13px',
                    padding: '8px 20px',
                    fontWeight: 700,
                    background: 'linear-gradient(135deg, #059669 0%, #10b981 100%)',
                    border: 'none',
                    boxShadow: '0 4px 14px rgba(16, 185, 129, 0.4)'
                  }}
                >
                  {submitting ? 'Submitting...' : '🚀 Approve & Submit to Auditor'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Embedded Full Dossier Modal for Preview */}
      <GeneratedReportModal
        isOpen={showFullPreview}
        onClose={() => setShowFullPreview(false)}
        caseId={caseId}
        reportData={reportData}
        reportHtml={reportHtml}
      />
    </>
  );
}

