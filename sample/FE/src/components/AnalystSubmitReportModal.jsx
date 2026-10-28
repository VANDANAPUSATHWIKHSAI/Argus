import React, { useState, useEffect } from 'react';
import { fetchReport, createCaseNote } from '../js/api';
import { generateHtmlFromReportData, handleDownloadHtml, handleDownloadJson } from '../js/reportUtils';
import GeneratedReportModal from './GeneratedReportModal';

export default function AnalystSubmitReportModal({
  isOpen,
  onClose,
  caseId,
  caseName,
  activeSummary,
  onSuccess
}) {
  const [loading, setLoading] = useState(true);
  const [reportData, setReportData] = useState(null);
  const [reportHtml, setReportHtml] = useState('');
  const [handoffNote, setHandoffNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [showFullPreview, setShowFullPreview] = useState(false);
  const [submittedSuccess, setSubmittedSuccess] = useState(false);

  const currentUser = JSON.parse(localStorage.getItem('argus_user') || '{}');
  const currentTheme = document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  const isDark = currentTheme === 'dark';

  useEffect(() => {
    if (!isOpen || !caseId) return;

    let isMounted = true;
    setLoading(true);
    setSubmittedSuccess(false);

    async function loadReportPayload() {
      try {
        const [repJsonRes, repHtmlRes] = await Promise.allSettled([
          fetchReport(caseId, 'json', true),
          fetchReport(caseId, 'html', true)
        ]);

        if (!isMounted) return;

        let rData = null;
        if (repJsonRes.status === 'fulfilled' && repJsonRes.value) {
          rData = typeof repJsonRes.value === 'string' ? JSON.parse(repJsonRes.value) : repJsonRes.value;
          setReportData(rData);
        }
        if (repHtmlRes.status === 'fulfilled' && repHtmlRes.value) {
          const hVal = typeof repHtmlRes.value === 'string' ? repHtmlRes.value : JSON.stringify(repHtmlRes.value);
          setReportHtml(hVal);
        }

        if (!rData) {
          setReportData({
            case_id: caseId,
            tenant_id: 'default',
            generated_at: new Date().toISOString(),
            findings: activeSummary?.findings || [],
            evidence_files: activeSummary?.formatted_evidence || [],
            timeline: [],
            executive_summary: activeSummary?.description || `Investigation report compiled by Analyst ${currentUser.name || 'Analyst'} for Case ${caseId}. Ready for Senior Analyst validation.`
          });
        }
      } catch (err) {
        console.warn('Error loading report for analyst submission:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    loadReportPayload();
    return () => { isMounted = false; };
  }, [isOpen, caseId]);

  if (!isOpen) return null;

  const findings = Array.isArray(reportData?.findings) ? reportData.findings : [];
  const evidence = Array.isArray(reportData?.evidence_files) ? reportData.evidence_files : [];
  const timeline = Array.isArray(reportData?.timeline) ? reportData.timeline : [];

  const critCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
  const highCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;

  const handleSubmitToSenior = async () => {
    setSubmitting(true);
    const analystName = currentUser.name || 'Analyst';
    const noteText = handoffNote.trim() || 'Multi-agent analysis, evidence hashes, and FIR findings have been generated and compiled into the official dossier. Ready for Senior Analyst validation.';

    try {
      // 1. Create durable Case Note for Senior Analyst review trail
      const notePayload = {
        title: `📑 Case Report Submitted for Senior Review`,
        content: `[OFFICIAL REPORT SUBMISSION TO SENIOR ANALYST]\n\nSubmitted By: ${analystName} (${currentUser.email || 'analyst@argus.local'})\nTimestamp: ${new Date().toLocaleString()}\nCase ID: ${caseId} (${caseName || caseId})\n\n[ANALYST HANDOFF MEMO]\n${noteText}\n\n[REPORT SUMMARY]\n• Triaged Findings: ${findings.length} (${critCount + highCount} Critical/High)\n• Evidence Artifacts: ${evidence.length}\n• Sequential Timeline Events: ${timeline.length}\n\nStatus: Pending Senior Analyst validation and confirmation.`,
        type: 'finding',
        priority: 'HIGH',
        related_evidence_id: null,
        related_finding_id: null
      };

      await createCaseNote(caseId, notePayload).catch(e => console.warn('Case note save warning:', e));

      // 2. Persist submission record in localStorage for synchronized UI telemetry
      const submissionRecord = {
        case_id: caseId,
        submitted: true,
        submitted_at: new Date().toISOString(),
        analyst_id: currentUser.id || 'analyst',
        analyst_name: analystName,
        note: noteText,
        findings_count: findings.length,
        evidence_count: evidence.length
      };

      localStorage.setItem(`argus_case_${caseId}_submitted_to_senior`, JSON.stringify(submissionRecord));
      window.dispatchEvent(new Event('storage'));

      setSubmittedSuccess(true);
      if (onSuccess) onSuccess(submissionRecord);

      setTimeout(() => {
        onClose();
      }, 1400);
    } catch (err) {
      console.error('Failed to submit report to senior analyst:', err);
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
          background: 'rgba(0, 0, 0, 0.78)',
          backdropFilter: 'blur(10px)',
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
            border: `1px solid ${isDark ? 'rgba(56, 189, 248, 0.3)' : '#cbd5e1'}`,
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
                background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: '0 4px 14px rgba(37, 99, 235, 0.35)',
                flexShrink: 0
              }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14 2 14 8 20 8"></polyline>
                  <line x1="16" y1="13" x2="8" y2="13"></line>
                  <line x1="16" y1="17" x2="8" y2="17"></line>
                </svg>
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: 'var(--glass-dash-blue, #38bdf8)', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
                    Analyst Investigation Handoff
                  </span>
                  <span style={{
                    fontSize: '10.5px',
                    fontWeight: 700,
                    background: 'rgba(59, 130, 246, 0.15)',
                    color: 'var(--glass-dash-blue, #38bdf8)',
                    padding: '1px 8px',
                    borderRadius: '999px',
                    border: '1px solid rgba(59, 130, 246, 0.3)'
                  }}>
                    READY TO SUBMIT
                  </span>
                </div>
                <h2 style={{ margin: '2px 0 0 0', fontSize: '18px', fontWeight: 800, color: isDark ? '#f8fafc' : '#0f172a' }}>
                  Generate Report for Senior Analyst
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
            {loading ? (
              <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
                Compiling multi-agent telemetry and compiling report dossier...
              </div>
            ) : submittedSuccess ? (
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
                  Report Successfully Submitted to Senior Analyst!
                </h3>
                <p style={{ margin: 0, fontSize: '14px', color: isDark ? '#cbd5e1' : '#475569', maxWidth: '480px', lineHeight: '1.6' }}>
                  Case #{caseId} has been promoted to Senior Analyst review. The Senior Analyst will validate triaged findings and confirm the legal-grade report.
                </p>
              </div>
            ) : (
              <>
                {/* Case Reference & Participants Bar */}
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
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Submitting Analyst</div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: '#38bdf8', marginTop: '2px' }}>
                        {currentUser.name || 'Analyst'}
                      </div>
                    </div>
                    <div style={{ color: 'var(--border-strong)' }}>&rarr;</div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Reviewer</div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: '#8b5cf6', marginTop: '2px' }}>
                        Senior Analyst Workspace
                      </div>
                    </div>
                  </div>
                </div>

                {/* Telemetry Highlights */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: findings.length > 0 ? '#38bdf8' : 'var(--text-main)' }}>{findings.length}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Triaged Findings</div>
                  </div>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: critCount + highCount > 0 ? '#ef4444' : '#10b981' }}>{critCount + highCount}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>High / Critical</div>
                  </div>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: '#10b981' }}>{evidence.length}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Evidence Files</div>
                  </div>
                  <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.025)' : '#f1f5f9', padding: '12px', borderRadius: '10px', textAlign: 'center', border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}` }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: '#f59e0b' }}>{timeline.length}</div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Timeline Events</div>
                  </div>
                </div>

                {/* Compiled Executive Assessment Preview */}
                <div style={{
                  background: isDark ? 'rgba(56, 189, 248, 0.06)' : 'rgba(37, 99, 235, 0.04)',
                  border: `1px solid ${isDark ? 'rgba(56, 189, 248, 0.2)' : 'rgba(37, 99, 235, 0.15)'}`,
                  borderLeft: '4px solid #38bdf8',
                  borderRadius: '12px',
                  padding: '14px 18px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ fontSize: '11.5px', fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      Generated Executive Assessment
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowFullPreview(true)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#38bdf8',
                        fontSize: '11.5px',
                        fontWeight: 700,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: 0
                      }}
                    >
                      <span>Inspect Full Dossier</span> &rarr;
                    </button>
                  </div>
                  <div style={{ fontSize: '13px', lineHeight: '1.6', color: isDark ? '#e2e8f0' : '#1e293b' }}>
                    {reportData?.executive_summary || `Forensic case baseline generated for Case ${caseId}. Contains ${evidence.length} cataloged evidence artifact(s) and ${findings.length} triaged finding(s).`}
                  </div>
                </div>

                {/* Optional Handoff Note for Senior Analyst */}
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 700, color: isDark ? '#f8fafc' : '#0f172a', marginBottom: '8px' }}>
                    Analyst Handoff Notes & Recommendations for Senior Review
                  </label>
                  <textarea
                    rows={3}
                    value={handoffNote}
                    onChange={(e) => setHandoffNote(e.target.value)}
                    placeholder="e.g. Initial access identified via spearphishing attachment in evidence file 1. Elevated persistence observed under registry Run key. Recommended for immediate FIR review."
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
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setShowFullPreview(true)}
                  disabled={loading || submitting}
                  className="btn btn-outline"
                  style={{ fontSize: '12.5px', padding: '7px 14px' }}
                >
                  Inspect Full Report
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadHtml(reportData, reportHtml, caseId)}
                  disabled={loading || submitting}
                  className="btn btn-outline"
                  style={{ fontSize: '12.5px', padding: '7px 14px' }}
                >
                  Download HTML
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadJson(reportData, caseId)}
                  disabled={loading || submitting}
                  className="btn btn-outline"
                  style={{ fontSize: '12.5px', padding: '7px 14px' }}
                >
                  JSON
                </button>
              </div>

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
                  onClick={handleSubmitToSenior}
                  disabled={loading || submitting}
                  className="btn btn-primary"
                  style={{
                    fontSize: '13px',
                    padding: '8px 20px',
                    fontWeight: 700,
                    background: 'linear-gradient(135deg, #2563eb 0%, #7c3aed 100%)',
                    border: 'none',
                    boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)'
                  }}
                >
                  {submitting ? 'Submitting to Senior...' : '🚀 Submit Report to Senior Analyst'}
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

