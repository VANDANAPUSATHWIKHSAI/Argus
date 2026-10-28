import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import NotificationMenu from '../components/NotificationMenu';
import { fetchCases, fetchCaseSummary, fetchEvidenceForCase, fetchFindings, fetchReport } from '../js/api';
import GeneratedReportCard from '../components/GeneratedReportCard';
import GeneratedReportModal from '../components/GeneratedReportModal';
import SeniorSubmitToAuditorModal from '../components/SeniorSubmitToAuditorModal';
import { safeFormatTime } from '../js/dateUtils';

const SeniorDashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [activeSummary, setActiveSummary] = useState(null);
  const [activeCaseDetails, setActiveCaseDetails] = useState(null);
  const [findings, setFindings] = useState([]);
  const [evidenceStats, setEvidenceStats] = useState({ available: 0, partial: 0, missing: 0 });
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');
  const [reportData, setReportData] = useState(null);
  const [reportHtml, setReportHtml] = useState('');
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [isSubmittedByAnalyst, setIsSubmittedByAnalyst] = useState(false);
  const [submitToAuditorOpen, setSubmitToAuditorOpen] = useState(false);
  const [isSubmittedToAuditor, setIsSubmittedToAuditor] = useState(false);
  const [auditorSubmissionDetails, setAuditorSubmissionDetails] = useState(null);
  
  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const userName = currentUser?.name || 'Senior Analyst';

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  async function loadData() {
    setLoading(true);
    try {
      const res = await fetchCases();
      const caseList = res.data || [];
      let targetCaseId = localStorage.getItem('active_case_id');
      
      if (!targetCaseId && caseList.length > 0) {
        targetCaseId = caseList[0].case_id;
        localStorage.setItem('active_case_id', targetCaseId);
      }
      
      if (targetCaseId) {
        const sub = localStorage.getItem(`argus_case_${targetCaseId}_submitted_to_senior`);
        setIsSubmittedByAnalyst(Boolean(sub));
        const subAud = localStorage.getItem(`argus_case_${targetCaseId}_submitted_to_auditor`);
        if (subAud) {
          try {
            const parsedAud = JSON.parse(subAud);
            setIsSubmittedToAuditor(Boolean(parsedAud?.submitted));
            setAuditorSubmissionDetails(parsedAud);
          } catch (_e) {
            setIsSubmittedToAuditor(false);
          }
        } else {
          setIsSubmittedToAuditor(false);
          setAuditorSubmissionDetails(null);
        }
        const currentCase = caseList.find(c => c.case_id === targetCaseId);
        if (currentCase) {
          setActiveCaseDetails(currentCase);
        }
        const summaryData = await fetchCaseSummary(targetCaseId).catch(() => null);
        if (summaryData) {
          setActiveSummary(summaryData);
        }

        const findingsRes = await fetchFindings(targetCaseId).catch(() => []);
        const findingsList = Array.isArray(findingsRes) ? findingsRes : (findingsRes.data || []);
        setFindings(findingsList);

        const evRes = await fetchEvidenceForCase(targetCaseId).catch(() => ({ data: [] }));
        const evList = evRes.data || [];
        let available = 0, partial = 0, missing = 0;
        evList.forEach(e => {
            const st = (e.status || '').toLowerCase();
            if (st === 'completed' || st === 'processed' || st === 'analyzed' || st === 'stored') available++;
            else if (st === 'processing' || st === 'pending' || st === 'uploaded') partial++;
            else missing++;
        });
        setEvidenceStats({ available, partial, missing });

        // Fetch authoritative generated report package
        try {
          const [repJsonRes, repHtmlRes] = await Promise.allSettled([
            fetchReport(targetCaseId, 'json', true),
            fetchReport(targetCaseId, 'html', true)
          ]);
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
              case_id: targetCaseId,
              findings: findingsList,
              evidence_files: evList,
              timeline: [],
              executive_summary: summaryData?.description || `Forensic case baseline compiled for Case ${targetCaseId}. Contains ${evList.length} evidence artifact(s) and ${findingsList.length} triaged finding(s).`
            });
          }
        } catch (repErr) {
          console.warn('Authoritative report fetch non-fatal error:', repErr);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadData(); }, []);

  const criticalHighCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high' || (f.severity || '').toLowerCase() === 'critical').length;
  const mediumCount = findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const lowCount = findings.filter(f => (f.severity || '').toLowerCase() === 'low' || (f.severity || '').toLowerCase() === 'info').length;

  return (
    <>
      <header className="glass-topbar-capsule topbar">
        <div className="glass-topbar-left">
          <h2 className="glass-welcome-title">Welcome, {userName}</h2>
          <p className="glass-welcome-sub">Senior Analyst Workspace &middot; Review and Validate Case Findings</p>
        </div>
        <div className="glass-topbar-right topbar-actions">
          <button className="glass-icon-btn icon-btn" onClick={toggleTheme} title="Toggle Theme">
            {theme === 'dark' ? (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            ) : (
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            )}
          </button>
          <NotificationMenu />
          <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
            <div className="glass-profile-avatar-dark avatar" style={{ background: 'var(--glass-dash-blue-soft)', color: 'var(--glass-dash-blue)' }}>SA</div>
            <span className="glass-profile-name">{userName}</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
            {showUserDropdown && (
              <div className="user-dropdown" style={{ display: 'block' }}>
                <div className="user-dropdown-header">
                  <div className="ud-name">{userName}</div>
                  <div className="ud-role">Senior Analyst</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>
      
      <div className="dashboard-scroll">
        
        {/* Case Header */}
        <div className="panel-card" style={{ padding: '28px 32px', marginBottom: '24px', borderRadius: '22px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
            <div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '8px' }}>
                <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>Case #{activeSummary?.case_id || 'ARG-2026-001'}</h1>
                {isSubmittedToAuditor ? (
                  <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.4)', padding: '4px 12px', borderRadius: '9999px', fontSize: '12px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    Escalated to Auditor &middot; Ready for Attestation
                  </span>
                ) : isSubmittedByAnalyst ? (
                  <span style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)', padding: '4px 12px', borderRadius: '9999px', fontSize: '12px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    Submitted by Analyst &middot; Ready for Review
                  </span>
                ) : (
                  <span style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.3)', padding: '4px 12px', borderRadius: '9999px', fontSize: '12px', fontWeight: 600 }}>Ready for Review</span>
                )}
              </div>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', fontSize: '15px', color: 'var(--text-muted)' }}>
                <span>{activeSummary?.name || activeCaseDetails?.name || 'Investigation Case'}</span>
                <span style={{ color: 'var(--border-strong)' }}>|</span>
                <span style={{ fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                  Analyst: <strong style={{ color: 'var(--text-main)' }}>{activeCaseDetails?.analyst_name || activeCaseDetails?.analyst_id || 'Unassigned'}</strong>
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <button
                onClick={() => navigate('/case-notes')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 16px',
                  borderRadius: '10px',
                  border: '1px solid var(--border-strong)',
                  background: 'var(--glass-dash-surface-nested)',
                  color: 'var(--text-main)',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
                Case Notes
              </button>

              <button
                onClick={() => navigate('/chatbot')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 16px',
                  borderRadius: '10px',
                  border: '1px solid var(--border-strong)',
                  background: 'var(--glass-dash-surface-nested)',
                  color: 'var(--text-main)',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                AI Assistant
              </button>

              <button
                onClick={() => navigate('/report')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 18px',
                  borderRadius: '10px',
                  border: 'none',
                  background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
                  color: '#ffffff',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 4px 12px rgba(37, 99, 235, 0.35)',
                  transition: 'all 0.2s'
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                Report Review
              </button>

              <button
                type="button"
                onClick={() => setSubmitToAuditorOpen(true)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 18px',
                  borderRadius: '10px',
                  border: 'none',
                  background: isSubmittedToAuditor ? '#10b981' : 'linear-gradient(135deg, #059669 0%, #10b981 100%)',
                  color: '#ffffff',
                  fontSize: '13px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 4px 12px rgba(16, 185, 129, 0.35)',
                  transition: 'all 0.2s'
                }}
                title={isSubmittedToAuditor ? 'Report already escalated to Auditor' : 'Approve findings and escalate to Auditor'}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  {isSubmittedToAuditor ? (
                    <polyline points="20 6 9 17 4 12"></polyline>
                  ) : (
                    <>
                      <line x1="22" y1="2" x2="11" y2="13"></line>
                      <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                    </>
                  )}
                </svg>
                {isSubmittedToAuditor ? '✓ Submitted to Auditor' : '🚀 Submit to Auditor'}
              </button>
            </div>
          </div>
          
          <div style={{ background: 'var(--glass-dash-surface-nested)', padding: '16px 22px', borderRadius: '16px', border: '1px solid var(--glass-dash-border-subtle)', display: 'flex', alignItems: 'center', gap: '14px' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--glass-dash-blue)" strokeWidth="2" style={{ flexShrink: 0, opacity: 0.85 }}>
              <path d="M3 21c3 0 7-1 7-8V5c0-1.25-.75-2-2-2H4c-1.25 0-2 .75-2 2v6c0 1.25.75 2 2 2 1 0 1 0 1 1 0 2-1 3-2 4v3zm14 0c3 0 7-1 7-8V5c0-1.25-.75-2-2-2h-4c-1.25 0-2 .75-2 2v6c0 1.25.75 2 2 2 1 0 1 0 1 1 0 2-1 3-2 4v3z"/>
            </svg>
            <p style={{ margin: 0, fontSize: '14px', color: 'var(--text-main)', lineHeight: '1.6', fontStyle: 'italic' }}>
              "{activeSummary?.description || activeCaseDetails?.description || 'No specific narrative description provided for this case yet. Review individual findings below to validate the intrusion timeline.'}"
            </p>
          </div>
        </div>

        {/* Official Generated Case Report Section */}
        <GeneratedReportCard
          caseId={activeSummary?.case_id || activeCaseDetails?.case_id || localStorage.getItem('active_case_id') || 'CASE'}
          caseName={activeSummary?.name || activeCaseDetails?.name}
          reportData={reportData}
          reportHtml={reportHtml}
          loading={loading}
          onOpenReportModal={() => setReportModalOpen(true)}
          role="senior_analyst"
          onSubmitToAuditor={() => setSubmitToAuditorOpen(true)}
          isSubmittedToAuditor={isSubmittedToAuditor}
        />

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', marginBottom: '24px' }}>
          
          {/* AI Findings Preview */}
          <div className="panel-card" style={{ padding: '28px', borderRadius: '22px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <div>
                <h2 style={{ margin: '0 0 4px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>AI Findings</h2>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{findings.length} Findings detected</div>
              </div>
              <div style={{ display: 'flex', gap: '16px', fontSize: '13px', fontWeight: 600 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ef4444' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444' }}></div> {criticalHighCount} High/Critical</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f59e0b' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b' }}></div> {mediumCount} Medium</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#3b82f6' }}><div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#3b82f6' }}></div> {lowCount} Low</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '24px' }}>
              {loading ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px' }}>
                  Loading findings...
                </div>
              ) : findings.length > 0 ? (
                [...findings]
                  .sort((a, b) => {
                    const sevMap = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                    const aSev = sevMap[(a.severity || '').toLowerCase()] || 0;
                    const bSev = sevMap[(b.severity || '').toLowerCase()] || 0;
                    if (bSev !== aSev) return bSev - aSev;
                    const aConf = (a.confidence > 1 ? a.confidence : a.confidence * 100) || 0;
                    const bConf = (b.confidence > 1 ? b.confidence : b.confidence * 100) || 0;
                    return bConf - aConf;
                  })
                  .slice(0, 4)
                  .map((f, idx) => {
                    const sev = (f.severity || 'medium').toLowerCase();
                    const sevColor = sev === 'high' || sev === 'critical' ? '#ef4444' : (sev === 'medium' ? '#f59e0b' : '#3b82f6');
                    const conf = Math.round((f.confidence > 1 ? f.confidence : f.confidence * 100) || 0);
                    const fKey = f.finding_id || f.id || `f-${idx}`;
                    return (
                      <div key={fKey} style={{ padding: '16px 20px', background: 'var(--glass-dash-surface-nested)', borderRadius: '14px', border: '1px solid var(--glass-dash-border-subtle)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: '13.5px' }}>{fKey} &mdash; {f.fact || 'Finding details recorded'}</div>
                        </div>
                        <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                          <span style={{ color: sevColor, fontWeight: 700, textTransform: 'capitalize' }}>{sev}</span> &middot; {conf}% confidence
                        </div>
                      </div>
                    );
                  })
              ) : (
                <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '14px', background: 'var(--glass-dash-surface-nested)', borderRadius: '14px', border: '1px dashed var(--glass-dash-border)' }}>
                  No AI findings available for this case yet.
                </div>
              )}
            </div>

            <div style={{ display: 'flex', gap: '12px' }}>
              <button onClick={() => navigate('/findings')} className="btn btn-outline" style={{ flex: 1, padding: '11px 18px', border: '1px solid var(--border-strong)', color: 'var(--text-main)', background: 'var(--bg-card)', borderRadius: '9999px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s', fontSize: '13px' }}>
                View All Findings
              </button>
              <button 
                onClick={() => navigate('/chatbot')} 
                style={{ 
                  flex: 1, 
                  padding: '11px 18px', 
                  background: 'rgba(59, 130, 246, 0.12)', 
                  border: '1px solid rgba(59, 130, 246, 0.35)', 
                  color: 'var(--glass-dash-blue, #60a5fa)', 
                  borderRadius: '9999px', 
                  fontWeight: 600, 
                  cursor: 'pointer', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  gap: '8px', 
                  fontSize: '13px',
                  boxShadow: '0 2px 10px rgba(0, 0, 0, 0.2)',
                  transition: 'all 0.2s ease'
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.background = 'rgba(59, 130, 246, 0.22)';
                  e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.55)';
                  e.currentTarget.style.color = '#93c5fd';
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.background = 'rgba(59, 130, 246, 0.12)';
                  e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.35)';
                  e.currentTarget.style.color = 'var(--glass-dash-blue, #60a5fa)';
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                Consult AI Assistant
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            
            {/* Evidence Coverage */}
            <div className="panel-card" style={{ padding: '24px', borderRadius: '22px', height: 'auto', boxSizing: 'border-box' }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '17px', fontWeight: 700, color: 'var(--text-main)' }}>Evidence Coverage</h2>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '20px' }}>
                <span style={{ color: '#22c55e', display: 'flex', alignItems: 'center', gap: 6 }}><div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e' }}></div> {evidenceStats.available} Available</span>
                <span style={{ color: '#f59e0b', display: 'flex', alignItems: 'center', gap: 6 }}><div style={{ width: 6, height: 6, borderRadius: '50%', background: '#f59e0b' }}></div> {evidenceStats.partial} Partial</span>
                <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 6 }}><div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }}></div> {evidenceStats.missing} Missing</span>
              </div>
              <button onClick={() => navigate('/report')} className="btn btn-outline" style={{ width: '100%', padding: '10px 16px', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', borderRadius: '9999px', fontWeight: 600, cursor: 'pointer', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                Review in Report
              </button>
            </div>

            {/* Timeline Preview */}
            <div className="panel-card" style={{ padding: '24px 24px 24px 24px', borderRadius: '22px', height: 'auto', display: 'flex', flexDirection: 'column', boxSizing: 'border-box' }}>
              <h2 style={{ margin: '0 0 4px 0', fontSize: '17px', fontWeight: 700, color: 'var(--text-main)' }}>Recent Timeline</h2>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '18px' }}>Recorded finding events</div>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
                {loading ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Loading timeline events...</div>
                ) : findings.length > 0 ? (
                  findings.slice(0, 4).map((f, idx) => {
                    const rawTime = f.created_at || f.timestamp;
                    const timeStr = safeFormatTime(rawTime, '--:--');
                    const fKey = f.finding_id || f.id || `tl-${idx}`;
                    return (
                      <div key={fKey} style={{ display: 'flex', gap: '12px', fontSize: '13px', alignItems: 'center', padding: '8px 12px', background: 'var(--glass-dash-surface-nested)', borderRadius: '10px', border: '1px solid var(--glass-dash-border-subtle)' }}>
                        <div style={{ color: 'var(--glass-dash-blue)', width: '50px', fontWeight: 700, flexShrink: 0, fontSize: '12px', fontFamily: 'monospace' }}>{timeStr}</div>
                        <div style={{ color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.fact || fKey}</div>
                      </div>
                    );
                  })
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: '13px', textAlign: 'center', padding: '16px', background: 'var(--glass-dash-surface-nested)', borderRadius: '10px', border: '1px dashed var(--glass-dash-border)' }}>No timeline events recorded yet.</div>
                )}
              </div>

              <div style={{ marginTop: 'auto', paddingTop: '4px' }}>
                <button onClick={() => navigate('/timeline')} className="btn btn-outline" style={{ width: '100%', padding: '10px 16px', background: 'var(--glass-dash-surface-nested)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', borderRadius: '9999px', fontWeight: 600, cursor: 'pointer', fontSize: '13px' }}>
                  View Full Timeline
                </button>
              </div>
            </div>

          </div>
        </div>

      </div>

      {/* Generated Report Preview Modal */}
      <GeneratedReportModal
        isOpen={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        caseId={activeSummary?.case_id || activeCaseDetails?.case_id || localStorage.getItem('active_case_id') || 'CASE'}
        reportData={reportData}
        reportHtml={reportHtml}
      />

      {/* Senior Analyst -> Auditor Escalation Modal */}
      <SeniorSubmitToAuditorModal
        isOpen={submitToAuditorOpen}
        onClose={() => setSubmitToAuditorOpen(false)}
        caseId={activeSummary?.case_id || activeCaseDetails?.case_id || localStorage.getItem('active_case_id') || 'CASE'}
        caseName={activeSummary?.name || activeCaseDetails?.name}
        reportData={reportData}
        reportHtml={reportHtml}
        onSuccess={(rec) => {
          setIsSubmittedToAuditor(true);
          setAuditorSubmissionDetails(rec);
        }}
      />
    </>
  );
};

export default SeniorDashboard;

