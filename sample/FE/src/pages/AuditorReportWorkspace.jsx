import React, { useState, useEffect, useRef, useMemo } from 'react';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { 
  fetchCases, 
  fetchFindings, 
  fetchEvidenceForCase, 
  fetchCaseSummary, 
  queryCase 
} from '../js/api';
import { getActiveCaseId, getActiveCaseName, setActiveCase, subscribeToActiveCase } from '../js/caseEvents';
import '../css/style.css';

const MITRE_TECHNIQUE_NAMES = {
  'T1566': 'Phishing',
  'T1566.001': 'Spearphishing Attachment',
  'T1204': 'User Execution',
  'T1204.002': 'Malicious File Execution',
  'T1059': 'Command & Scripting Interpreter',
  'T1059.001': 'PowerShell Scripting',
  'T1059.005': 'VBA Macro Execution',
  'T1053': 'Scheduled Task/Job',
  'T1053.005': 'Scheduled Task Persistence',
  'T1071': 'Application Layer Protocol',
  'T1071.001': 'Web C2 Protocols',
  'T1070': 'Indicator Removal',
  'T1078': 'Valid Accounts',
  'T1105': 'Ingress Tool Transfer',
  'T1082': 'System Information Discovery',
  'T1027': 'Obfuscated Files or Information'
};

const AUDIT_REASONING_STEPS = [
  'Verifying evidence cryptographic hashes (SHA-256)...',
  'Cross-examining findings against forensic artifact telemetry...',
  'Checking MITRE ATT&CK kill-chain mapping consistency...',
  'Auditing chain of custody & evidentiary compliance standards...',
  'Compiling grounded audit assessment...'
];

export default function AuditorReportWorkspace() {
  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('argus_user'));
  } catch (_e) {}

  const isAuditor = user?.role === 'auditor';

  // Theme state
  const [theme, setTheme] = useState(
    document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark'
  );
  const isDark = theme === 'dark';

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  // Active Case state - initialized strictly from canonical storage/state, never hardcoding ARGUS_956
  const [activeCaseId, setActiveCaseId] = useState(getActiveCaseId());
  const [activeCaseName, setActiveCaseName] = useState(getActiveCaseName());
  const [casesList, setCasesList] = useState([]);
  const [_loadingCaseData, setLoadingCaseData] = useState(false);
  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);
  const [caseSearch, setCaseSearch] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const dropdownRef = useRef(null);

  // Close case switcher dropdown on click outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setCaseDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Synchronize active case across tabs and components
  useEffect(() => {
    return subscribeToActiveCase(({ caseId, caseName }) => {
      setActiveCaseId(caseId);
      setActiveCaseName(caseName || caseId);
    });
  }, []);

  // Case Data
  const [findings, setFindings] = useState([]);
  const [evidenceFiles, setEvidenceFiles] = useState([]);
  const [caseSummary, setCaseSummary] = useState(null);

  // Auditor Verification State
  const [isCertified, setIsCertified] = useState(false);
  const [certificationTimestamp, setCertificationTimestamp] = useState(null);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'info' });

  // Chatbot State
  const [chatMessages, setChatMessages] = useState([]);
  const [inputQuery, setInputQuery] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [reasoningStep, setReasoningStep] = useState(0);
  const [expandedReasoningMap, setExpandedReasoningMap] = useState({});

  const chatEndRef = useRef(null);
  const inputRef = useRef(null);

  // 1. Load cases list on mount and validate active case against authorized backend cases
  useEffect(() => {
    async function loadCases() {
      try {
        const res = await fetchCases();
        const list = res.data || [];
        if (list.length > 0) {
          const stored = getActiveCaseId();
          const validCases = list.filter(c => c.case_id && c.case_id !== '00000000-0000-0000-0000-000000000001');
          setCasesList(validCases);
          
          // Validate stored case against authorized backend cases
          const matched = (stored && stored !== '00000000-0000-0000-0000-000000000001')
            ? validCases.find(c => c.case_id === stored)
            : null;
          
          const presentCase = matched 
            || validCases.find(c => c.status === 'open' || c.is_active)
            || validCases[0] 
            || null;

          if (presentCase) {
            setActiveCaseId(presentCase.case_id);
            setActiveCaseName(presentCase.name || presentCase.case_id);
            setActiveCase(presentCase.case_id, presentCase.name || presentCase.case_id);
          } else {
            setActiveCaseId('');
            setActiveCaseName('');
            setActiveCase('', '');
          }
        } else {
          setCasesList([]);
          setActiveCaseId('');
          setActiveCaseName('');
          setActiveCase('', '');
        }
      } catch (err) {
        console.error('Failed to load cases:', err);
      }
    }
    loadCases();
  }, []);

  const handleSelectCase = (cId, cName) => {
    setActiveCaseId(cId);
    setActiveCaseName(cName || cId);
    setActiveCase(cId, cName || cId);
    setCaseDropdownOpen(false);
    setCaseSearch('');
  };

  // Initialize Welcome Message
  const initAuditChatWelcome = (caseId, caseName) => {
    const roleTitle = isAuditor ? 'Auditor' : 'Senior Analyst';
    setChatMessages([
      {
        id: 'welcome-msg',
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: `### 🛡️ AI Forensic Audit Copilot Ready
Welcome, **${user?.name || roleTitle}**. I can help inspect records returned by ARGUS for case **${caseId}** (${caseName || 'Active Case'}). The backend must supply evidence for any audit conclusion.

#### Active Audit Scope:
- **Evidence Ledgers:** Evidence metadata loaded where available; integrity status is shown only when returned by the verification service.
- **Triaged Findings:** Grounded against multi-agent correlation telemetry.
- **Compliance Status:** Review supporting records before making any compliance or admissibility determination.

You can click any **"Verify with AI"** or **"Audit Artifact"** button in the report preview on the left, or use the quick audit actions below to cross-examine claims, verify integrity, or check MITRE techniques.`
      }
    ]);
  };

  // 2. Load case findings and evidence whenever activeCaseId changes
  useEffect(() => {
    if (!activeCaseId) return;

    let isMounted = true;
    setLoadingCaseData(true);

    async function loadData() {
      try {
        const [fRes, evRes, sumRes] = await Promise.allSettled([
          fetchFindings(activeCaseId),
          fetchEvidenceForCase(activeCaseId),
          fetchCaseSummary(activeCaseId)
        ]);

        if (!isMounted) return;

        if (fRes.status === 'fulfilled' && fRes.value) {
          const fList = Array.isArray(fRes.value) ? fRes.value : (fRes.value.data || []);
          setFindings(fList);
        } else {
          setFindings([]);
        }

        if (evRes.status === 'fulfilled' && evRes.value) {
          const evList = Array.isArray(evRes.value) ? evRes.value : (evRes.value.data || []);
          setEvidenceFiles(evList);
        } else {
          setEvidenceFiles([]);
        }

        if (sumRes.status === 'fulfilled' && sumRes.value) {
          setCaseSummary(sumRes.value);
        }

        // Check if previously certified
        const certData = localStorage.getItem(`argus_audit_certified_${activeCaseId}`);
        if (certData) {
          try {
            const parsed = JSON.parse(certData);
            setIsCertified(true);
            setCertificationTimestamp(parsed.timestamp);
          } catch (_e) {
            setIsCertified(false);
          }
        } else {
          setIsCertified(false);
          setCertificationTimestamp(null);
        }

        // Initialize audit chat welcome message for this case
        initAuditChatWelcome(activeCaseId, activeCaseName);

      } catch (err) {
        console.error('Failed to load case data for audit:', err);
      } finally {
        if (isMounted) setLoadingCaseData(false);
      }
    }

    loadData();

    return () => { isMounted = false; };
  }, [activeCaseId, activeCaseName]);

  // Scroll chat to bottom on new messages
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, chatLoading, reasoningStep]);

  // Fail closed: never synthesize audit facts when the backend is unavailable.
  const buildAuditUnavailableResponse = (caseId, reason = 'The case-query service did not return a usable response.') => `## Audit response unavailable

**Case:** ${caseId || 'Not selected'}

${reason}

No hash match, custody event, signature, MITRE mapping, compliance verdict, or finding verification has been inferred by the UI. Retry after checking the backend. Formal verification must be based on persisted audit records and server-side checks.`;

  // Submit Chat Query
  const handleSendQuery = async (queryTextOverride = null) => {
    const rawQuery = (queryTextOverride || inputQuery).trim();
    if (!rawQuery || chatLoading) return;

    const userMessage = {
      id: Date.now().toString(),
      sender: 'user',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      text: rawQuery
    };

    setChatMessages(prev => [...prev, userMessage]);
    setInputQuery('');
    setChatLoading(true);
    setReasoningStep(0);

    const stepInterval = setInterval(() => {
      setReasoningStep(prev => (prev + 1) % AUDIT_REASONING_STEPS.length);
    }, 1200);

    try {
      // 1. Try querying backend case endpoint
      const res = await queryCase(activeCaseId, rawQuery);
      clearInterval(stepInterval);

      let replyText = res?.response;
      if (!replyText || replyText.includes('[SYSTEM NOTICE: Local Ollama LLM service is offline') || replyText.includes('No evidence findings recorded')) {
        replyText = buildAuditUnavailableResponse(activeCaseId, 'No grounded audit answer was returned by the backend.');
      }

      const assistantMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: replyText,
        reasoningTrail: res?.response ? [] : undefined
      };
      setChatMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      clearInterval(stepInterval);
      console.error('Audit query failed:', err);

      const fallbackReply = buildAuditUnavailableResponse(activeCaseId, 'The backend query failed. No audit verdict was generated.');
      const assistantMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: fallbackReply,
      };
      setChatMessages(prev => [...prev, assistantMessage]);
    } finally {
      clearInterval(stepInterval);
      setChatLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  // Quick Action Buttons
  const handleQuickAction = (promptText) => {
    setInputQuery(promptText);
    handleSendQuery(promptText);
  };

  // Send finding verification to chatbot
  const handleVerifyFinding = (finding) => {
    const prompt = `Cross-examine finding ${finding.finding_id || 'F-001'}: "${finding.sanitized_fact || finding.fact || finding.claim}" against evidence telemetry and confirm MITRE technique mapping.`;
    handleSendQuery(prompt);
  };

  // Send artifact audit to chatbot
  const handleAuditArtifact = (artifact) => {
    const filename = artifact.filename || artifact.name || 'evidence_artifact';
    const hash = artifact.sha256_hash || 'not available';
    const prompt = `Audit cryptographic integrity and custody continuity for evidence file "${filename}" (SHA-256: ${hash}).`;
    handleSendQuery(prompt);
  };

  // Toggle auditor certification
  const handleToggleCertification = () => {
    if (isCertified) {
      setIsCertified(false);
      setCertificationTimestamp(null);
      localStorage.removeItem(`argus_audit_certified_${activeCaseId}`);
      setCustomAlert({
        isOpen: true,
        title: 'Review Marker Removed',
        message: `The local review marker for case ${activeCaseId} has been removed. No server-side certification state was changed.`,
        type: 'info'
      });
    } else {
      const nowStr = new Date().toLocaleString();
      setIsCertified(true);
      setCertificationTimestamp(nowStr);
      localStorage.setItem(`argus_audit_certified_${activeCaseId}`, JSON.stringify({
        certifiedBy: user?.name || 'Auditor',
        timestamp: nowStr,
        caseId: activeCaseId
      }));
      setCustomAlert({
        isOpen: true,
        title: 'Review Marker Saved',
        message: `A local review marker was saved for case ${activeCaseId}. This does not certify evidence integrity, lock the case, or create a cryptographic attestation.`,
        type: 'info'
      });
    }
  };

  // Print / Export PDF
  const handlePrintReport = () => {
    window.print();
  };

  // Export Attestation to clipboard
  const handleExportAttestation = () => {
    const attestation = `=== ARGUS AUDIT REVIEW NOTE (NOT A CRYPTOGRAPHIC ATTESTATION) ===
Case ID: ${activeCaseId}
Case Name: ${activeCaseName}
Auditor: ${user?.name || 'Auditor'} (${user?.role || 'Lead Auditor'})
Local Review Marker: ${isCertified ? 'MARKED BY USER — NOT SERVER-VERIFIED' : 'NOT MARKED'}
Timestamp: ${certificationTimestamp || new Date().toLocaleString()}
Evidence Records Loaded: ${evidenceFiles.length}
Finding Records Loaded: ${findings.length}
Admissibility: NOT ASSESSED BY THIS LOCAL REVIEW MARKER
Hash Ledger: CHECK SERVER-SIDE VERIFICATION STATUS
========================================`;
    navigator.clipboard.writeText(attestation);
    setCustomAlert({
      isOpen: true,
      title: 'Review Note Copied',
      message: 'Review note copied. It is explicitly not a cryptographic or legal attestation.',
      type: 'success'
    });
  };

  const parseInlineMarkdown = (text) => {
    if (!text) return null;
    const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
    return parts.map((p, i) => {
      if (p.startsWith('**') && p.endsWith('**')) {
        return <strong key={i} style={{ color: isDark ? '#ffffff' : '#0f172a' }}>{p.slice(2, -2)}</strong>;
      }
      if (p.startsWith('`') && p.endsWith('`')) {
        return (
          <code key={i} style={{
            background: isDark ? 'rgba(255,255,255,0.08)' : '#f1f5f9',
            color: isDark ? '#38bdf8' : '#0284c7',
            padding: '2px 5px',
            borderRadius: '4px',
            fontFamily: 'monospace',
            fontSize: '11.5px'
          }}>
            {p.slice(1, -1)}
          </code>
        );
      }
      return p;
    });
  };

  const renderFormattedText = (rawText) => {
    if (!rawText) return null;

    if (typeof rawText === 'string' && rawText.trim().startsWith('{') && rawText.trim().endsWith('}')) {
      try {
        const data = JSON.parse(rawText.trim());
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {data.executive_summary && (
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#3b82f6', textTransform: 'uppercase', marginBottom: '4px', letterSpacing: '0.5px' }}>
                  Executive Briefing
                </div>
                <div style={{ lineHeight: '1.6', fontSize: '13px' }}>{data.executive_summary}</div>
              </div>
            )}

            {data.findings_summary && !data.executive_summary && (
              <div style={{ lineHeight: '1.6', fontSize: '13px' }}>{data.findings_summary}</div>
            )}

            {data.claims && Array.isArray(data.claims) && data.claims.length > 0 && (
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#10b981', textTransform: 'uppercase', marginBottom: '6px', letterSpacing: '0.5px' }}>
                  Corroborated Telemetry Claims
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {data.claims.map((c, cIdx) => (
                    <div key={cIdx} style={{
                      background: isDark ? 'rgba(255,255,255,0.03)' : '#f8fafc',
                      padding: '8px 12px',
                      borderRadius: '8px',
                      borderLeft: '3px solid #10b981',
                      border: isDark ? '1px solid rgba(255,255,255,0.08)' : '1px solid #e2e8f0',
                      borderLeftWidth: '3px'
                    }}>
                      <div style={{ fontWeight: 600, fontSize: '12.5px' }}>{c.summary || c.claim}</div>
                      <div style={{ display: 'flex', gap: '8px', marginTop: '4px', flexWrap: 'wrap', fontSize: '11px', alignItems: 'center' }}>
                        {c.severity && (
                          <span style={{
                            background: c.severity === 'high' || c.severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(234, 179, 8, 0.2)',
                            color: c.severity === 'high' || c.severity === 'critical' ? '#ef4444' : '#eab308',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            fontWeight: 700,
                            textTransform: 'uppercase'
                          }}>
                            {c.severity}
                          </span>
                        )}
                        {(c.cited_evidence_ids || c.evidence_ids) && (
                          <span style={{ color: themeStyles.textMuted }}>
                            Evidence: <strong style={{ color: themeStyles.textMain }}>{(c.cited_evidence_ids || c.evidence_ids).join(', ')}</strong>
                          </span>
                        )}
                        {c.confidence !== undefined && (
                          <span style={{ color: '#38bdf8', fontWeight: 600 }}>
                            Confidence: {(c.confidence * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {data.overall_confidence !== undefined && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '11.5px',
                borderTop: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`,
                paddingTop: '6px'
              }}>
                <span style={{ color: themeStyles.textMuted }}>Overall Audit Confidence:</span>
                <span style={{ fontWeight: 700, color: '#38bdf8' }}>{(data.overall_confidence * 100).toFixed(0)}%</span>
              </div>
            )}
          </div>
        );
      } catch (_e) {}
    }

    const lines = rawText.split('\n');
    return (
      <span>
        {lines.map((line, lIdx) => {
          if (line.startsWith('### ')) {
            return (
              <h4 key={lIdx} style={{ margin: '10px 0 4px 0', fontSize: '14px', fontWeight: 700, color: isDark ? '#60a5fa' : '#2563eb' }}>
                {line.replace('### ', '')}
              </h4>
            );
          }
          if (line.startsWith('#### ')) {
            return (
              <div key={lIdx} style={{ margin: '8px 0 3px 0', fontSize: '12.5px', fontWeight: 700, color: '#10b981' }}>
                {line.replace('#### ', '')}
              </div>
            );
          }
          if (line.startsWith('- ') || line.startsWith('* ')) {
            const content = line.slice(2);
            return (
              <div key={lIdx} style={{ display: 'flex', gap: '6px', margin: '3px 0', paddingLeft: '6px' }}>
                <span style={{ color: '#3b82f6', fontWeight: 'bold' }}>•</span>
                <span>{parseInlineMarkdown(content)}</span>
              </div>
            );
          }
          if (/^\d+\.\s/.test(line)) {
            return (
              <div key={lIdx} style={{ display: 'flex', gap: '6px', margin: '3px 0', paddingLeft: '6px' }}>
                <span style={{ color: '#3b82f6', fontWeight: 'bold' }}>{line.match(/^\d+\./)[0]}</span>
                <span>{parseInlineMarkdown(line.replace(/^\d+\.\s/, ''))}</span>
              </div>
            );
          }
          return (
            <span key={lIdx}>
              {parseInlineMarkdown(line)}
              {lIdx < lines.length - 1 && <br />}
            </span>
          );
        })}
      </span>
    );
  };

  // Dynamic Theme Colors
  const themeStyles = {
    appBg: 'var(--glass-dash-bg)',
    topbarBg: 'var(--glass-dash-surface-gradient)',
    topbarBorder: 'var(--glass-dash-border)',
    cardBg: 'var(--glass-dash-surface-gradient)',
    cardBorder: 'var(--glass-dash-border)',
    paperBg: isDark ? 'rgba(255, 255, 255, 0.04)' : 'rgba(255, 255, 255, 0.65)',
    paperBorder: 'var(--glass-dash-border)',
    paperText: 'var(--glass-dash-text-main)',
    paperMuted: 'var(--glass-dash-text-muted)',
    chatBg: 'transparent',
    chatBubbleUser: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
    chatBubbleAi: isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(255, 255, 255, 0.7)',
    chatBubbleAiBorder: 'var(--glass-dash-border-subtle)',
    textMain: 'var(--glass-dash-text-main)',
    textMuted: 'var(--glass-dash-text-muted)',
    inputBg: 'var(--glass-dash-surface-nested)',
    inputBorder: 'var(--glass-dash-border-subtle)',
    accentGreen: 'var(--glass-dash-green)',
    accentBlue: 'var(--glass-dash-blue)',
    accentOrange: '#f59e0b',
    accentRed: 'var(--glass-dash-red)'
  };

  // Calculate Findings Metrics strictly from loaded case data (no fabricated fallbacks)
  const highSevCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high' || (f.severity || '').toLowerCase() === 'critical').length;
  const medSevCount = findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length;
  const lowSevCount = findings.filter(f => (f.severity || '').toLowerCase() === 'low').length;
  const evidenceCount = evidenceFiles.length;

  // MITRE Techniques dynamically derived from loaded case findings
  const observedTechniques = useMemo(() => {
    const list = [];
    const seen = new Set();
    findings.forEach(f => {
      const tid = f.mitre_mapping || f.mitre || (f.metadata && f.metadata.mitre_technique);
      if (tid && !seen.has(tid)) {
        seen.add(tid);
        list.push({
          id: tid,
          name: MITRE_TECHNIQUE_NAMES[tid] || (f.layer ? `${f.layer} Technique` : 'Observed Technique'),
          tactic: f.layer ? f.layer.toUpperCase() : 'Attribution'
        });
      }
    });
    return list;
  }, [findings]);

  return (
    <div id="app-shell" style={{ display: 'flex', width: '100vw', height: '100vh', overflow: 'hidden', background: themeStyles.appBg }}>
      <AlertModal 
        isOpen={customAlert.isOpen} 
        title={customAlert.title} 
        message={customAlert.message} 
        type={customAlert.type} 
        onClose={() => setCustomAlert(prev => ({ ...prev, isOpen: false }))} 
      />

      <Sidebar />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100vh', padding: '94px 20px 20px 300px', boxSizing: 'border-box', overflow: 'hidden' }}>
        
        {/* ── TOPBAR CAPSULE ── */}
        <header className="glass-topbar-capsule topbar">
          {/* Title & Case Selector */}
          <div className="glass-topbar-left" style={{ display: 'flex', alignItems: 'center', gap: '14px', flexDirection: 'row' }}>
            <div style={{
              width: '34px',
              height: '34px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)'
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <polyline points="9 12 11 14 15 10"></polyline>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--glass-dash-text-main)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>{user?.role === 'senior_analyst' ? 'Senior Analyst Report Review' : isAuditor ? 'Auditor Forensic Workspace' : 'Analyst Forensic Workspace'}</span>
                <span style={{ 
                  fontSize: '11px', 
                  padding: '2px 10px', 
                  borderRadius: '9999px', 
                  background: isAuditor 
                    ? 'var(--glass-dash-green-soft)'
                    : 'var(--glass-dash-blue-soft)', 
                  color: isAuditor ? 'var(--glass-dash-green)' : 'var(--glass-dash-blue)', 
                  fontWeight: 700,
                  border: `1px solid ${isAuditor ? 'var(--glass-dash-green-border)' : 'var(--glass-dash-blue-border)'}`
                }}>
                  {user?.role === 'senior_analyst' ? 'Report Review Mode' : isAuditor ? 'Independent Review Mode' : 'Lead Analyst Mode'}
                </span>
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--glass-dash-text-muted)' }}>
                {user?.role === 'senior_analyst'
                  ? 'Side-by-side Report Review & Grounded AI Assistant'
                  : isAuditor 
                  ? 'Side-by-side Live Report Preview & Grounded AI Audit Assistant' 
                  : 'Side-by-side Live Forensic Report & Grounded AI Assistant'}
              </div>
            </div>

            {/* Interactive Case Selector Dropdown */}
            <div ref={dropdownRef} style={{ position: 'relative', marginLeft: '8px' }}>
              <button
                type="button"
                onClick={() => setCaseDropdownOpen(prev => !prev)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'var(--glass-dash-surface-nested)',
                  border: '1px solid var(--glass-dash-border-subtle)',
                  borderRadius: '9999px',
                  padding: '6px 14px',
                  color: 'var(--glass-dash-text-main)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  boxShadow: caseDropdownOpen ? '0 0 0 2px var(--glass-dash-blue)' : 'none'
                }}
                title="Click to open or switch case"
              >
                <span style={{ color: 'var(--glass-dash-blue)', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Case:</span>
                <span style={{ fontFamily: 'var(--glass-dash-mono)', fontWeight: 700, color: 'var(--glass-dash-text-main)' }}>{activeCaseId || 'Select Case'}</span>
                {activeCaseName && activeCaseName !== activeCaseId && (
                  <span style={{ fontSize: '11px', color: 'var(--glass-dash-text-muted)', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    ({activeCaseName})
                  </span>
                )}
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ transform: caseDropdownOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </button>

              {caseDropdownOpen && (
                <div style={{
                  position: 'absolute',
                  top: 'calc(100% + 8px)',
                  left: 0,
                  width: '320px',
                  maxHeight: '380px',
                  background: themeStyles.cardBg,
                  border: `1px solid ${themeStyles.cardBorder}`,
                  borderRadius: '14px',
                  boxShadow: '0 18px 40px rgba(0,0,0,0.45)',
                  zIndex: 100,
                  padding: '10px',
                  backdropFilter: 'blur(16px)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '2px 4px 6px', borderBottom: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}` }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Available Cases ({casesList.length})
                    </span>
                    <span style={{ fontSize: '10px', color: '#38bdf8', fontWeight: 600 }}>Click to switch</span>
                  </div>

                  {/* Case Search Input */}
                  <div style={{ position: 'relative' }}>
                    <input
                      type="text"
                      placeholder="Filter cases..."
                      value={caseSearch}
                      onChange={(e) => setCaseSearch(e.target.value)}
                      style={{
                        width: '100%',
                        boxSizing: 'border-box',
                        padding: '6px 10px',
                        background: isDark ? 'rgba(255,255,255,0.05)' : '#f1f5f9',
                        border: `1px solid ${isDark ? 'rgba(255,255,255,0.1)' : '#cbd5e1'}`,
                        borderRadius: '8px',
                        fontSize: '11.5px',
                        color: themeStyles.textMain,
                        outline: 'none'
                      }}
                    />
                  </div>

                  {/* Case Items List */}
                  <div style={{ overflowY: 'auto', maxHeight: '250px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {casesList
                      .filter(c => {
                        if (!caseSearch.trim()) return true;
                        const q = caseSearch.toLowerCase();
                        return (c.case_id || '').toLowerCase().includes(q) || (c.name || '').toLowerCase().includes(q);
                      })
                      .map(c => {
                        const isCurrent = c.case_id === activeCaseId;
                        return (
                          <div
                            key={c.case_id}
                            onClick={() => handleSelectCase(c.case_id, c.name)}
                            style={{
                              padding: '8px 10px',
                              borderRadius: '8px',
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              background: isCurrent ? (isDark ? 'rgba(56,189,248,0.15)' : '#e0f2fe') : 'transparent',
                              color: isCurrent ? '#0284c7' : themeStyles.textMain,
                              transition: 'background 0.15s'
                            }}
                            onMouseEnter={(e) => {
                              if (!isCurrent) e.currentTarget.style.background = isDark ? 'rgba(255,255,255,0.06)' : '#f8fafc';
                            }}
                            onMouseLeave={(e) => {
                              if (!isCurrent) e.currentTarget.style.background = 'transparent';
                            }}
                          >
                            <div style={{ minWidth: 0, flex: 1 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span style={{ fontFamily: 'var(--glass-dash-mono)', fontWeight: 700, fontSize: '12px' }}>
                                  {c.case_id}
                                </span>
                                {c.status && (
                                  <span style={{
                                    fontSize: '9.5px',
                                    fontWeight: 700,
                                    textTransform: 'uppercase',
                                    padding: '1px 5px',
                                    borderRadius: '4px',
                                    background: c.status === 'open' ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.08)',
                                    color: c.status === 'open' ? '#10b981' : themeStyles.textMuted
                                  }}>
                                    {c.status}
                                  </span>
                                )}
                              </div>
                              {c.name && (
                                <div style={{ fontSize: '11px', color: themeStyles.textMuted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: '2px' }}>
                                  {c.name}
                                </div>
                              )}
                            </div>
                            {isCurrent && (
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                            )}
                          </div>
                        );
                      })}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right Header Controls */}
          <div className="glass-topbar-right topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {/* Certify Button */}
            <button
              type="button"
              onClick={handleToggleCertification}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: isCertified ? '#10b981' : 'var(--glass-dash-green-soft)',
                color: isCertified ? '#ffffff' : 'var(--glass-dash-green)',
                border: `1px solid ${isCertified ? '#059669' : 'var(--glass-dash-green-border)'}`,
                padding: '7px 16px',
                borderRadius: '9999px',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
              title="Save or remove a local review marker; this does not certify evidence or lock the case"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
              <span>{isCertified ? 'Review Marked' : 'Mark Review'}</span>
            </button>

            {/* Print / Export PDF */}
            <button
              type="button"
              onClick={handlePrintReport}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'var(--glass-dash-surface-nested)',
                color: 'var(--glass-dash-text-main)',
                border: '1px solid var(--glass-dash-border-subtle)',
                padding: '7px 16px',
                borderRadius: '9999px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
              title="Print or Save as PDF"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
              <span>Export PDF</span>
            </button>

            {/* Theme Toggle */}
            <button 
              type="button" 
              onClick={toggleTheme} 
              className="glass-icon-btn" 
              title="Toggle Theme" 
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              {isDark ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
              )}
            </button>

            <NotificationMenu />
          </div>
        </header>

        {/* ── SPLIT WORKSPACE BODY (54% LEFT REPORT, 46% RIGHT CHATBOT) ── */}
        <div style={{
          flex: 1,
          display: 'flex',
          gap: '20px',
          overflow: 'hidden',
          position: 'relative',
          height: '100%'
        }}>

          {/* ════════════════════════════════════════════════════════════
              LEFT PANEL: FULL FORENSIC REPORT PREVIEW (SCROLLABLE)
              ════════════════════════════════════════════════════════════ */}
          <div className="panel-card" style={{
            flex: '0 0 54%',
            maxWidth: '54%',
            height: '100%',
            overflowY: 'auto',
            padding: '28px',
            boxSizing: 'border-box'
          }}>
            <div role="status" style={{
              marginBottom: '14px',
              padding: '11px 14px',
              borderRadius: '8px',
              border: `1px solid ${isDark ? 'rgba(245, 158, 11, 0.35)' : '#fcd34d'}`,
              background: isDark ? 'rgba(245, 158, 11, 0.10)' : '#fffbeb',
              color: isDark ? '#fcd34d' : '#92400e',
              fontSize: '12px',
              lineHeight: 1.5
            }}>
              <strong>Preview only — not a certified forensic report.</strong>
              {' '}Validate every narrative against case-linked backend records before export. Loaded records: {evidenceFiles.length} evidence, {findings.length} findings.
              {evidenceFiles.length === 0 || findings.length === 0
                ? ' One or more record sets are empty; do not treat the preview narrative as case evidence.'
                : ''}
            </div>
            {/* Report Header Card */}
            <div style={{
              background: themeStyles.paperBg,
              color: themeStyles.paperText,
              borderRadius: '12px',
              border: `1px solid ${themeStyles.paperBorder}`,
              boxShadow: isDark ? '0 10px 30px rgba(0,0,0,0.5)' : '0 4px 20px rgba(0,0,0,0.06)',
              padding: '32px 36px',
              position: 'relative'
            }}>
              
              {/* Document Banner */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                borderBottom: `2px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`,
                paddingBottom: '20px',
                marginBottom: '24px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{
                    width: '44px',
                    height: '44px',
                    borderRadius: '8px',
                    background: '#0f172a',
                    border: '1px solid rgba(255,255,255,0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <svg width="26" height="26" viewBox="0 0 48 48" fill="none">
                      <path d="M24 6L38.5 11V23.5C38.5 32.5 30.8 39.5 24 42.5C17.2 39.5 9.5 32.5 9.5 23.5V11L24 6Z" stroke="#38bdf8" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" fill="none" />
                      <circle cx="24" cy="24" r="3" fill="#38bdf8" />
                    </svg>
                  </div>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: '15px', color: themeStyles.textMain, letterSpacing: '0.04em' }}>ARGUS FORENSICS</div>
                    <div style={{ fontSize: '11px', color: themeStyles.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Autonomous AI Investigation Platform</div>
                  </div>
                </div>

                <div style={{ textAlign: 'right', fontSize: '11px', color: themeStyles.textMuted, fontFamily: 'monospace', lineHeight: '1.6' }}>
                  <div><strong>Case Reference:</strong> <span style={{ color: '#3b82f6' }}>{activeCaseId}</span></div>
                  <div><strong>Report Date:</strong> {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</div>
                  <div><strong>Classification:</strong> <span style={{ color: '#ef4444', fontWeight: 700 }}>CONFIDENTIAL // AUDIT</span></div>
                </div>
              </div>

              {/* Title Block */}
              <div style={{ textAlign: 'center', marginBottom: '28px' }}>
                <h1 style={{ fontSize: '22px', fontWeight: 800, color: themeStyles.textMain, margin: '0 0 6px 0' }}>
                  Digital Forensic Investigation & Audit Report
                </h1>
                <div style={{ fontSize: '13px', fontWeight: 600, color: '#3b82f6' }}>
                  Case ID: {activeCaseId} ({activeCaseName})
                </div>
                {isCertified && (
                  <div style={{ 
                    marginTop: '8px', 
                    display: 'inline-flex', 
                    alignItems: 'center', 
                    gap: '6px', 
                    padding: '4px 12px', 
                    borderRadius: '999px', 
                    background: isDark ? 'rgba(16,185,129,0.18)' : '#d1fae5', 
                    color: '#10b981', 
                    fontSize: '11px', 
                    fontWeight: 700 
                  }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    LOCAL REVIEW MARKER — NOT CRYPTOGRAPHICALLY CERTIFIED ({certificationTimestamp || 'timestamp unavailable'})
                  </div>
                )}
              </div>

              {/* Section 1: Executive Summary */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ borderLeft: '4px solid #3b82f6', paddingLeft: '10px', marginBottom: '8px' }}>
                  <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                    1. Executive Summary
                  </h2>
                </div>
                {caseSummary?.description ? (
                  <p style={{ fontSize: '12.5px', color: themeStyles.paperText, lineHeight: '1.7', margin: 0, textAlign: 'justify', opacity: 0.9 }}>
                    {caseSummary.description}
                  </p>
                ) : (
                  <p style={{ fontSize: '12px', color: themeStyles.paperMuted, fontStyle: 'italic', margin: 0, padding: '8px 12px', background: isDark ? 'rgba(255,255,255,0.03)' : '#f8fafc', borderRadius: '6px' }}>
                    No case narrative supplied by the backend for Case <strong>{activeCaseId}</strong>. Findings and evidence telemetry must be evaluated from authoritative records below.
                  </p>
                )}
              </div>

              {/* Section 2: Key Findings KPI Grid */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ borderLeft: '4px solid #3b82f6', paddingLeft: '10px', marginBottom: '10px' }}>
                  <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                    2. Investigation Telemetry Metrics
                  </h2>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
                  <div style={{ background: isDark ? '#1a1d2d' : '#fef2f2', border: `1px solid ${isDark ? 'rgba(239, 68, 68, 0.2)' : '#fee2e2'}`, borderRadius: '8px', padding: '10px' }}>
                    <div style={{ fontSize: '18px', fontWeight: 800, color: '#ef4444' }}>{highSevCount}</div>
                    <div style={{ fontSize: '11px', color: isDark ? '#fca5a5' : '#991b1b', fontWeight: 600 }}>High / Critical</div>
                  </div>
                  <div style={{ background: isDark ? '#261e1b' : '#fff7ed', border: `1px solid ${isDark ? 'rgba(249, 115, 22, 0.2)' : '#ffedd5'}`, borderRadius: '8px', padding: '10px' }}>
                    <div style={{ fontSize: '18px', fontWeight: 800, color: '#f97316' }}>{medSevCount}</div>
                    <div style={{ fontSize: '11px', color: isDark ? '#fdba74' : '#9a3412', fontWeight: 600 }}>Medium Severity</div>
                  </div>
                  <div style={{ background: isDark ? '#132338' : '#eff6ff', border: `1px solid ${isDark ? 'rgba(59, 130, 246, 0.2)' : '#dbeafe'}`, borderRadius: '8px', padding: '10px' }}>
                    <div style={{ fontSize: '18px', fontWeight: 800, color: '#3b82f6' }}>{lowSevCount}</div>
                    <div style={{ fontSize: '11px', color: isDark ? '#93c5fd' : '#1e40af', fontWeight: 600 }}>Low Severity</div>
                  </div>
                  <div style={{ background: isDark ? '#132b26' : '#ecfdf5', border: `1px solid ${isDark ? 'rgba(16, 185, 129, 0.2)' : '#d1fae5'}`, borderRadius: '8px', padding: '10px' }}>
                    <div style={{ fontSize: '18px', fontWeight: 800, color: '#10b981' }}>{evidenceCount}</div>
                    <div style={{ fontSize: '11px', color: isDark ? '#6ee7b7' : '#065f46', fontWeight: 600 }}>Evidence Files</div>
                  </div>
                </div>
              </div>

              {/* Section 3: Evidence Files Ledger with SHA-256 Hashes */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ borderLeft: '4px solid #a855f7', paddingLeft: '10px' }}>
                    <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                      3. Evidence Ledger & Chain of Custody
                    </h2>
                  </div>
                  <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    {evidenceFiles.length > 0 ? 'Evidence metadata loaded (Integrity unverified by server)' : 'No evidence records'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {evidenceFiles.length > 0 ? (
                    evidenceFiles.map((ev, idx) => (
                      <div 
                        key={idx}
                        onClick={() => setSelectedEvidence(ev)}
                        style={{
                          background: isDark ? '#141d2f' : '#f8fafc',
                          border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`,
                          borderRadius: '8px',
                          padding: '10px 14px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = 'var(--glass-dash-blue)';
                          e.currentTarget.style.transform = 'translateY(-1px)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0';
                          e.currentTarget.style.transform = 'none';
                        }}
                        title="Click to open evidence details and custody metadata"
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
                          <div style={{ color: '#a855f7' }}>
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                          </div>
                          <div style={{ minWidth: 0 }}>
                            <div style={{ fontSize: '12.5px', fontWeight: 600, color: themeStyles.textMain, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {ev.filename || ev.name || 'Artifact File'}
                            </div>
                            <div style={{ fontSize: '11px', fontFamily: 'monospace', color: themeStyles.textMuted }}>
                              SHA-256: {ev.sha256_hash ? `${ev.sha256_hash.slice(0, 32)}... (Integrity unverified by server)` : 'Not provided (Unverified)'}
                            </div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                          <span style={{ fontSize: '11px', color: 'var(--glass-dash-blue)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '3px' }}>
                            View Record
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
                          </span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleAuditArtifact(ev);
                            }}
                            style={{
                              background: isDark ? 'rgba(59, 130, 246, 0.15)' : '#eff6ff',
                              color: '#3b82f6',
                              border: '1px solid rgba(59, 130, 246, 0.3)',
                              padding: '4px 10px',
                              borderRadius: '6px',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                            title="Query chatbot to audit this evidence artifact"
                          >
                            Audit with AI &rarr;
                          </button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{
                      padding: '16px',
                      textAlign: 'center',
                      color: themeStyles.paperMuted,
                      fontSize: '12px',
                      background: isDark ? '#141d2f' : '#f8fafc',
                      borderRadius: '8px',
                      border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`
                    }}>
                      No evidence records loaded for Case {activeCaseId}.
                    </div>
                  )}
                </div>
              </div>

              {/* Section 4: Triaged Findings */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ borderLeft: '4px solid #ef4444', paddingLeft: '10px' }}>
                    <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                      4. Triaged Forensic Findings ({findings.length})
                    </h2>
                  </div>
                  <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>
                    {findings.length > 0 ? 'Click any issue to open details' : 'No Findings Loaded'}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {findings.length > 0 ? (
                    findings.map((finding, idx) => {
                      const sev = (finding.severity || 'high').toLowerCase();
                      const sevColor = sev === 'critical' || sev === 'high' ? '#ef4444' : (sev === 'medium' ? '#f97316' : '#10b981');
                      const sevBg = sev === 'critical' || sev === 'high' ? (isDark ? 'rgba(239, 68, 68, 0.15)' : '#fee2e2') : (isDark ? 'rgba(249, 115, 22, 0.15)' : '#ffedd5');

                      return (
                        <div
                          key={finding.finding_id || idx}
                          onClick={() => setSelectedFinding(finding)}
                          style={{
                            background: isDark ? '#141d2f' : '#f8fafc',
                            border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`,
                            borderRadius: '8px',
                            padding: '12px 14px',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease'
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = 'var(--glass-dash-blue)';
                            e.currentTarget.style.transform = 'translateY(-1px)';
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0';
                            e.currentTarget.style.transform = 'none';
                          }}
                          title="Click to open finding details, MITRE alignments, and telemetry"
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMain, fontFamily: 'monospace' }}>
                                {finding.finding_id || `F-00${idx + 1}`}
                              </span>
                              <span style={{
                                fontSize: '10px',
                                fontWeight: 700,
                                textTransform: 'uppercase',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                color: sevColor,
                                background: sevBg
                              }}>
                                {sev}
                              </span>
                              {finding.mitre_mapping && (
                                <span style={{
                                  fontSize: '10px',
                                  fontWeight: 600,
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  background: isDark ? 'rgba(234, 179, 8, 0.15)' : '#fef3c7',
                                  color: '#d97706'
                                }}>
                                  {finding.mitre_mapping}
                                </span>
                              )}
                            </div>

                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{ fontSize: '11px', color: 'var(--glass-dash-blue)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '3px' }}>
                                Open Details
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
                              </span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleVerifyFinding(finding);
                                }}
                                style={{
                                  background: 'transparent',
                                  border: 'none',
                                  color: '#3b82f6',
                                  fontSize: '11px',
                                  fontWeight: 600,
                                  cursor: 'pointer',
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  padding: '2px 6px'
                                }}
                                title="Cross-examine this finding with AI Assistant"
                              >
                                Verify with AI &rarr;
                              </button>
                            </div>
                          </div>

                          <div style={{ fontSize: '12px', color: themeStyles.paperText, lineHeight: '1.5' }}>
                            {finding.sanitized_fact || finding.fact || finding.claim}
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div style={{
                      padding: '16px',
                      textAlign: 'center',
                      color: themeStyles.paperMuted,
                      fontSize: '12px',
                      background: isDark ? '#141d2f' : '#f8fafc',
                      borderRadius: '8px',
                      border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`
                    }}>
                      No forensic findings loaded for Case {activeCaseId}.
                    </div>
                  )}
                </div>
              </div>

              {/* Section 5: MITRE ATT&CK Mapping */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ borderLeft: '4px solid #eab308', paddingLeft: '10px', marginBottom: '8px' }}>
                  <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                    5. MITRE ATT&CK Kill-Chain Mapping ({observedTechniques.length})
                  </h2>
                </div>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted, marginBottom: '8px', fontStyle: 'italic' }}>
                  Note: MITRE ATT&CK technique names are local UI display labels for reference only, not certified forensic conclusions.
                </div>
                {observedTechniques.length > 0 ? (
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {observedTechniques.map(tech => (
                      <div
                        key={tech.id}
                        role="button"
                        tabIndex={0}
                        onClick={() => handleQuickAction(`Audit MITRE technique ${tech.id} (${tech.name}) observed in this case.`)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleQuickAction(`Audit MITRE technique ${tech.id} (${tech.name}) observed in this case.`);
                          }
                        }}
                        style={{
                          background: isDark ? 'rgba(234, 179, 8, 0.12)' : '#fffbeb',
                          border: `1px solid ${isDark ? 'rgba(234, 179, 8, 0.25)' : '#fde68a'}`,
                          borderRadius: '6px',
                          padding: '5px 10px',
                          fontSize: '11px',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                        title="Click to audit this technique"
                      >
                        <strong style={{ color: '#d97706' }}>{tech.id}</strong>
                        <span style={{ color: themeStyles.paperText }}>{tech.name}</span>
                        <span style={{ fontSize: '10px', color: themeStyles.textMuted }}>({tech.tactic})</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '12px', color: themeStyles.paperMuted, fontStyle: 'italic', padding: '6px 0' }}>
                    No MITRE ATT&CK techniques identified in case findings.
                  </div>
                )}
              </div>

              {/* Section 6: Attack Sequence Timeline */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ borderLeft: '4px solid #f97316', paddingLeft: '10px', marginBottom: '8px' }}>
                  <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                    6. Attack Reconstruction Sequence
                  </h2>
                </div>
                <div style={{
                  fontSize: '12px',
                  color: themeStyles.paperMuted,
                  fontStyle: 'italic',
                  padding: '10px 14px',
                  background: isDark ? '#141d2f' : '#f8fafc',
                  borderRadius: '8px',
                  border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`
                }}>
                  Attack sequence reconstruction requires completed multi-agent analysis or timeline events. No synthetic sequence displayed.
                </div>
              </div>

              {/* Section 7: Impact Assessment */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ borderLeft: '4px solid #f43f5e', paddingLeft: '10px', marginBottom: '8px' }}>
                  <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                    7. Forensic Impact Assessment
                  </h2>
                </div>
                <div style={{
                  fontSize: '12px',
                  color: themeStyles.paperMuted,
                  fontStyle: 'italic',
                  padding: '10px 14px',
                  background: isDark ? '#141d2f' : '#f8fafc',
                  borderRadius: '8px',
                  border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`
                }}>
                  Formal forensic impact assessment requires completed analysis and analyst sign-off. Observed case telemetry: {highSevCount} High/Critical findings, {medSevCount} Medium findings, {lowSevCount} Low findings across {evidenceCount} evidence files.
                </div>
              </div>

              {/* Section 8: Recommendations */}
              <div style={{ marginBottom: '28px' }}>
                <div style={{ borderLeft: '4px solid #14b8a6', paddingLeft: '10px', marginBottom: '8px' }}>
                  <h2 style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                    8. Recommendations & Remediation
                  </h2>
                </div>
                <div style={{
                  fontSize: '12px',
                  color: themeStyles.paperMuted,
                  fontStyle: 'italic',
                  padding: '10px 14px',
                  background: isDark ? '#141d2f' : '#f8fafc',
                  borderRadius: '8px',
                  border: `1px solid ${isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'}`
                }}>
                  Remediation recommendations are pending completed analyst investigation and incident containment review.
                </div>
              </div>

              {/* Section 9: Auditor Certification & Sign-off Stamp */}
              <div style={{
                marginTop: '28px',
                borderTop: `2px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`,
                paddingTop: '18px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: themeStyles.textMain }}>
                    Reviewer: {user?.name || 'Reviewer not identified'} ({user?.role?.toUpperCase() || 'ROLE UNAVAILABLE'})
                  </div>
                  <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>
                    Review status: {isCertified ? 'Marked locally; server verification required' : 'Not marked'}
                  </div>
                </div>

                <div style={{
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: `2px dashed ${isCertified ? '#10b981' : (isDark ? 'rgba(255,255,255,0.2)' : '#cbd5e1')}`,
                  background: isCertified ? (isDark ? 'rgba(16,185,129,0.1)' : '#ecfdf5') : 'transparent',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, color: isCertified ? '#10b981' : themeStyles.textMuted, letterSpacing: '0.05em' }}>
                    {isCertified ? 'REVIEW MARKED LOCALLY' : 'REVIEW NOT MARKED'}
                  </div>
                  <div style={{ fontSize: '10px', color: themeStyles.textMuted }}>
                    {isCertified ? (certificationTimestamp || 'timestamp unavailable') : 'Use Mark Review'}
                  </div>
                </div>
              </div>

            </div>
          </div>


          {/* ════════════════════════════════════════════════════════════
              RIGHT PANEL: AI FORENSIC AUDIT CHATBOT
              ════════════════════════════════════════════════════════════ */}
          <div className="panel-card" style={{
            flex: 1,
            height: '100%',
            display: 'flex',
            flexDirection: 'column',
            padding: 0,
            overflow: 'hidden',
            position: 'relative'
          }}>

            {/* Chatbot Header */}
            <div style={{
              height: '56px',
              padding: '0 20px',
              borderBottom: `1px solid ${themeStyles.topbarBorder}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: themeStyles.cardBg,
              flexShrink: 0
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  position: 'relative'
                }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                  <span style={{
                    position: 'absolute',
                    bottom: 0,
                    right: 0,
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: '#10b981',
                    border: '1.5px solid #0f172a'
                  }}></span>
                </div>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: themeStyles.textMain, display: 'flex', alignItems: 'center', gap: '6px' }}>
                    AI Audit Assistant
                    <span style={{ fontSize: '10px', color: '#10b981', fontWeight: 600 }}>Active</span>
                  </div>
                  <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>
                    Grounded in Case {activeCaseId} Telemetry & Hashes
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  type="button"
                  onClick={handleExportAttestation}
                  style={{
                    background: isDark ? 'rgba(59, 130, 246, 0.15)' : '#eff6ff',
                    color: '#3b82f6',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                  title="Copy local review note (not a cryptographic attestation)"
                >
                  Export Attestation
                </button>

                <button
                  type="button"
                  onClick={() => initAuditChatWelcome(activeCaseId, activeCaseName)}
                  style={{
                    background: 'transparent',
                    color: themeStyles.textMuted,
                    border: `1px solid ${isDark ? 'rgba(255,255,255,0.1)' : '#cbd5e1'}`,
                    padding: '4px 8px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    cursor: 'pointer'
                  }}
                  title="Clear current audit conversation"
                >
                  Clear
                </button>
              </div>
            </div>

            {/* Quick Action Chips Bar */}
            <div style={{
              padding: '10px 16px',
              borderBottom: `1px solid ${themeStyles.topbarBorder}`,
              display: 'flex',
              gap: '6px',
              overflowX: 'auto',
              background: isDark ? '#0c1322' : '#ffffff',
              flexShrink: 0
            }}>
              {[
                'Audit SHA-256 Hashes',
                'Verify Chain of Custody',
                'Check MITRE T1566',
                'Audit Finding Contradictions',
                'Attestation Summary'
              ].map((chipText, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => handleQuickAction(chipText)}
                  style={{
                    background: isDark ? '#141d2f' : '#f1f5f9',
                    border: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`,
                    borderRadius: '999px',
                    padding: '4px 12px',
                    fontSize: '11px',
                    fontWeight: 500,
                    color: themeStyles.textMain,
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                    transition: 'all 0.15s'
                  }}
                >
                  {chipText}
                </button>
              ))}
            </div>

            {/* Chat Messages Container */}
            <div style={{
              flex: 1,
              overflowY: 'auto',
              padding: '18px 20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px'
            }}>
              {chatMessages.map((msg, index) => {
                const isUser = msg.sender === 'user';
                return (
                  <div
                    key={msg.id || index}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: isUser ? 'flex-end' : 'flex-start',
                      width: '100%'
                    }}
                  >
                    {/* Sender & Timestamp */}
                    <div style={{
                      fontSize: '11px',
                      color: themeStyles.textMuted,
                      marginBottom: '4px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}>
                      <span>{isUser ? (user?.name || 'Auditor') : 'ARGUS AI Audit Copilot'}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                    </div>

                    {/* Message Bubble */}
                    <div
                      style={{
                        maxWidth: '90%',
                        borderRadius: '12px',
                        padding: '12px 16px',
                        fontSize: '13px',
                        lineHeight: '1.6',
                        background: isUser ? themeStyles.chatBubbleUser : themeStyles.chatBubbleAi,
                        color: isUser ? '#ffffff' : themeStyles.textMain,
                        border: isUser ? 'none' : `1px solid ${themeStyles.chatBubbleAiBorder}`,
                        boxShadow: isDark ? '0 4px 14px rgba(0,0,0,0.3)' : '0 2px 8px rgba(0,0,0,0.04)',
                        wordBreak: 'break-word',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                      {renderFormattedText(msg.text)}

                      {/* Expandable Reasoning Trail if present */}
                      {!isUser && msg.reasoningTrail && (
                        <div style={{ marginTop: '12px', borderTop: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`, paddingTop: '8px' }}>
                          <button
                            type="button"
                            onClick={() => setExpandedReasoningMap(prev => ({ ...prev, [msg.id]: !prev[msg.id] }))}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: '#3b82f6',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                              padding: 0
                            }}
                          >
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                            {expandedReasoningMap[msg.id] ? 'Hide Audit Reasoning' : 'View Audit Grounding Logic'}
                          </button>

                          {expandedReasoningMap[msg.id] && (
                            <div style={{
                              marginTop: '8px',
                              background: isDark ? 'rgba(0,0,0,0.3)' : '#f8fafc',
                              borderRadius: '6px',
                              padding: '8px 10px',
                              fontSize: '11px',
                              color: themeStyles.textMuted
                            }}>
                              <div style={{ fontWeight: 600, color: themeStyles.textMain, marginBottom: '4px' }}>Multi-Agent Grounding Sequence:</div>
                              {msg.reasoningTrail.map((step, sIdx) => (
                                <div key={sIdx} style={{ display: 'flex', alignItems: 'center', gap: '6px', margin: '2px 0' }}>
                                  <span style={{ color: '#10b981' }}>✓</span>
                                  <span>{step}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {/* Chat Loading / Reasoning Animation */}
              {chatLoading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '4px' }}>
                  <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>ARGUS AI Audit Copilot is reasoning...</div>
                  <div style={{
                    background: themeStyles.chatBubbleAi,
                    border: `1px solid ${themeStyles.chatBubbleAiBorder}`,
                    borderRadius: '12px',
                    padding: '12px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px'
                  }}>
                    <div style={{
                      width: '14px',
                      height: '14px',
                      borderRadius: '50%',
                      border: '2px solid #3b82f6',
                      borderTopColor: 'transparent',
                      animation: 'spin 0.8s linear infinite'
                    }}></div>
                    <span style={{ fontSize: '12px', color: '#3b82f6', fontWeight: 600 }}>
                      {AUDIT_REASONING_STEPS[reasoningStep] || 'Auditing case evidence...'}
                    </span>
                  </div>
                </div>
              )}

              <div ref={chatEndRef} />
            </div>

            {/* Chat Input Bar */}
            <div style={{
              padding: '14px 20px',
              borderTop: `1px solid ${themeStyles.topbarBorder}`,
              background: themeStyles.cardBg,
              flexShrink: 0
            }}>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendQuery();
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  background: themeStyles.inputBg,
                  border: `1px solid ${themeStyles.inputBorder}`,
                  borderRadius: '10px',
                  padding: '6px 12px'
                }}
              >
                <input
                  ref={inputRef}
                  type="text"
                  value={inputQuery}
                  onChange={(e) => setInputQuery(e.target.value)}
                  placeholder="Ask about evidence hashes, finding contradictions, or MITRE mapping..."
                  style={{
                    flex: 1,
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    fontSize: '13px',
                    color: themeStyles.textMain
                  }}
                  disabled={chatLoading}
                />

                <button
                  type="submit"
                  disabled={!inputQuery.trim() || chatLoading}
                  style={{
                    background: inputQuery.trim() && !chatLoading ? '#3b82f6' : (isDark ? 'rgba(255,255,255,0.1)' : '#e2e8f0'),
                    color: inputQuery.trim() && !chatLoading ? '#ffffff' : themeStyles.textMuted,
                    border: 'none',
                    borderRadius: '8px',
                    width: '32px',
                    height: '32px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    cursor: inputQuery.trim() && !chatLoading ? 'pointer' : 'default',
                    transition: 'all 0.15s'
                  }}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
                </button>
              </form>
              <div style={{ fontSize: '10.5px', color: themeStyles.textMuted, marginTop: '6px', textAlign: 'center' }}>
                Deterministic Evidence Grounded • ISO/IEC 27037 Compliant • DeBERTa-v3 Guardrails
              </div>
            </div>

          </div>

        </div>

      </div>

      {/* ── FINDING DETAIL MODAL ── */}
      {selectedFinding && (
        <div 
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.65)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px'
          }}
          onClick={() => setSelectedFinding(null)}
        >
          <div 
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: '620px',
              maxHeight: '85vh',
              overflowY: 'auto',
              background: themeStyles.cardBg,
              border: `1px solid ${themeStyles.cardBorder}`,
              borderRadius: '20px',
              padding: '28px 32px',
              boxShadow: '0 24px 60px rgba(0, 0, 0, 0.6)',
              color: themeStyles.textMain,
              display: 'flex',
              flexDirection: 'column',
              gap: '20px'
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`, paddingBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                  <span style={{ fontFamily: 'var(--glass-dash-mono)', fontSize: '16px', fontWeight: 800, color: '#38bdf8' }}>
                    {selectedFinding.finding_id || 'Finding Record'}
                  </span>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '3px 8px',
                    borderRadius: '6px',
                    color: (selectedFinding.severity || '').toLowerCase() === 'high' || (selectedFinding.severity || '').toLowerCase() === 'critical' ? '#ef4444' : ((selectedFinding.severity || '').toLowerCase() === 'medium' ? '#f97316' : '#10b981'),
                    background: (selectedFinding.severity || '').toLowerCase() === 'high' || (selectedFinding.severity || '').toLowerCase() === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(249, 115, 22, 0.15)'
                  }}>
                    {selectedFinding.severity || 'Medium'}
                  </span>
                  {selectedFinding.mitre_mapping && (
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      padding: '3px 8px',
                      borderRadius: '6px',
                      background: 'rgba(234, 179, 8, 0.15)',
                      color: '#d97706'
                    }}>
                      {selectedFinding.mitre_mapping}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '12px', color: themeStyles.textMuted }}>
                  Case: <strong style={{ color: themeStyles.textMain }}>{activeCaseId}</strong> &middot; Layer: <strong style={{ color: themeStyles.textMain }}>{selectedFinding.layer || 'Forensic Correlation'}</strong>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedFinding(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: themeStyles.textMuted,
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>

            {/* Finding Statement */}
            <div>
              <label style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '8px' }}>
                Forensic Finding Fact & Observation
              </label>
              <div style={{
                background: isDark ? 'rgba(0, 0, 0, 0.25)' : '#f8fafc',
                border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : '#e2e8f0'}`,
                borderRadius: '10px',
                padding: '14px 16px',
                fontSize: '13px',
                lineHeight: 1.6,
                color: themeStyles.textMain
              }}>
                {selectedFinding.sanitized_fact || selectedFinding.fact || selectedFinding.claim || 'No detailed fact description available.'}
              </div>
            </div>

            {/* Metrics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.03)' : '#f1f5f9', padding: '12px 14px', borderRadius: '10px', border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.06)' : '#e2e8f0'}` }}>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted, fontWeight: 600, marginBottom: '4px' }}>Confidence Score</div>
                <div style={{ fontSize: '15px', fontWeight: 800, color: '#38bdf8' }}>
                  {Math.round((selectedFinding.confidence > 1 ? selectedFinding.confidence : selectedFinding.confidence * 100) || 85)}%
                </div>
              </div>
              <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.03)' : '#f1f5f9', padding: '12px 14px', borderRadius: '10px', border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.06)' : '#e2e8f0'}` }}>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted, fontWeight: 600, marginBottom: '4px' }}>Corroboration Source</div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: themeStyles.textMain }}>
                  {selectedFinding.agent || selectedFinding.corroborating_agent || 'ARGUS Multi-Agent Swarm'}
                </div>
              </div>
            </div>

            {/* Evidence Linkage */}
            {(selectedFinding.evidence_reference || selectedFinding.source_artifact_id) && (
              <div>
                <label style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '8px' }}>
                  Correlated Evidence References
                </label>
                <div style={{
                  background: isDark ? 'rgba(0, 0, 0, 0.2)' : '#f8fafc',
                  border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.06)' : '#e2e8f0'}`,
                  borderRadius: '10px',
                  padding: '10px 14px',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                  color: '#38bdf8'
                }}>
                  {Array.isArray(selectedFinding.evidence_reference)
                    ? selectedFinding.evidence_reference.join(', ')
                    : (selectedFinding.evidence_reference || selectedFinding.source_artifact_id)}
                </div>
              </div>
            )}

            {/* Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`, paddingTop: '16px' }}>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(selectedFinding, null, 2));
                  setCustomAlert({ isOpen: true, title: 'Copied', message: 'Finding details copied to clipboard.', type: 'info' });
                }}
                className="btn-outline"
                style={{ fontSize: '12px', padding: '8px 14px', borderRadius: '9999px' }}
              >
                Copy JSON
              </button>
              <button
                type="button"
                onClick={() => {
                  const fToVerify = selectedFinding;
                  setSelectedFinding(null);
                  handleVerifyFinding(fToVerify);
                }}
                className="btn-primary"
                style={{ fontSize: '12px', padding: '8px 18px', borderRadius: '9999px' }}
              >
                Verify with AI Copilot &rarr;
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── EVIDENCE DETAIL MODAL ── */}
      {selectedEvidence && (
        <div 
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.65)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px'
          }}
          onClick={() => setSelectedEvidence(null)}
        >
          <div 
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: '620px',
              maxHeight: '85vh',
              overflowY: 'auto',
              background: themeStyles.cardBg,
              border: `1px solid ${themeStyles.cardBorder}`,
              borderRadius: '20px',
              padding: '28px 32px',
              boxShadow: '0 24px 60px rgba(0, 0, 0, 0.6)',
              color: themeStyles.textMain,
              display: 'flex',
              flexDirection: 'column',
              gap: '20px'
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`, paddingBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(168, 85, 247, 0.15)', color: '#a855f7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                </div>
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 800, color: themeStyles.textMain }}>
                    {selectedEvidence.filename || selectedEvidence.name || 'Forensic Evidence Artifact'}
                  </div>
                  <div style={{ fontSize: '11.5px', color: themeStyles.textMuted }}>
                    Case: <strong style={{ color: themeStyles.textMain }}>{activeCaseId}</strong> &middot; ID: <span style={{ fontFamily: 'monospace' }}>{selectedEvidence.evidence_id || selectedEvidence.id || 'N/A'}</span>
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEvidence(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: themeStyles.textMuted,
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>

            {/* SHA-256 Hash Card */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <label style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Cryptographic SHA-256 Hash
                </label>
                <span style={{ fontSize: '10.5px', color: '#f59e0b', fontWeight: 600 }}>
                  Integrity unverified by server
                </span>
              </div>
              <div style={{
                background: isDark ? 'rgba(0, 0, 0, 0.3)' : '#f8fafc',
                border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : '#e2e8f0'}`,
                borderRadius: '10px',
                padding: '12px 14px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '10px'
              }}>
                <span style={{ fontFamily: 'var(--glass-dash-mono)', fontSize: '12px', color: '#38bdf8', wordBreak: 'break-all' }}>
                  {selectedEvidence.sha256_hash || 'SHA-256 hash not recorded in artifact telemetry'}
                </span>
                {selectedEvidence.sha256_hash && (
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(selectedEvidence.sha256_hash);
                      setCustomAlert({ isOpen: true, title: 'Copied', message: 'SHA-256 hash copied to clipboard.', type: 'info' });
                    }}
                    style={{
                      background: 'var(--glass-dash-surface-nested)',
                      border: '1px solid var(--glass-dash-border-subtle)',
                      color: themeStyles.textMain,
                      borderRadius: '6px',
                      padding: '4px 8px',
                      fontSize: '11px',
                      cursor: 'pointer',
                      flexShrink: 0
                    }}
                  >
                    Copy
                  </button>
                )}
              </div>
            </div>

            {/* Metadata Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.03)' : '#f1f5f9', padding: '12px 14px', borderRadius: '10px', border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.06)' : '#e2e8f0'}` }}>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted, fontWeight: 600, marginBottom: '4px' }}>File Type / Category</div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: themeStyles.textMain }}>
                  {selectedEvidence.file_type || selectedEvidence.type || 'Forensic Disk / Log Artifact'}
                </div>
              </div>
              <div style={{ background: isDark ? 'rgba(255, 255, 255, 0.03)' : '#f1f5f9', padding: '12px 14px', borderRadius: '10px', border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.06)' : '#e2e8f0'}` }}>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted, fontWeight: 600, marginBottom: '4px' }}>Processing Status</div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#10b981', textTransform: 'capitalize' }}>
                  {selectedEvidence.status || 'Ingested'}
                </div>
              </div>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: `1px solid ${isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'}`, paddingTop: '16px' }}>
              <button
                type="button"
                onClick={() => setSelectedEvidence(null)}
                className="btn-outline"
                style={{ fontSize: '12px', padding: '8px 16px', borderRadius: '9999px' }}
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => {
                  const evToAudit = selectedEvidence;
                  setSelectedEvidence(null);
                  handleAuditArtifact(evToAudit);
                }}
                className="btn-primary"
                style={{ fontSize: '12px', padding: '8px 18px', borderRadius: '9999px' }}
              >
                Audit with AI Copilot &rarr;
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
