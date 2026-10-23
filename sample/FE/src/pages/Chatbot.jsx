import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { 
  queryCase, 
  fetchCases, 
  fetchFindings, 
  fetchEvidenceForCase, 
  createCaseNote,
  createReviewNote, 
  API_BASE_URL, 
  DEFAULT_TENANT_ID 
} from '../js/api';
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

const buildUnavailableResponse = (caseId, reason = 'The case-query service did not return a usable response.') => `## Grounded response unavailable

**Case:** ${caseId || 'Not selected'}

${reason}

ARGUS has not generated a forensic conclusion for this request. Check the case selection, API connection, and backend logs, then retry. Any claim about evidence, hashes, malware behavior, MITRE techniques, or chain of custody must come from retrieved case records—not a UI fallback.`; 

export default function Chatbot() {
  const navigate = useNavigate();
  
  // Theme state: robust dark and light mode synchronization
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

  let currentUser = null;
  try {
    currentUser = JSON.parse(localStorage.getItem('argus_user'));
  } catch (e) {}

  // Active Case state
  const [activeCaseId, setActiveCaseId] = useState(localStorage.getItem('active_case_id') || 'CASE-2026-001');
  const [activeCaseName, setActiveCaseName] = useState(localStorage.getItem('active_case_name') || 'CASE-2026-001');
  // Side Drawer state for Evidence & Artifacts Inspector
  const [drawerOpen, setDrawerOpen] = useState(true);

  // Case context metadata
  const [caseFindings, setCaseFindings] = useState([]);
  const [caseEvidence, setCaseEvidence] = useState([]);
  const [contextLoading, setContextLoading] = useState(false);

  // Quick notes pad inside drawer
  const [quickNoteText, setQuickNoteText] = useState('');
  const [quickNotesList, setQuickNotesList] = useState([]);

  // Toast / feedback message
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3200);
  };

  // Chat messages
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      sender: 'assistant',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      text: `Hello Analyst! I am your **ARGUS AI Forensic Assistant**. I answer using case records returned by the ARGUS backend and show uncertainty when the available records do not support a conclusion.

### Capabilities:
- **Evidence Cross-Correlation**: Ask questions across disk, memory, network, and registry logs.
- **MITRE ATT&CK Mapping**: Map adversary behavior to tactics, techniques, and procedures.
- **Threat Actor Profiling & IOC Extraction**: Isolate indicators, command lines, and C2 beacons.
- **Evidence-grounded explanations**: Explain retrieved findings and cite their record identifiers.
- **Report drafting**: Prepare text for analyst review; this chat does not approve or certify a case.

Select a quick prompt below or type your forensic query to begin querying Case **${activeCaseId}**.`
    }
  ]);

  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [reasoningStep, setReasoningStep] = useState(0);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const REASONING_STEPS = [
    'Ingesting case artifacts & FIR findings...',
    'Screening query through DeBERTa-v3 Injection Gate...',
    'Correlating Neo4j Graph & MITRE kill-chain...',
    'Synthesizing analytical forensic insight with Qwen3-8B...'
  ];

  // Auto-scroll on new message or during reasoning
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading, reasoningStep]);

  // Load active case details
  useEffect(() => {
    async function loadCases() {
      try {
        const res = await fetchCases();
        const list = res.data || [];
        if (list.length > 0) {
          const stored = localStorage.getItem('active_case_id');
          const matched = list.find(c => c.case_id === stored) || list[0];
          setActiveCaseId(matched.case_id);
          setActiveCaseName(matched.name || matched.case_id);
        }
      } catch (err) {
        console.error('Failed to load cases:', err);
      }
    }
    loadCases();
  }, []);

  // Load case context (findings & evidence) whenever activeCaseId changes
  useEffect(() => {
    if (!activeCaseId) return;
    async function loadContext() {
      setContextLoading(true);
      try {
        const [findingsRes, evidenceRes] = await Promise.allSettled([
          fetchFindings(activeCaseId),
          fetchEvidenceForCase(activeCaseId)
        ]);

        if (findingsRes.status === 'fulfilled' && findingsRes.value) {
          const fList = Array.isArray(findingsRes.value)
            ? findingsRes.value
            : (findingsRes.value.data || []);
          setCaseFindings(fList);
        } else {
          setCaseFindings([]);
        }

        if (evidenceRes.status === 'fulfilled' && evidenceRes.value) {
          const eList = Array.isArray(evidenceRes.value)
            ? evidenceRes.value
            : (evidenceRes.value.data || []);
          setCaseEvidence(eList);
        } else {
          setCaseEvidence([]);
        }

        // Load saved quick notes for this case
        const storedNotes = JSON.parse(localStorage.getItem(`quick_notes_${activeCaseId}`) || '[]');
        setQuickNotesList(storedNotes);
      } catch (e) {
        console.error('Error fetching case context:', e);
      } finally {
        setContextLoading(false);
      }
    }
    loadContext();
  }, [activeCaseId]);

  // Compute dynamic observed MITRE techniques from actual case findings
  const observedTechniques = useMemo(() => {
    const techMap = new Map();
    (caseFindings || []).forEach(f => {
      const rawMapping = f.mitre_mapping || f.mitre_technique || (f.sanitized_context && f.sanitized_context.mitre_mapping);
      if (rawMapping) {
        const match = rawMapping.match(/T\d{4}(?:\.\d{3})?/i);
        const techId = match ? match[0].toUpperCase() : rawMapping;
        const count = techMap.get(techId) || 0;
        techMap.set(techId, count + 1);
      }
    });

    if (techMap.size > 0) {
      return Array.from(techMap.entries()).map(([id, count]) => ({
        id,
        name: MITRE_TECHNIQUE_NAMES[id] || 'Adversary Technique',
        count
      }));
    }

    // Never display inferred techniques when no finding actually maps to one.
    return [];
  }, [caseFindings]);

  // Submit Query
  const handleSendQuery = async (queryTextOverride = null) => {
    const rawQuery = (queryTextOverride || inputQuery).trim();
    if (!rawQuery || loading) return;

    if (!activeCaseId) {
      setCustomAlert({
        isOpen: true,
        title: 'No Active Case',
        message: 'Please select an active investigation case before querying the Assistant.',
        type: 'warning'
      });
      return;
    }

    const userMessage = {
      id: Date.now().toString(),
      sender: 'user',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      text: rawQuery
    };

    setMessages(prev => [...prev, userMessage]);
    setInputQuery('');
    setLoading(true);
    setReasoningStep(0);

    const stepInterval = setInterval(() => {
      setReasoningStep(prev => (prev + 1) % REASONING_STEPS.length);
    }, 1500);

    try {
      const res = await queryCase(activeCaseId, rawQuery);
      clearInterval(stepInterval);

      let replyText = res?.response;
      if (!replyText || replyText.includes('[SYSTEM NOTICE: Local Ollama LLM service is offline') || replyText.includes('No evidence findings recorded')) {
        replyText = buildUnavailableResponse(activeCaseId, 'No grounded answer was returned by the backend for this query.');
      }

      const assistantMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: replyText,
        injection_flagged: res.injection_flagged,
        injection_score: res.injection_score
      };
      setMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      clearInterval(stepInterval);
      console.error('Error querying assistant:', err);

      const fallbackResponse = buildUnavailableResponse(activeCaseId, 'The backend query failed. No fallback forensic narrative was generated.');

      const assistantMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: fallbackResponse,
        injection_flagged: false,
        injection_score: 0.0,
        isOfflineFallback: true
      };
      setMessages(prev => [...prev, assistantMessage]);
    } finally {
      clearInterval(stepInterval);
      setLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  // Check for pre-filled query from Timeline or external navigation
  useEffect(() => {
    const prefill = sessionStorage.getItem('argus_chatbot_prefill');
    if (prefill) {
      sessionStorage.removeItem('argus_chatbot_prefill');
      setInputQuery(prefill);
      setTimeout(() => {
        handleSendQuery(prefill);
      }, 400);
    }
  }, [activeCaseId]);

  // Copy message to clipboard
  const handleCopyText = (text) => {
    navigator.clipboard.writeText(text);
    showToast('Copied to clipboard!');
  };

  // Save to Case Notes
  const handleSaveToNotes = async (text) => {
    if (!activeCaseId) {
      showToast('Error: No active case selected');
      return;
    }

    let noteTitle = `AI Forensic Insight (${new Date().toLocaleDateString()})`;
    let noteContent = text;

    try {
      if (typeof text === 'string' && text.trim().startsWith('{') && text.trim().endsWith('}')) {
        const parsed = JSON.parse(text.trim());
        noteTitle = `AI Insight: ${parsed.claims?.[0]?.summary?.slice(0, 45) || 'Verified Observation'}`;
        noteContent = `[EXECUTIVE SUMMARY]\n${parsed.executive_summary || ''}\n\n` +
          (parsed.claims && Array.isArray(parsed.claims) ? `[CLAIMS]\n` + parsed.claims.map(c => `- ${c.summary || c.claim} (Severity: ${c.severity || 'N/A'}, Citations: ${(c.cited_evidence_ids || []).join(', ')})`).join('\n') + '\n\n' : '') +
          (parsed.attack_timeline && Array.isArray(parsed.attack_timeline) ? `[TIMELINE]\n` + parsed.attack_timeline.map(t => `- ${t.stage || 'Stage'}: ${t.summary} (${t.timestamp || ''})`).join('\n') : '');
      }
    } catch (e) {}

    const notePayload = {
      title: noteTitle,
      content: noteContent,
      type: 'finding',
      priority: 'HIGH',
      related_evidence_id: null,
      related_finding_id: null
    };

    // 1. Save to backend /cases/{caseId}/notes
    try {
      await createCaseNote(activeCaseId, notePayload);
      showToast('Saved to Case Notes!');
    } catch (err) {
      console.warn('Backend note save failed, updating local fallback cache:', err);
      showToast('Saved to Case Notes (offline cache)!');
    }

    // 2. Always sync with localStorage so CaseNotes.jsx instantly displays the note
    try {
      const existing = JSON.parse(localStorage.getItem(`case_notes_${activeCaseId}`) || '[]');
      existing.unshift({
        noteId: `NOTE-${Date.now()}`,
        title: noteTitle,
        content: noteContent,
        type: 'finding',
        priority: 'HIGH',
        createdBy: currentUser?.name || 'Analyst',
        createdAt: new Date().toISOString()
      });
      localStorage.setItem(`case_notes_${activeCaseId}`, JSON.stringify(existing));
    } catch (e) {}

    // 3. Update scratchpad drawer
    const quickNote = {
      id: Date.now().toString(),
      text: noteTitle,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setQuickNotesList(prev => [quickNote, ...prev]);
  };

  // Add to Report
  const handleAddToReport = (text) => {
    let cleanText = text;
    try {
      if (typeof text === 'string' && text.trim().startsWith('{') && text.trim().endsWith('}')) {
        const parsed = JSON.parse(text.trim());
        cleanText = `${parsed.executive_summary || ''}\n\n` +
          (parsed.claims && Array.isArray(parsed.claims) ? `Key Claims:\n` + parsed.claims.map(c => `• ${c.summary || c.claim}`).join('\n') : '');
      }
    } catch (e) {}

    localStorage.setItem('argus_report_insight', cleanText);
    showToast('Redirecting to Report Builder...');
    setTimeout(() => {
      navigate('/report');
    }, 300);
  };

  // Add quick note in drawer
  const handleAddQuickNote = (e) => {
    e.preventDefault();
    if (!quickNoteText.trim()) return;
    const newNote = {
      id: Date.now().toString(),
      text: quickNoteText.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    const updated = [newNote, ...quickNotesList];
    setQuickNotesList(updated);
    localStorage.setItem(`quick_notes_${activeCaseId}`, JSON.stringify(updated));
    setQuickNoteText('');
    showToast('Quick note recorded');
  };

  // Clear conversation
  const handleClearChat = () => {
    setMessages([
      {
        id: 'welcome',
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        text: `Conversation cleared. Ready for new queries regarding **Case ${activeCaseId}**.`
      }
    ]);
    showToast('Conversation cleared');
  };

  // Export conversation
  const handleExportChat = () => {
    const chatLog = messages.map(m => `[${m.timestamp}] ${m.sender.toUpperCase()}:\n${m.text}\n\n`).join('---\n\n');
    const blob = new Blob([chatLog], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ARGUS_Investigation_Chat_${activeCaseId}_${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Chat log exported!');
  };

  // Suggested prompt pills
  const SUGGESTED_PROMPTS = [
    { label: '🔍 Summarize Findings', query: 'Provide an executive summary of all critical and high-severity findings for this case.' },
    { label: '🛡️ MITRE ATT&CK Mapping', query: 'Map all observed attacker behaviors, persistence mechanisms, and evasion techniques to MITRE ATT&CK IDs.' },
    { label: '⚠️ High-Risk IOCs', query: 'List all extracted Indicators of Compromise (hashes, suspicious IPs, domains, and registry keys).' },
    { label: '⏱️ Attack Timeline', query: 'Reconstruct a chronological timeline of initial compromise, lateral movement, and data staging.' },
    { label: '🧬 Process Execution Tree', query: 'Analyze suspicious process spawning hierarchy and parent-child relationships found in telemetry.' },
    { label: '📋 Containment Steps', query: 'What immediate tactical containment and eradication actions are recommended for this incident?' }
  ];

  // Markdown & JSON Card Parser
  const renderFormattedText = (rawText) => {
    if (!rawText) return null;

    // Detect and unpack structured JSON forensic reasoning output
    if (typeof rawText === 'string' && rawText.trim().startsWith('{') && rawText.trim().endsWith('}')) {
      try {
        const data = JSON.parse(rawText.trim());
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {data.executive_summary && (
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: isDark ? '#60a5fa' : '#2563eb', textTransform: 'uppercase', marginBottom: '4px', letterSpacing: '0.5px' }}>
                  Executive Summary
                </div>
                <div style={{ lineHeight: '1.6', fontSize: '13.5px' }}>{data.executive_summary}</div>
              </div>
            )}

            {data.findings_summary && !data.executive_summary && (
              <div style={{ lineHeight: '1.6', fontSize: '13.5px' }}>{data.findings_summary}</div>
            )}

            {data.claims && Array.isArray(data.claims) && data.claims.length > 0 && (
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#10b981', textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '0.5px' }}>
                  Claims Returned by Backend
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {data.claims.map((c, cIdx) => (
                    <div key={cIdx} style={{
                      background: isDark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)',
                      padding: '10px 14px',
                      borderRadius: '8px',
                      borderLeft: '3px solid #10b981',
                      border: isDark ? '1px solid #1e293b' : '1px solid #e2e8f0',
                      borderLeftWidth: '3px'
                    }}>
                      <div style={{ fontWeight: 600, fontSize: '13px' }}>{c.summary || c.claim}</div>
                      <div style={{ display: 'flex', gap: '10px', marginTop: '6px', flexWrap: 'wrap', fontSize: '11px', alignItems: 'center' }}>
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
                        {c.mitre_techniques && (
                          <span style={{
                            background: isDark ? 'rgba(59, 130, 246, 0.2)' : 'rgba(59, 130, 246, 0.1)',
                            color: isDark ? '#93c5fd' : '#2563eb',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            fontWeight: 600
                          }}>
                            MITRE: {c.mitre_techniques.join(', ')}
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

            {data.attack_timeline && Array.isArray(data.attack_timeline) && data.attack_timeline.length > 0 && (
              <div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '0.5px' }}>
                  Observed Attack Timeline
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {data.attack_timeline.map((item, tIdx) => (
                    <div key={tIdx} style={{ display: 'flex', gap: '10px', fontSize: '12px', alignItems: 'baseline' }}>
                      <span style={{ color: '#f59e0b', fontWeight: 700 }}>•</span>
                      <strong style={{ color: themeStyles.textMain }}>{item.stage || 'Event'}:</strong>
                      <span>{item.summary}</span>
                      {item.timestamp && <span style={{ color: themeStyles.textMuted, fontSize: '11px' }}>({item.timestamp})</span>}
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
                borderTop: `1px solid ${isDark ? '#1e293b' : '#e2e8f0'}`,
                paddingTop: '8px'
              }}>
                <span style={{ color: themeStyles.textMuted }}>Overall Forensic Confidence:</span>
                <span style={{ fontWeight: 700, color: '#38bdf8' }}>{(data.overall_confidence * 100).toFixed(0)}%</span>
              </div>
            )}
          </div>
        );
      } catch (e) {
        // fallback to standard markdown parsing
      }
    }

    // Split text by code blocks ```
    const parts = rawText.split(/(```[\s\S]*?```)/g);

    return parts.map((part, idx) => {
      if (part.startsWith('```') && part.endsWith('```')) {
        const codeLines = part.slice(3, -3).trim();
        const firstLineBreak = codeLines.indexOf('\n');
        const lang = firstLineBreak > 0 ? codeLines.slice(0, firstLineBreak).trim() : '';
        const code = firstLineBreak > 0 ? codeLines.slice(firstLineBreak + 1) : codeLines;

        return (
          <div key={idx} style={{
            position: 'relative',
            margin: '12px 0',
            background: isDark ? '#090d16' : '#1e293b',
            color: '#e2e8f0',
            borderRadius: '8px',
            overflow: 'hidden',
            fontFamily: 'Consolas, Monaco, monospace',
            fontSize: '12.5px',
            border: isDark ? '1px solid #1e293b' : '1px solid #334155'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '6px 14px',
              background: 'rgba(0,0,0,0.3)',
              borderBottom: '1px solid rgba(255,255,255,0.08)',
              fontSize: '11px',
              color: '#94a3b8',
              fontWeight: 600
            }}>
              <span>{lang || 'COMMAND / LOG'}</span>
              <button
                type="button"
                onClick={() => handleCopyText(code)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#38bdf8',
                  cursor: 'pointer',
                  fontSize: '11px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                Copy
              </button>
            </div>
            <pre style={{ margin: 0, padding: '14px', overflowX: 'auto', lineHeight: '1.5' }}>
              <code>{code}</code>
            </pre>
          </div>
        );
      }

      // Format markdown paragraphs, bold text, headers, and bullet points
      const lines = part.split('\n');
      return (
        <span key={idx}>
          {lines.map((line, lIdx) => {
            if (line.startsWith('### ')) {
              return (
                <h4 key={lIdx} style={{ margin: '14px 0 6px 0', fontSize: '15px', fontWeight: 700, color: isDark ? '#60a5fa' : '#2563eb' }}>
                  {line.replace('### ', '')}
                </h4>
              );
            }
            if (line.startsWith('## ')) {
              return (
                <h3 key={lIdx} style={{ margin: '16px 0 8px 0', fontSize: '16px', fontWeight: 800, color: isDark ? '#93c5fd' : '#1d4ed8' }}>
                  {line.replace('## ', '')}
                </h3>
              );
            }
            if (line.startsWith('- ') || line.startsWith('* ')) {
              const content = line.slice(2);
              return (
                <div key={lIdx} style={{ display: 'flex', gap: '8px', margin: '4px 0', paddingLeft: '8px' }}>
                  <span style={{ color: '#3b82f6', fontWeight: 'bold' }}>•</span>
                  <span>{parseInlineMarkdown(content)}</span>
                </div>
              );
            }
            if (/^\d+\.\s/.test(line)) {
              return (
                <div key={lIdx} style={{ display: 'flex', gap: '8px', margin: '4px 0', paddingLeft: '8px' }}>
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
    });
  };

  const parseInlineMarkdown = (text) => {
    if (!text) return null;
    const parts = text.split(/(\*\*.*?\*\*)/g);
    return parts.map((p, i) => {
      if (p.startsWith('**') && p.endsWith('**')) {
        return <strong key={i} style={{ color: isDark ? '#ffffff' : '#0f172a' }}>{p.slice(2, -2)}</strong>;
      }
      return p;
    });
  };

  // Color tokens
  const themeStyles = isDark ? {
    bg: '#0b0f19',
    cardBg: '#111827',
    topbarBg: '#0f172a',
    topbarBorder: '#1e293b',
    border: '#1e293b',
    borderLight: '#334155',
    textMain: '#f8fafc',
    textMuted: '#94a3b8',
    inputBg: '#0b0f19',
    cardSubtle: '#1e293b',
    assistantBubbleBg: '#111827',
    assistantBubbleBorder: '#1e293b',
    userBubbleBg: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
    userBubbleText: '#ffffff',
    drawerBg: '#0d1322'
  } : {
    bg: '#f8fafc',
    cardBg: '#ffffff',
    topbarBg: '#ffffff',
    topbarBorder: '#e2e8f0',
    border: '#e2e8f0',
    borderLight: '#cbd5e1',
    textMain: '#0f172a',
    textMuted: '#64748b',
    inputBg: '#f8fafc',
    cardSubtle: '#f1f5f9',
    assistantBubbleBg: '#ffffff',
    assistantBubbleBorder: '#e2e8f0',
    userBubbleBg: 'linear-gradient(135deg, #3b82f6, #2563eb)',
    userBubbleText: '#ffffff',
    drawerBg: '#f1f5f9'
  };

  return (
    <div id="app-shell" style={{ background: themeStyles.bg, minHeight: '100vh', display: 'flex' }}>
      <AlertModal 
        isOpen={customAlert.isOpen} 
        title={customAlert.title} 
        message={customAlert.message} 
        type={customAlert.type} 
        onClose={() => setCustomAlert(prev => ({ ...prev, isOpen: false }))} 
      />

      {/* Floating Toast Notification */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          top: '24px',
          right: '32px',
          zIndex: 9999,
          background: '#10b981',
          color: '#ffffff',
          padding: '10px 18px',
          borderRadius: '8px',
          fontSize: '13px',
          fontWeight: 600,
          boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          animation: 'fadeIn 0.2s ease-out'
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          {toastMessage}
        </div>
      )}

      {/* Main Navigation Sidebar */}
      <Sidebar active="chatbot" />

      {/* Main Workspace */}
      <div style={{
        flex: 1,
        display: 'flex',
        height: '100vh',
        overflow: 'hidden',
        position: 'relative'
      }}>
        {/* CENTER CHAT COLUMN */}
        <main className="main-content" style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          height: '100vh',
          overflow: 'hidden',
          background: themeStyles.bg
        }}>
          {/* TOPBAR */}
          <header style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '14px 28px',
            borderBottom: `1px solid ${themeStyles.topbarBorder}`,
            background: themeStyles.topbarBg,
            position: 'sticky',
            top: 0,
            zIndex: 40,
            transition: 'background-color 0.2s, border-color 0.2s'
          }}>
            {/* Header Title & Case Info */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '34px',
                height: '34px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: '0 4px 12px rgba(59, 130, 246, 0.25)'
              }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
              </div>
              <div>
                <div style={{ fontSize: '15px', fontWeight: 700, color: themeStyles.textMain, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>AI Investigation Assistant</span>
                  {activeCaseId && (
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      color: isDark ? '#93c5fd' : '#2563eb',
                      background: isDark ? 'rgba(59, 130, 246, 0.15)' : 'rgba(59, 130, 246, 0.1)',
                      border: '1px solid rgba(59, 130, 246, 0.3)',
                      padding: '2px 8px',
                      borderRadius: '12px'
                    }}>
                      Case: {activeCaseId}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>
                  Autonomous multi-agent forensic reasoning & evidence correlation
                </div>
              </div>
            </div>

            {/* Topbar Controls */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              {/* Drawer Toggle */}
              <button
                type="button"
                onClick={() => setDrawerOpen(!drawerOpen)}
                title="Toggle Case Artifacts Drawer"
                style={{
                  background: drawerOpen ? (isDark ? 'rgba(59,130,246,0.2)' : 'rgba(59,130,246,0.1)') : 'transparent',
                  border: `1px solid ${drawerOpen ? '#3b82f6' : themeStyles.border}`,
                  color: drawerOpen ? (isDark ? '#60a5fa' : '#2563eb') : themeStyles.textMuted,
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                  <line x1="15" y1="3" x2="15" y2="21"></line>
                </svg>
                {drawerOpen ? 'Hide Artifacts' : 'Case Artifacts'}
              </button>

              {/* Theme Toggle */}
              <button
                type="button"
                onClick={toggleTheme}
                title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
                style={{
                  background: isDark ? '#1e293b' : '#f1f5f9',
                  border: `1px solid ${themeStyles.border}`,
                  borderRadius: '8px',
                  width: '36px',
                  height: '36px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  cursor: 'pointer',
                  color: isDark ? '#f59e0b' : '#64748b'
                }}
              >
                {isDark ? (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="5"></circle>
                    <line x1="12" y1="1" x2="12" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="23"></line>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                    <line x1="1" y1="12" x2="3" y2="12"></line>
                    <line x1="21" y1="12" x2="23" y2="12"></line>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                  </svg>
                ) : (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                  </svg>
                )}
              </button>

              {/* Clear */}
              <button
                type="button"
                onClick={handleClearChat}
                title="Clear Conversation"
                style={{
                  background: 'transparent',
                  border: `1px solid ${themeStyles.border}`,
                  color: themeStyles.textMuted,
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
                Clear
              </button>

              {/* Export */}
              <button
                type="button"
                onClick={handleExportChat}
                title="Export Conversation Log"
                style={{
                  background: isDark ? 'rgba(59, 130, 246, 0.15)' : 'rgba(59, 130, 246, 0.1)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  color: isDark ? '#60a5fa' : '#2563eb',
                  padding: '6px 12px',
                  borderRadius: '8px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="7 10 12 15 17 10"></polyline>
                  <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
                Export
              </button>

              <NotificationMenu />
            </div>
          </header>

          {/* Evidence context strip: counts reflect records returned by the API, not inferred coverage. */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
            padding: '10px 28px',
            background: themeStyles.cardBg,
            borderBottom: `1px solid ${themeStyles.topbarBorder}`,
            fontSize: '11px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: themeStyles.textMuted }}>
              <span style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: contextLoading ? '#f59e0b' : '#10b981',
                display: 'inline-block'
              }} />
              <span>{contextLoading ? 'Loading case records…' : 'Case context loaded'}</span>
              <span style={{ color: themeStyles.borderLight }}>•</span>
              <span>{caseFindings.length} finding record{caseFindings.length === 1 ? '' : 's'}</span>
              <span style={{ color: themeStyles.borderLight }}>•</span>
              <span>{caseEvidence.length} evidence record{caseEvidence.length === 1 ? '' : 's'}</span>
            </div>
            <div style={{
              color: themeStyles.textMuted,
              background: isDark ? 'rgba(245, 158, 11, 0.10)' : '#fffbeb',
              border: `1px solid ${isDark ? 'rgba(245, 158, 11, 0.25)' : '#fde68a'}`,
              padding: '4px 9px',
              borderRadius: '6px'
            }}>
              Evidence-grounded · No unsupported fallback claims
            </div>
          </div>

          {/* CHAT MESSAGES SCROLLER */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            padding: '24px 28px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px'
          }}>
            {messages.map((msg) => {
              if (msg.sender === 'system') {
                return (
                  <div key={msg.id} style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}>
                    <div style={{
                      background: isDark ? 'rgba(51, 65, 85, 0.5)' : '#e2e8f0',
                      color: themeStyles.textMuted,
                      fontSize: '12px',
                      padding: '4px 14px',
                      borderRadius: '20px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}>
                      <span>ℹ️</span>
                      <span>{renderFormattedText(msg.text)}</span>
                    </div>
                  </div>
                );
              }

              const isUser = msg.sender === 'user';

              return (
                <div
                  key={msg.id}
                  style={{
                    display: 'flex',
                    gap: '12px',
                    justifyContent: isUser ? 'flex-end' : 'flex-start',
                    alignItems: 'flex-start'
                  }}
                >
                  {/* Assistant Avatar */}
                  {!isUser && (
                    <div style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '10px',
                      background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: '#ffffff',
                      fontWeight: 700,
                      fontSize: '14px',
                      flexShrink: 0,
                      boxShadow: '0 4px 12px rgba(59, 130, 246, 0.3)'
                    }}>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 2a10 10 0 0 1 10 10c0 5.523-4.477 10-10 10S2 17.523 2 12 6.477 2 12 2z"></path>
                        <path d="M12 6v6l4 2"></path>
                      </svg>
                    </div>
                  )}

                  {/* Message Bubble Container */}
                  <div style={{
                    maxWidth: isUser ? '75%' : '85%',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: isUser ? 'flex-end' : 'flex-start'
                  }}>
                    {/* Header */}
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      marginBottom: '6px',
                      fontSize: '11px',
                      color: themeStyles.textMuted
                    }}>
                      <span style={{ fontWeight: 700, color: isUser ? (isDark ? '#93c5fd' : '#2563eb') : (isDark ? '#c084fc' : '#7c3aed') }}>
                        {isUser ? (currentUser?.name || 'Analyst') : 'ARGUS AI Forensic Engine'}
                      </span>
                      <span>{msg.timestamp}</span>
                      {msg.isOfflineFallback && (
                        <span style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', padding: '1px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 600 }}>
                          Local Engine
                        </span>
                      )}
                    </div>

                    {/* Security Passthrough Warning */}
                    {msg.injection_flagged && (
                      <div style={{
                        background: 'rgba(249, 115, 22, 0.15)',
                        border: '1px solid #f97316',
                        padding: '8px 12px',
                        borderRadius: '8px',
                        fontSize: '11px',
                        fontWeight: 600,
                        color: '#f97316',
                        marginBottom: '8px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <span>⚠️</span>
                        <span>INJECTION GATE: Query context evaluated with risk score {msg.injection_score}. Neutralized & executed in read-only sandbox.</span>
                      </div>
                    )}

                    {/* Bubble Content */}
                    <div style={{
                      padding: '16px 20px',
                      borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
                      background: isUser ? themeStyles.userBubbleBg : themeStyles.assistantBubbleBg,
                      color: isUser ? themeStyles.userBubbleText : themeStyles.textMain,
                      border: isUser ? 'none' : `1px solid ${themeStyles.assistantBubbleBorder}`,
                      fontSize: '13.5px',
                      lineHeight: '1.6',
                      boxShadow: isDark ? '0 4px 16px rgba(0,0,0,0.2)' : '0 2px 8px rgba(0,0,0,0.06)',
                      wordBreak: 'break-word',
                      width: '100%'
                    }}>
                      {renderFormattedText(msg.text)}
                    </div>

                    {/* Action Bar */}
                    {!isUser && (
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '14px',
                        marginTop: '8px',
                        fontSize: '11px',
                        color: themeStyles.textMuted
                      }}>
                        <button
                          type="button"
                          onClick={() => handleCopyText(msg.text)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: themeStyles.textMuted,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                            fontSize: '11px'
                          }}
                          className="hover:text-blue-500"
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                          </svg>
                          Copy
                        </button>

                        <button
                          type="button"
                          onClick={() => handleSaveToNotes(msg.text)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: themeStyles.textMuted,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                            fontSize: '11px'
                          }}
                          className="hover:text-blue-500"
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
                            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
                          </svg>
                          Save to Notes
                        </button>

                        <button
                          type="button"
                          onClick={() => handleAddToReport(msg.text)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: themeStyles.textMuted,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                            fontSize: '11px'
                          }}
                          className="hover:text-blue-500"
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                          </svg>
                          Add to Report
                        </button>
                      </div>
                    )}
                  </div>

                  {/* User Avatar */}
                  {isUser && (
                    <div style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '10px',
                      background: isDark ? '#1e293b' : '#e2e8f0',
                      border: `1px solid ${themeStyles.border}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: isDark ? '#93c5fd' : '#2563eb',
                      fontWeight: 700,
                      fontSize: '14px',
                      flexShrink: 0
                    }}>
                      {currentUser?.name ? currentUser.name[0].toUpperCase() : 'A'}
                    </div>
                  )}
                </div>
              );
            })}

            {/* Reasoning / Thinking Indicator */}
            {loading && (
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '10px',
                  background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  fontWeight: 700,
                  flexShrink: 0
                }}>
                  <div className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px', borderColor: '#ffffff', borderTopColor: 'transparent' }}></div>
                </div>

                <div style={{
                  padding: '12px 18px',
                  borderRadius: '16px 16px 16px 4px',
                  background: themeStyles.assistantBubbleBg,
                  border: `1px solid ${themeStyles.assistantBubbleBorder}`,
                  color: themeStyles.textMuted,
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px'
                }}>
                  <span style={{ color: '#3b82f6', fontWeight: 600 }}>•</span>
                  <span>{REASONING_STEPS[reasoningStep]}</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* PROMPT SUGGESTIONS CHIPS */}
          <div style={{
            padding: '8px 28px 0 28px',
            display: 'flex',
            gap: '8px',
            overflowX: 'auto',
            whiteSpace: 'nowrap',
            scrollbarWidth: 'none'
          }}>
            {SUGGESTED_PROMPTS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                disabled={loading}
                onClick={() => handleSendQuery(p.query)}
                style={{
                  background: isDark ? '#1e293b' : '#f1f5f9',
                  border: `1px solid ${themeStyles.border}`,
                  color: themeStyles.textMain,
                  padding: '6px 12px',
                  borderRadius: '20px',
                  fontSize: '11.5px',
                  fontWeight: 500,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  transition: 'background-color 0.2s, border-color 0.2s',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  flexShrink: 0
                }}
                className="hover:border-blue-500"
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* INPUT DOCK */}
          <div style={{
            padding: '12px 28px 20px 28px',
            background: themeStyles.topbarBg,
            borderTop: `1px solid ${themeStyles.topbarBorder}`
          }}>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendQuery();
              }}
              style={{
                display: 'flex',
                gap: '12px',
                alignItems: 'center'
              }}
            >
              <div style={{
                flex: 1,
                position: 'relative',
                display: 'flex',
                alignItems: 'center'
              }}>
                <input
                  ref={inputRef}
                  type="text"
                  placeholder={activeCaseId ? `Query Case ${activeCaseId} findings, telemetry, hashes, or MITRE tactics...` : 'Type your forensic query...'}
                  value={inputQuery}
                  onChange={(e) => setInputQuery(e.target.value)}
                  disabled={!activeCaseId || loading}
                  style={{
                    width: '100%',
                    background: themeStyles.inputBg,
                    color: themeStyles.textMain,
                    border: `1px solid ${themeStyles.border}`,
                    borderRadius: '12px',
                    padding: '14px 20px',
                    fontSize: '14px',
                    outline: 'none',
                    boxShadow: isDark ? 'inset 0 2px 4px rgba(0,0,0,0.3)' : 'inset 0 1px 2px rgba(0,0,0,0.05)',
                    transition: 'border-color 0.2s'
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={!activeCaseId || loading || !inputQuery.trim()}
                style={{
                  background: (!activeCaseId || loading || !inputQuery.trim()) 
                    ? (isDark ? '#334155' : '#cbd5e1')
                    : 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '12px',
                  padding: '0 24px',
                  height: '48px',
                  fontSize: '14px',
                  fontWeight: 600,
                  cursor: (!activeCaseId || loading || !inputQuery.trim()) ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: (!activeCaseId || loading || !inputQuery.trim()) ? 'none' : '0 4px 14px rgba(59, 130, 246, 0.4)',
                  transition: 'all 0.2s'
                }}
              >
                <span>Ask</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="22" y1="2" x2="11" y2="13"></line>
                  <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                </svg>
              </button>
            </form>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px', fontSize: '11px', color: themeStyles.textMuted }}>
              <span>Deterministic forensic grounding & DeBERTa-v3 injection screening active.</span>
              <span>Press Enter to send</span>
            </div>
          </div>
        </main>

        {/* RIGHT COLLAPSIBLE DRAWER: Case Artifacts & Evidence Inspector */}
        {drawerOpen && (
          <aside style={{
            width: '320px',
            borderLeft: `1px solid ${themeStyles.border}`,
            background: themeStyles.drawerBg,
            display: 'flex',
            flexDirection: 'column',
            height: '100vh',
            overflowY: 'auto',
            padding: '20px',
            gap: '18px',
            zIndex: 30
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '13px', fontWeight: 700, color: themeStyles.textMain, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Case Artifacts & Evidence
              </div>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: themeStyles.textMuted,
                  cursor: 'pointer',
                  fontSize: '14px'
                }}
              >
                ✕
              </button>
            </div>

            {/* Case Snapshot Card */}
            <div style={{
              background: themeStyles.cardBg,
              border: `1px solid ${themeStyles.border}`,
              borderRadius: '10px',
              padding: '14px',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '13px', fontWeight: 800, color: isDark ? '#93c5fa' : '#2563eb' }}>
                  {activeCaseId}
                </span>
                <span style={{
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: '#10b981',
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontSize: '10px',
                  fontWeight: 700
                }}>
                  ACTIVE
                </span>
              </div>
              {activeCaseName && activeCaseName.toLowerCase() !== 'dark' && activeCaseName !== activeCaseId && (
                <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>
                  Title: <span style={{ color: themeStyles.textMain, fontWeight: 600 }}>{activeCaseName}</span>
                </div>
              )}

              {/* Counts Grid */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '8px',
                marginTop: '4px'
              }}>
                <div style={{
                  background: isDark ? '#0b0f19' : '#f8fafc',
                  border: `1px solid ${themeStyles.border}`,
                  padding: '8px',
                  borderRadius: '6px',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: '16px', fontWeight: 800, color: themeStyles.textMain }}>
                    {caseEvidence.length}
                  </div>
                  <div style={{ fontSize: '10px', color: themeStyles.textMuted }}>Evidence Files</div>
                </div>

                <div style={{
                  background: isDark ? '#0b0f19' : '#f8fafc',
                  border: `1px solid ${themeStyles.border}`,
                  padding: '8px',
                  borderRadius: '6px',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: '16px', fontWeight: 800, color: '#ef4444' }}>
                    {caseFindings.length}
                  </div>
                  <div style={{ fontSize: '10px', color: themeStyles.textMuted }}>Triaged Findings</div>
                </div>
              </div>
            </div>

            {/* Evidence Artifacts Quick-Query */}
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Evidence Files ({caseEvidence.length})</span>
              </div>

              {caseEvidence.length === 0 ? (
                <div style={{ fontSize: '12px', color: themeStyles.textMuted, fontStyle: 'italic' }}>
                  No evidence uploaded for this case.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '160px', overflowY: 'auto' }}>
                  {caseEvidence.map((ev, eIdx) => (
                    <button
                      key={eIdx}
                      type="button"
                      onClick={() => handleSendQuery(`Perform deep forensic analysis on evidence file "${ev.filename || ev.name || ev.id}" and extract all suspicious indicators.`)}
                      title="Click to query this evidence file"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 10px',
                        background: themeStyles.cardBg,
                        border: `1px solid ${themeStyles.border}`,
                        borderRadius: '6px',
                        cursor: 'pointer',
                        textAlign: 'left',
                        color: themeStyles.textMain,
                        fontSize: '11.5px',
                        transition: 'border-color 0.2s'
                      }}
                      className="hover:border-blue-500"
                    >
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }}>
                        📄 {ev.filename || ev.name || `Artifact #${eIdx + 1}`}
                      </span>
                      <span style={{ fontSize: '10px', color: isDark ? '#60a5fa' : '#2563eb', fontWeight: 600 }}>Ask &rsaquo;</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Triaged Findings Quick-Query */}
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Triaged Findings ({caseFindings.length})</span>
              </div>

              {caseFindings.length === 0 ? (
                <div style={{ fontSize: '12px', color: themeStyles.textMuted, fontStyle: 'italic' }}>
                  No triaged findings for this case yet.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '170px', overflowY: 'auto' }}>
                  {caseFindings.map((f, fIdx) => {
                    const sev = (f.severity || 'medium').toLowerCase();
                    const isCrit = sev === 'critical' || sev === 'high';
                    return (
                      <button
                        key={f.finding_id || fIdx}
                        type="button"
                        onClick={() => handleSendQuery(`Provide detailed forensic breakdown for finding ${f.finding_id || `#${fIdx+1}`}: "${f.sanitized_fact || f.fact}". Explain threat impact, attack vector, and mitigation.`)}
                        title={f.sanitized_fact || f.fact}
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '4px',
                          padding: '8px 10px',
                          background: themeStyles.cardBg,
                          border: `1px solid ${themeStyles.border}`,
                          borderRadius: '6px',
                          cursor: 'pointer',
                          textAlign: 'left',
                          color: themeStyles.textMain,
                          fontSize: '11.5px',
                          transition: 'border-color 0.2s'
                        }}
                        className="hover:border-blue-500"
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                          <span style={{ 
                            fontSize: '9.5px', 
                            fontWeight: 700, 
                            padding: '1px 6px', 
                            borderRadius: '4px',
                            background: isCrit ? 'rgba(239, 68, 68, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                            color: isCrit ? '#ef4444' : '#3b82f6',
                            textTransform: 'uppercase'
                          }}>
                            {f.severity || 'Medium'}
                          </span>
                          <span style={{ fontSize: '10px', color: isDark ? '#60a5fa' : '#2563eb', fontWeight: 600 }}>Ask &rsaquo;</span>
                        </div>
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '260px', fontSize: '11px', color: themeStyles.textMain }}>
                          {f.sanitized_fact || f.fact || `Finding ${f.finding_id}`}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Observed MITRE Techniques Radar */}
            <div>
              <div style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>Observed MITRE Techniques ({observedTechniques.length})</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {observedTechniques.map(tech => (
                  <button
                    key={tech.id}
                    type="button"
                    onClick={() => handleSendQuery(`Analyze observed activity matching MITRE Technique ${tech.id} (${tech.name}) in Case ${activeCaseId}.`)}
                    title={`Query activity matching ${tech.id}: ${tech.name}`}
                    style={{
                      background: isDark ? 'rgba(59,130,246,0.15)' : 'rgba(59,130,246,0.1)',
                      border: '1px solid rgba(59,130,246,0.3)',
                      color: isDark ? '#93c5fd' : '#2563eb',
                      padding: '5px 8px',
                      borderRadius: '5px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '5px',
                      transition: 'all 0.15s ease'
                    }}
                    className="hover:border-blue-500 hover:scale-105"
                  >
                    <span>{tech.id}: {tech.name}</span>
                    {tech.count > 1 && (
                      <span style={{
                        background: '#3b82f6',
                        color: '#ffffff',
                        fontSize: '9px',
                        padding: '1px 4px',
                        borderRadius: '8px',
                        fontWeight: 700
                      }}>
                        {tech.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Analyst Quick Notes Scratchpad */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: 'auto' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMuted, textTransform: 'uppercase' }}>
                Analyst Quick Scratchpad
              </div>
              <form onSubmit={handleAddQuickNote} style={{ display: 'flex', gap: '6px' }}>
                <input
                  type="text"
                  placeholder="Record note..."
                  value={quickNoteText}
                  onChange={(e) => setQuickNoteText(e.target.value)}
                  style={{
                    flex: 1,
                    background: themeStyles.inputBg,
                    border: `1px solid ${themeStyles.border}`,
                    color: themeStyles.textMain,
                    borderRadius: '6px',
                    padding: '6px 10px',
                    fontSize: '12px',
                    outline: 'none'
                  }}
                />
                <button
                  type="submit"
                  style={{
                    background: '#3b82f6',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '0 10px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Save
                </button>
              </form>

              {/* Notes List */}
              <div style={{ maxHeight: '120px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {quickNotesList.length === 0 ? (
                  <div style={{ fontSize: '11px', color: themeStyles.textMuted, fontStyle: 'italic' }}>
                    No notes pinned yet.
                  </div>
                ) : (
                  quickNotesList.map(n => (
                    <div key={n.id} style={{
                      background: themeStyles.cardBg,
                      border: `1px solid ${themeStyles.border}`,
                      padding: '6px 8px',
                      borderRadius: '6px',
                      fontSize: '11px',
                      color: themeStyles.textMain
                    }}>
                      <div>{n.text}</div>
                      <div style={{ fontSize: '9px', color: themeStyles.textMuted, marginTop: '2px' }}>{n.timestamp}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
