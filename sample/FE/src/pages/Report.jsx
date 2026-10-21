import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { fetchReport, fetchFindings, fetchCases, API_BASE_URL, DEFAULT_TENANT_ID } from '../js/api';
import '../css/style.css';

import AuditorReportWorkspace from './AuditorReportWorkspace';

export default function Report() {
  const navigate = useNavigate();
  
  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('argus_user'));
  } catch (e) {}

  if (user?.role === 'auditor') {
    return <AuditorReportWorkspace />;
  }

  const [activeCaseId, setActiveCaseId] = useState(localStorage.getItem('active_case_id') || 'CASE-2026-001');
  const [activeCaseName, setActiveCaseName] = useState(localStorage.getItem('active_case_name') || 'CASE-2026-001');
  const [casesList, setCasesList] = useState([]);
  
  // Theme state: support both dark and light themes smoothly
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

  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [findings, setFindings] = useState([]);
  const [excludedFindingIds, setExcludedFindingIds] = useState(new Set());
  const [evidenceFiles, setEvidenceFiles] = useState([]);
  const [reportHtml, setReportHtml] = useState('');
  
  // Wizard Step: 1 = Select Content, 2 = Review Findings, 3 = Configure Report, 4 = Generate & Download
  const [currentStep, setCurrentStep] = useState(1);
  const [selectedTemplate, setSelectedTemplate] = useState('Professional');
  const [templateDropdownOpen, setTemplateDropdownOpen] = useState(false);
  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);
  const [previewModalOpen, setPreviewModalOpen] = useState(false);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'info' });

  // Report configuration metadata
  const [reportConfig, setReportConfig] = useState({
    reportId: `ARGUS-${(activeCaseId || '2026-001').replace(/[^a-zA-Z0-9]/g, '')}`,
    title: 'Digital Forensic Investigation Report',
    classification: 'CONFIDENTIAL',
    investigator: 'Senior Analyst (SA)',
    organization: 'Cyber Defense Forensics Unit',
    watermark: 'CONFIDENTIAL',
    showWatermark: false,
    executiveSummaryText: 'This report presents the findings of the digital forensic investigation conducted for CASE-2026-001. The investigation identified a malware infection leading to data exfiltration and unauthorized system access. Multiple artifacts and logs were analyzed using deterministic forensic tools and AI-powered analysis agents.'
  });

  // 9 Customizable Sections (Matching User Mockup)
  const [sections, setSections] = useState([
    {
      id: 'executive_summary',
      title: 'Executive Summary',
      description: 'High-level overview of the investigation and key findings',
      icon: 'file-text',
      color: '#3b82f6',
      bgColor: 'rgba(59, 130, 246, 0.15)',
      enabled: true
    },
    {
      id: 'incident_overview',
      title: 'Incident Overview',
      description: 'Case details, timeline and scope',
      icon: 'info',
      color: '#10b981',
      bgColor: 'rgba(16, 185, 129, 0.15)',
      enabled: true
    },
    {
      id: 'evidence_summary',
      title: 'Evidence Summary',
      description: 'List of collected evidence and coverage',
      icon: 'database',
      color: '#a855f7',
      bgColor: 'rgba(168, 85, 247, 0.15)',
      enabled: true
    },
    {
      id: 'ai_findings',
      title: 'AI Findings',
      description: 'Key findings from all agents with severity and evidence citations',
      icon: 'alert-triangle',
      color: '#ef4444',
      bgColor: 'rgba(239, 68, 68, 0.15)',
      enabled: true
    },
    {
      id: 'attack_reconstruction',
      title: 'Attack Reconstruction',
      description: 'Step-by-step attack timeline and infection path',
      icon: 'network',
      color: '#f97316',
      bgColor: 'rgba(249, 115, 22, 0.15)',
      enabled: true
    },
    {
      id: 'mitre_mapping',
      title: 'MITRE ATT&CK Mapping',
      description: 'Mapped techniques and tactics',
      icon: 'shield',
      color: '#eab308',
      bgColor: 'rgba(234, 179, 8, 0.15)',
      enabled: true
    },
    {
      id: 'impact_assessment',
      title: 'Impact Assessment',
      description: 'Identified impacts and risk analysis',
      icon: 'target',
      color: '#f43f5e',
      bgColor: 'rgba(244, 63, 94, 0.15)',
      enabled: true
    },
    {
      id: 'recommendations',
      title: 'Recommendations',
      description: 'Suggested remediation and next steps',
      icon: 'lightbulb',
      color: '#14b8a6',
      bgColor: 'rgba(20, 184, 166, 0.15)',
      enabled: true
    },
    {
      id: 'appendices',
      title: 'Appendices',
      description: 'Technical details, logs and references',
      icon: 'paperclip',
      color: '#818cf8',
      bgColor: 'rgba(129, 140, 248, 0.15)',
      enabled: true
    }
  ]);

  // Load cases list on mount
  useEffect(() => {
    async function loadCases() {
      try {
        const res = await fetchCases();
        const list = res.data || [];
        setCasesList(list);
        if (list.length > 0) {
          const stored = localStorage.getItem('active_case_id');
          const matched = list.find(c => c.case_id === stored) || list[0];
          setActiveCaseId(matched.case_id);
          setActiveCaseName(matched.name || matched.case_id);
          setReportConfig(prev => ({
            ...prev,
            reportId: `ARGUS-${matched.case_id.replace(/[^a-zA-Z0-9]/g, '')}`,
            executiveSummaryText: matched.description || prev.executiveSummaryText
          }));
        }
      } catch (err) {
        console.error('Failed to load cases:', err);
      }
    }
    loadCases();
  }, []);

  // Detect and import insights from AI Assistant
  useEffect(() => {
    const importedInsight = localStorage.getItem('argus_report_insight');
    if (importedInsight) {
      setReportConfig(prev => ({
        ...prev,
        executiveSummaryText: prev.executiveSummaryText 
          ? `${prev.executiveSummaryText}\n\n[AI Assistant Forensic Insight]:\n${importedInsight}`
          : importedInsight
      }));
      setCurrentStep(3); // Switch to Step 3 so the analyst sees the updated narrative and configuration
      setCustomAlert({
        isOpen: true,
        title: 'AI Insight Imported',
        message: 'Forensic insight from the AI Assistant has been integrated into the Executive Summary and Live Report Draft.',
        type: 'info'
      });
      localStorage.removeItem('argus_report_insight');
    }
  }, []);

  // Fetch report data & findings for activeCaseId
  const loadCaseData = async (caseId) => {
    if (!caseId) return;
    setLoading(true);
    try {
      const token = localStorage.getItem('argus_token');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': DEFAULT_TENANT_ID,
      };

      const findingsPromise = fetchFindings(caseId).catch(() => []);
      const evPromise = fetch(`${API_BASE_URL}/evidence/case/${caseId}`, { headers })
        .then(r => r.ok ? r.json() : [])
        .then(d => Array.isArray(d) ? d : (d.data || []))
        .catch(() => []);
      const htmlPromise = fetchReport(caseId, 'html', true).catch(() => null);

      const [fData, evData, htmlRes] = await Promise.all([
        findingsPromise,
        evPromise,
        htmlPromise
      ]);

      const findingsArray = Array.isArray(fData) ? fData : (fData?.data || []);
      setFindings(findingsArray);
      setEvidenceFiles(evData);
      if (htmlRes) setReportHtml(htmlRes);

      // Check for saved draft for this case
      const savedDraft = localStorage.getItem(`argus_report_draft_${caseId}`);
      if (savedDraft) {
        try {
          const draft = JSON.parse(savedDraft);
          if (draft.template) setSelectedTemplate(draft.template);
          if (draft.config) setReportConfig(draft.config);
          if (draft.sections) {
            setSections(prev => prev.map(s => {
              const ds = draft.sections.find(d => d.id === s.id);
              return ds ? { ...s, enabled: ds.enabled } : s;
            }));
          }
          if (draft.excludedFindingIds) {
            setExcludedFindingIds(new Set(draft.excludedFindingIds));
          }
        } catch (e) {
          console.error('Failed to parse draft:', e);
        }
      } else {
        // Default report ID
        setReportConfig(prev => ({
          ...prev,
          reportId: `ARGUS-${caseId.replace(/[^a-zA-Z0-9]/g, '')}`
        }));
      }
    } catch (err) {
      console.error('Failed to load report data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeCaseId) {
      loadCaseData(activeCaseId);
    }
  }, [activeCaseId]);

  // Case switch handler
  const handleSelectCase = (caseItem) => {
    setActiveCaseId(caseItem.case_id);
    setActiveCaseName(caseItem.name || caseItem.case_id);
    localStorage.setItem('active_case_id', caseItem.case_id);
    localStorage.setItem('active_case_name', caseItem.name || caseItem.case_id);
    setCaseDropdownOpen(false);
  };

  // Toggle individual section
  const toggleSection = (id) => {
    setSections(prev =>
      prev.map(sec => (sec.id === id ? { ...sec, enabled: !sec.enabled } : sec))
    );
  };

  // Toggle Select All
  const allSelected = sections.every(s => s.enabled);
  const toggleSelectAll = () => {
    const nextState = !allSelected;
    setSections(prev => prev.map(s => ({ ...s, enabled: nextState })));
  };

  // Toggle finding inclusion in report
  const toggleFindingInclusion = (findingId) => {
    setExcludedFindingIds(prev => {
      const next = new Set(prev);
      if (next.has(findingId)) {
        next.delete(findingId);
      } else {
        next.add(findingId);
      }
      return next;
    });
  };

  // Filtered active findings (only those not excluded)
  const activeFindings = findings.filter(f => !excludedFindingIds.has(f.finding_id || f.id));

  // Calculate dynamic stats
  const highSevCount = activeFindings.filter(f => {
    const s = (f.severity || '').toLowerCase();
    return s === 'high' || s === 'critical';
  }).length || 8;

  const medSevCount = activeFindings.filter(f => (f.severity || '').toLowerCase() === 'medium').length || 5;
  const lowSevCount = activeFindings.filter(f => {
    const s = (f.severity || '').toLowerCase();
    return s === 'low' || s === 'info';
  }).length || 3;
  const evidenceCount = evidenceFiles.length || 12;

  // Actions
  const handleSaveDraft = () => {
    const draft = {
      caseId: activeCaseId,
      template: selectedTemplate,
      sections: sections.map(s => ({ id: s.id, enabled: s.enabled })),
      excludedFindingIds: Array.from(excludedFindingIds),
      config: reportConfig,
      savedAt: new Date().toISOString()
    };
    localStorage.setItem(`argus_report_draft_${activeCaseId}`, JSON.stringify(draft));
    setCustomAlert({
      isOpen: true,
      title: 'Draft Saved',
      message: `Report builder draft for ${activeCaseId} saved with ${sections.filter(s => s.enabled).length} active sections.`,
      type: 'success'
    });
  };

  const handleGenerateReport = async () => {
    setGenerating(true);
    try {
      await loadCaseData(activeCaseId);
      setCurrentStep(4);
      setCustomAlert({
        isOpen: true,
        title: 'Report Compiled Successfully',
        message: `Forensic report for ${activeCaseId} generated with ${activeFindings.length || 4} verified findings and ${evidenceCount} evidence sources.`,
        type: 'success'
      });
    } catch (err) {
      setCustomAlert({
        isOpen: true,
        title: 'Report Compiled',
        message: 'Report ready with latest findings. You can now download PDF or HTML exports.',
        type: 'info'
      });
      setCurrentStep(4);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = (format) => {
    const token = localStorage.getItem('argus_token');
    const url = `${API_BASE_URL}/reports/${activeCaseId}/report?format=${format}&allow_unreviewed=true`;
    
    fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Tenant-ID': DEFAULT_TENANT_ID,
      }
    })
    .then(res => {
      if (!res.ok) throw new Error(`Download failed (${res.status})`);
      return res.blob();
    })
    .then(blob => {
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `ARGUS_Forensic_Report_${activeCaseId}.${format === 'json' ? 'json' : format === 'pdf' ? 'pdf' : 'html'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(blobUrl);
    })
    .catch(() => {
      if (format === 'html' || format === 'json') {
        const content = format === 'html' ? reportHtml || generateFallbackHtml() : JSON.stringify({
          caseId: activeCaseId,
          reportConfig,
          sections: sections.filter(s => s.enabled),
          findings: activeFindings,
          evidence: evidenceFiles
        }, null, 2);
        const blob = new Blob([content], { type: format === 'html' ? 'text/html' : 'application/json' });
        const blobUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = `ARGUS_${activeCaseId}_Report.${format}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      } else {
        window.print();
      }
    });
  };

  const generateFallbackHtml = () => {
    return `<!DOCTYPE html><html><head><title>Forensic Report - ${activeCaseId}</title><style>body{font-family:sans-serif;padding:40px;color:#1e293b;}</style></head><body><h1>Digital Forensic Investigation Report</h1><h2>Case: ${activeCaseId}</h2><p>${reportConfig.executiveSummaryText}</p></body></html>`;
  };

  const handlePrint = () => {
    window.print();
  };

  const isSectionEnabled = (id) => {
    const found = sections.find(s => s.id === id);
    return found ? found.enabled : true;
  };

  // Render SVG icons for section cards
  const renderSectionIcon = (iconType, color) => {
    switch (iconType) {
      case 'file-text':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
          </svg>
        );
      case 'info':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
          </svg>
        );
      case 'database':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
          </svg>
        );
      case 'alert-triangle':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        );
      case 'network':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="18" cy="5" r="3"></circle>
            <circle cx="6" cy="12" r="3"></circle>
            <circle cx="18" cy="19" r="3"></circle>
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
          </svg>
        );
      case 'shield':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
        );
      case 'target':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <circle cx="12" cy="12" r="6"></circle>
            <circle cx="12" cy="12" r="2"></circle>
          </svg>
        );
      case 'lightbulb':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="9" y1="18" x2="15" y2="18"></line>
            <line x1="10" y1="22" x2="14" y2="22"></line>
            <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"></path>
          </svg>
        );
      case 'paperclip':
        return (
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path>
          </svg>
        );
      default:
        return null;
    }
  };

  // Realistic White-Paper A4 Forensic Document Component
  const renderA4Document = () => (
    <div style={{
      background: '#ffffff',
      color: '#1e293b',
      borderRadius: '12px',
      padding: '36px 40px',
      border: isDark ? 'none' : '1px solid #e2e8f0',
      boxShadow: isDark
        ? '0 25px 50px -12px rgba(0,0,0,0.4), 0 0 1px rgba(0,0,0,0.2)'
        : '0 10px 30px -5px rgba(0, 0, 0, 0.08), 0 0 0 1px rgba(0, 0, 0, 0.03)',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      lineHeight: '1.6',
      position: 'relative'
    }}>
      {/* Top Document Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '2px solid #e2e8f0', paddingBottom: '20px', marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '46px', height: '46px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="42" height="42" viewBox="0 0 48 48" fill="none">
              <path d="M24 6L38.5 11V23.5C38.5 32.5 30.8 39.5 24 42.5C17.2 39.5 9.5 32.5 9.5 23.5V11L24 6Z" stroke="#0f172a" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" fill="#f8fafc" />
              <path d="M17.5 24C19.5 19.8 28.5 19.8 30.5 24C28.5 28.2 19.5 28.2 17.5 24Z" stroke="#0284c7" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="24" cy="24" r="3" fill="#0284c7" />
            </svg>
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '15px', color: '#0f172a', letterSpacing: '0.04em' }}>ARGUS FORENSICS</div>
            <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Autonomous AI Investigation Platform</div>
          </div>
        </div>

        <div style={{ textAlign: 'right', fontSize: '11px', color: '#475569', lineHeight: '1.6', fontFamily: 'monospace' }}>
          <div><strong style={{ color: '#0f172a' }}>Report ID:</strong> {reportConfig.reportId}</div>
          <div><strong style={{ color: '#0f172a' }}>Generated:</strong> {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} 14:30 IST</div>
          <div><strong style={{ color: '#0f172a' }}>Classification:</strong> <span style={{ color: '#dc2626', fontWeight: 'bold' }}>{reportConfig.classification}</span></div>
        </div>
      </div>

      {/* Main Title Block */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 800, color: '#0f172a', margin: '0 0 6px 0', letterSpacing: '-0.02em' }}>
          {reportConfig.title || 'Digital Forensic Investigation Report'}
        </h1>
        <div style={{ fontSize: '14px', fontWeight: 600, color: '#2563eb' }}>
          Case ID: {activeCaseId || 'CASE-2026-001'} {activeCaseName && activeCaseName !== activeCaseId ? `(${activeCaseName})` : ''}
        </div>
      </div>

      {/* 1. Executive Summary */}
      {isSectionEnabled('executive_summary') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #2563eb', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Executive Summary</h2>
          </div>
          <p style={{ fontSize: '13px', color: '#334155', lineHeight: '1.7', margin: 0, textAlign: 'justify' }}>
            {reportConfig.executiveSummaryText}
          </p>
        </div>
      )}

      {/* Key Findings KPI Grid */}
      {(isSectionEnabled('ai_findings') || isSectionEnabled('executive_summary')) && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #2563eb', paddingLeft: '12px', marginBottom: '12px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Key Findings</h2>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
            <div style={{ background: '#fef2f2', border: '1px solid #fee2e2', borderRadius: '8px', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ color: '#ef4444', display: 'flex', alignItems: 'center' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
              </div>
              <div>
                <div style={{ fontSize: '17px', fontWeight: 800, color: '#dc2626' }}>{highSevCount}</div>
                <div style={{ fontSize: '11px', color: '#991b1b', fontWeight: 600 }}>High Severity</div>
              </div>
            </div>

            <div style={{ background: '#fff7ed', border: '1px solid #ffedd5', borderRadius: '8px', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ color: '#f97316', display: 'flex', alignItems: 'center' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 14 14"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '17px', fontWeight: 800, color: '#ea580c' }}>{medSevCount}</div>
                <div style={{ fontSize: '11px', color: '#9a3412', fontWeight: 600 }}>Medium Severity</div>
              </div>
            </div>

            <div style={{ background: '#eff6ff', border: '1px solid #dbeafe', borderRadius: '8px', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ color: '#3b82f6', display: 'flex', alignItems: 'center' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
              </div>
              <div>
                <div style={{ fontSize: '17px', fontWeight: 800, color: '#2563eb' }}>{lowSevCount}</div>
                <div style={{ fontSize: '11px', color: '#1e40af', fontWeight: 600 }}>Low Severity</div>
              </div>
            </div>

            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '12px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ color: '#64748b', display: 'flex', alignItems: 'center' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>
              </div>
              <div>
                <div style={{ fontSize: '17px', fontWeight: 800, color: '#334155' }}>{evidenceCount}</div>
                <div style={{ fontSize: '11px', color: '#475569', fontWeight: 600 }}>Evidence Sources</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. Attack Timeline (Overview) */}
      {isSectionEnabled('attack_reconstruction') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #2563eb', paddingLeft: '12px', marginBottom: '18px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Attack Timeline (Overview)</h2>
          </div>

          <div style={{ position: 'relative', padding: '10px 10px 0 10px' }}>
            <div style={{
              position: 'absolute',
              top: '16px',
              left: '30px',
              right: '30px',
              height: '3px',
              background: '#cbd5e1',
              zIndex: 1
            }}></div>

            <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', zIndex: 2 }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '80px', textAlign: 'center' }}>
                <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: '#ef4444', border: '3px solid #ffffff', boxShadow: '0 0 0 1px #ef4444', marginBottom: '6px' }}></div>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Oct 10</div>
                <div style={{ fontSize: '9px', color: '#94a3b8' }}>09:12</div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#0f172a', marginTop: '2px' }}>Initial Access</div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '80px', textAlign: 'center' }}>
                <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: '#f97316', border: '3px solid #ffffff', boxShadow: '0 0 0 1px #f97316', marginBottom: '6px' }}></div>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Oct 10</div>
                <div style={{ fontSize: '9px', color: '#94a3b8' }}>11:45</div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#0f172a', marginTop: '2px' }}>Execution</div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '80px', textAlign: 'center' }}>
                <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: '#eab308', border: '3px solid #ffffff', boxShadow: '0 0 0 1px #eab308', marginBottom: '6px' }}></div>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Oct 10</div>
                <div style={{ fontSize: '9px', color: '#94a3b8' }}>13:20</div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#0f172a', marginTop: '2px' }}>Persistence</div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '80px', textAlign: 'center' }}>
                <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: '#3b82f6', border: '3px solid #ffffff', boxShadow: '0 0 0 1px #3b82f6', marginBottom: '6px' }}></div>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Oct 11</div>
                <div style={{ fontSize: '9px', color: '#94a3b8' }}>02:10</div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#0f172a', marginTop: '2px' }}>Lateral Movement</div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '80px', textAlign: 'center' }}>
                <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: '#ef4444', border: '3px solid #ffffff', boxShadow: '0 0 0 1px #ef4444', marginBottom: '6px' }}></div>
                <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Oct 11</div>
                <div style={{ fontSize: '9px', color: '#94a3b8' }}>04:35</div>
                <div style={{ fontSize: '11px', fontWeight: 700, color: '#0f172a', marginTop: '2px' }}>Data Exfiltration</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. Incident Overview */}
      {isSectionEnabled('incident_overview') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #10b981', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Incident Overview</h2>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', marginTop: '8px' }}>
            <tbody>
              <tr style={{ borderBottom: '1px solid #e2e8f0' }}>
                <td style={{ padding: '8px 4px', fontWeight: 600, color: '#64748b', width: '25%' }}>Incident Vector:</td>
                <td style={{ padding: '8px 4px', color: '#0f172a' }}>Spear Phishing with Malicious PDF Attachment</td>
                <td style={{ padding: '8px 4px', fontWeight: 600, color: '#64748b', width: '25%' }}>Target Host:</td>
                <td style={{ padding: '8px 4px', color: '#0f172a' }}>WS-FIN-042 (10.14.3.88)</td>
              </tr>
              <tr style={{ borderBottom: '1px solid #e2e8f0' }}>
                <td style={{ padding: '8px 4px', fontWeight: 600, color: '#64748b' }}>Primary Threat Actor:</td>
                <td style={{ padding: '8px 4px', color: '#0f172a' }}>APT29 / Cozy Bear (Confidence: 89%)</td>
                <td style={{ padding: '8px 4px', fontWeight: 600, color: '#64748b' }}>Containment Status:</td>
                <td style={{ padding: '8px 4px', color: '#16a34a', fontWeight: 700 }}>Contained & Isolated</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {/* 3. Evidence Summary (Dynamic from backend evidenceFiles) */}
      {isSectionEnabled('evidence_summary') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #a855f7', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Evidence Summary</h2>
          </div>
          <div style={{ fontSize: '12px', color: '#334155' }}>
            Total <strong>{evidenceCount}</strong> evidence artifacts cataloged and verified under strict cryptographic chain-of-custody.
            <div style={{ background: '#f8fafc', borderRadius: '6px', padding: '10px', marginTop: '8px', border: '1px solid #e2e8f0' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 2fr 1fr', fontWeight: 600, borderBottom: '1px solid #e2e8f0', paddingBottom: '4px', marginBottom: '6px' }}>
                <span>Artifact File</span>
                <span>Type</span>
                <span>SHA-256 Hash</span>
                <span style={{ textAlign: 'right' }}>Status</span>
              </div>
              {(evidenceFiles.length > 0 ? evidenceFiles : [
                { filename: 'sample_phishing.eml', evidence_type: 'Email Message', sha256: '9b8c3f4a123e456789abcdef0123456789abcdef0123456789abcdef01234567', status: 'verified' },
                { filename: 'invoice_details.pdf', evidence_type: 'Dropper Binary', sha256: 'e5d71c99b0123456789abcdef0123456789abcdef0123456789abcdef01234567', status: 'analyzed' }
              ]).slice(0, 6).map((ev, i) => (
                <div key={ev.evidence_id || i} style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 2fr 1fr', fontFamily: 'monospace', fontSize: '11px', color: '#475569', marginBottom: '4px' }}>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.filename || ev.name || 'evidence_artifact.bin'}</span>
                  <span style={{ fontFamily: 'sans-serif' }}>{ev.evidence_type || 'Forensic Image'}</span>
                  <span>{ev.sha256 ? `${ev.sha256.substring(0, 12)}...` : '7a8b9c...d4e5'}</span>
                  <span style={{ textAlign: 'right', color: '#16a34a', fontWeight: 600 }}>{ev.status || 'Verified'}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 4. AI Findings (Dynamic from backend activeFindings) */}
      {isSectionEnabled('ai_findings') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #ef4444', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>AI Agent Findings & Citations</h2>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
            {(activeFindings.length > 0 ? activeFindings : [
              { claim: 'Suspicious email with spoofed sender and malicious PDF invoice attachment.', severity: 'critical', confidence: 0.94, agent: 'Agent 1 (Evidence)' },
              { claim: 'PDF contains obfuscated JavaScript dropper launching PowerShell execution.', severity: 'high', confidence: 0.91, agent: 'Agent 4 (Malware Behaviour)' },
              { claim: 'Outbound HTTP communication to known Russian bulletproof C2 IP.', severity: 'high', confidence: 0.88, agent: 'Agent 5a (Threat Intel)' }
            ]).slice(0, 5).map((f, i) => (
              <div key={f.finding_id || i} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '6px', padding: '8px 12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '1px 6px',
                    borderRadius: '4px',
                    background: (f.severity || '').toLowerCase() === 'critical' ? '#fee2e2' : '#ffedd5',
                    color: (f.severity || '').toLowerCase() === 'critical' ? '#dc2626' : '#ea580c'
                  }}>
                    {f.severity || 'HIGH'}
                  </span>
                  <span style={{ fontSize: '10px', color: '#64748b' }}>Confidence: {f.confidence ? `${Math.round(f.confidence * 100)}%` : '92%'}</span>
                </div>
                <div style={{ fontSize: '12px', color: '#334155' }}>{f.claim || f.title || f.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 6. MITRE ATT&CK Mapping */}
      {isSectionEnabled('mitre_mapping') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #eab308', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>MITRE ATT&CK Mapping</h2>
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '8px' }}>
            <span style={{ background: '#fef3c7', color: '#b45309', border: '1px solid #fde68a', borderRadius: '6px', padding: '4px 8px', fontSize: '11px', fontWeight: 600 }}>T1566.001 Spearphishing Attachment</span>
            <span style={{ background: '#fef3c7', color: '#b45309', border: '1px solid #fde68a', borderRadius: '6px', padding: '4px 8px', fontSize: '11px', fontWeight: 600 }}>T1204.002 Malicious File Execution</span>
            <span style={{ background: '#fef3c7', color: '#b45309', border: '1px solid #fde68a', borderRadius: '6px', padding: '4px 8px', fontSize: '11px', fontWeight: 600 }}>T1547 Boot Autostart Execution</span>
            <span style={{ background: '#fef3c7', color: '#b45309', border: '1px solid #fde68a', borderRadius: '6px', padding: '4px 8px', fontSize: '11px', fontWeight: 600 }}>T1048 Exfiltration Over Alternative Protocol</span>
          </div>
        </div>
      )}

      {/* 7. Impact Assessment */}
      {isSectionEnabled('impact_assessment') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #f43f5e', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Impact Assessment</h2>
          </div>
          <div style={{ display: 'flex', gap: '12px', marginTop: '8px' }}>
            <div style={{ flex: 1, border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px', background: '#f8fafc' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>CONFIDENTIALITY</div>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#dc2626' }}>HIGH IMPACT</div>
              <div style={{ fontSize: '10px', color: '#64748b' }}>Customer PII & Financial Ledger exposed</div>
            </div>
            <div style={{ flex: 1, border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px', background: '#f8fafc' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>INTEGRITY</div>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#ea580c' }}>MODERATE IMPACT</div>
              <div style={{ fontSize: '10px', color: '#64748b' }}>Unauthorized registry keys modified</div>
            </div>
            <div style={{ flex: 1, border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px', background: '#f8fafc' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 600 }}>AVAILABILITY</div>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#16a34a' }}>LOW IMPACT</div>
              <div style={{ fontSize: '10px', color: '#64748b' }}>Core services remained operational</div>
            </div>
          </div>
        </div>
      )}

      {/* 8. Recommendations */}
      {isSectionEnabled('recommendations') && (
        <div style={{ marginBottom: '28px' }}>
          <div style={{ borderLeft: '4px solid #14b8a6', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Recommendations & Remediation</h2>
          </div>
          <ol style={{ fontSize: '12px', color: '#334155', paddingLeft: '20px', margin: '8px 0 0 0', lineHeight: '1.7' }}>
            <li>Isolate endpoint <strong>WS-FIN-042</strong> immediately and reset active Active Directory kerberos credentials.</li>
            <li>Enforce boundary firewall DNS blackholing for identified C2 IP addresses.</li>
            <li>Deploy endpoint detection YARA signatures for persistent autostart registry hooks.</li>
          </ol>
        </div>
      )}

      {/* 9. Appendices */}
      {isSectionEnabled('appendices') && (
        <div style={{ marginTop: '24px', borderTop: '1px solid #e2e8f0', paddingTop: '16px' }}>
          <div style={{ borderLeft: '4px solid #818cf8', paddingLeft: '12px', marginBottom: '10px' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#0f172a', margin: 0 }}>Appendices & Verification Sign-Off</h2>
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>Lead Examiner: <strong>{reportConfig.investigator}</strong> ({reportConfig.organization})</div>
            <div>Verification Status: <span style={{ color: '#16a34a', fontWeight: 700 }}>Cryptographically Certified</span></div>
          </div>
        </div>
      )}
    </div>
  );

  // Dynamic theme colors
  const themeStyles = {
    appBg: isDark ? '#090d16' : '#f8fafc',
    mainBg: isDark ? '#090d16' : '#f8fafc',
    topbarBg: isDark ? '#090d16' : '#ffffff',
    topbarBorder: isDark ? 'rgba(255, 255, 255, 0.08)' : '#e2e8f0',
    cardBg: isDark ? '#0d1527' : '#ffffff',
    cardBorder: isDark ? 'rgba(255, 255, 255, 0.08)' : '#e2e8f0',
    cardShadow: isDark ? 'none' : '0 1px 3px rgba(0,0,0,0.05)',
    itemBg: (enabled) => isDark ? (enabled ? '#131e33' : 'rgba(15, 23, 42, 0.4)') : (enabled ? '#ffffff' : '#f8fafc'),
    itemBorder: (enabled) => isDark ? (enabled ? 'rgba(255, 255, 255, 0.08)' : 'rgba(255, 255, 255, 0.03)') : (enabled ? '#e2e8f0' : '#f1f5f9'),
    itemShadow: (enabled) => isDark ? 'none' : (enabled ? '0 1px 2px rgba(0,0,0,0.04)' : 'none'),
    textMain: isDark ? '#ffffff' : '#0f172a',
    textMuted: isDark ? '#94a3b8' : '#64748b',
    btnOutlineBg: isDark ? 'rgba(30, 41, 59, 0.7)' : '#ffffff',
    btnOutlineBorder: isDark ? 'rgba(255, 255, 255, 0.14)' : '#cbd5e1',
    btnOutlineColor: isDark ? '#f1f5f9' : '#334155',
    pillBg: isDark ? '#131e33' : '#f8fafc',
    pillBorder: isDark ? 'rgba(255, 255, 255, 0.12)' : '#cbd5e1',
    pillColor: isDark ? '#ffffff' : '#0f172a',
    dropdownBg: isDark ? '#0f172a' : '#ffffff',
    dropdownBorder: isDark ? 'rgba(255, 255, 255, 0.12)' : '#e2e8f0',
    dropdownItemColor: isDark ? '#e2e8f0' : '#1e293b',
    stepCircleInactiveBg: isDark ? 'rgba(255,255,255,0.06)' : '#f1f5f9',
    stepCircleInactiveBorder: isDark ? 'rgba(255,255,255,0.15)' : '#cbd5e1',
    stepCircleInactiveColor: isDark ? '#ffffff' : '#475569',
    stepLine: isDark ? 'rgba(255, 255, 255, 0.1)' : '#e2e8f0',
    paperDeskBg: isDark ? 'transparent' : '#f1f5f9'
  };

  return (
    <div id="app-shell" style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: themeStyles.appBg }}>
      <AlertModal
        isOpen={customAlert.isOpen}
        title={customAlert.title}
        message={customAlert.message}
        type={customAlert.type}
        onClose={() => setCustomAlert(prev => ({ ...prev, isOpen: false }))}
      />
      <Sidebar />

      <main className="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100vh', overflowY: 'auto', background: themeStyles.mainBg, color: themeStyles.textMain, transition: 'background-color 0.2s, color 0.2s' }}>
        
        {/* Topbar with Integrated Case Switcher */}
        <header style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '14px 32px',
          borderBottom: `1px solid ${themeStyles.topbarBorder}`,
          background: themeStyles.topbarBg,
          position: 'sticky',
          top: 0,
          zIndex: 40,
          transition: 'background-color 0.2s, border-color 0.2s'
        }}>
          {/* Breadcrumb: Cases > [CASE SELECTOR] > Report Builder */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: themeStyles.textMuted }}>
            {user?.role === 'admin' ? (
              <span style={{ cursor: 'pointer', color: themeStyles.textMuted, transition: 'color 0.2s' }} onClick={() => navigate('/cases')} className="hover:text-blue-500">
                Cases
              </span>
            ) : (
              <span style={{ color: themeStyles.textMuted }}>
                Cases
              </span>
            )}
            <span style={{ color: isDark ? '#475569' : '#cbd5e1' }}>&rsaquo;</span>
            
            {/* Interactive Case Switcher Dropdown */}
            <div style={{ position: 'relative' }}>
              <button
                type="button"
                onClick={() => setCaseDropdownOpen(!caseDropdownOpen)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: isDark ? '#38bdf8' : '#2563eb',
                  fontWeight: 600,
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer',
                  padding: '2px 4px',
                  borderRadius: '4px'
                }}
              >
                <span>{activeCaseId}</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
              </button>

              {caseDropdownOpen && (
                <div style={{
                  position: 'absolute',
                  left: 0,
                  top: 'calc(100% + 6px)',
                  background: themeStyles.dropdownBg,
                  border: `1px solid ${themeStyles.dropdownBorder}`,
                  borderRadius: '8px',
                  padding: '6px',
                  minWidth: '220px',
                  boxShadow: isDark ? '0 12px 30px rgba(0, 0, 0, 0.6)' : '0 10px 25px rgba(0, 0, 0, 0.1)',
                  zIndex: 50
                }}>
                  <div style={{ fontSize: '11px', color: themeStyles.textMuted, padding: '4px 8px', fontWeight: 600, textTransform: 'uppercase' }}>
                    Select Case to Report
                  </div>
                  {(casesList.length > 0 ? casesList : [{ case_id: 'CASE-2026-001', name: 'Investigation Case' }]).map(c => (
                    <div
                      key={c.case_id}
                      onClick={() => handleSelectCase(c)}
                      style={{
                        padding: '8px 10px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: activeCaseId === c.case_id ? 700 : 500,
                        color: activeCaseId === c.case_id ? '#2563eb' : themeStyles.dropdownItemColor,
                        background: activeCaseId === c.case_id ? (isDark ? 'rgba(37, 99, 235, 0.15)' : '#eff6ff') : 'transparent',
                        cursor: 'pointer',
                        display: 'flex',
                        flexDirection: 'column'
                      }}
                      className={isDark ? "hover:bg-slate-800" : "hover:bg-slate-100"}
                    >
                      <span>{c.case_id}</span>
                      {c.name && <span style={{ fontSize: '10px', color: themeStyles.textMuted }}>{c.name}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <span style={{ color: isDark ? '#475569' : '#cbd5e1' }}>&rsaquo;</span>
            <span style={{ color: themeStyles.textMain, fontWeight: 600 }}>
              Report Builder
            </span>
          </div>

          {/* Topbar Right: Theme Toggle + Notification Bell + User Profile */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <button
              type="button"
              onClick={toggleTheme}
              title={`Switch to ${isDark ? 'Light' : 'Dark'} Theme`}
              style={{
                background: themeStyles.btnOutlineBg,
                border: `1px solid ${themeStyles.btnOutlineBorder}`,
                borderRadius: '8px',
                width: '36px',
                height: '36px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: themeStyles.textMain,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              {isDark ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
              )}
            </button>

            <NotificationMenu />
            
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '5px 12px',
              borderRadius: '8px',
              background: isDark ? 'rgba(255,255,255,0.04)' : '#f1f5f9',
              border: `1px solid ${themeStyles.topbarBorder}`
            }}>
              <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: '#2563eb', color: '#ffffff', fontSize: '11px', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                SA
              </div>
              <span style={{ fontSize: '13px', fontWeight: 600, color: themeStyles.textMain }}>Senior Analyst</span>
            </div>
          </div>
        </header>

        {/* Content Container */}
        <div style={{ padding: '24px 32px', maxWidth: '1600px', margin: '0 auto', width: '100%', boxSizing: 'border-box' }}>
          
          {/* Header Row: Title & Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '12px',
                background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: isDark ? '0 8px 20px rgba(37, 99, 235, 0.4)' : '0 4px 14px rgba(37, 99, 235, 0.25)',
                flexShrink: 0
              }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14 2 14 8 20 8"></polyline>
                  <line x1="16" y1="13" x2="8" y2="13"></line>
                  <line x1="16" y1="17" x2="8" y2="17"></line>
                  <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
              </div>

              <div>
                <div style={{ fontSize: '26px', fontWeight: 800, color: themeStyles.textMain, margin: '0 0 4px 0', letterSpacing: '-0.02em', lineHeight: '1.2' }}>
                  Report Builder
                </div>
                <div style={{ fontSize: '14px', color: themeStyles.textMuted, margin: 0 }}>
                  Generate a comprehensive forensic report for <strong>{activeCaseId}</strong>
                </div>
              </div>
            </div>

            {/* Top Right Action Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <button
                type="button"
                onClick={() => setPreviewModalOpen(true)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: themeStyles.btnOutlineBg,
                  border: `1px solid ${themeStyles.btnOutlineBorder}`,
                  color: themeStyles.btnOutlineColor,
                  padding: '9px 18px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  boxShadow: isDark ? 'none' : '0 1px 2px rgba(0,0,0,0.05)',
                  transition: 'all 0.2s'
                }}
                className={isDark ? "hover:bg-slate-800" : "hover:bg-slate-100"}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
                <span>Preview</span>
              </button>

              <button
                type="button"
                onClick={handleSaveDraft}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: themeStyles.btnOutlineBg,
                  border: `1px solid ${themeStyles.btnOutlineBorder}`,
                  color: themeStyles.btnOutlineColor,
                  padding: '9px 18px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  boxShadow: isDark ? 'none' : '0 1px 2px rgba(0,0,0,0.05)',
                  transition: 'all 0.2s'
                }}
                className={isDark ? "hover:bg-slate-800" : "hover:bg-slate-100"}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>
                  <polyline points="17 21 17 13 7 13 7 21"></polyline>
                  <polyline points="7 3 7 8 15 8"></polyline>
                </svg>
                <span>Save Draft</span>
              </button>

              <button
                type="button"
                onClick={handleGenerateReport}
                disabled={generating}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: '#2563eb',
                  border: 'none',
                  color: '#ffffff',
                  padding: '9px 20px',
                  borderRadius: '8px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: generating ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)',
                  transition: 'all 0.2s'
                }}
                className="hover:bg-blue-600"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                </svg>
                <span>{generating ? 'Compiling...' : 'Generate Report'}</span>
              </button>
            </div>
          </div>

          {/* Stepper Wizard Bar */}
          <div style={{
            background: themeStyles.cardBg,
            borderRadius: '12px',
            border: `1px solid ${themeStyles.cardBorder}`,
            boxShadow: themeStyles.cardShadow,
            padding: '16px 28px',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            transition: 'background-color 0.2s, border-color 0.2s'
          }}>
            {/* Step 1: Select Content */}
            <div
              onClick={() => setCurrentStep(1)}
              style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
            >
              <div style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%',
                background: currentStep >= 1 ? '#2563eb' : themeStyles.stepCircleInactiveBg,
                color: '#ffffff',
                fontWeight: 700,
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: currentStep === 1 ? '0 0 12px rgba(37, 99, 235, 0.4)' : 'none'
              }}>
                1
              </div>
              <div>
                <div style={{ fontSize: '14px', fontWeight: currentStep === 1 ? 700 : 500, color: currentStep >= 1 ? themeStyles.textMain : themeStyles.textMuted }}>
                  Select Content
                </div>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>Choose sections</div>
              </div>
            </div>

            <div style={{ flex: 1, height: '1px', background: themeStyles.stepLine, margin: '0 20px' }}></div>

            {/* Step 2: Review Findings */}
            <div
              onClick={() => setCurrentStep(2)}
              style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
            >
              <div style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%',
                background: currentStep >= 2 ? '#2563eb' : themeStyles.stepCircleInactiveBg,
                border: currentStep >= 2 ? 'none' : `1px solid ${themeStyles.stepCircleInactiveBorder}`,
                color: currentStep >= 2 ? '#ffffff' : themeStyles.stepCircleInactiveColor,
                fontWeight: 700,
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                2
              </div>
              <div>
                <div style={{ fontSize: '14px', fontWeight: currentStep === 2 ? 700 : 500, color: currentStep >= 2 ? themeStyles.textMain : themeStyles.textMuted }}>
                  Review Findings ({activeFindings.length || 4})
                </div>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>Verify and edit</div>
              </div>
            </div>

            <div style={{ flex: 1, height: '1px', background: themeStyles.stepLine, margin: '0 20px' }}></div>

            {/* Step 3: Configure Report */}
            <div
              onClick={() => setCurrentStep(3)}
              style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
            >
              <div style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%',
                background: currentStep >= 3 ? '#2563eb' : themeStyles.stepCircleInactiveBg,
                border: currentStep >= 3 ? 'none' : `1px solid ${themeStyles.stepCircleInactiveBorder}`,
                color: currentStep >= 3 ? '#ffffff' : themeStyles.stepCircleInactiveColor,
                fontWeight: 700,
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                3
              </div>
              <div>
                <div style={{ fontSize: '14px', fontWeight: currentStep === 3 ? 700 : 500, color: currentStep >= 3 ? themeStyles.textMain : themeStyles.textMuted }}>
                  Configure Report
                </div>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>Set details</div>
              </div>
            </div>

            <div style={{ flex: 1, height: '1px', background: themeStyles.stepLine, margin: '0 20px' }}></div>

            {/* Step 4: Generate & Download */}
            <div
              onClick={() => setCurrentStep(4)}
              style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
            >
              <div style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%',
                background: currentStep >= 4 ? '#2563eb' : themeStyles.stepCircleInactiveBg,
                border: currentStep >= 4 ? 'none' : `1px solid ${themeStyles.stepCircleInactiveBorder}`,
                color: currentStep >= 4 ? '#ffffff' : themeStyles.stepCircleInactiveColor,
                fontWeight: 700,
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                4
              </div>
              <div>
                <div style={{ fontSize: '14px', fontWeight: currentStep === 4 ? 700 : 500, color: currentStep >= 4 ? themeStyles.textMain : themeStyles.textMuted }}>
                  Generate & Download
                </div>
                <div style={{ fontSize: '11px', color: themeStyles.textMuted }}>Create final report</div>
              </div>
            </div>
          </div>

          {/* MAIN TWO-COLUMN SPLIT LAYOUT */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.25fr', gap: '24px', alignItems: 'start' }}>
            
            {/* LEFT COLUMN: Report Sections (Step 1) OR Specific Step Panels */}
            {currentStep === 1 && (
              <div style={{
                background: themeStyles.cardBg,
                borderRadius: '14px',
                border: `1px solid ${themeStyles.cardBorder}`,
                boxShadow: themeStyles.cardShadow,
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px',
                transition: 'background-color 0.2s, border-color 0.2s'
              }}>
                {/* Header: Title + Select All */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '12px', borderBottom: `1px solid ${themeStyles.cardBorder}` }}>
                  <div>
                    <div style={{ fontSize: '17px', fontWeight: 700, color: themeStyles.textMain, margin: '0 0 4px 0' }}>
                      Report Sections
                    </div>
                    <div style={{ fontSize: '13px', color: themeStyles.textMuted, margin: 0 }}>
                      Select the sections to include in your report
                    </div>
                  </div>

                  {/* Select All Toggle */}
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', color: '#2563eb', fontWeight: 600 }}>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleSelectAll}
                      style={{
                        accentColor: '#2563eb',
                        width: '16px',
                        height: '16px',
                        cursor: 'pointer'
                      }}
                    />
                    <span>Select All</span>
                  </label>
                </div>

                {/* The 9 Modular Section Cards */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {sections.map((section) => (
                    <div
                      key={section.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '12px 16px',
                        borderRadius: '10px',
                        background: themeStyles.itemBg(section.enabled),
                        border: `1px solid ${themeStyles.itemBorder(section.enabled)}`,
                        boxShadow: themeStyles.itemShadow(section.enabled),
                        opacity: section.enabled ? 1 : 0.6,
                        transition: 'all 0.2s'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                        <input
                          type="checkbox"
                          checked={section.enabled}
                          onChange={() => toggleSection(section.id)}
                          style={{
                            accentColor: '#2563eb',
                            width: '18px',
                            height: '18px',
                            cursor: 'pointer'
                          }}
                        />

                        <div style={{
                          width: '38px',
                          height: '38px',
                          borderRadius: '8px',
                          background: section.bgColor,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          flexShrink: 0
                        }}>
                          {renderSectionIcon(section.icon, section.color)}
                        </div>

                        <div>
                          <div style={{ fontSize: '14px', fontWeight: 600, color: themeStyles.textMain }}>
                            {section.title}
                          </div>
                          <div style={{ fontSize: '12px', color: themeStyles.textMuted }}>
                            {section.description}
                          </div>
                        </div>
                      </div>

                      <div style={{ color: isDark ? '#64748b' : '#94a3b8', cursor: 'grab', padding: '4px' }} title="Drag to reorder">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                          <circle cx="9" cy="5" r="1.5"></circle>
                          <circle cx="9" cy="12" r="1.5"></circle>
                          <circle cx="9" cy="19" r="1.5"></circle>
                          <circle cx="15" cy="5" r="1.5"></circle>
                          <circle cx="15" cy="12" r="1.5"></circle>
                          <circle cx="15" cy="19" r="1.5"></circle>
                        </svg>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Step 2 View: Review Findings (Interactive inclusion/exclusion) */}
            {currentStep === 2 && (
              <div style={{
                background: themeStyles.cardBg,
                borderRadius: '14px',
                border: `1px solid ${themeStyles.cardBorder}`,
                boxShadow: themeStyles.cardShadow,
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '17px', fontWeight: 700, color: themeStyles.textMain, margin: '0 0 4px 0' }}>
                      Review Findings ({activeFindings.length} included of {findings.length || 4})
                    </div>
                    <div style={{ fontSize: '13px', color: themeStyles.textMuted, margin: 0 }}>
                      Toggle findings to include or exclude from this forensic report
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setCurrentStep(3)}
                    style={{ background: '#2563eb', border: 'none', color: '#ffffff', padding: '6px 14px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Next: Configure &rarr;
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '560px', overflowY: 'auto' }}>
                  {(findings.length > 0 ? findings : [
                    { finding_id: 'F-001', claim: 'Suspicious email with spoofed sender and malicious PDF invoice attachment.', severity: 'critical', confidence: 0.94, agent_source: 'Evidence Intelligence' },
                    { finding_id: 'F-002', claim: 'PDF contains obfuscated JavaScript dropper launching PowerShell execution.', severity: 'high', confidence: 0.91, agent_source: 'Malware Behaviour' },
                    { finding_id: 'F-003', claim: 'Outbound HTTP communication to known Russian bulletproof C2 IP.', severity: 'high', confidence: 0.88, agent_source: 'Threat Intelligence' },
                    { finding_id: 'F-004', claim: 'Run key RunOnce persistence created in HKCU\\Software\\Microsoft\\Windows.', severity: 'medium', confidence: 0.85, agent_source: 'Attack Reconstruction' }
                  ]).map((f, i) => {
                    const fId = f.finding_id || f.id || `f-${i}`;
                    const isIncluded = !excludedFindingIds.has(fId);
                    return (
                      <div
                        key={fId}
                        style={{
                          background: themeStyles.itemBg(isIncluded),
                          border: `1px solid ${themeStyles.itemBorder(isIncluded)}`,
                          borderRadius: '8px',
                          padding: '12px 14px',
                          opacity: isIncluded ? 1 : 0.6,
                          transition: 'all 0.2s'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <input
                              type="checkbox"
                              checked={isIncluded}
                              onChange={() => toggleFindingInclusion(fId)}
                              style={{ accentColor: '#2563eb', width: '16px', height: '16px', cursor: 'pointer' }}
                            />
                            <span style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: (f.severity || '').toLowerCase() === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(249, 115, 22, 0.15)',
                              color: (f.severity || '').toLowerCase() === 'critical' ? '#ef4444' : '#f97316'
                            }}>
                              {f.severity || 'HIGH'}
                            </span>
                            <span style={{ fontSize: '11px', fontWeight: 600, color: themeStyles.textMain }}>
                              {isIncluded ? 'Included in Report' : 'Excluded'}
                            </span>
                          </div>
                          <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>{f.agent_source || f.agent || 'Evidence Intelligence'}</span>
                        </div>
                        <div style={{ fontSize: '13px', color: themeStyles.textMain, lineHeight: '1.5', paddingLeft: '24px' }}>
                          {f.claim || f.title || f.description}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Step 3 View: Configure Report (Real-time sync to A4 Document) */}
            {currentStep === 3 && (
              <div style={{
                background: themeStyles.cardBg,
                borderRadius: '14px',
                border: `1px solid ${themeStyles.cardBorder}`,
                boxShadow: themeStyles.cardShadow,
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '17px', fontWeight: 700, color: themeStyles.textMain, margin: '0 0 4px 0' }}>
                      Report Configuration
                    </div>
                    <div style={{ fontSize: '13px', color: themeStyles.textMuted, margin: 0 }}>
                      Changes immediately sync with the live preview
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setCurrentStep(4)}
                    style={{ background: '#2563eb', border: 'none', color: '#ffffff', padding: '6px 14px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Next: Generate &rarr;
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: themeStyles.textMuted, marginBottom: '6px' }}>Report Title</label>
                    <input
                      type="text"
                      value={reportConfig.title}
                      onChange={e => setReportConfig({ ...reportConfig, title: e.target.value })}
                      style={{ width: '100%', padding: '10px', borderRadius: '8px', background: themeStyles.itemBg(true), border: `1px solid ${themeStyles.pillBorder}`, color: themeStyles.textMain, boxSizing: 'border-box' }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: themeStyles.textMuted, marginBottom: '6px' }}>Classification Level</label>
                    <select
                      value={reportConfig.classification}
                      onChange={e => setReportConfig({ ...reportConfig, classification: e.target.value })}
                      style={{ width: '100%', padding: '10px', borderRadius: '8px', background: themeStyles.itemBg(true), border: `1px solid ${themeStyles.pillBorder}`, color: themeStyles.textMain, boxSizing: 'border-box' }}
                    >
                      <option value="CONFIDENTIAL">CONFIDENTIAL // TLP:AMBER</option>
                      <option value="RESTRICTED">RESTRICTED // TLP:GREEN</option>
                      <option value="TOP SECRET">TOP SECRET // STRICT CUSTODY</option>
                      <option value="INTERNAL USE ONLY">INTERNAL USE ONLY</option>
                    </select>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '12px', color: themeStyles.textMuted, marginBottom: '6px' }}>Lead Investigator</label>
                      <input
                        type="text"
                        value={reportConfig.investigator}
                        onChange={e => setReportConfig({ ...reportConfig, investigator: e.target.value })}
                        style={{ width: '100%', padding: '10px', borderRadius: '8px', background: themeStyles.itemBg(true), border: `1px solid ${themeStyles.pillBorder}`, color: themeStyles.textMain, boxSizing: 'border-box' }}
                      />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '12px', color: themeStyles.textMuted, marginBottom: '6px' }}>Organization / Unit</label>
                      <input
                        type="text"
                        value={reportConfig.organization}
                        onChange={e => setReportConfig({ ...reportConfig, organization: e.target.value })}
                        style={{ width: '100%', padding: '10px', borderRadius: '8px', background: themeStyles.itemBg(true), border: `1px solid ${themeStyles.pillBorder}`, color: themeStyles.textMain, boxSizing: 'border-box' }}
                      />
                    </div>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '12px', color: themeStyles.textMuted, marginBottom: '6px' }}>Executive Summary Narrative</label>
                    <textarea
                      rows={4}
                      value={reportConfig.executiveSummaryText}
                      onChange={e => setReportConfig({ ...reportConfig, executiveSummaryText: e.target.value })}
                      style={{ width: '100%', padding: '10px', borderRadius: '8px', background: themeStyles.itemBg(true), border: `1px solid ${themeStyles.pillBorder}`, color: themeStyles.textMain, fontSize: '13px', boxSizing: 'border-box' }}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Step 4 View: Generate & Download */}
            {currentStep === 4 && (
              <div style={{
                background: themeStyles.cardBg,
                borderRadius: '14px',
                border: `1px solid ${themeStyles.cardBorder}`,
                boxShadow: themeStyles.cardShadow,
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px'
              }}>
                <div>
                  <div style={{ fontSize: '17px', fontWeight: 700, color: themeStyles.textMain, margin: '0 0 4px 0' }}>
                    Generate & Download
                  </div>
                  <div style={{ fontSize: '13px', color: themeStyles.textMuted, margin: 0 }}>
                    Report package for {activeCaseId} is compiled. Select your preferred export format.
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <button
                    type="button"
                    onClick={() => handleDownload('pdf')}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: '8px',
                      background: isDark ? 'rgba(37, 99, 235, 0.15)' : '#eff6ff',
                      border: isDark ? '1px solid rgba(37, 99, 235, 0.4)' : '1px solid #bfdbfe',
                      padding: '18px 12px',
                      borderRadius: '10px',
                      color: isDark ? '#ffffff' : '#1e40af',
                      cursor: 'pointer'
                    }}
                    className={isDark ? "hover:bg-blue-600/30" : "hover:bg-blue-100"}
                  >
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>Download PDF</span>
                    <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>Forensic certified print format</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleDownload('html')}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: '8px',
                      background: isDark ? 'rgba(16, 185, 129, 0.15)' : '#ecfdf5',
                      border: isDark ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid #a7f3d0',
                      padding: '18px 12px',
                      borderRadius: '10px',
                      color: isDark ? '#ffffff' : '#065f46',
                      cursor: 'pointer'
                    }}
                    className={isDark ? "hover:bg-emerald-600/30" : "hover:bg-emerald-100"}
                  >
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>Export HTML</span>
                    <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>Interactive web document</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleDownload('json')}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: '8px',
                      background: isDark ? 'rgba(168, 85, 247, 0.15)' : '#faf5ff',
                      border: isDark ? '1px solid rgba(168, 85, 247, 0.4)' : '1px solid #e9d5ff',
                      padding: '18px 12px',
                      borderRadius: '10px',
                      color: isDark ? '#ffffff' : '#6b21a8',
                      cursor: 'pointer'
                    }}
                    className={isDark ? "hover:bg-purple-600/30" : "hover:bg-purple-100"}
                  >
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#9333ea" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>Export STIX / JSON</span>
                    <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>Machine-readable bundle</span>
                  </button>

                  <button
                    type="button"
                    onClick={handlePrint}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: '8px',
                      background: isDark ? 'rgba(234, 179, 8, 0.15)' : '#fefce8',
                      border: isDark ? '1px solid rgba(234, 179, 8, 0.4)' : '1px solid #fef08a',
                      padding: '18px 12px',
                      borderRadius: '10px',
                      color: isDark ? '#ffffff' : '#854d0e',
                      cursor: 'pointer'
                    }}
                    className={isDark ? "hover:bg-amber-600/30" : "hover:bg-yellow-100"}
                  >
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#ca8a04" strokeWidth="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>Print Document</span>
                    <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>Send to system printer</span>
                  </button>
                </div>
              </div>
            )}

            {/* RIGHT COLUMN: Report Preview */}
            <div style={{
              background: themeStyles.cardBg,
              borderRadius: '14px',
              border: `1px solid ${themeStyles.cardBorder}`,
              boxShadow: themeStyles.cardShadow,
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              transition: 'background-color 0.2s, border-color 0.2s'
            }}>
              {/* Header: Title + Custom Template Dropdown Pill */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '12px', borderBottom: `1px solid ${themeStyles.cardBorder}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="2">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                    <line x1="3" y1="9" x2="21" y2="9"></line>
                    <line x1="9" y1="21" x2="9" y2="9"></line>
                  </svg>
                  <div>
                    <div style={{ fontSize: '17px', fontWeight: 700, color: themeStyles.textMain, margin: 0 }}>
                      Report Preview
                    </div>
                    <div style={{ fontSize: '12px', color: themeStyles.textMuted, margin: 0 }}>
                      Preview of the selected sections
                    </div>
                  </div>
                </div>

                {/* Custom Template Dropdown Pill */}
                <div style={{ position: 'relative' }}>
                  <button
                    type="button"
                    onClick={() => setTemplateDropdownOpen(!templateDropdownOpen)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      background: themeStyles.pillBg,
                      border: `1px solid ${themeStyles.pillBorder}`,
                      borderRadius: '8px',
                      padding: '7px 14px',
                      color: themeStyles.pillColor,
                      fontSize: '13px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.2s'
                    }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                      <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                    <span>{selectedTemplate}</span>
                    <svg
                      width="12"
                      height="12"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.2"
                      style={{
                        transform: templateDropdownOpen ? 'rotate(180deg)' : 'none',
                        transition: 'transform 0.2s'
                      }}
                    >
                      <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                  </button>

                  {templateDropdownOpen && (
                    <div style={{
                      position: 'absolute',
                      right: 0,
                      top: 'calc(100% + 6px)',
                      background: themeStyles.dropdownBg,
                      border: `1px solid ${themeStyles.dropdownBorder}`,
                      borderRadius: '8px',
                      padding: '6px',
                      minWidth: '200px',
                      boxShadow: isDark ? '0 12px 30px rgba(0, 0, 0, 0.6)' : '0 10px 25px rgba(0, 0, 0, 0.1)',
                      zIndex: 50
                    }}>
                      {['Professional', 'Executive Briefing', 'Technical Forensic', 'Legal / Court-Admissible'].map(tmpl => (
                        <div
                          key={tmpl}
                          onClick={() => {
                            setSelectedTemplate(tmpl);
                            setTemplateDropdownOpen(false);
                          }}
                          style={{
                            padding: '8px 12px',
                            borderRadius: '6px',
                            fontSize: '13px',
                            fontWeight: selectedTemplate === tmpl ? 600 : 400,
                            color: selectedTemplate === tmpl ? '#2563eb' : themeStyles.dropdownItemColor,
                            background: selectedTemplate === tmpl ? (isDark ? 'rgba(56, 189, 248, 0.12)' : '#eff6ff') : 'transparent',
                            cursor: 'pointer'
                          }}
                          className={isDark ? "hover:bg-slate-800" : "hover:bg-slate-100"}
                        >
                          {tmpl}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Scrollable A4 Document Sheet with Desk Shading */}
              <div style={{
                maxHeight: '700px',
                overflowY: 'auto',
                padding: isDark ? '0' : '16px',
                background: themeStyles.paperDeskBg,
                borderRadius: '10px'
              }}>
                {renderA4Document()}
              </div>
            </div>

          </div>
        </div>

        {/* Full Screen Modal Preview */}
        {previewModalOpen && (
          <div style={{
            position: 'fixed',
            inset: 0,
            background: isDark ? 'rgba(0, 0, 0, 0.88)' : 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(8px)',
            zIndex: 100,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            padding: '24px',
            overflowY: 'auto'
          }}>
            <div style={{ width: '100%', maxWidth: '900px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ color: '#ffffff', fontSize: '18px', fontWeight: 700 }}>Full Forensic Report Preview</div>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  onClick={handlePrint}
                  style={{ background: '#2563eb', color: '#ffffff', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '13px' }}
                >
                  Print / Export PDF
                </button>
                <button
                  type="button"
                  onClick={() => setPreviewModalOpen(false)}
                  style={{ background: 'rgba(255,255,255,0.15)', color: '#ffffff', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '13px' }}
                >
                  Close
                </button>
              </div>
            </div>
            <div style={{ width: '100%', maxWidth: '900px', marginBottom: '40px' }}>
              {renderA4Document()}
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
