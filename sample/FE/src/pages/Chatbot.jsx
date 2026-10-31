import React, { useState, useEffect, useRef, useMemo } from 'react';

import { useNavigate } from 'react-router-dom';

import Sidebar from '../components/Sidebar';

import AlertModal from '../components/AlertModal';

import NotificationMenu from '../components/NotificationMenu';

import CaseNotAssigned from '../components/CaseNotAssigned';

import { 

  queryCase, 

  fetchCases, 

  fetchFindings, 

  fetchEvidenceForCase, 

  createCaseNote,

  createReviewNote, 

  fetchReport,

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



// Helper to construct a standalone HTML report package if needed

function generateHtmlFromReportData(reportData) {

  const caseId = reportData?.case_id || 'UNKNOWN';

  const genAt = reportData?.generated_at 

    ? (String(reportData.generated_at).includes('IST') 

        ? String(reportData.generated_at) 

        : new Date(reportData.generated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST') 

    : new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST';

  const findings = Array.isArray(reportData?.findings) ? reportData.findings : [];

  const evidence = Array.isArray(reportData?.evidence_files) ? reportData.evidence_files : [];

  const timeline = Array.isArray(reportData?.timeline) ? reportData.timeline : [];

  const summary = reportData?.executive_summary || `Legal-grade forensic case report for ${caseId}. Includes ${evidence.length} evidence file(s) and ${findings.length} finding(s).`;

  

  const critCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;

  const highCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;



  return `<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>ARGUS Forensic Report - ${caseId}</title>

    <style>

        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }

        .container { max-width: 1200px; margin: 0 auto; background: #111827; border-radius: 16px; border: 1px solid #1f2937; box-shadow: 0 10px 30px rgba(0,0,0,0.5); overflow: hidden; }

        .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #ffffff; padding: 32px; border-bottom: 1px solid #1f2937; }

        .header h1 { margin: 0 0 8px 0; font-size: 26px; color: #38bdf8; }

        .header .meta { display: flex; gap: 24px; font-size: 13px; color: #94a3b8; flex-wrap: wrap; }

        .section { padding: 28px 32px; border-bottom: 1px solid #1f2937; }

        .section h2 { margin-top: 0; font-size: 18px; color: #38bdf8; border-bottom: 2px solid #1f2937; padding-bottom: 8px; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }

        .stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; text-align: center; }

        .stat-card .value { font-size: 28px; font-weight: 700; color: #38bdf8; }

        .stat-card .label { font-size: 12px; color: #94a3b8; text-transform: uppercase; }

        table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }

        th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #1f2937; }

        th { background: #1e293b; color: #94a3b8; font-weight: 600; }

        .badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }

        .badge-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }

        .badge-high { background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }

        .badge-medium { background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }

        .badge-low { background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid #3b82f6; }

        .hash-code { font-family: Consolas, monospace; font-size: 11px; color: #38bdf8; background: #0b0f19; padding: 2px 6px; border-radius: 4px; }

        .disclaimer { font-size: 11px; color: #64748b; margin-top: 24px; line-height: 1.6; }

    </style>

</head>

<body>

    <div class="container">

        <div class="header">

            <h1>ARGUS Digital Forensic Report</h1>

            <div class="meta">

                <div>Case ID: <strong>${caseId}</strong></div>

                <div>Generated: <strong>${genAt}</strong></div>

                <div>Classification: <strong>OFFICIAL // FORENSIC CONFIDENTIAL</strong></div>

            </div>

        </div>

        <div class="section">

            <h2>Executive Summary</h2>

            <div class="stats-grid">

                <div class="stat-card"><div class="value">${findings.length}</div><div class="label">Total Findings</div></div>

                <div class="stat-card"><div class="value" style="color:#ef4444">${critCount}</div><div class="label">Critical Findings</div></div>

                <div class="stat-card"><div class="value" style="color:#10b981">${evidence.length}</div><div class="label">Evidence Artifacts</div></div>

                <div class="stat-card"><div class="value" style="color:#f59e0b">${timeline.length}</div><div class="label">Timeline Events</div></div>

            </div>

            <p style="font-size: 14px; line-height: 1.6; color: #e2e8f0;">${summary}</p>

        </div>

        <div class="section">

            <h2>Evidence Files & Cryptographic Hashes</h2>

            ${evidence.length === 0 ? '<p style="color:#94a3b8;font-style:italic">No evidence files recorded.</p>' : `

            <table>

                <thead><tr><th>Filename</th><th>Status</th><th>SHA-256 Hash</th></tr></thead>

                <tbody>${evidence.map(e => `<tr><td><strong>${e.filename || 'Evidence File'}</strong></td><td><span class="badge" style="background:rgba(16,185,129,0.2);color:#10b981">${e.status || 'stored'}</span></td><td><span class="hash-code">${e.sha256_hash || 'Pending'}</span></td></tr>`).join('')}</tbody>

            </table>`}

        </div>

        <div class="section">

            <h2>Triaged Forensic Findings</h2>

            ${findings.length === 0 ? '<p style="color:#94a3b8;font-style:italic">No anomalous findings triaged yet.</p>' : `

            <table>

                <thead><tr><th>Severity</th><th>Finding / Observation</th><th>MITRE Technique</th><th>Source</th></tr></thead>

                <tbody>${findings.map(f => {

                  const s = (f.severity || 'medium').toLowerCase();

                  return `<tr><td><span class="badge badge-${s}">${f.severity || 'Medium'}</span></td><td>${f.sanitized_fact || f.fact || 'Observed telemetry'}</td><td><span style="color:#38bdf8;font-weight:600">${f.mitre_mapping || f.mitre_technique || 'N/A'}</span></td><td>${f.source_tool || 'ARGUS Engine'}</td></tr>`;

                }).join('')}</tbody>

            </table>`}

        </div>

        <div class="section">

            <p class="disclaimer"><strong>LEGAL DISCLAIMER &amp; CHAIN OF CUSTODY NOTICE:</strong> This document contains automated and analyst-verified forensic insights compiled by the ARGUS Multi-Agent Digital Forensics Platform. All evidence hashes and telemetry records are cryptographically stamped. Timestamps: Indian Standard Time (IST / UTC+05:30).</p>

        </div>

    </div>

</body>

</html>`;

}



// Interactive In-Chat Case Forensic Report Card Component

function CaseReportCard({ 

  reportData, 

  reportHtml, 

  isDark, 

  themeStyles, 

  onPreviewHtml, 

  onDownloadHtml, 

  onDownloadJson, 

  onDownloadPdf, 

  onSaveToNotes, 

  showToast 

}) {

  const [activeTab, setActiveTab] = useState('findings'); // 'findings' | 'evidence' | 'timeline' | 'mitre'

  

  if (!reportData) return null;



  const caseId = reportData.case_id || 'Case';

  const genAt = reportData.generated_at 

    ? (String(reportData.generated_at).includes('IST') 

        ? String(reportData.generated_at) 

        : new Date(reportData.generated_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST') 

    : new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST';

  const findings = Array.isArray(reportData.findings) ? reportData.findings : [];

  const evidence = Array.isArray(reportData.evidence_files) ? reportData.evidence_files : [];

  const timeline = Array.isArray(reportData.timeline) ? reportData.timeline : [];

  

  const critCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;

  const highCount = findings.filter(f => (f.severity || '').toLowerCase() === 'high').length;



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

  if (Array.isArray(reportData.mitre_techniques)) {

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



  const execSummary = reportData.executive_summary || (

    findings.length > 0

      ? `Forensic investigation package compiled for Case ${caseId}. Triaged ${findings.length} finding(s) with ${critCount + highCount} prioritized critical/high-severity indicator(s) across ${evidence.length} ingested evidence file(s).`

      : `Forensic case baseline compiled for Case ${caseId}. Contains ${evidence.length} cataloged evidence artifact(s). No anomalous threat indicators identified at current triage stage.`

  );



  const effectiveHtml = reportHtml || generateHtmlFromReportData(reportData);



  return (

    <div style={{

      display: 'flex',

      flexDirection: 'column',

      gap: '16px',

      background: isDark ? 'linear-gradient(145deg, #0d1322 0%, #151d30 100%)' : '#ffffff',

      border: `1px solid ${isDark ? 'rgba(56, 189, 248, 0.35)' : 'rgba(37, 99, 235, 0.25)'}`,

      borderRadius: '20px',

      padding: '24px',

      boxShadow: isDark 

        ? '0 12px 32px rgba(0, 0, 0, 0.45), 0 0 16px rgba(56, 189, 248, 0.1)' 

        : '0 12px 32px rgba(37, 99, 235, 0.08)',

      width: '100%'

    }}>

      {/* Header Banner */}

      <div style={{

        display: 'flex',

        justifyContent: 'space-between',

        alignItems: 'flex-start',

        flexWrap: 'wrap',

        gap: '12px',

        borderBottom: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)'}`,

        paddingBottom: '16px'

      }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>

          <div style={{

            width: '42px',

            height: '42px',

            borderRadius: '12px',

            background: 'linear-gradient(135deg, #2563eb 0%, #7c3aed 100%)',

            display: 'flex',

            alignItems: 'center',

            justifyContent: 'center',

            color: '#ffffff',

            boxShadow: '0 4px 14px rgba(37, 99, 235, 0.35)',

            flexShrink: 0

          }}>

            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

              <polyline points="14 2 14 8 20 8"></polyline>

              <line x1="16" y1="13" x2="8" y2="13"></line>

              <line x1="16" y1="17" x2="8" y2="17"></line>

              <polyline points="10 9 9 9 8 9"></polyline>

            </svg>

          </div>

          <div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>

              <span style={{

                fontSize: '11px',

                fontWeight: 800,

                color: '#38bdf8',

                letterSpacing: '1px',

                textTransform: 'uppercase'

              }}>

                ARGUS Forensic Report

              </span>

              <span style={{

                fontSize: '10px',

                fontWeight: 700,

                background: 'rgba(16, 185, 129, 0.15)',

                color: '#10b981',

                padding: '1px 8px',

                borderRadius: '9999px',

                border: '1px solid rgba(16, 185, 129, 0.3)'

              }}>

                LEGAL-GRADE DRAFT

              </span>

            </div>

            <div style={{ fontSize: '17px', fontWeight: 800, color: isDark ? '#f8fafc' : '#0f172a', marginTop: '2px' }}>

              Case: {caseId}

            </div>

            <div style={{ fontSize: '11.5px', color: themeStyles.textMuted }}>

              Compiled: {genAt} • Tenant: {reportData.tenant_id || 'default'}

            </div>

          </div>

        </div>



        {/* Top Quick Actions */}

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>

          <button

            type="button"

            onClick={() => onPreviewHtml(effectiveHtml)}

            className="btn-primary"

            style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

          >

            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>

              <circle cx="12" cy="12" r="3"></circle>

            </svg>

            <span>Preview Full Report</span>

          </button>

        </div>

      </div>



      {/* Metrics Row */}

      <div style={{

        display: 'grid',

        gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',

        gap: '10px'

      }}>

        <div style={{

          background: isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',

          border: `1px solid ${themeStyles.border}`,

          borderRadius: '12px',

          padding: '12px',

          textAlign: 'center'

        }}>

          <div style={{ fontSize: '20px', fontWeight: 800, color: findings.length > 0 ? (critCount > 0 ? '#ef4444' : '#38bdf8') : themeStyles.textMain }}>

            {findings.length}

          </div>

          <div style={{ fontSize: '10.5px', color: themeStyles.textMuted, fontWeight: 600, textTransform: 'uppercase' }}>

            Triaged Findings

          </div>

          {(critCount > 0 || highCount > 0) && (

            <div style={{ display: 'flex', justifyContent: 'center', gap: '4px', marginTop: '4px' }}>

              {critCount > 0 && <span style={{ fontSize: '9px', color: '#ef4444', fontWeight: 700 }}>{critCount} Crit</span>}

              {highCount > 0 && <span style={{ fontSize: '9px', color: '#f97316', fontWeight: 700 }}>{highCount} High</span>}

            </div>

          )}

        </div>



        <div style={{

          background: isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',

          border: `1px solid ${themeStyles.border}`,

          borderRadius: '12px',

          padding: '12px',

          textAlign: 'center'

        }}>

          <div style={{ fontSize: '20px', fontWeight: 800, color: '#10b981' }}>

            {evidence.length}

          </div>

          <div style={{ fontSize: '10.5px', color: themeStyles.textMuted, fontWeight: 600, textTransform: 'uppercase' }}>

            Evidence Files

          </div>

        </div>



        <div style={{

          background: isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',

          border: `1px solid ${themeStyles.border}`,

          borderRadius: '12px',

          padding: '12px',

          textAlign: 'center'

        }}>

          <div style={{ fontSize: '20px', fontWeight: 800, color: '#f59e0b' }}>

            {timeline.length}

          </div>

          <div style={{ fontSize: '10.5px', color: themeStyles.textMuted, fontWeight: 600, textTransform: 'uppercase' }}>

            Timeline Events

          </div>

        </div>



        <div style={{

          background: isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(0, 0, 0, 0.02)',

          border: `1px solid ${themeStyles.border}`,

          borderRadius: '12px',

          padding: '12px',

          textAlign: 'center'

        }}>

          <div style={{ fontSize: '20px', fontWeight: 800, color: '#a78bfa' }}>

            {mitreList.length}

          </div>

          <div style={{ fontSize: '10.5px', color: themeStyles.textMuted, fontWeight: 600, textTransform: 'uppercase' }}>

            MITRE ATT&CK

          </div>

        </div>

      </div>



      {/* Executive Summary Box */}

      <div style={{

        background: isDark ? 'rgba(56, 189, 248, 0.05)' : 'rgba(37, 99, 235, 0.04)',

        border: `1px solid ${isDark ? 'rgba(56, 189, 248, 0.2)' : 'rgba(37, 99, 235, 0.15)'}`,

        borderLeft: '4px solid #38bdf8',

        borderRadius: '12px',

        padding: '14px 16px'

      }}>

        <div style={{ fontSize: '11px', fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase', marginBottom: '6px', letterSpacing: '0.5px' }}>

          Executive Forensic Assessment

        </div>

        <div style={{ fontSize: '13px', lineHeight: '1.6', color: isDark ? '#e2e8f0' : '#1e293b' }}>

          {execSummary}

        </div>

      </div>



      {/* Tab Selectors */}

      <div style={{

        display: 'flex',

        gap: '6px',

        borderBottom: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)'}`,

        paddingBottom: '8px',

        overflowX: 'auto'

      }}>

        <button

          type="button"

          onClick={() => setActiveTab('findings')}

          className="btn-outline"

          style={{

            padding: '6px 14px',

            fontSize: '12px',

            fontWeight: 600,

            background: activeTab === 'findings' ? 'var(--glass-dash-blue-soft)' : 'transparent',

            color: activeTab === 'findings' ? 'var(--glass-dash-blue)' : themeStyles.textMuted,

            borderColor: activeTab === 'findings' ? 'var(--glass-dash-blue-border)' : 'transparent'

          }}

        >

          🔍 Findings ({findings.length})

        </button>



        <button

          type="button"

          onClick={() => setActiveTab('evidence')}

          className="btn-outline"

          style={{

            padding: '6px 14px',

            fontSize: '12px',

            fontWeight: 600,

            background: activeTab === 'evidence' ? 'var(--glass-dash-blue-soft)' : 'transparent',

            color: activeTab === 'evidence' ? 'var(--glass-dash-blue)' : themeStyles.textMuted,

            borderColor: activeTab === 'evidence' ? 'var(--glass-dash-blue-border)' : 'transparent'

          }}

        >

          📁 Evidence Files ({evidence.length})

        </button>



        <button

          type="button"

          onClick={() => setActiveTab('timeline')}

          className="btn-outline"

          style={{

            padding: '6px 14px',

            fontSize: '12px',

            fontWeight: 600,

            background: activeTab === 'timeline' ? 'var(--glass-dash-blue-soft)' : 'transparent',

            color: activeTab === 'timeline' ? 'var(--glass-dash-blue)' : themeStyles.textMuted,

            borderColor: activeTab === 'timeline' ? 'var(--glass-dash-blue-border)' : 'transparent'

          }}

        >

          ⏱️ Timeline ({timeline.length})

        </button>



        <button

          type="button"

          onClick={() => setActiveTab('mitre')}

          className="btn-outline"

          style={{

            padding: '6px 14px',

            fontSize: '12px',

            fontWeight: 600,

            background: activeTab === 'mitre' ? 'var(--glass-dash-blue-soft)' : 'transparent',

            color: activeTab === 'mitre' ? 'var(--glass-dash-blue)' : themeStyles.textMuted,

            borderColor: activeTab === 'mitre' ? 'var(--glass-dash-blue-border)' : 'transparent'

          }}

        >

          🛡️ MITRE Matrix ({mitreList.length})

        </button>

      </div>



      {/* Tab Panels */}

      <div style={{ minHeight: '120px' }}>

        {/* TAB 1: Findings */}

        {activeTab === 'findings' && (

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>

            {findings.length === 0 ? (

              <div style={{

                padding: '24px',

                textAlign: 'center',

                color: themeStyles.textMuted,

                fontSize: '12.5px',

                background: isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)',

                borderRadius: '12px',

                border: `1px dashed ${themeStyles.border}`

              }}>

                No anomalous findings triaged yet for this case. Evidence files cataloged below are available for agent correlation.

              </div>

            ) : (

              findings.map((f, idx) => {

                const sev = (f.severity || 'medium').toLowerCase();

                const isCrit = sev === 'critical' || sev === 'high';

                return (

                  <div key={idx} style={{

                    padding: '12px 14px',

                    borderRadius: '10px',

                    background: isDark ? 'rgba(255,255,255,0.025)' : 'rgba(0,0,0,0.02)',

                    border: `1px solid ${themeStyles.border}`,

                    borderLeft: `4px solid ${isCrit ? (sev === 'critical' ? '#ef4444' : '#f97316') : '#3b82f6'}`

                  }}>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>

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

                        <span style={{ fontSize: '11px', color: themeStyles.textMuted }}>

                          {f.finding_id || `#${idx + 1}`}

                        </span>

                      </div>

                      {f.source_tool && (

                        <span style={{ fontSize: '10.5px', color: themeStyles.textMuted }}>

                          Source: <strong style={{ color: themeStyles.textMain }}>{f.source_tool}</strong>

                        </span>

                      )}

                    </div>

                    <div style={{ fontSize: '13px', lineHeight: '1.5', color: themeStyles.textMain }}>

                      {f.sanitized_fact || f.fact || 'Observed telemetry event'}

                    </div>

                    <div style={{ display: 'flex', gap: '10px', marginTop: '8px', flexWrap: 'wrap', fontSize: '11px' }}>

                      {(f.mitre_mapping || f.mitre_technique) && (

                        <span style={{

                          background: isDark ? 'rgba(56, 189, 248, 0.15)' : 'rgba(37, 99, 235, 0.1)',

                          color: '#38bdf8',

                          padding: '2px 8px',

                          borderRadius: '6px',

                          fontWeight: 600

                        }}>

                          MITRE: {f.mitre_mapping || f.mitre_technique}

                        </span>

                      )}

                      {f.confidence !== undefined && (

                        <span style={{ color: '#10b981', fontWeight: 600 }}>

                          Confidence: {(f.confidence * 100).toFixed(0)}%

                        </span>

                      )}

                    </div>

                  </div>

                );

              })

            )}

          </div>

        )}



        {/* TAB 2: Evidence Files */}

        {activeTab === 'evidence' && (

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>

            {evidence.length === 0 ? (

              <div style={{

                padding: '24px',

                textAlign: 'center',

                color: themeStyles.textMuted,

                fontSize: '12.5px',

                background: isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)',

                borderRadius: '12px',

                border: `1px dashed ${themeStyles.border}`

              }}>

                No evidence artifacts uploaded for this case yet.

              </div>

            ) : (

              evidence.map((ev, idx) => (

                <div key={idx} style={{

                  padding: '12px 14px',

                  borderRadius: '10px',

                  background: isDark ? 'rgba(255,255,255,0.025)' : 'rgba(0,0,0,0.02)',

                  border: `1px solid ${themeStyles.border}`,

                  display: 'flex',

                  flexDirection: 'column',

                  gap: '6px'

                }}>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>

                      <span style={{ fontSize: '14px' }}>📄</span>

                      <strong style={{ fontSize: '13px', color: themeStyles.textMain }}>{ev.filename || 'Evidence File'}</strong>

                    </div>

                    <span style={{

                      fontSize: '10px',

                      fontWeight: 700,

                      background: 'rgba(16, 185, 129, 0.15)',

                      color: '#10b981',

                      padding: '2px 8px',

                      borderRadius: '6px',

                      textTransform: 'uppercase'

                    }}>

                      {ev.status || 'stored'}

                    </span>

                  </div>

                  {ev.sha256_hash && (

                    <div style={{

                      display: 'flex',

                      alignItems: 'center',

                      justifyContent: 'space-between',

                      background: isDark ? '#0b0f19' : '#f1f5f9',

                      padding: '6px 10px',

                      borderRadius: '6px',

                      marginTop: '4px'

                    }}>

                      <div style={{ fontSize: '11px', fontFamily: 'Consolas, monospace', color: '#38bdf8', overflow: 'hidden', textOverflow: 'ellipsis' }}>

                        SHA-256: {ev.sha256_hash}

                      </div>

                      <button

                        type="button"

                        onClick={() => {

                          navigator.clipboard.writeText(ev.sha256_hash);

                          showToast('Hash copied to clipboard!');

                        }}

                        style={{

                          background: 'none',

                          border: 'none',

                          color: '#38bdf8',

                          cursor: 'pointer',

                          fontSize: '11px',

                          fontWeight: 600,

                          flexShrink: 0,

                          marginLeft: '8px'

                        }}

                      >

                        Copy

                      </button>

                    </div>

                  )}

                </div>

              ))

            )}

          </div>

        )}



        {/* TAB 3: Timeline */}

        {activeTab === 'timeline' && (

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>

            {timeline.length === 0 ? (

              <div style={{

                padding: '24px',

                textAlign: 'center',

                color: themeStyles.textMuted,

                fontSize: '12.5px',

                background: isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)',

                borderRadius: '12px',

                border: `1px dashed ${themeStyles.border}`

              }}>

                No chronological attack timeline events recorded yet.

              </div>

            ) : (

              timeline.map((t, idx) => (

                <div key={idx} style={{

                  padding: '10px 14px',

                  borderRadius: '10px',

                  background: isDark ? 'rgba(255,255,255,0.025)' : 'rgba(0,0,0,0.02)',

                  border: `1px solid ${themeStyles.border}`,

                  display: 'flex',

                  gap: '12px',

                  alignItems: 'baseline'

                }}>

                  <div style={{

                    width: '8px',

                    height: '8px',

                    borderRadius: '50%',

                    background: '#f59e0b',

                    flexShrink: 0

                  }} />

                  <div style={{ flex: 1 }}>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>

                      <span style={{ fontSize: '11.5px', fontWeight: 700, color: '#38bdf8' }}>

                        {t.timestamp || 'Chronological Event'}

                      </span>

                      {t.event_type && (

                        <span style={{

                          fontSize: '10px',

                          background: 'rgba(245, 158, 11, 0.15)',

                          color: '#f59e0b',

                          padding: '1px 6px',

                          borderRadius: '4px',

                          fontWeight: 600

                        }}>

                          {t.event_type}

                        </span>

                      )}

                    </div>

                    <div style={{ fontSize: '12.5px', color: themeStyles.textMain }}>{t.summary}</div>

                  </div>

                </div>

              ))

            )}

          </div>

        )}



        {/* TAB 4: MITRE ATT&CK */}

        {activeTab === 'mitre' && (

          <div>

            {mitreList.length === 0 ? (

              <div style={{

                padding: '24px',

                textAlign: 'center',

                color: themeStyles.textMuted,

                fontSize: '12.5px',

                background: isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)',

                borderRadius: '12px',

                border: `1px dashed ${themeStyles.border}`

              }}>

                No MITRE ATT&CK techniques mapped to current case findings.

              </div>

            ) : (

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '8px' }}>

                {mitreList.map(t => (

                  <div key={t.id} style={{

                    padding: '10px 12px',

                    borderRadius: '8px',

                    background: isDark ? 'rgba(56, 189, 248, 0.08)' : 'rgba(37, 99, 235, 0.06)',

                    border: `1px solid ${isDark ? 'rgba(56, 189, 248, 0.2)' : 'rgba(37, 99, 235, 0.2)'}`,

                    display: 'flex',

                    flexDirection: 'column',

                    gap: '4px'

                  }}>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

                      <strong style={{ fontSize: '12px', color: '#38bdf8' }}>{t.id}</strong>

                      {t.count > 1 && (

                        <span style={{

                          background: '#38bdf8',

                          color: '#0f172a',

                          fontSize: '9px',

                          padding: '1px 5px',

                          borderRadius: '9999px',

                          fontWeight: 700

                        }}>

                          {t.count}x

                        </span>

                      )}

                    </div>

                    <div style={{ fontSize: '11px', color: themeStyles.textMain }}>{t.name}</div>

                  </div>

                ))}

              </div>

            )}

          </div>

        )}

      </div>



      {/* Action Footer Bar */}

      <div style={{

        display: 'flex',

        alignItems: 'center',

        justifyContent: 'space-between',

        flexWrap: 'wrap',

        gap: '8px',

        borderTop: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)'}`,

        paddingTop: '16px'

      }}>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>

          <button

            type="button"

            onClick={() => onPreviewHtml(effectiveHtml)}

            className="btn-primary"

            style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

          >

            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>

              <circle cx="12" cy="12" r="3"></circle>

            </svg>

            <span>Preview HTML</span>

          </button>



          <button

            type="button"

            onClick={() => onDownloadHtml(reportData, effectiveHtml)}

            className="btn-outline"

            style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

          >

            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>

              <polyline points="7 10 12 15 17 10"></polyline>

              <line x1="12" y1="15" x2="12" y2="3"></line>

            </svg>

            <span>Download HTML</span>

          </button>



          <button

            type="button"

            onClick={() => onDownloadJson(reportData)}

            className="btn-outline"

            style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

          >

            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <polyline points="16 18 22 12 16 6"></polyline>

              <polyline points="8 6 2 12 8 18"></polyline>

            </svg>

            <span>Download JSON</span>

          </button>



          <button

            type="button"

            onClick={() => onDownloadPdf(reportData, effectiveHtml)}

            className="btn-outline"

            style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

          >

            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

              <polyline points="14 2 14 8 20 8"></polyline>

            </svg>

            <span>Download PDF</span>

          </button>



          <button

            type="button"

            onClick={() => onSaveToNotes(`[FORENSIC REPORT SUMMARY - ${caseId}]\n${execSummary}\nFindings: ${findings.length} | Evidence: ${evidence.length}`)}

            className="btn-outline"

            style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

          >

            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>

              <polyline points="17 21 17 13 7 13 7 21"></polyline>

              <polyline points="7 3 7 8 15 8"></polyline>

            </svg>

            <span>Pin to Case Notes</span>

          </button>

        </div>



        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center' }}>

          <button

            type="button"

            onClick={() => {

              const u = JSON.parse(localStorage.getItem('argus_user') || '{}');

              const record = {

                case_id: caseId,

                submitted: true,

                submitted_at: new Date().toISOString(),

                analyst_name: u?.name || 'Analyst',

                findings_count: findings.length,

                evidence_count: evidence.length

              };

              localStorage.setItem(`argus_case_${caseId}_submitted_to_senior`, JSON.stringify(record));

              window.dispatchEvent(new Event('storage'));

              showToast('Report submitted to Senior Analyst for validation!');

            }}

            style={{

              display: 'inline-flex',

              alignItems: 'center',

              justifyContent: 'center',

              gap: '8px',

              padding: '9px 22px',

              fontSize: '13.5px',

              fontWeight: 700,

              letterSpacing: '0.2px',

              color: '#ffffff',

              background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',

              border: '1px solid rgba(220, 38, 38, 0.6)',

              borderRadius: '9999px',

              boxShadow: '0 4px 14px rgba(239, 68, 68, 0.4)',

              cursor: 'pointer',

              transition: 'all 0.2s ease'

            }}

            onMouseEnter={(e) => {

              e.currentTarget.style.transform = 'translateY(-1px)';

              e.currentTarget.style.boxShadow = '0 6px 18px rgba(239, 68, 68, 0.5)';

            }}

            onMouseLeave={(e) => {

              e.currentTarget.style.transform = 'translateY(0)';

              e.currentTarget.style.boxShadow = '0 4px 14px rgba(239, 68, 68, 0.4)';

            }}

          >

            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" style={{ flexShrink: 0 }}>

              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

              <polyline points="14 2 14 8 20 8"></polyline>

              <line x1="16" y1="13" x2="8" y2="13"></line>

              <line x1="16" y1="17" x2="8" y2="17"></line>

            </svg>

            <span>Submit to Senior Analyst</span>

          </button>

        </div>

      </div>

    </div>

  );

}



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

  const [activeCaseId, setActiveCaseId] = useState(localStorage.getItem('active_case_id') || '');

  const [activeCaseName, setActiveCaseName] = useState(localStorage.getItem('active_case_name') || '');

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

  const [generatingReport, setGeneratingReport] = useState(false);

  const [reportModalOpen, setReportModalOpen] = useState(false);

  const [activeModalReportHtml, setActiveModalReportHtml] = useState('');

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

        const openCases = list.filter(c => c.status === 'open' || c.status === 'in_progress');
        if (openCases.length > 0) {
          const stored = localStorage.getItem('active_case_id');
          const matched = stored ? openCases.find(c => c.case_id === stored) : null;
          const targetCase = matched || openCases[0];
          setActiveCaseId(targetCase.case_id);
          setActiveCaseName(targetCase.name || targetCase.case_id);
        } else {
          setActiveCaseId('');
          setActiveCaseName('');
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



  // Detect if query is requesting case report generation

  const isReportRequest = (q) => {

    if (!q) return false;

    const s = q.trim().toLowerCase();

    return s === 'generate report' ||

      s === 'case report' ||

      s === 'show report' ||

      s === 'report' ||

      s === 'create report' ||

      s === 'view report' ||

      s === 'fetch report' ||

      s.includes('generate report') ||

      s.includes('generate case report') ||

      s.includes('show case report') ||

      s.includes('view case report') ||

      s.includes('forensic report');

  };



  // Download HTML report package

  const handleDownloadHtml = (reportData, reportHtml) => {

    const caseId = reportData?.case_id || activeCaseId;

    const content = reportHtml || generateHtmlFromReportData(reportData);

    const blob = new Blob([content], { type: 'text/html' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = `ARGUS_Forensic_Report_${caseId}_${Date.now()}.html`;

    a.click();

    URL.revokeObjectURL(url);

    showToast('HTML Report downloaded');

  };



  // Download JSON report package

  const handleDownloadJson = (reportData) => {

    const caseId = reportData?.case_id || activeCaseId;

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = `ARGUS_Forensic_Report_${caseId}_${Date.now()}.json`;

    a.click();

    URL.revokeObjectURL(url);

    showToast('JSON Report downloaded');

  };



  // Download PDF report package

  const handleDownloadPdf = async (reportData, reportHtml) => {

    const caseId = reportData?.case_id || activeCaseId;

    try {

      const token = localStorage.getItem('argus_token');

      const tenantId = localStorage.getItem('argus_tenant_id') || 'default';

      const res = await fetch(`${API_BASE_URL}/reports/${encodeURIComponent(caseId)}/report?format=pdf&allow_unreviewed=true`, {

        headers: {

          'Authorization': `Bearer ${token}`,

          'X-Tenant-ID': tenantId

        }

      });

      if (res.ok) {

        const blob = await res.blob();

        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');

        a.href = url;

        a.download = `ARGUS_Forensic_Report_${caseId}_${Date.now()}.pdf`;

        a.click();

        URL.revokeObjectURL(url);

        showToast('PDF Report downloaded');

        return;

      }

    } catch (err) {

      console.warn('PDF download fallback to print:', err);

    }

    

    // Fallback: Open print dialog

    const content = reportHtml || generateHtmlFromReportData(reportData);

    const printWindow = window.open('', '_blank');

    if (printWindow) {

      printWindow.document.write(content);

      printWindow.document.close();

      printWindow.focus();

      setTimeout(() => printWindow.print(), 400);

    }

  };



  // Primary Forensic Report Generator for AI Assistant

  const handleGenerateReport = async (customPrompt = null) => {

    if (!activeCaseId) {

      setCustomAlert({

        isOpen: true,

        title: 'No Active Case',

        message: 'Please select an active investigation case before generating a report.',

        type: 'warning'

      });

      return;

    }



    if (generatingReport || loading) return;



    setGeneratingReport(true);

    const userPrompt = customPrompt || `Generate comprehensive Case Forensic Report for Case ${activeCaseId}`;

    

    // Push user message

    const userMessage = {

      id: Date.now().toString(),

      sender: 'user',

      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),

      text: userPrompt

    };

    setMessages(prev => [...prev, userMessage]);

    setInputQuery('');



    // Spinner reasoning indicator

    setLoading(true);

    setReasoningStep(0);

    const stepInterval = setInterval(() => {

      setReasoningStep(prev => (prev + 1) % REASONING_STEPS.length);

    }, 1200);



    try {

      // Fetch both JSON structured report data and HTML package

      const [jsonRes, htmlRes] = await Promise.allSettled([

        fetchReport(activeCaseId, 'json', true),

        fetchReport(activeCaseId, 'html', true)

      ]);



      clearInterval(stepInterval);



      let reportData = null;

      if (jsonRes.status === 'fulfilled' && jsonRes.value) {

        reportData = typeof jsonRes.value === 'string' ? JSON.parse(jsonRes.value) : jsonRes.value;

      }



      let reportHtml = '';

      if (htmlRes.status === 'fulfilled' && htmlRes.value) {

        reportHtml = typeof htmlRes.value === 'string' ? htmlRes.value : JSON.stringify(htmlRes.value);

      }



      // If backend returned 404 or case is not yet persisted with evidence

      if (!reportData) {

        reportData = {

          case_id: activeCaseId,

          tenant_id: DEFAULT_TENANT_ID || 'default',

          generated_at: new Date().toISOString(),

          findings: caseFindings || [],

          evidence_files: caseEvidence || [],

          timeline: [],

          executive_summary: `Initial case status report for ${activeCaseId}. Currently contains ${(caseEvidence || []).length} evidence file(s) and ${(caseFindings || []).length} triaged finding(s).`

        };

      }



      if (!reportHtml) {

        reportHtml = generateHtmlFromReportData(reportData);

      }



      const assistantMessage = {

        id: (Date.now() + 1).toString(),

        sender: 'assistant',

        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),

        text: `Official Forensic Investigation Report compiled for Case **${activeCaseId}**.`,

        isReport: true,

        reportData: reportData,

        reportHtml: reportHtml

      };



      setMessages(prev => [...prev, assistantMessage]);

      showToast('Case Forensic Report generated successfully!');

    } catch (err) {

      clearInterval(stepInterval);

      console.error('Error generating report:', err);

      const fallbackReport = {

        case_id: activeCaseId,

        tenant_id: 'default',

        generated_at: new Date().toISOString(),

        findings: caseFindings || [],

        evidence_files: caseEvidence || [],

        timeline: [],

        executive_summary: `Forensic report draft for Case ${activeCaseId}. Includes ${caseEvidence.length} evidence artifact(s) and ${caseFindings.length} finding(s) cataloged in case context.`

      };

      const assistantMessage = {

        id: (Date.now() + 1).toString(),

        sender: 'assistant',

        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),

        text: `Forensic Investigation Report for Case **${activeCaseId}**.`,

        isReport: true,

        reportData: fallbackReport,

        reportHtml: generateHtmlFromReportData(fallbackReport)

      };

      setMessages(prev => [...prev, assistantMessage]);

      showToast('Report generated from case context.');

    } finally {

      clearInterval(stepInterval);

      setLoading(false);

      setGeneratingReport(false);

      setTimeout(() => inputRef.current?.focus(), 100);

    }

  };



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



    // Intercept report requests to render official case forensic report

    if (isReportRequest(rawQuery)) {

      handleGenerateReport(rawQuery);

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

      const historyPayload = messages.slice(-6).map(m => ({
        role: m.sender === 'user' ? 'user' : 'assistant',
        content: typeof m.text === 'string' ? m.text : ''
      })).filter(h => h.content && !h.content.trim().startsWith('{'));
      const res = await queryCase(activeCaseId, rawQuery, historyPayload);

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

        injection_flagged: null,

        injection_score: null,

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



    // If user is an analyst, generate report directly in assistant view

    if (currentUser?.role === 'analyst') {

      showToast('Compiling Forensic Report in AI Assistant...');

      handleGenerateReport(`Generate updated Case Forensic Report for ${activeCaseId}`);

      return;

    }



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

    { label: '📑 Generate Case Report', query: 'generate report' },

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

            borderRadius: '16px',

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

  const themeStyles = {

    bg: 'var(--glass-dash-bg)',

    cardBg: 'var(--glass-dash-surface-gradient)',

    topbarBg: 'var(--glass-dash-surface-gradient)',

    topbarBorder: 'var(--glass-dash-border)',

    border: 'var(--glass-dash-border)',

    borderLight: 'var(--glass-dash-border-subtle)',

    textMain: 'var(--glass-dash-text-main)',

    textMuted: 'var(--glass-dash-text-muted)',

    inputBg: 'var(--glass-dash-surface-nested)',

    cardSubtle: 'var(--glass-dash-surface-nested)',

    assistantBubbleBg: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(255, 255, 255, 0.65)',

    assistantBubbleBorder: 'var(--glass-dash-border)',

    userBubbleBg: 'linear-gradient(135deg, #2563eb, #1d4ed8)',

    userBubbleText: '#ffffff',

    drawerBg: 'var(--glass-dash-surface-gradient)'

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



      {/* FLOATING TOPBAR CAPSULE */}

      <header className="glass-topbar-capsule topbar">

        <div className="glass-topbar-left" style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', gap: '14px' }}>

          <div style={{

            width: '38px',

            height: '38px',

            borderRadius: '12px',

            background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',

            display: 'flex',

            alignItems: 'center',

            justifyContent: 'center',

            color: '#ffffff',

            boxShadow: '0 4px 14px rgba(59, 130, 246, 0.35)',

            flexShrink: 0

          }}>

            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>

            </svg>

          </div>

          <div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>

              <h2 className="glass-welcome-title" style={{ margin: 0, fontSize: '15px', fontWeight: 700 }}>

                AI Investigation Assistant

              </h2>

              {activeCaseId && (

                <span style={{

                  fontSize: '11px',

                  fontWeight: 700,

                  color: 'var(--glass-dash-blue)',

                  background: 'var(--glass-dash-blue-soft)',

                  border: '1px solid var(--glass-dash-blue-border)',

                  padding: '2px 10px',

                  borderRadius: '9999px',

                  whiteSpace: 'nowrap'

                }}>

                  Case: {activeCaseId}

                </span>

              )}

            </div>

            <p className="glass-welcome-sub" style={{ margin: 0, fontSize: '11px', opacity: 0.75 }}>

              Autonomous multi-agent forensic reasoning &amp; evidence correlation

            </p>

          </div>

        </div>



        {/* Topbar Controls */}

        <div className="glass-topbar-right topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>

          {/* Drawer Toggle */}

          <button

            type="button"

            onClick={() => setDrawerOpen(!drawerOpen)}

            title="Toggle Case Artifacts Drawer"

            className="btn-outline"

            style={{

              display: 'inline-flex',

              alignItems: 'center',

              justifyContent: 'center',

              gap: '8px',

              height: '34px',

              padding: '0 16px',

              fontSize: '12.5px',

              fontWeight: 600,

              letterSpacing: '0.15px',

              borderRadius: '9999px',

              cursor: 'pointer',

              transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',

              background: isDark ? 'rgba(255, 255, 255, 0.06)' : '#ffffff',

              color: isDark ? '#f1f5f9' : '#0f172a',

              border: isDark ? '1px solid rgba(255, 255, 255, 0.14)' : '1px solid rgba(0, 0, 0, 0.12)',

              boxShadow: isDark ? '0 2px 6px rgba(0, 0, 0, 0.2)' : '0 1px 3px rgba(0, 0, 0, 0.06)'

            }}

          >

            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>

              <rect x="3" y="3" width="18" height="18" rx="3" ry="3"></rect>

              <line x1="15" y1="3" x2="15" y2="21"></line>

            </svg>

            <span>{drawerOpen ? 'Hide Artifacts' : 'Case Artifacts'}</span>

          </button>



          {/* Clear */}

          <button

            type="button"

            onClick={handleClearChat}

            title="Clear Conversation"

            className="btn-outline"

            style={{

              display: 'inline-flex',

              alignItems: 'center',

              justifyContent: 'center',

              gap: '8px',

              height: '34px',

              padding: '0 16px',

              fontSize: '12.5px',

              fontWeight: 600,

              letterSpacing: '0.15px',

              borderRadius: '9999px',

              cursor: 'pointer',

              transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',

              background: isDark ? 'rgba(255, 255, 255, 0.06)' : '#ffffff',

              color: isDark ? '#94a3b8' : '#475569',

              border: isDark ? '1px solid rgba(255, 255, 255, 0.14)' : '1px solid rgba(0, 0, 0, 0.12)',

              boxShadow: isDark ? '0 2px 6px rgba(0, 0, 0, 0.2)' : '0 1px 3px rgba(0, 0, 0, 0.06)'

            }}

          >

            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>

              <polyline points="3 6 5 6 21 6"></polyline>

              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>

            </svg>

            <span>Clear</span>

          </button>



          {/* Theme Toggle */}

          <button

            type="button"

            className="glass-icon-btn icon-btn"

            onClick={toggleTheme}

            title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}

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



          <NotificationMenu />

        </div>

      </header>



      {/* Main Workspace Layout */}

      <main className="main-content chatbot-layout">

        {!activeCaseId ? (

          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px' }}>

            <CaseNotAssigned />

          </div>

        ) : (

          <>

        {/* CENTER CHAT COLUMN */}

        <div style={{

          flex: 1,

          minWidth: 0,

          display: 'flex',

          flexDirection: 'column',

          height: '100%',

          overflow: 'hidden'

        }}>





          {/* Evidence context strip */}

          <div style={{

            display: 'flex',

            alignItems: 'center',

            justifyContent: 'space-between',

            gap: '12px',

            flexWrap: 'wrap',

            padding: '10px 22px',

            background: 'var(--glass-dash-surface-nested)',

            border: '1px solid var(--glass-dash-border-subtle)',

            borderRadius: '9999px',

            fontSize: '11.5px',

            marginBottom: '14px',

            backdropFilter: 'blur(16px)',

            flexShrink: 0

          }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--glass-dash-text-muted)' }}>

              <span style={{

                width: '7px',

                height: '7px',

                borderRadius: '50%',

                background: contextLoading ? '#f59e0b' : '#10b981',

                display: 'inline-block'

              }} />

              <span style={{ fontWeight: 600 }}>{contextLoading ? 'Loading case records...' : 'Case context loaded'}</span>

              <span style={{ opacity: 0.4 }}>•</span>

              <span>{caseFindings.length} finding record{caseFindings.length === 1 ? '' : 's'}</span>

              <span style={{ opacity: 0.4 }}>•</span>

              <span>{caseEvidence.length} evidence record{caseEvidence.length === 1 ? '' : 's'}</span>

            </div>

            <div style={{

              color: '#f59e0b',

              background: 'rgba(245, 158, 11, 0.12)',

              border: '1px solid rgba(245, 158, 11, 0.3)',

              padding: '3px 12px',

              borderRadius: '9999px',

              fontWeight: 700,

              fontSize: '11px'

            }}>

              Evidence-grounded · No unsupported fallback claims

            </div>

          </div>



          {/* CHAT MESSAGES SCROLLER */}

          <div style={{

            flex: 1,

            minHeight: 0,

            overflowY: 'auto',

            padding: '16px 20px',

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

                      borderRadius: '12px',

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

                        padding: '10px 14px',

                        borderRadius: '14px',

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

                      padding: msg.isReport ? '0' : '24px 28px',

                      borderRadius: '24px',

                      background: msg.isReport ? 'transparent' : (isUser ? 'linear-gradient(135deg, rgba(37, 99, 235, 0.35) 0%, rgba(29, 78, 216, 0.2) 100%)' : 'var(--glass-dash-surface-gradient)'),

                      backdropFilter: msg.isReport ? 'none' : 'blur(28px) saturate(190%)',

                      WebkitBackdropFilter: msg.isReport ? 'none' : 'blur(28px) saturate(190%)',

                      border: msg.isReport ? 'none' : `1px solid ${isUser ? 'rgba(59, 130, 246, 0.45)' : 'var(--glass-dash-border)'}`,

                      boxShadow: msg.isReport ? 'none' : (isUser ? '0 8px 24px rgba(37, 99, 235, 0.25)' : 'var(--glass-dash-shadow-card)'),

                      color: isUser ? '#ffffff' : 'var(--glass-dash-text-main)',

                      fontSize: '13.5px',

                      lineHeight: '1.65',

                      wordBreak: 'break-word',

                      width: '100%'

                    }}>

                      {msg.isReport ? (

                        <CaseReportCard

                          reportData={msg.reportData}

                          reportHtml={msg.reportHtml}

                          isDark={isDark}

                          themeStyles={themeStyles}

                          onPreviewHtml={(html) => {

                            setActiveModalReportHtml(html);

                            setReportModalOpen(true);

                          }}

                          onDownloadHtml={handleDownloadHtml}

                          onDownloadJson={handleDownloadJson}

                          onDownloadPdf={handleDownloadPdf}

                          onSaveToNotes={handleSaveToNotes}

                          showToast={showToast}

                        />

                      ) : (

                        renderFormattedText(msg.text)

                      )}

                    </div>



                    {/* Action Bar */}

                    {!isUser && !msg.isReport && (

                      <div style={{

                        display: 'flex',

                        alignItems: 'center',

                        gap: '8px',

                        marginTop: '12px'

                      }}>

                        <button

                          type="button"

                          onClick={() => handleCopyText(msg.text)}

                          className="btn-outline"

                          style={{

                            padding: '4px 12px',

                            fontSize: '11.5px',

                            gap: '6px'

                          }}

                        >

                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>

                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>

                          </svg>

                          <span>Copy</span>

                        </button>



                        <button

                          type="button"

                          onClick={() => handleSaveToNotes(msg.text)}

                          className="btn-outline"

                          style={{

                            padding: '4px 12px',

                            fontSize: '11.5px',

                            gap: '6px'

                          }}

                        >

                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

                            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>

                            <polyline points="17 21 17 13 7 13 7 21"></polyline>

                            <polyline points="7 3 7 8 15 8"></polyline>

                          </svg>

                          <span>Save to Notes</span>

                        </button>



                        <button

                          type="button"

                          onClick={() => handleAddToReport(msg.text)}

                          className="btn-outline"

                          style={{

                            padding: '4px 12px',

                            fontSize: '11.5px',

                            gap: '6px'

                          }}

                        >

                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

                            <polyline points="14 2 14 8 20 8"></polyline>

                            <line x1="12" y1="18" x2="12" y2="12"></line>

                            <line x1="9" y1="15" x2="15" y2="15"></line>

                          </svg>

                          <span>Add to Report</span>

                        </button>

                      </div>

                    )}

                  </div>



                  {/* User Avatar */}

                  {isUser && (

                    <div style={{

                      width: '36px',

                      height: '36px',

                      borderRadius: '12px',

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

                  borderRadius: '12px',

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

                  borderRadius: '20px 20px 20px 6px',

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

            padding: '8px 4px',

            display: 'flex',

            gap: '8px',

            overflowX: 'auto',

            whiteSpace: 'nowrap',

            scrollbarWidth: 'none',

            flexShrink: 0

          }}>

            {SUGGESTED_PROMPTS.map((p, idx) => (

              <button

                key={idx}

                type="button"

                disabled={loading}

                onClick={() => handleSendQuery(p.query)}

                className="btn-outline"

                style={{

                  padding: '7px 16px',

                  fontSize: '12px',

                  fontWeight: 600,

                  gap: '6px',

                  flexShrink: 0,

                  cursor: loading ? 'not-allowed' : 'pointer'

                }}

              >

                {p.label}

              </button>

            ))}

          </div>



          {/* FLOATING GLASS INPUT DOCK */}

          <div style={{

            padding: '10px 0 4px 0',

            flexShrink: 0

          }}>

            <form

              onSubmit={(e) => {

                e.preventDefault();

                handleSendQuery();

              }}

              className="chatbot-input-capsule"

            >

              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--glass-dash-blue)" strokeWidth="2" style={{ flexShrink: 0, opacity: 0.85, marginRight: '4px' }}>

                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>

              </svg>

              <input

                ref={inputRef}

                type="text"

                className="chatbot-input-field"

                placeholder={activeCaseId ? `Query Case ${activeCaseId} findings, telemetry, hashes, or MITRE tactics...` : 'Type your forensic query...'}

                value={inputQuery}

                onChange={(e) => setInputQuery(e.target.value)}

                disabled={!activeCaseId || loading}

              />



              <button

                type="submit"

                disabled={!activeCaseId || loading || !inputQuery.trim()}

                className="btn-primary"

                style={{

                  padding: '10px 24px',

                  fontSize: '13.5px',

                  gap: '8px',

                  flexShrink: 0,

                  opacity: (!activeCaseId || loading || !inputQuery.trim()) ? 0.45 : 1,

                  cursor: (!activeCaseId || loading || !inputQuery.trim()) ? 'not-allowed' : 'pointer'

                }}

              >

                <span>Ask</span>

                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">

                  <line x1="22" y1="2" x2="11" y2="13"></line>

                  <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>

                </svg>

              </button>

            </form>

            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 18px 0 18px', fontSize: '11px', color: 'var(--glass-dash-text-muted)' }}>

              <span>Deterministic forensic grounding &amp; DeBERTa-v3 injection screening active.</span>

              <span>Press Enter to send</span>

            </div>

          </div>

        </div>



        {/* RIGHT COLLAPSIBLE DRAWER: Case Artifacts & Evidence Inspector */}

        {drawerOpen && (

          <aside style={{

            width: '340px',

            background: 'var(--glass-dash-surface-gradient)',

            backdropFilter: 'blur(28px) saturate(190%)',

            WebkitBackdropFilter: 'blur(28px) saturate(190%)',

            border: '1px solid var(--glass-dash-border)',

            borderRadius: '24px',

            boxShadow: 'var(--glass-dash-shadow-card)',

            display: 'flex',

            flexDirection: 'column',

            height: '100%',

            overflowY: 'auto',

            padding: '22px',

            gap: '18px',

            flexShrink: 0

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

              borderRadius: '18px',

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

                  borderRadius: '14px',

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

                  borderRadius: '14px',

                  textAlign: 'center'

                }}>

                  <div style={{ fontSize: '16px', fontWeight: 800, color: '#ef4444' }}>

                    {caseFindings.length}

                  </div>

                  <div style={{ fontSize: '10px', color: themeStyles.textMuted }}>Triaged Findings</div>

                </div>

              </div>

            </div>



            {/* Case Forensic Report Card in Drawer */}

            <div style={{

              background: themeStyles.cardBg,

              border: `1px solid ${themeStyles.border}`,

              borderRadius: '18px',

              padding: '14px',

              display: 'flex',

              flexDirection: 'column',

              gap: '10px'

            }}>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>

                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--glass-dash-blue)" strokeWidth="2">

                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

                    <polyline points="14 2 14 8 20 8"></polyline>

                    <line x1="16" y1="13" x2="8" y2="13"></line>

                    <line x1="16" y1="17" x2="8" y2="17"></line>

                  </svg>

                  <span style={{ fontSize: '11px', fontWeight: 700, color: themeStyles.textMain, textTransform: 'uppercase', letterSpacing: '0.5px' }}>

                    Forensic Case Report

                  </span>

                </div>

                <span style={{

                  fontSize: '10px',

                  color: '#10b981',

                  background: 'rgba(16, 185, 129, 0.12)',

                  padding: '2px 8px',

                  borderRadius: '8px',

                  fontWeight: 700

                }}>

                  READY

                </span>

              </div>

              <p style={{ margin: 0, fontSize: '11px', color: themeStyles.textMuted, lineHeight: '1.4' }}>

                Generate legal-grade case forensic report package directly in this assistant.

              </p>

              <button

                type="button"

                onClick={() => handleGenerateReport()}

                disabled={generatingReport}

                className="btn-primary"

                style={{

                  padding: '8px 12px',

                  fontSize: '11.5px',

                  fontWeight: 600,

                  gap: '6px',

                  justifyContent: 'center',

                  borderRadius: '12px'

                }}

              >

                {generatingReport ? (

                  <>

                    <div className="spinner" style={{ width: '12px', height: '12px', borderWidth: '2px', borderColor: '#ffffff', borderTopColor: 'transparent' }} />

                    <span>Compiling Report...</span>

                  </>

                ) : (

                  <>

                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">

                      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>

                    </svg>

                    <span>Generate Case Report</span>

                  </>

                )}

              </button>

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

                        borderRadius: '14px',

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

                          borderRadius: '14px',

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

                      borderRadius: '9999px',

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

                    borderRadius: '14px',

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

                    borderRadius: '14px',

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

                      borderRadius: '14px',

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

          </>

        )}

      </main>



      {/* Full HTML Report Package Preview Modal */}

      {reportModalOpen && (

        <div style={{

          position: 'fixed',

          inset: 0,

          zIndex: 99999,

          background: 'rgba(0, 0, 0, 0.78)',

          backdropFilter: 'blur(10px)',

          display: 'flex',

          alignItems: 'center',

          justifyContent: 'center',

          padding: '24px'

        }}>

          <div style={{

            width: '95vw',

            maxWidth: '1240px',

            height: '90vh',

            background: isDark ? '#0f172a' : '#ffffff',

            borderRadius: '24px',

            border: `1px solid ${isDark ? '#334155' : '#cbd5e1'}`,

            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.65)',

            display: 'flex',

            flexDirection: 'column',

            overflow: 'hidden'

          }}>

            {/* Modal Top Header */}

            <div style={{

              padding: '16px 24px',

              borderBottom: `1px solid ${isDark ? '#1e293b' : '#e2e8f0'}`,

              display: 'flex',

              alignItems: 'center',

              justifyContent: 'space-between',

              background: isDark ? '#1e293b' : '#f8fafc'

            }}>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>

                <div style={{

                  width: '36px',

                  height: '36px',

                  borderRadius: '10px',

                  background: 'linear-gradient(135deg, #2563eb, #7c3aed)',

                  display: 'flex',

                  alignItems: 'center',

                  justifyContent: 'center',

                  color: '#fff'

                }}>

                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>

                    <polyline points="14 2 14 8 20 8"></polyline>

                  </svg>

                </div>

                <div>

                  <div style={{ fontWeight: 800, fontSize: '15px', color: isDark ? '#f8fafc' : '#0f172a' }}>

                    ARGUS Legal-Grade Forensic Report

                  </div>

                  <div style={{ fontSize: '12px', color: isDark ? '#94a3b8' : '#64748b' }}>

                    Case: <strong style={{ color: '#38bdf8' }}>{activeCaseId}</strong> • Official Case Artifact Package

                  </div>

                </div>

              </div>



              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>

                <button

                  type="button"

                  onClick={() => {

                    const frame = document.getElementById('argus-report-iframe');

                    if (frame && frame.contentWindow) {

                      frame.contentWindow.print();

                    }

                  }}

                  className="btn-outline"

                  style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

                >

                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

                    <polyline points="6 9 6 2 18 2 18 9"></polyline>

                    <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path>

                    <rect x="6" y="14" width="12" height="8"></rect>

                  </svg>

                  <span>Print Report</span>

                </button>



                <button

                  type="button"

                  onClick={() => handleDownloadHtml({ case_id: activeCaseId }, activeModalReportHtml)}

                  className="btn-primary"

                  style={{ padding: '6px 14px', fontSize: '12px', gap: '6px' }}

                >

                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">

                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>

                    <polyline points="7 10 12 15 17 10"></polyline>

                    <line x1="12" y1="15" x2="12" y2="3"></line>

                  </svg>

                  <span>Download HTML</span>

                </button>



                <button

                  type="button"

                  onClick={() => setReportModalOpen(false)}

                  style={{

                    background: 'none',

                    border: 'none',

                    color: isDark ? '#94a3b8' : '#64748b',

                    cursor: 'pointer',

                    fontSize: '18px',

                    padding: '6px 10px',

                    borderRadius: '8px'

                  }}

                >

                  ✕

                </button>

              </div>

            </div>



            {/* Modal Body with embedded iframe */}

            <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>

              <iframe

                id="argus-report-iframe"

                title="Case Forensic Report"

                srcDoc={activeModalReportHtml}

                style={{

                  width: '100%',

                  height: '100%',

                  border: 'none',

                  background: '#ffffff'

                }}

              />

            </div>

          </div>

        </div>

      )}

    </div>

  );

}

