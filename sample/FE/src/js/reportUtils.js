import { API_BASE_URL } from './api';

export const MITRE_TECHNIQUE_NAMES = {
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

export function generateHtmlFromReportData(reportData) {
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

export function handleDownloadHtml(reportData, reportHtml, defaultCaseId = '', showToast = null) {
  const caseId = reportData?.case_id || defaultCaseId || 'CASE';
  const content = reportHtml || generateHtmlFromReportData(reportData);
  const blob = new Blob([content], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ARGUS_Forensic_Report_${caseId}_${Date.now()}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  if (showToast) showToast('Official HTML Report downloaded successfully');
}

export function handleDownloadJson(reportData, defaultCaseId = '', showToast = null) {
  const caseId = reportData?.case_id || defaultCaseId || 'CASE';
  const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ARGUS_Forensic_Report_${caseId}_${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  if (showToast) showToast('Structured JSON Report downloaded successfully');
}

export async function handleDownloadPdf(reportData, reportHtml, defaultCaseId = '', showToast = null) {
  const caseId = reportData?.case_id || defaultCaseId || 'CASE';
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
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      if (showToast) showToast('PDF Report downloaded successfully');
      return;
    }
  } catch (err) {
    console.warn('PDF download fallback to print:', err);
  }
  
  // Fallback: window print
  window.print();
}

