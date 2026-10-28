import React, { useEffect } from 'react';
import { generateHtmlFromReportData, handleDownloadHtml, handleDownloadJson } from '../js/reportUtils';

export default function GeneratedReportModal({
  isOpen,
  onClose,
  caseId,
  reportData,
  reportHtml
}) {
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const currentTheme = document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  const isDark = currentTheme === 'dark';

  const effectiveHtml = reportHtml || generateHtmlFromReportData(reportData || { case_id: caseId });

  const handlePrint = () => {
    const frame = document.getElementById('argus-modal-report-iframe');
    if (frame && frame.contentWindow) {
      frame.contentWindow.focus();
      frame.contentWindow.print();
    } else {
      window.print();
    }
  };

  return (
    <div 
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 99999,
        background: 'rgba(0, 0, 0, 0.78)',
        backdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px'
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div 
        style={{
          width: '95vw',
          maxWidth: '1280px',
          height: '92vh',
          background: isDark ? '#0f172a' : '#ffffff',
          borderRadius: '20px',
          border: `1px solid ${isDark ? '#334155' : '#cbd5e1'}`,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.65)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden'
        }}
      >
        {/* Top Header */}
        <div 
          style={{
            padding: '16px 24px',
            borderBottom: `1px solid ${isDark ? '#1e293b' : '#e2e8f0'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: isDark ? '#1e293b' : '#f8fafc',
            flexWrap: 'wrap',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '38px',
              height: '38px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 4px 12px rgba(37, 99, 235, 0.35)'
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
              </svg>
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: '15.5px', color: isDark ? '#f8fafc' : '#0f172a', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>Official Forensic Investigation Dossier</span>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '999px',
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: '#10b981',
                  border: '1px solid rgba(16, 185, 129, 0.3)'
                }}>
                  GENERATED
                </span>
              </div>
              <div style={{ fontSize: '12px', color: isDark ? '#94a3b8' : '#64748b' }}>
                Case Reference: <strong style={{ color: '#38bdf8' }}>{caseId}</strong> &middot; Multi-Audience Synthesis
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              type="button"
              onClick={handlePrint}
              className="btn btn-outline"
              style={{
                padding: '7px 14px',
                fontSize: '12.5px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: isDark ? 'rgba(255, 255, 255, 0.05)' : '#ffffff',
                border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.15)' : '#cbd5e1'}`,
                color: isDark ? '#e2e8f0' : '#1e293b',
                borderRadius: '8px',
                cursor: 'pointer',
                fontWeight: 600
              }}
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
              onClick={() => handleDownloadHtml(reportData, effectiveHtml, caseId)}
              className="btn btn-primary"
              style={{
                padding: '7px 14px',
                fontSize: '12.5px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                borderRadius: '8px',
                cursor: 'pointer',
                fontWeight: 600
              }}
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
              onClick={() => handleDownloadJson(reportData, caseId)}
              className="btn btn-outline"
              style={{
                padding: '7px 14px',
                fontSize: '12.5px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: isDark ? 'rgba(255, 255, 255, 0.05)' : '#ffffff',
                border: `1px solid ${isDark ? 'rgba(255, 255, 255, 0.15)' : '#cbd5e1'}`,
                color: isDark ? '#e2e8f0' : '#1e293b',
                borderRadius: '8px',
                cursor: 'pointer',
                fontWeight: 600
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="16 18 22 12 16 6"></polyline>
                <polyline points="8 6 2 12 8 18"></polyline>
              </svg>
              <span>Download JSON</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'none',
                border: 'none',
                color: isDark ? '#94a3b8' : '#64748b',
                cursor: 'pointer',
                fontSize: '18px',
                padding: '6px 10px',
                borderRadius: '8px',
                marginLeft: '6px'
              }}
              title="Close Report (Esc)"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Modal Iframe Body */}
        <div style={{ flex: 1, minHeight: 0, position: 'relative', background: '#f8fafc' }}>
          <iframe
            id="argus-modal-report-iframe"
            title="Generated Forensic Report"
            srcDoc={effectiveHtml}
            style={{
              width: '100%',
              height: '100%',
              border: 'none',
              display: 'block'
            }}
          />
        </div>
      </div>
    </div>
  );
}

