import React, { useEffect } from 'react';
import { safeFormatDateTime } from '../js/dateUtils';
import { isCaseReportGenerated } from '../js/caseUtils';

const CaseDescriptionModal = ({ isOpen, onClose, caseData }) => {
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !caseData) return null;

  const currentTheme =
    (typeof document !== 'undefined' && document.documentElement.getAttribute('data-theme')) ||
    (typeof localStorage !== 'undefined' && localStorage.getItem('argus_theme')) ||
    'dark';
  const isDark = currentTheme === 'dark';

  const isOpenStatus = caseData.status === 'open' || caseData.status === 'in_progress';
  const displayName = caseData.name && caseData.name !== caseData.case_id ? caseData.name : 'Unnamed Case';

  const closureReason =
    caseData.closed_reason ||
    caseData.closure_reason ||
    (typeof localStorage !== 'undefined' && caseData.case_id && localStorage.getItem(`argus_case_${caseData.case_id}_closed_reason`)) ||
    (!isOpenStatus && caseData.description ? caseData.description : null);

  const hasReport = isCaseReportGenerated(caseData);

  return (
    <div
      className="modal-overlay"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'transparent',
        backdropFilter: 'none',
        WebkitBackdropFilter: 'none',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="modal-content"
        style={{
          width: '100%',
          maxWidth: '540px',
          height: 'auto',
          maxHeight: '90vh',
          background: isDark ? '#181a20' : '#ffffff',
          borderRadius: '20px',
          border: isDark ? '1px solid rgba(255, 255, 255, 0.14)' : '1px solid rgba(0, 0, 0, 0.1)',
          boxShadow: isDark
            ? '0 25px 60px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.05)'
            : '0 20px 50px rgba(0, 0, 0, 0.18), 0 0 0 1px rgba(0, 0, 0, 0.05)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'fadeIn 0.2s ease-out',
          color: isDark ? '#f8fafc' : '#0f172a',
          padding: 0,
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '18px 24px',
            borderBottom: isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(0, 0, 0, 0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '11px',
                background: isDark ? 'rgba(59, 130, 246, 0.15)' : 'rgba(37, 99, 235, 0.1)',
                color: isDark ? '#60a5fa' : '#2563eb',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
                <polyline points="10 9 9 9 8 9"></polyline>
              </svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: isDark ? '#f8fafc' : '#0f172a' }}>
                Case Dossier Details
              </h3>
              <span
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  fontFamily: 'monospace',
                  color: isDark ? '#94a3b8' : '#64748b',
                }}
              >
                {caseData.case_id}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{
              background: isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(15, 23, 42, 0.05)',
              border: isDark ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid rgba(0, 0, 0, 0.08)',
              color: isDark ? '#94a3b8' : '#64748b',
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 0,
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.1)';
              e.currentTarget.style.color = isDark ? '#ffffff' : '#0f172a';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(15, 23, 42, 0.05)';
              e.currentTarget.style.color = isDark ? '#94a3b8' : '#64748b';
            }}
            title="Close"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        {/* Scrollable Body */}
        <div
          style={{
            padding: '22px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '18px',
            overflowY: 'auto',
            maxHeight: 'calc(90vh - 130px)',
          }}
        >
          {/* Title & Status */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
            <div>
              <div
                style={{
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.6px',
                  color: isDark ? '#94a3b8' : '#64748b',
                  fontWeight: 700,
                }}
              >
                Case Name
              </div>
              <div
                style={{
                  fontSize: '17px',
                  fontWeight: 700,
                  color: isDark ? '#f8fafc' : '#0f172a',
                  marginTop: '3px',
                }}
              >
                {displayName}
              </div>
            </div>
            <span
              style={{
                background: isOpenStatus ? 'rgba(16, 185, 129, 0.12)' : 'rgba(148, 163, 184, 0.12)',
                color: isOpenStatus ? '#10b981' : (isDark ? '#94a3b8' : '#64748b'),
                border: `1px solid ${isOpenStatus ? 'rgba(16, 185, 129, 0.3)' : (isDark ? 'rgba(148, 163, 184, 0.3)' : 'rgba(100, 116, 139, 0.25)')}`,
                padding: '5px 12px',
                borderRadius: '999px',
                fontSize: '11px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: isOpenStatus ? '#10b981' : '#94a3b8',
                }}
              />
              {caseData.status || 'open'}
            </span>
          </div>

          {/* Metadata Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(2, 1fr)',
              gap: '14px',
              background: isDark ? 'rgba(255, 255, 255, 0.03)' : 'rgba(241, 245, 249, 0.75)',
              padding: '16px',
              borderRadius: '14px',
              border: isDark ? '1px solid rgba(255, 255, 255, 0.07)' : '1px solid rgba(226, 232, 240, 0.9)',
            }}
          >
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: isDark ? '#94a3b8' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Lead Analyst</div>
              <div style={{ fontSize: '13.5px', fontWeight: 600, color: isDark ? '#f1f5f9' : '#1e293b', marginTop: '3px' }}>
                {caseData.analyst_name || caseData.analyst_id || caseData.created_by || 'Unassigned'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: isDark ? '#94a3b8' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Senior Analyst</div>
              <div style={{ fontSize: '13.5px', fontWeight: 600, color: isDark ? '#f1f5f9' : '#1e293b', marginTop: '3px' }}>
                {caseData.senior_analyst_name || caseData.senior_analyst_id || 'Unassigned'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: isDark ? '#94a3b8' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Created Timestamp</div>
              <div style={{ fontSize: '13.5px', fontWeight: 600, color: isDark ? '#f1f5f9' : '#1e293b', marginTop: '3px' }}>
                {safeFormatDateTime(caseData.created_at)}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: isDark ? '#94a3b8' : '#64748b', textTransform: 'uppercase', letterSpacing: '0.4px' }}>Tenant Isolation</div>
              <div style={{ fontSize: '13.5px', fontWeight: 600, color: isDark ? '#f1f5f9' : '#1e293b', marginTop: '3px' }}>
                {caseData.tenant_id || 'default'}
              </div>
            </div>
          </div>

          {/* If Closed: Prominent Closure Reason Section */}
          {!isOpenStatus && (
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '8px',
                  gap: '8px'
                }}
              >
                <div
                  style={{
                    fontSize: '12px',
                    fontWeight: 700,
                    color: isDark ? '#f87171' : '#dc2626',
                    textTransform: 'uppercase',
                    letterSpacing: '0.4px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                  </svg>
                  Closure Reason
                </div>
                {!hasReport && (
                  <span
                    style={{
                      fontSize: '10.5px',
                      fontWeight: 700,
                      color: '#f59e0b',
                      background: isDark ? 'rgba(245, 158, 11, 0.15)' : 'rgba(245, 158, 11, 0.12)',
                      border: '1px solid rgba(245, 158, 11, 0.3)',
                      padding: '2px 8px',
                      borderRadius: '6px',
                      textTransform: 'uppercase',
                      letterSpacing: '0.3px'
                    }}
                  >
                    Closed Before Report Generation
                  </span>
                )}
              </div>
              <div
                style={{
                  padding: '16px 18px',
                  borderRadius: '14px',
                  background: isDark ? 'rgba(239, 68, 68, 0.08)' : 'rgba(239, 68, 68, 0.05)',
                  border: isDark ? '1px solid rgba(239, 68, 68, 0.25)' : '1px solid rgba(239, 68, 68, 0.2)',
                  fontSize: '13.5px',
                  lineHeight: '1.65',
                  color: closureReason ? (isDark ? '#f8fafc' : '#0f172a') : (isDark ? '#94a3b8' : '#64748b'),
                  fontWeight: closureReason ? 500 : 400,
                  fontStyle: closureReason ? 'normal' : 'italic',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '180px',
                  overflowY: 'auto'
                }}
              >
                {closureReason || 'No closure rationale was recorded for this case.'}
              </div>
            </div>
          )}

          {/* Case Scope / Initial Description */}
          {isOpenStatus ? (
            <div>
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  color: isDark ? '#cbd5e1' : '#334155',
                  marginBottom: '8px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.4px',
                }}
              >
                Case Description &amp; Investigation Scope
              </div>
              <div
                style={{
                  padding: '16px 18px',
                  borderRadius: '14px',
                  background: isDark ? 'rgba(255, 255, 255, 0.02)' : 'rgba(248, 250, 252, 0.85)',
                  border: isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(226, 232, 240, 0.9)',
                  fontSize: '13.5px',
                  lineHeight: '1.65',
                  color: caseData.description ? (isDark ? '#f1f5f9' : '#1e293b') : (isDark ? '#94a3b8' : '#64748b'),
                  fontStyle: caseData.description ? 'normal' : 'italic',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '220px',
                  overflowY: 'auto',
                }}
              >
                {caseData.description || 'No detailed case description was provided for this case.'}
              </div>
            </div>
          ) : (
            caseData.description && caseData.description !== closureReason && (
              <div>
                <div
                  style={{
                    fontSize: '11.5px',
                    fontWeight: 700,
                    color: isDark ? '#94a3b8' : '#64748b',
                    marginBottom: '6px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.4px',
                  }}
                >
                  Initial Scope &amp; Background
                </div>
                <div
                  style={{
                    padding: '14px 16px',
                    borderRadius: '12px',
                    background: isDark ? 'rgba(255, 255, 255, 0.02)' : 'rgba(248, 250, 252, 0.85)',
                    border: isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(226, 232, 240, 0.9)',
                    fontSize: '13px',
                    lineHeight: '1.6',
                    color: isDark ? '#cbd5e1' : '#334155',
                    whiteSpace: 'pre-wrap',
                    maxHeight: '140px',
                    overflowY: 'auto'
                  }}
                >
                  {caseData.description}
                </div>
              </div>
            )
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '14px 24px',
            borderTop: isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(0, 0, 0, 0.07)',
            display: 'flex',
            justifyContent: 'flex-end',
            background: isDark ? 'rgba(0, 0, 0, 0.15)' : 'rgba(248, 250, 252, 0.85)',
          }}
        >
          <button
            onClick={onClose}
            type="button"
            style={{
              padding: '8px 22px',
              fontSize: '13px',
              fontWeight: 600,
              borderRadius: '10px',
              cursor: 'pointer',
              background: isDark ? 'rgba(255, 255, 255, 0.08)' : '#ffffff',
              border: isDark ? '1px solid rgba(255, 255, 255, 0.15)' : '1px solid #cbd5e1',
              color: isDark ? '#f8fafc' : '#1e293b',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.14)' : '#f1f5f9';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.08)' : '#ffffff';
            }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default CaseDescriptionModal;
