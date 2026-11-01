import React from 'react';
import { safeFormatDateTime } from '../js/dateUtils';

const CaseDescriptionModal = ({ isOpen, onClose, caseData }) => {
  if (!isOpen || !caseData) return null;

  const isOpenStatus = caseData.status === 'open' || caseData.status === 'in_progress';
  const displayName = caseData.name && caseData.name !== caseData.case_id ? caseData.name : 'Unnamed Case';

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        backdropFilter: 'blur(6px)',
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
        className="panel-card"
        style={{
          width: '100%',
          maxWidth: '560px',
          background: 'var(--bg-card, #1e222b)',
          borderRadius: '16px',
          border: '1px solid var(--border-strong, rgba(255, 255, 255, 0.12))',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.45)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'fadeIn 0.2s ease-out',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.08))',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '10px',
                background: 'rgba(59, 130, 246, 0.15)',
                color: '#3b82f6',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
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
              <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--text-main, #ffffff)' }}>
                Case Dossier Details
              </h3>
              <span style={{ fontSize: '12px', color: 'var(--text-muted, #94a3b8)' }}>
                {caseData.case_id}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted, #94a3b8)',
              fontSize: '20px',
              cursor: 'pointer',
              padding: '4px 8px',
              borderRadius: '6px',
              lineHeight: 1,
            }}
            title="Close"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Title & Status */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>
                Case Name
              </div>
              <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-main, #ffffff)', marginTop: '2px' }}>
                {displayName}
              </div>
            </div>
            <span
              style={{
                background: isOpenStatus ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                color: isOpenStatus ? '#10b981' : '#94a3b8',
                border: `1px solid ${isOpenStatus ? 'rgba(16, 185, 129, 0.35)' : 'rgba(148, 163, 184, 0.35)'}`,
                padding: '4px 10px',
                borderRadius: '999px',
                fontSize: '11px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.4px',
              }}
            >
              {caseData.status || 'open'}
            </span>
          </div>

          {/* Metadata Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(2, 1fr)',
              gap: '12px',
              background: 'var(--bg-app, rgba(0, 0, 0, 0.2))',
              padding: '14px',
              borderRadius: '10px',
              border: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.05))',
            }}
          >
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #94a3b8)' }}>Lead Analyst</div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-main, #fff)', marginTop: '2px' }}>
                {caseData.analyst_name || caseData.analyst_id || caseData.created_by || 'Unassigned'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #94a3b8)' }}>Senior Analyst</div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-main, #fff)', marginTop: '2px' }}>
                {caseData.senior_analyst_name || caseData.senior_analyst_id || 'Unassigned'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #94a3b8)' }}>Created Timestamp</div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-main, #fff)', marginTop: '2px' }}>
                {safeFormatDateTime(caseData.created_at)}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #94a3b8)' }}>Tenant Isolation</div>
              <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-main, #fff)', marginTop: '2px' }}>
                {caseData.tenant_id || 'default'}
              </div>
            </div>
          </div>

          {/* Description / Closure Reason Box */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted, #94a3b8)', marginBottom: '6px' }}>
              {!isOpenStatus ? 'Case Description & Closure Rationale' : 'Case Description & Investigation Scope'}
            </div>
            <div
              style={{
                padding: '14px 16px',
                borderRadius: '10px',
                background: 'var(--bg-app, rgba(0, 0, 0, 0.2))',
                border: '1px solid var(--border-strong, rgba(255, 255, 255, 0.1))',
                fontSize: '13.5px',
                lineHeight: '1.6',
                color: caseData.description ? 'var(--text-main, #ffffff)' : 'var(--text-muted, #94a3b8)',
                whiteSpace: 'pre-wrap',
                maxHeight: '200px',
                overflowY: 'auto',
              }}
            >
              {caseData.description || 'No detailed case description or closure rationale was provided for this case.'}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '14px 24px',
            borderTop: '1px solid var(--border-subtle, rgba(255, 255, 255, 0.08))',
            display: 'flex',
            justifyContent: 'flex-end',
            background: 'var(--bg-app, rgba(0, 0, 0, 0.1))',
          }}
        >
          <button
            onClick={onClose}
            className="btn btn-secondary"
            style={{
              padding: '8px 20px',
              fontSize: '13px',
              borderRadius: '8px',
              cursor: 'pointer',
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
