import React, { useState, useEffect, useRef } from 'react';

/**
 * Modal dialog that prompts the user to supply a mandatory closure rationale
 * when attempting to close an active forensic case before a report has been generated.
 */
const CloseCaseReasonModal = ({
  isOpen,
  onClose,
  onConfirm,
  caseId,
  caseName,
  isSubmitting = false
}) => {
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const textareaRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      setReason('');
      setError('');
      setTimeout(() => {
        if (textareaRef.current) {
          textareaRef.current.focus();
        }
      }, 50);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && !isSubmitting) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, isSubmitting]);

  if (!isOpen) return null;

  const currentTheme =
    (typeof document !== 'undefined' && document.documentElement.getAttribute('data-theme')) ||
    (typeof localStorage !== 'undefined' && localStorage.getItem('argus_theme')) ||
    'dark';
  const isDark = currentTheme === 'dark';

  const PRESET_REASONS = [
    'False positive investigation',
    'Administrative closure / Out of scope',
    'Duplicate of another active case',
    'Insufficient evidence to proceed',
    'Merged with primary incident'
  ];

  const handleSelectPreset = (preset) => {
    setReason(preset);
    setError('');
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  };

  const handleSubmit = (e) => {
    if (e) e.preventDefault();
    const trimmed = reason.trim();
    if (!trimmed) {
      setError('A valid reason is required to close a case before report generation.');
      if (textareaRef.current) textareaRef.current.focus();
      return;
    }
    setError('');
    onConfirm(trimmed);
  };

  const displayName = caseName && caseName !== caseId ? caseName : (caseId || 'Active Case');

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="close-case-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget && !isSubmitting) onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'transparent',
        backdropFilter: 'none',
        WebkitBackdropFilter: 'none',
        zIndex: 99999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
        animation: 'argusFadeIn 0.15s ease-out'
      }}
    >
      <style>{`
        @keyframes argusFadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes argusPopUp { from { opacity: 0; transform: scale(0.96) translateY(8px); } to { opacity: 1; transform: scale(1) translateY(0); } }
      `}</style>

      <div
        className="modal-content"
        style={{
          width: '100%',
          maxWidth: '520px',
          background: isDark ? '#181a20' : '#ffffff',
          color: isDark ? '#f8fafc' : '#0f172a',
          borderRadius: '20px',
          border: isDark ? '1px solid rgba(255, 255, 255, 0.12)' : '1px solid rgba(0, 0, 0, 0.12)',
          boxShadow: isDark
            ? '0 25px 60px rgba(0, 0, 0, 0.75), 0 0 0 1px rgba(255, 255, 255, 0.05)'
            : '0 20px 50px rgba(0, 0, 0, 0.2), 0 0 0 1px rgba(0, 0, 0, 0.05)',
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          animation: 'argusPopUp 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          padding: 0
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px 16px 24px',
            borderBottom: isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(0, 0, 0, 0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
            <div
              style={{
                width: '40px',
                height: '40px',
                borderRadius: '12px',
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#f59e0b',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div style={{ minWidth: 0 }}>
              <h3
                id="close-case-modal-title"
                style={{
                  margin: 0,
                  fontSize: '17px',
                  fontWeight: 700,
                  color: isDark ? '#f8fafc' : '#0f172a',
                  letterSpacing: '-0.2px'
                }}
              >
                Closure Reason Required
              </h3>
              <div
                style={{
                  fontSize: '12px',
                  color: isDark ? '#94a3b8' : '#64748b',
                  marginTop: '2px',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis'
                }}
              >
                Case: <span style={{ fontWeight: 600, color: isDark ? '#cbd5e1' : '#334155' }}>{displayName}</span> {caseId && caseId !== displayName ? `(${caseId})` : ''}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={isSubmitting}
            type="button"
            aria-label="Close"
            style={{
              background: isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(15, 23, 42, 0.05)',
              border: isDark ? '1px solid rgba(255, 255, 255, 0.1)' : '1px solid rgba(0, 0, 0, 0.08)',
              color: isDark ? '#94a3b8' : '#64748b',
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 0,
              flexShrink: 0
            }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} style={{ margin: 0, display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              padding: '20px 24px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px'
            }}
          >
            {/* Warning callout */}
            <div
              style={{
                background: isDark ? 'rgba(245, 158, 11, 0.08)' : 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.25)',
                borderRadius: '12px',
                padding: '12px 14px',
                display: 'flex',
                gap: '10px',
                alignItems: 'flex-start'
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2" style={{ flexShrink: 0, marginTop: '2px' }}>
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="16" x2="12" y2="12"></line>
                <line x1="12" y1="8" x2="12.01" y2="8"></line>
              </svg>
              <div style={{ fontSize: '12.5px', lineHeight: '1.5', color: isDark ? '#fde68a' : '#92400e' }}>
                A forensic report has <strong>not yet been generated</strong> for this case. Closing before report generation requires an audit-verified reason for chain-of-custody compliance.
              </div>
            </div>

            {/* Quick preset chips */}
            <div>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.4px',
                  color: isDark ? '#94a3b8' : '#64748b',
                  marginBottom: '8px'
                }}
              >
                Suggested Rationale
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {PRESET_REASONS.map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => handleSelectPreset(preset)}
                    disabled={isSubmitting}
                    style={{
                      background: reason === preset
                        ? (isDark ? 'rgba(59, 130, 246, 0.25)' : 'rgba(37, 99, 235, 0.15)')
                        : (isDark ? 'rgba(255, 255, 255, 0.04)' : 'rgba(0, 0, 0, 0.04)'),
                      color: reason === preset
                        ? (isDark ? '#93c5fd' : '#1d4ed8')
                        : (isDark ? '#cbd5e1' : '#475569'),
                      border: reason === preset
                        ? '1px solid rgba(59, 130, 246, 0.5)'
                        : (isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(0, 0, 0, 0.08)'),
                      borderRadius: '8px',
                      padding: '4px 10px',
                      fontSize: '11.5px',
                      fontWeight: 500,
                      cursor: 'pointer',
                      transition: 'all 0.12s ease'
                    }}
                  >
                    {preset}
                  </button>
                ))}
              </div>
            </div>

            {/* Reason Textarea */}
            <div>
              <label
                htmlFor="close-case-reason-textarea"
                style={{
                  display: 'block',
                  fontSize: '12px',
                  fontWeight: 600,
                  color: isDark ? '#f1f5f9' : '#1e293b',
                  marginBottom: '6px'
                }}
              >
                Closure Justification <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <textarea
                id="close-case-reason-textarea"
                ref={textareaRef}
                value={reason}
                onChange={(e) => {
                  setReason(e.target.value);
                  if (error) setError('');
                }}
                disabled={isSubmitting}
                placeholder="Detail why this investigation is being concluded before report export..."
                rows={4}
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  borderRadius: '12px',
                  padding: '12px 14px',
                  fontSize: '13.5px',
                  lineHeight: '1.5',
                  background: isDark ? 'rgba(0, 0, 0, 0.25)' : 'rgba(248, 250, 252, 0.9)',
                  color: isDark ? '#f8fafc' : '#0f172a',
                  border: error
                    ? '1px solid #ef4444'
                    : (isDark ? '1px solid rgba(255, 255, 255, 0.12)' : '1px solid rgba(0, 0, 0, 0.15)'),
                  outline: 'none',
                  resize: 'vertical',
                  fontFamily: 'inherit'
                }}
              />
              {error && (
                <div
                  style={{
                    color: '#ef4444',
                    fontSize: '12px',
                    marginTop: '5px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                  </svg>
                  <span>{error}</span>
                </div>
              )}
            </div>
          </div>

          {/* Footer */}
          <div
            style={{
              padding: '14px 24px',
              borderTop: isDark ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(0, 0, 0, 0.08)',
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '10px',
              background: isDark ? 'rgba(0, 0, 0, 0.15)' : 'rgba(248, 250, 252, 0.85)'
            }}
          >
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              style={{
                padding: '9px 18px',
                fontSize: '13px',
                fontWeight: 600,
                borderRadius: '10px',
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                background: 'transparent',
                border: isDark ? '1px solid rgba(255, 255, 255, 0.12)' : '1px solid rgba(0, 0, 0, 0.12)',
                color: isDark ? '#cbd5e1' : '#475569',
                transition: 'all 0.15s ease'
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !reason.trim()}
              style={{
                padding: '9px 20px',
                fontSize: '13px',
                fontWeight: 600,
                borderRadius: '10px',
                cursor: (isSubmitting || !reason.trim()) ? 'not-allowed' : 'pointer',
                background: (isSubmitting || !reason.trim())
                  ? (isDark ? 'rgba(239, 68, 68, 0.3)' : 'rgba(239, 68, 68, 0.4)')
                  : 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
                color: '#ffffff',
                border: 'none',
                boxShadow: (isSubmitting || !reason.trim()) ? 'none' : '0 4px 12px rgba(239, 68, 68, 0.35)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'all 0.15s ease'
              }}
            >
              {isSubmitting ? (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ animation: 'spin 1s linear infinite' }}>
                    <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                  </svg>
                  <span>Closing...</span>
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                  <span>Confirm &amp; Close Case</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default CloseCaseReasonModal;

