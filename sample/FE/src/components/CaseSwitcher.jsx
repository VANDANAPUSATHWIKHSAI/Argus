import React from 'react';

/**
 * CaseSwitcher
 * Static active case badge.
 * Case switching is intentionally disabled: only one active case can be handled at a time.
 * Displays the current assigned case or "Case Not Assigned" state.
 */
const CaseSwitcher = ({
  cases = [],
  activeCaseId = '',
  id = 'evidence-topbar-case-select',
  placeholder = 'Case Not Assigned',
  style = {},
  buttonStyle = {},
  loading = false
}) => {
  const activeCase = (cases && cases.length > 0)
    ? (cases.find((c) => c.case_id === activeCaseId) || (activeCaseId ? { case_id: activeCaseId } : cases[0]))
    : (activeCaseId ? { case_id: activeCaseId } : null);

  const isAssigned = Boolean(activeCase && activeCase.case_id);

  return (
    <div
      id={id}
      style={{
        position: 'relative',
        display: 'inline-block',
        ...style
      }}
    >
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          background: 'var(--glass-dash-surface-nested, var(--bg-card, rgba(255, 255, 255, 0.08)))',
          color: 'var(--text-main, #f8fafc)',
          border: '1px solid var(--glass-dash-border-subtle, var(--border-subtle, rgba(255, 255, 255, 0.12)))',
          borderRadius: '20px',
          padding: '6px 14px',
          fontSize: '13px',
          fontWeight: 500,
          userSelect: 'none',
          maxWidth: '440px',
          minWidth: 'fit-content',
          whiteSpace: 'nowrap',
          ...buttonStyle
        }}
      >
        {loading ? (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted, #94a3b8)' }}>
            <span className="spinner" style={{ width: '12px', height: '12px', borderWidth: '1.5px' }}></span>
            Loading case...
          </span>
        ) : isAssigned ? (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              minWidth: 0
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: 'var(--glass-dash-green, #10b981)',
                boxShadow: '0 0 6px var(--glass-dash-green, #10b981)',
                flexShrink: 0
              }}
            />
            <span
              style={{
                fontFamily: 'var(--glass-dash-mono, monospace)',
                fontWeight: 700,
                color: 'var(--glass-dash-blue, #3b82f6)',
                flexShrink: 0
              }}
            >
              {activeCase.case_id}
            </span>
            {activeCase.name && activeCase.name !== activeCase.case_id && (
              <>
                <span style={{ color: 'var(--text-muted, #94a3b8)', flexShrink: 0 }}>—</span>
                <span
                  style={{
                    color: 'var(--text-main, #f8fafc)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: '280px'
                  }}
                  title={activeCase.name}
                >
                  {activeCase.name}
                </span>
              </>
            )}
          </span>
        ) : (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted, #94a3b8)' }}>
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: '#64748b',
                flexShrink: 0
              }}
            />
            <span>Case Not Assigned</span>
          </span>
        )}
      </div>
    </div>
  );
};

export default CaseSwitcher;
