import React from 'react';

/**
 * CaseNotAssigned
 * Reusable full-panel restricted state when a user has no assigned case or
 * attempts to view a case they are not assigned to.
 * Ensures zero case data leakage and renders a clean, professional restricted state.
 */
const CaseNotAssigned = ({
  title = 'Case Not Assigned',
  message = 'You are not assigned to this case. Access is restricted.',
  description = 'Only personnel specifically assigned to an active investigation can view evidence, findings, intelligence graphs, or run agent analysis.',
  style = {}
}) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '80px 24px',
        margin: '24px auto',
        maxWidth: '680px',
        background: 'var(--glass-dash-surface-nested, var(--bg-card, rgba(255, 255, 255, 0.04)))',
        border: '1px solid var(--glass-dash-border-subtle, var(--border-subtle, rgba(255, 255, 255, 0.1)))',
        borderRadius: '20px',
        boxShadow: 'var(--glass-dash-shadow-card, 0 20px 48px -12px rgba(0, 0, 0, 0.45))',
        textAlign: 'center',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        ...style
      }}
    >
      {/* Restricted Shield / Lock Icon */}
      <div
        style={{
          width: '64px',
          height: '64px',
          borderRadius: '50%',
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '20px',
          color: '#ef4444'
        }}
      >
        <svg
          width="28"
          height="28"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      </div>

      {/* Pill Badge */}
      <span
        style={{
          display: 'inline-block',
          padding: '3px 12px',
          borderRadius: '9999px',
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          color: '#f87171',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          marginBottom: '14px'
        }}
      >
        Access Restricted
      </span>

      {/* Primary Title */}
      <h2
        style={{
          fontSize: '22px',
          fontWeight: 700,
          color: 'var(--text-main, #f8fafc)',
          margin: '0 0 10px 0',
          letterSpacing: '-0.01em'
        }}
      >
        {title}
      </h2>

      {/* Message */}
      <p
        style={{
          fontSize: '14.5px',
          fontWeight: 500,
          color: 'var(--text-muted, #94a3b8)',
          margin: '0 0 12px 0',
          maxWidth: '480px',
          lineHeight: 1.5
        }}
      >
        {message}
      </p>

      {/* Detail description */}
      <p
        style={{
          fontSize: '12.5px',
          color: 'var(--text-muted, #64748b)',
          margin: 0,
          maxWidth: '460px',
          lineHeight: 1.6
        }}
      >
        {description}
      </p>
    </div>
  );
};

export default CaseNotAssigned;

