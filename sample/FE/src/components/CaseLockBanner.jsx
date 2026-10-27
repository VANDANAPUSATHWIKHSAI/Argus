import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { syncCaseLock } from '../js/caseLockService';

/**
 * CaseLockBanner
 * =============
 * Renders an informative glass banner when a case is locked by another analyst
 * and currently in Read-Only investigation mode.
 */
const CaseLockBanner = ({ lockState, caseId, onLockRefreshed, compact = false }) => {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(false);

  if (!lockState || !lockState.readOnly) {
    return null;
  }

  const analystName = lockState.lockedBy?.name || 'Another Forensic Analyst';

  const handleRefresh = async () => {
    if (!caseId) return;
    setChecking(true);
    try {
      const refreshed = await syncCaseLock(caseId);
      if (onLockRefreshed) {
        onLockRefreshed(refreshed);
      }
    } finally {
      setChecking(false);
    }
  };

  if (compact) {
    return (
      <div 
        className="case-lock-badge-compact"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          background: 'rgba(245, 158, 11, 0.15)',
          border: '1px solid rgba(245, 158, 11, 0.4)',
          color: '#f59e0b',
          padding: '3px 10px',
          borderRadius: 9999,
          fontSize: 11,
          fontWeight: 800
        }}
        title={`Locked by ${analystName}. Read-Only access.`}
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>READ-ONLY ({analystName})</span>
      </div>
    );
  }

  return (
    <div 
      className="case-lock-banner"
      style={{
        background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.14) 0%, rgba(217, 119, 6, 0.08) 100%)',
        border: '1px solid rgba(245, 158, 11, 0.45)',
        borderRadius: 16,
        padding: '16px 20px',
        marginBottom: 18,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 16,
        boxShadow: '0 8px 24px rgba(245, 158, 11, 0.08)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)'
      }}
      role="alert"
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, maxWidth: '820px' }}>
        <div style={{
          width: 38,
          height: 38,
          borderRadius: 10,
          background: 'rgba(245, 158, 11, 0.2)',
          border: '1px solid rgba(245, 158, 11, 0.5)',
          color: '#f59e0b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0
        }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>

        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{
              background: 'rgba(245, 158, 11, 0.25)',
              color: '#f59e0b',
              fontWeight: 900,
              fontSize: 10.5,
              padding: '1px 7px',
              borderRadius: 6,
              letterSpacing: '0.04em',
              textTransform: 'uppercase'
            }}>
              CASE LOCK IN EFFECT
            </span>
            <strong style={{ fontSize: 14, color: 'var(--text-main)', fontWeight: 800 }}>
              Read-Only Access: Case Under Active Investigation
            </strong>
          </div>
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
            Analyst <strong style={{ color: 'var(--text-main)' }}>{analystName}</strong> is currently investigating this case.
            To preserve forensic integrity and avoid conflicting conclusions, modifications such as running automated agents, uploading artifacts, and altering case notes are disabled.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={checking}
          style={{
            background: 'var(--glass-dash-surface-nested)',
            border: '1px solid rgba(245, 158, 11, 0.35)',
            color: 'var(--text-main)',
            padding: '7px 14px',
            borderRadius: 8,
            fontSize: 12,
            fontWeight: 700,
            cursor: checking ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}
          title="Check if the other analyst has finished or released the lock"
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ animation: checking ? 'spin 1s linear infinite' : 'none' }}>
            <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
          <span>{checking ? 'Checking...' : 'Check Status'}</span>
        </button>

        <button
          type="button"
          onClick={() => navigate('/cases')}
          style={{
            background: 'rgba(245, 158, 11, 0.2)',
            border: '1px solid rgba(245, 158, 11, 0.5)',
            color: '#f59e0b',
            padding: '7px 14px',
            borderRadius: 8,
            fontSize: 12,
            fontWeight: 700,
            cursor: 'pointer'
          }}
        >
          Switch Case
        </button>
      </div>
    </div>
  );
};

export default CaseLockBanner;
