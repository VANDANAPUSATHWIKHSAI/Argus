import React from 'react';

const AlertModal = ({ 
  isOpen, 
  title, 
  message, 
  type = 'warning', 
  onClose,
  onConfirm,
  confirmText,
  cancelText = 'Cancel'
}) => {
  if (!isOpen) return null;

  const currentTheme = document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  const isDark = currentTheme === 'dark';

  const config = {
    warning: {
      iconBg: isDark ? 'rgba(245, 158, 11, 0.15)' : 'rgba(245, 158, 11, 0.12)',
      iconColor: '#f59e0b',
      borderAccent: 'rgba(245, 158, 11, 0.3)',
      btnBg: 'linear-gradient(135deg, #d97706 0%, #b45309 100%)',
      btnShadow: '0 4px 12px rgba(217, 119, 6, 0.35)',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      )
    },
    danger: {
      iconBg: isDark ? 'rgba(239, 68, 68, 0.15)' : 'rgba(239, 68, 68, 0.12)',
      iconColor: '#ef4444',
      borderAccent: 'rgba(239, 68, 68, 0.3)',
      btnBg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
      btnShadow: '0 4px 12px rgba(239, 68, 68, 0.35)',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          <line x1="10" y1="11" x2="10" y2="17"></line>
          <line x1="14" y1="11" x2="14" y2="17"></line>
        </svg>
      )
    },
    error: {
      iconBg: isDark ? 'rgba(239, 68, 68, 0.15)' : 'rgba(239, 68, 68, 0.12)',
      iconColor: '#ef4444',
      borderAccent: 'rgba(239, 68, 68, 0.3)',
      btnBg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
      btnShadow: '0 4px 12px rgba(239, 68, 68, 0.35)',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="15" y1="9" x2="9" y2="15"></line>
          <line x1="9" y1="9" x2="15" y2="15"></line>
        </svg>
      )
    },
    info: {
      iconBg: isDark ? 'rgba(59, 130, 246, 0.15)' : 'rgba(37, 99, 235, 0.1)',
      iconColor: isDark ? '#60a5fa' : '#2563eb',
      borderAccent: 'rgba(37, 99, 235, 0.25)',
      btnBg: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
      btnShadow: '0 4px 14px rgba(37, 99, 235, 0.35)',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="16" x2="12" y2="12"></line>
          <line x1="12" y1="8" x2="12.01" y2="8"></line>
        </svg>
      )
    },
    success: {
      iconBg: isDark ? 'rgba(16, 185, 129, 0.15)' : 'rgba(16, 185, 129, 0.12)',
      iconColor: '#10b981',
      borderAccent: 'rgba(16, 185, 129, 0.3)',
      btnBg: 'linear-gradient(135deg, #059669 0%, #10b981 100%)',
      btnShadow: '0 4px 12px rgba(16, 185, 129, 0.35)',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
      )
    }
  };

  const currentConfig = config[type] || config.info;
  const resolvedConfirmText = confirmText || (onConfirm ? 'Confirm' : 'Acknowledge');

  return (
    <div 
      onClick={(e) => {
        if (e.target === e.currentTarget && onClose) onClose();
      }}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'transparent',
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
        @keyframes argusSlidePop { from { opacity: 0; transform: scale(0.96) translateY(6px); } to { opacity: 1; transform: scale(1) translateY(0); } }
      `}</style>
      
      <div 
        style={{
          background: isDark ? '#181e2b' : '#ffffff',
          color: isDark ? '#f8fafc' : '#0f172a',
          padding: '24px 28px',
          borderRadius: '16px',
          width: '420px',
          maxWidth: '100%',
          boxShadow: isDark
            ? '0 20px 40px -8px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.1)'
            : '0 20px 40px -8px rgba(0, 0, 0, 0.14), 0 0 0 1px rgba(0, 0, 0, 0.08)',
          animation: 'argusSlidePop 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          position: 'relative',
          boxSizing: 'border-box'
        }}
      >
        {/* Close (X) button */}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{
              position: 'absolute',
              top: '16px',
              right: '16px',
              background: 'transparent',
              border: 'none',
              color: isDark ? '#94a3b8' : '#64748b',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.06)';
              e.currentTarget.style.color = isDark ? '#ffffff' : '#0f172a';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = isDark ? '#94a3b8' : '#64748b';
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        )}

        {/* Header: Icon + Title */}
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '14px', gap: '14px' }}>
          <div style={{
            background: currentConfig.iconBg,
            color: currentConfig.iconColor,
            border: `1px solid ${currentConfig.borderAccent}`,
            width: '42px',
            height: '42px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            {currentConfig.icon}
          </div>
          <h3 style={{ margin: 0, color: isDark ? '#f8fafc' : '#0f172a', fontSize: '17px', fontWeight: 700, letterSpacing: '-0.2px' }}>
            {title || "Alert"}
          </h3>
        </div>
        
        {/* Body Message */}
        <p style={{
          margin: '0 0 22px 0',
          color: isDark ? '#94a3b8' : '#475569',
          fontSize: '13.5px',
          lineHeight: '1.6',
          fontWeight: 400
        }}>
          {message}
        </p>

        {/* Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
          {onConfirm && (
            <button 
              type="button"
              onClick={onClose}
              style={{
                background: isDark ? 'rgba(255, 255, 255, 0.06)' : '#f1f5f9',
                color: isDark ? '#cbd5e1' : '#475569',
                border: isDark ? '1px solid rgba(255, 255, 255, 0.12)' : '1px solid rgba(0, 0, 0, 0.1)',
                padding: '8px 18px',
                borderRadius: '9999px',
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: '13px',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.1)' : '#e2e8f0';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = isDark ? 'rgba(255, 255, 255, 0.06)' : '#f1f5f9';
              }}
            >
              {cancelText}
            </button>
          )}
          <button 
            type="button"
            onClick={onConfirm || onClose}
            style={{
              background: currentConfig.btnBg,
              color: '#ffffff',
              border: 'none',
              padding: '8px 22px',
              borderRadius: '9999px',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '13px',
              letterSpacing: '0.15px',
              boxShadow: currentConfig.btnShadow,
              transition: 'all 0.15s ease'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-1px)';
              e.currentTarget.style.filter = 'brightness(1.06)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.filter = 'none';
            }}
          >
            {resolvedConfirmText}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlertModal;
