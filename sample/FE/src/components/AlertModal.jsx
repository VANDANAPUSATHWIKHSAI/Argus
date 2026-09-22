import React from 'react';

const AlertModal = ({ isOpen, title, message, type = 'warning', onClose }) => {
  if (!isOpen) return null;

  const config = {
    warning: {
      bg: 'var(--orange-light, #ffedd5)',
      color: 'var(--orange, #ea580c)',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      )
    },
    info: {
      bg: 'var(--blue-light, #dbeafe)',
      color: 'var(--blue, #2563eb)',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="16" x2="12" y2="12"></line>
          <line x1="12" y1="8" x2="12.01" y2="8"></line>
        </svg>
      )
    },
    success: {
      bg: 'var(--green-light, #d1fae5)',
      color: 'var(--green, #059669)',
      icon: (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
      )
    }
  };

  const currentConfig = config[type] || config.warning;

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)', zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      animation: 'fadeIn 0.2s ease'
    }}>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
      <div style={{
        background: 'var(--bg-card)', 
        padding: '24px', 
        borderRadius: '12px', 
        width: '400px', 
        maxWidth: '90%',
        boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
        border: '1px solid var(--border-subtle)',
        animation: 'slideUp 0.3s ease'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '16px', gap: '12px' }}>
          <div style={{
            background: currentConfig.bg, 
            color: currentConfig.color, 
            width: '40px', height: '40px', 
            borderRadius: '50%', 
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0
          }}>
            {currentConfig.icon}
          </div>
          <h3 style={{ margin: 0, color: 'var(--text-main)', fontSize: '18px', fontWeight: 600 }}>
            {title || "Alert"}
          </h3>
        </div>
        
        <p style={{ margin: '0 0 24px 0', color: 'var(--text-muted)', fontSize: '14px', lineHeight: '1.5' }}>
          {message}
        </p>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button 
            onClick={onClose}
            style={{
              background: 'var(--blue)', 
              color: '#fff', 
              border: 'none', 
              padding: '8px 24px', 
              borderRadius: '6px', 
              cursor: 'pointer',
              fontWeight: 500,
              fontSize: '14px',
              transition: 'background 0.2s'
            }}
            onMouseOver={(e) => e.currentTarget.style.background = 'var(--blue-dark, #1d4ed8)'}
            onMouseOut={(e) => e.currentTarget.style.background = 'var(--blue)'}
          >
            Acknowledge
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlertModal;
