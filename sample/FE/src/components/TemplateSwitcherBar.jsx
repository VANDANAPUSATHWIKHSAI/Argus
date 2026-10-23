import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

export default function TemplateSwitcherBar() {
  const navigate = useNavigate();
  const location = useLocation();

  const templates = [
    {
      id: 'argus-v1',
      path: '/argus-v1',
      badge: '1',
      name: 'Conservative Improvement',
      tagline: 'Preserved structure • Cleaned spacing & hierarchy',
      color: '#3b82f6'
    },
    {
      id: 'argus-v2',
      path: '/argus-v2',
      badge: '2',
      name: 'Refined Improvement',
      tagline: 'Dual Canvas Tabs • Actionable Metrics & Stepper',
      color: '#10b981'
    },
    {
      id: 'argus-v3',
      path: '/argus-v3',
      badge: '3',
      name: 'Ambitious Improvement',
      tagline: 'Multi-Pane Correlation • Integrated Forensic Workbench',
      color: '#8b5cf6'
    }
  ];

  const currentPath = location.pathname;

  return (
    <div style={{
      position: 'sticky',
      top: 0,
      zIndex: 99999,
      background: 'rgba(18, 18, 18, 0.98)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid rgba(255, 255, 255, 0.12)',
      boxShadow: '0 2px 10px rgba(0, 0, 0, 0.5)',
      padding: '7px 16px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '12px',
      fontFamily: "'Poppins', -apple-system, sans-serif"
    }}>
      {/* Brand / Mode Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{
          width: '26px',
          height: '26px',
          borderRadius: '6px',
          background: '#3b82f6',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: '900',
          fontSize: '13px',
          color: '#ffffff'
        }}>
          Λ
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: '700', color: '#f8fafc', letterSpacing: '0.5px' }}>
              ARGUS UI EVOLUTION
            </span>
            <span style={{
              fontSize: '10px',
              padding: '1px 6px',
              borderRadius: '4px',
              background: 'rgba(59, 130, 246, 0.15)',
              color: '#60a5fa',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              fontWeight: '600'
            }}>
              3 LEVELS OF REFINEMENT
            </span>
          </div>
        </div>
      </div>

      {/* Switcher Buttons */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        {templates.map(t => {
          const isActive = currentPath === t.path;
          return (
            <button
              key={t.id}
              onClick={() => navigate(t.path)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '5px 12px',
                borderRadius: '6px',
                background: isActive ? `${t.color}25` : '#1e1e1e',
                border: isActive ? `1.5px solid ${t.color}` : '1px solid rgba(255, 255, 255, 0.08)',
                color: isActive ? '#ffffff' : '#cbd5e1',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                textAlign: 'left'
              }}
            >
              <span style={{
                fontSize: '10px',
                fontWeight: '800',
                padding: '2px 6px',
                borderRadius: '3px',
                background: isActive ? t.color : 'rgba(255, 255, 255, 0.1)',
                color: '#ffffff'
              }}>
                {t.badge}
              </span>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', lineHeight: 1.2 }}>
                  {t.name}
                </div>
                <div style={{ fontSize: '9px', color: isActive ? t.color : '#94a3b8', lineHeight: 1.1 }}>
                  {t.tagline}
                </div>
              </div>
            </button>
          );
        })}

        {/* Original baseline link */}
        <button
          onClick={() => navigate('/dashboard')}
          style={{
            padding: '5px 10px',
            borderRadius: '6px',
            background: 'transparent',
            border: '1px dashed rgba(255, 255, 255, 0.15)',
            color: '#94a3b8',
            fontSize: '11px',
            cursor: 'pointer',
            marginLeft: '4px'
          }}
          title="Return to original ARGUS dashboard"
        >
          Original Baseline
        </button>
      </div>
    </div>
  );
}
