import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function TemplateV2SwitcherBar({ activeName }) {
  const location = useLocation();
  const path = location.pathname;

  return (
    <div className="v2-switcher-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <strong style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '15px', letterSpacing: '0.05em' }}>ARGUS V2 PREVIEWS</strong>
        <span style={{ fontSize: '11px', background: '#334155', padding: '2px 8px', borderRadius: 4, color: '#94A3B8' }}>
          {activeName || 'Design Exploration'}
        </span>
      </div>

      <div className="v2-switcher-links">
        <Link to="/templates-v2" className={`v2-btn ${path === '/templates-v2' ? 'active' : ''}`}>
          Hub Showcase
        </Link>
        <Link to="/templates/v2-minimal" className={`v2-btn ${path === '/templates/v2-minimal' ? 'active' : ''}`}>
          1: Minimal & Professional
        </Link>
        <Link to="/templates/v2-technical" className={`v2-btn ${path === '/templates/v2-technical' ? 'active' : ''}`}>
          2: Technical Workstation
        </Link>
        <Link to="/templates/v2-premium" className={`v2-btn ${path === '/templates/v2-premium' ? 'active' : ''}`}>
          3: Premium Briefing
        </Link>
        <Link to="/templates/v2-overhaul" className={`v2-btn ${path === '/templates/v2-overhaul' ? 'active' : ''}`}>
          4: Canvas Kanban Overhaul
        </Link>

        <Link to="/dashboard" className="v2-btn prod">
          ← Back to Production App
        </Link>
      </div>
    </div>
  );
}
