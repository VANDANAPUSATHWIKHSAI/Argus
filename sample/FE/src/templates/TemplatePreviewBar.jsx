import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function TemplatePreviewBar({ activeName }) {
  const location = useLocation();
  const currentPath = location.pathname;

  return (
    <div className="argus-top-switcher">
      <div className="brand-group">
        <span>ARGUS</span>
        <span className="tag-badge">6 Approved-Direction Templates</span>
        {activeName && <span style={{ color: '#C5CDD5', fontWeight: 500 }}>— {activeName}</span>}
      </div>

      <div className="btn-group" style={{ flexWrap: 'wrap', gap: 4 }}>
        <Link to="/templates" className={`argus-switcher-btn ${currentPath === '/templates' ? 'active' : ''}`}>
          Hub Overview
        </Link>
        <Link to="/templates/technical-minimal" className={`argus-switcher-btn ${currentPath === '/templates/technical-minimal' ? 'active' : ''}`}>
          T1: Technical Minimal Refined+
        </Link>
        <Link to="/templates/modern-workspace" className={`argus-switcher-btn ${currentPath === '/templates/modern-workspace' ? 'active' : ''}`}>
          T2: Modern Workspace+
        </Link>
        <Link to="/templates/technical-minimal-compact" className={`argus-switcher-btn ${currentPath === '/templates/technical-minimal-compact' ? 'active' : ''}`}>
          T3: Technical Minimal Compact
        </Link>
        <Link to="/templates/technical-minimal-advanced" className={`argus-switcher-btn ${currentPath === '/templates/technical-minimal-advanced' ? 'active' : ''}`}>
          T4: Technical Minimal Advanced
        </Link>
        <Link to="/templates/modern-workspace-detailed" className={`argus-switcher-btn ${currentPath === '/templates/modern-workspace-detailed' ? 'active' : ''}`}>
          T5: Modern Workspace Detailed
        </Link>
        <Link to="/templates/modern-workspace-split" className={`argus-switcher-btn ${currentPath === '/templates/modern-workspace-split' ? 'active' : ''}`}>
          T6: Modern Workspace Split View
        </Link>

        <Link to="/dashboard" className="argus-switcher-btn prod-back">
          ← Production App
        </Link>
      </div>
    </div>
  );
}
