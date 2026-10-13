import React from 'react';
import { Link, useLocation } from 'react-router-dom';

export default function TemplateSwitcherBar({ activeTemplateName }) {
  const location = useLocation();
  const currentPath = location.pathname;

  return (
    <div className="template-switcher-bar">
      <div className="brand">
        <span>ARGUS</span>
        <span className="badge">Design Exploration</span>
        {activeTemplateName && <span style={{ color: '#aaa', marginLeft: 8 }}>— {activeTemplateName}</span>}
      </div>

      <div className="template-switcher-links">
        <Link 
          to="/templates" 
          className={`template-btn ${currentPath === '/templates' ? 'active' : ''}`}
        >
          Hub Overview
        </Link>
        <Link 
          to="/templates/minimal-editorial" 
          className={`template-btn ${currentPath === '/templates/minimal-editorial' ? 'active' : ''}`}
        >
          A: Minimal Editorial
        </Link>
        <Link 
          to="/templates/monochrome-workspace" 
          className={`template-btn ${currentPath === '/templates/monochrome-workspace' ? 'active' : ''}`}
        >
          B: Monochrome Workspace
        </Link>
        <Link 
          to="/templates/premium-editorial" 
          className={`template-btn ${currentPath === '/templates/premium-editorial' ? 'active' : ''}`}
        >
          C: Premium Editorial
        </Link>
        <Link 
          to="/templates/visual-overhaul" 
          className={`template-btn ${currentPath === '/templates/visual-overhaul' ? 'active' : ''}`}
        >
          D: Visual Overhaul
        </Link>
        
        <Link to="/dashboard" className="template-btn prod-btn">
          ← Return to Production App
        </Link>
      </div>
    </div>
  );
}
