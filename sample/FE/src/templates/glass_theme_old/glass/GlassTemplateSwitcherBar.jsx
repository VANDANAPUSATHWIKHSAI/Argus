import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import ArgusLogo from '../../components/ArgusLogo';
import './GlassTemplateSwitcherBar.css';

export default function GlassTemplateSwitcherBar({ currentTemplate = '', onQuickFill = null }) {
  const location = useLocation();
  const [theme, setTheme] = useState(() => {
    return document.documentElement.getAttribute('data-theme') || localStorage.getItem('argus_theme') || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('argus_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('argus_theme', next);
  };

  const templates = [
    { id: 'architectural', label: 'T1: Architectural', path: '/templates/glass/architectural' },
    { id: 'liquid', label: 'T2: Liquid Glass', path: '/templates/glass/liquid' },
    { id: 'obsidian', label: 'T3: Obsidian Glass', path: '/templates/glass/obsidian' },
    { id: 'aurora', label: 'T4: Aurora Glass', path: '/templates/glass/aurora' },
    { id: 'prismatic', label: 'T5: Prismatic Glass', path: '/templates/glass/prismatic' },
  ];

  return (
    <header className="glass-switcher-bar" role="navigation" aria-label="Glassmorphism Template Switcher">
      <Link to="/templates/glass" className="glass-switcher-brand" title="View Glassmorphism Template Gallery">
        <ArgusLogo size={24} />
        <span className="glass-switcher-brand-title">ARGUS Glass</span>
        <span className="glass-switcher-badge">Gallery</span>
      </Link>

      <nav className="glass-switcher-nav">
        <Link 
          to="/templates/glass" 
          className={`glass-switcher-pill ${location.pathname === '/templates/glass' ? 'active' : ''}`}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <rect x="3" y="3" width="7" height="7" />
            <rect x="14" y="3" width="7" height="7" />
            <rect x="14" y="14" width="7" height="7" />
            <rect x="3" y="14" width="7" height="7" />
          </svg>
          Overview
        </Link>

        {templates.map((tpl) => (
          <Link
            key={tpl.id}
            to={tpl.path}
            className={`glass-switcher-pill ${currentTemplate === tpl.id || location.pathname === tpl.path ? 'active' : ''}`}
          >
            {tpl.label}
          </Link>
        ))}
      </nav>

      <div className="glass-switcher-actions">
        {onQuickFill && (
          <button 
            type="button" 
            className="glass-switcher-text-btn" 
            onClick={onQuickFill}
            title="Auto-fill verified demo analyst credentials"
          >
            ⚡ Demo Fill
          </button>
        )}

        <button
          type="button"
          className="glass-switcher-btn"
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
          aria-label="Toggle Light and Dark Mode"
        >
          {theme === 'dark' ? (
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="5" />
              <line x1="12" y1="1" x2="12" y2="3" />
              <line x1="12" y1="21" x2="12" y2="23" />
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
              <line x1="1" y1="12" x2="3" y2="12" />
              <line x1="21" y1="12" x2="23" y2="12" />
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
            </svg>
          ) : (
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          )}
        </button>

        <Link to="/login" className="glass-switcher-text-btn" title="Go to default production login">
          Prod Login →
        </Link>
      </div>
    </header>
  );
}
