import React from 'react';
import { Link } from 'react-router-dom';
import TemplateV2SwitcherBar from './TemplateV2SwitcherBar';
import './templates_v2.css';

export default function TemplateV2Hub() {
  const templates = [
    {
      code: 'Template 1',
      name: 'Minimal & Professional',
      route: '/templates/v2-minimal',
      tagline: 'Clean split-pane layout with left vertical navigation rail and 2px sharp black offset borders.',
      features: [
        'Pure white (#FFFFFF) & slate (#F8FAFC) background',
        'Fixed left vertical navigation rail',
        'High-contrast stat boxes with 4px black drop shadows',
        'Structured case dossier card grid'
      ]
    },
    {
      code: 'Template 2',
      name: 'Technical & Investigative Workstation',
      route: '/templates/v2-technical',
      tagline: 'Multi-pane technical command console for high-density forensic analysis.',
      features: [
        'Dark command top bar + 3-panel technical grid',
        'Column 1: Case & Artifact tree navigation',
        'Column 2: Correlated findings matrix table',
        'Column 3: Monospaced terminal inspector & hash verifier'
      ]
    },
    {
      code: 'Template 3',
      name: 'Premium & Distinctive Briefing',
      route: '/templates/v2-premium',
      tagline: 'Stark black hero header with asymmetrical offset-shadow dossier cards.',
      features: [
        'Stark black (#111111) hero header with live parameters',
        'Asymmetrical 2-column dossier layout',
        'Offset shadow cards (box-shadow: 6px 6px 0px #111111)',
        'Serif headlines paired with bold monochromatic tags'
      ]
    },
    {
      code: 'Template 4',
      name: 'Complete Visual Overhaul (Canvas & Board)',
      route: '/templates/v2-overhaul',
      tagline: 'Reimagines ARGUS into a 4-column investigation pipeline board with slide-out inspector drawer.',
      features: [
        '4-Column Pipeline: Ingestion -> Sanitization -> Findings -> Dossier',
        'Interactive card inspection drawer on demand',
        'Horizontal workflow stage tracking',
        'Radically distinct layout from traditional dashboard'
      ]
    }
  ];

  return (
    <div className="v2-wrapper" style={{ paddingBottom: 80 }}>
      <TemplateV2SwitcherBar activeName="V2 Showcase Hub" />

      {/* Header */}
      <div style={{ background: '#111111', color: '#FFFFFF', padding: '56px 64px', borderBottom: '4px solid #0F172A' }}>
        <div style={{ fontFamily: 'var(--v2-mono-font)', fontSize: '12px', color: '#94A3B8', letterSpacing: '0.12em', uppercase: 'true', marginBottom: 8 }}>
          ARGUS V2 EXPLORATION &bull; 4 RADICALLY DISTINCT TEMPLATES
        </div>
        <h1 style={{ fontFamily: 'var(--v2-serif-font)', fontSize: '42px', fontWeight: 400, margin: '0 0 16px 0' }}>
          High-Contrast White & Monochromatic Forensics
        </h1>
        <p style={{ fontSize: '16px', lineHeight: 1.6, color: '#CBD5E1', maxWidth: 840, margin: 0 }}>
          Four genuinely different layout architectures built with high contrast, defined black borders (`2px solid #111111`), zero pastel/washed-out tones, and zero AI-purple gradients.
        </p>
      </div>

      {/* Grid */}
      <div style={{ maxWidth: 1440, margin: '0 auto', padding: '48px 64px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 32 }}>
          {templates.map((tpl, i) => (
            <div key={i} style={{ background: '#FFFFFF', border: '2px solid #111111', boxShadow: '6px 6px 0px #111111', padding: 32, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <span style={{ fontFamily: 'var(--v2-mono-font)', fontWeight: 800, fontSize: '13px', background: '#111111', color: '#FFFFFF', padding: '4px 10px' }}>
                    {tpl.code}
                  </span>
                  <span style={{ fontSize: '11px', fontWeight: 800, color: '#64748B', uppercase: 'true' }}>V2 PREVIEW</span>
                </div>

                <h2 style={{ fontSize: '24px', fontWeight: 800, margin: '0 0 8px 0', color: '#111111' }}>
                  {tpl.name}
                </h2>

                <p style={{ fontSize: '14px', lineHeight: 1.5, color: '#334155', marginBottom: 20 }}>
                  {tpl.tagline}
                </p>

                <div style={{ borderTop: '2px solid #111111', paddingTop: 16, marginBottom: 24 }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, fontFamily: 'var(--v2-mono-font)', color: '#64748B', marginBottom: 8 }}>KEY ARCHITECTURE:</div>
                  <ul style={{ margin: 0, paddingLeft: 20, fontSize: '13px', color: '#0F172A', lineHeight: 1.6 }}>
                    {tpl.features.map((f, idx) => (
                      <li key={idx}>{f}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <Link 
                to={tpl.route}
                style={{
                  display: 'block',
                  textAlign: 'center',
                  background: '#111111',
                  color: '#FFFFFF',
                  padding: '12px 24px',
                  fontFamily: 'var(--v2-mono-font)',
                  fontSize: '13px',
                  fontWeight: 800,
                  textDecoration: 'none',
                  border: '2px solid #111111',
                  boxShadow: '3px 3px 0px #0F172A'
                }}
              >
                LAUNCH {tpl.code.toUpperCase()} PREVIEW →
              </Link>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
