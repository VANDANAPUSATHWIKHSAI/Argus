import React from 'react';
import { Link } from 'react-router-dom';
import TemplatePreviewBar from './TemplatePreviewBar';
import './templates.css';

export default function TemplateHub() {
  const templates = [
    {
      code: 'Glass UI',
      name: 'Glass UI Dashboard (Frosted Glass)',
      route: '/templates/glass-dashboard',
      foundation: 'Approved Glass UI: Frosted Acrylic & Prismatic Glints',
      tagline: 'A luxurious glassmorphism reimagining of the ARGUS dashboard with frosted acrylic cards, luminous accent glows, specular border rims, and dark/light switching.',
      highlights: [
        'Translucent frosted acrylic cards with backdrop-filter: blur(18px)',
        'Glowing interactive stepper pipeline with animated progress gradient',
        'Glass buttons, pills, chips, and neon micro-indicator dots',
        'Dark obsidian & light daylight frosted glass modes with live theme toggle'
      ]
    },
    {
      code: 'Template 1',
      name: 'Technical Minimal Refined+',
      route: '/templates/technical-minimal',
      foundation: 'Approved Base 1: Left Sidebar Layout',
      tagline: 'Refines the approved Technical Minimal design with clean graphite typography, precise borders, steel-blue top accents, and full view switching.',
      highlights: [
        'Recognizable ARGUS left sidebar navigation foundation',
        'White workspace (#F4F5F6) with graphite typography (#20262E)',
        'Steel-blue accents (#405D78) on active tags and top border card highlights',
        'Full view navigation across all 8 major ARGUS modules'
      ]
    },
    {
      code: 'Template 2',
      name: 'Modern Workspace+',
      route: '/templates/modern-workspace',
      foundation: 'Approved Base 2: Top Horizontal Workspace Header',
      tagline: 'Refines the approved Modern Workspace with top horizontal navigation, spacious 2-column layout, and clear context drawer separation.',
      highlights: [
        'Top horizontal workspace header bar with clean active indicators',
        'Spacious 2-column layout (Main Content + Right Context Drawer)',
        'Crisp visual hierarchy with generous whitespace & steel-blue accents',
        'Full view navigation across all 8 major ARGUS modules'
      ]
    },
    {
      code: 'Template 3',
      name: 'Technical Minimal Compact',
      route: '/templates/technical-minimal-compact',
      foundation: 'Derived from Base 1: High-Density Compact Sidebar',
      tagline: 'A compact, data-dense variation of Technical Minimal designed for analysts working with high-volume evidence logs and findings streams.',
      highlights: [
        'Tighter padding and compact table row spacing for high data density',
        'Streamlined metric pills and inline filter toolbar',
        'Retains pure white/graphite palette and steel-blue indicator tags',
        'Full view navigation across all 8 major ARGUS modules'
      ]
    },
    {
      code: 'Template 4',
      name: 'Technical Minimal Advanced',
      route: '/templates/technical-minimal-advanced',
      foundation: 'Derived from Base 1: Multi-Panel Sidebar Inspector',
      tagline: 'An advanced multi-panel variation of Technical Minimal featuring a dedicated right-side finding detail inspector & SHA-256 hash vault.',
      highlights: [
        '3-zone layout: Left Sidebar + Center Findings Matrix + Right Inspector Panel',
        'Interactive record selection with real-time cryptographic hash inspection',
        'Enhanced visual hierarchy with MITRE ATT&CK tactic badges',
        'Full view navigation across all 8 major ARGUS modules'
      ]
    },
    {
      code: 'Template 5',
      name: 'Modern Workspace Detailed',
      route: '/templates/modern-workspace-detailed',
      foundation: 'Derived from Base 2: Expanded Top Header & Context Drawer',
      tagline: 'A detailed variation of Modern Workspace featuring an expanded top header bar with live case metrics and a multi-tab context drawer.',
      highlights: [
        'Expanded header displaying multi-severity findings counts (Critical/High/Med)',
        'Richer right context drawer with deep artifact metadata & tenant parameters',
        'Spacious open layout with clear visual hierarchy',
        'Full view navigation across all 8 major ARGUS modules'
      ]
    },
    {
      code: 'Template 6',
      name: 'Modern Workspace Split View',
      route: '/templates/modern-workspace-split',
      foundation: 'Derived from Base 2: 3-Column Split Workspace',
      tagline: 'A distinct split-workspace variation of Modern Workspace arranging case dossiers, findings streams, and inspector tools side by side.',
      highlights: [
        '3-column split view: Left Dossiers Rail | Center Findings Matrix | Right Inspector Vault',
        'Side-by-side record inspection without hiding underlying context',
        'Clean white surface with graphite headers and steel-blue highlights',
        'Full view navigation across all 8 major ARGUS modules'
      ]
    }
  ];

  return (
    <div className="argus-preview-page" style={{ paddingBottom: 80 }}>
      <TemplatePreviewBar activeName="Hub Overview" />

      {/* Header */}
      <div style={{ background: 'var(--argus-dark-steel)', color: '#FFFFFF', padding: '48px 56px', borderBottom: '3px solid var(--argus-steel-blue)' }}>
        <div style={{ fontSize: '12px', color: '#94A3B8', fontWeight: 800, uppercase: 'true', letterSpacing: '0.1em', marginBottom: 8, fontFamily: 'var(--argus-mono)' }}>
          ARGUS TEMPLATE COLLECTION &bull; SIX APPROVED-DIRECTION PREVIEWS
        </div>
        <h1 style={{ fontSize: '36px', fontWeight: 900, margin: '0 0 12px 0', letterSpacing: '-0.02em', fontFamily: 'var(--argus-mono)' }}>
          Rebuilt Around Technical Minimal & Modern Workspace
        </h1>
        <p style={{ fontSize: '15px', lineHeight: 1.6, color: '#CBD5E1', maxWidth: 840, margin: 0 }}>
          Six distinct, fully previewable design templates built exclusively on the two approved visual foundations. Compare variations in density, composition, multi-panel inspection, and split workspace layouts.
        </p>
      </div>

      {/* Grid */}
      <div style={{ maxWidth: 1440, margin: '0 auto', padding: '48px 56px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 32 }}>
          {templates.map((tpl, i) => (
            <div key={i} style={{ background: '#FFFFFF', border: '1px solid var(--argus-border-strong)', borderRadius: 6, padding: 32, boxShadow: '0 2px 8px rgba(0,0,0,0.04)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <span style={{ fontSize: '12px', fontWeight: 800, background: 'var(--argus-steel-blue)', color: '#FFFFFF', padding: '3px 10px', borderRadius: 4, fontFamily: 'var(--argus-mono)' }}>
                    {tpl.code}
                  </span>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--argus-text-subtle)', uppercase: 'true' }}>
                    {tpl.foundation}
                  </span>
                </div>

                <h2 style={{ fontSize: '24px', fontWeight: 900, margin: '0 0 8px 0', color: 'var(--argus-graphite)' }}>
                  {tpl.name}
                </h2>

                <p style={{ fontSize: '14px', lineHeight: 1.5, color: 'var(--argus-text-subtle)', marginBottom: 20 }}>
                  {tpl.tagline}
                </p>

                <div style={{ borderTop: '1px solid var(--argus-border-light)', paddingTop: 16, marginBottom: 24 }}>
                  <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--argus-text-subtle)', uppercase: 'true', marginBottom: 8, fontFamily: 'var(--argus-mono)' }}>KEY COMPOSITION & FEATURES:</div>
                  <ul style={{ margin: 0, paddingLeft: 20, fontSize: '13px', color: 'var(--argus-graphite)', lineHeight: 1.6 }}>
                    {tpl.highlights.map((h, idx) => (
                      <li key={idx}>{h}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <Link 
                to={tpl.route}
                style={{
                  display: 'block',
                  textAlign: 'center',
                  background: 'var(--argus-graphite)',
                  color: '#FFFFFF',
                  padding: '12px 24px',
                  borderRadius: 4,
                  fontSize: '13px',
                  fontWeight: 800,
                  fontFamily: 'var(--argus-mono)',
                  textDecoration: 'none',
                  transition: 'background 0.15s ease'
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
