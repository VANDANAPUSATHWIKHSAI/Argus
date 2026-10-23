import React from 'react';
import { Link } from 'react-router-dom';
import ArgusLogo from '../../components/ArgusLogo';
import GlassTemplateSwitcherBar from './GlassTemplateSwitcherBar';
import ForensicGlobeCanvas from './ForensicGlobeCanvas';
import './GlassSystem.css';
import './GlassTemplateGallery.css';

export default function GlassTemplateGallery() {
  const templates = [
    {
      id: 'architectural',
      num: '01',
      name: 'Architectural Frosted Glass',
      tag: 'OS-SURFACE / RESTRAINED ACRYLIC',
      route: '/templates/glass/architectural',
      classPrefix: 'thumb-architectural',
      desc: 'Restrained, institutional frosted acrylic panels with fine 1px reflective borders, subtle background diffusion, and clean orthogonal drafting coordinates.',
      traits: ['Double-Refraction Acrylic', 'Hairline Specular Borders', 'Cobalt Pill Action', 'Architectural Drafting Grid'],
      blur: '32px (Saturate 190%)',
      material: 'Titanium-Frosted Glass',
      accents: 'Cool Cobalt & Steel'
    },
    {
      id: 'liquid',
      num: '02',
      name: 'Liquid Glass',
      tag: 'ORGANIC CAUSTICS / FLUID MENISCUS',
      route: '/templates/glass/liquid',
      classPrefix: 'thumb-liquid',
      desc: 'Fluid optical depth emphasizing curved glass meniscuses (28px radius), directional caustic reflections, and tactile floating capsule tiles.',
      traits: ['Meniscus Curved Borders', 'Liquid Caustic Pool', 'Glossy Hemispheric Sheen', 'Floating Pill Capsules'],
      blur: '34px (Saturate 200%)',
      material: 'Fluid Curved Meniscus',
      accents: 'Cyan, Cerulean, Emerald'
    },
    {
      id: 'obsidian',
      num: '03',
      name: 'Obsidian Glass',
      tag: 'NOCTURNAL TACTICAL / ZERO-TRUST',
      route: '/templates/glass/obsidian',
      classPrefix: 'thumb-obsidian',
      desc: 'Deep volcanic charcoal vitreous glass with razor-sharp cool-white edge bevels, monospace telemetry racks, and disciplined electric cyan threat nodes.',
      traits: ['Vitreous Smoked Obsidian', 'Razor Cool-White Edge', 'Monospace Telemetry Rack', 'Electric Cyan Nodes'],
      blur: '34px (High Opacity)',
      material: 'Deep Smoked Obsidian',
      accents: 'Electric Cyan & Crimson'
    },
    {
      id: 'aurora',
      num: '04',
      name: 'Aurora Glass',
      tag: 'BOREAL LIGHT / GLACIAL TRANSLUCENCY',
      route: '/templates/glass/aurora',
      classPrefix: 'thumb-aurora',
      desc: 'Ethereal glacial crystal surfaces with soft boreal light curtains undulating underneath, high optical clarity, and emerald/violet ridges.',
      traits: ['Atmospheric Polar Curtains', 'Glacial Ice-Crystal Glass', 'High Translucency', 'Boreal Glow Buttons'],
      blur: '32px (Saturate 200%)',
      material: 'Frosted Glacial Crystal',
      accents: 'Arctic Emerald & Violet'
    },
    {
      id: 'prismatic',
      num: '05',
      name: 'Prismatic Glass',
      tag: 'OPTICAL DISPERSION / CHROMATIC FACETS',
      route: '/templates/glass/prismatic',
      classPrefix: 'thumb-prismatic',
      desc: 'Diamond-faceted crystal surfaces featuring delicate spectral rainbow hairline fringe reflections, multi-tiered panels, and chromatic bevel buttons.',
      traits: ['Spectral Hairline Fringe', 'Diamond-Faceted Depth', 'Dispersion Prismatic Accents', 'Chromatic Bevel Buttons'],
      blur: '32px (High Saturation)',
      material: 'Diamond-Cut Crown Glass',
      accents: 'Subtle Spectral Rainbow Sheen'
    }
  ];

  return (
    <div className="glass-gallery-page">
      {/* Floating Optical Glass Navigation Capsule */}
      <GlassTemplateSwitcherBar currentTemplate="gallery" />

      {/* Restored 3D Forensic Globe Background */}
      <ForensicGlobeCanvas 
        centerXRatio={0.5} 
        centerYRatio={0.32} 
        radiusRatio={0.4} 
        pointCount={650}
        className="gallery-globe-layer"
      />

      {/* Ambient Lighting Depth */}
      <div className="glass-gallery-backdrop" aria-hidden="true">
        <div className="gallery-orb-1" />
        <div className="gallery-orb-2" />
      </div>

      {/* Hero Showcase Section */}
      <header className="gallery-hero">
        <div className="gallery-badge">
          <span className="gallery-badge-dot" />
          <span>ARGUS RESEARCH &bull; 5 DISTINCT GLASSMORPHISM DIRECTIONS</span>
        </div>

        <h1 className="gallery-title">
          The <span className="gallery-title-gradient">Glassmorphism</span> Login Collection
        </h1>

        <p className="gallery-subtitle">
          Compare five genuinely different, high-quality optical glass interfaces developed for the ARGUS Digital Forensics platform. Each template demonstrates distinct material depth, surface reflections, bespoke lighting dynamics, the restored 3D forensic network globe, and full operational authentication.
        </p>

        <div className="gallery-hero-actions">
          <a href="#templates-grid" className="btn-glass-primary gallery-hero-btn">
            Browse All 5 Templates ↓
          </a>
          <Link to="/templates" className="btn-glass-outline gallery-hero-btn">
            ← Workspace Templates Hub
          </Link>
          <Link to="/login" className="btn-glass-outline gallery-hero-btn">
            Standard Production Login →
          </Link>
        </div>
      </header>

      {/* Templates Grid */}
      <main id="templates-grid" className="gallery-grid">
        {templates.map((tpl) => (
          <div key={tpl.id} className="gallery-card glass-tile-card">
            <div className="gallery-card-specular-edge" />
            <div>
              <div className="gallery-card-top">
                <span className="gallery-card-tag">{tpl.tag}</span>
                <span className="gallery-theme-badge">
                  <span>🌙 Dark</span> &bull; <span>☀️ Light</span>
                </span>
              </div>

              {/* Interactive Thumbnail Frame */}
              <div className={`gallery-thumbnail-frame ${tpl.classPrefix}`}>
                <div className="thumb-mini-card">
                  <ArgusLogo size={24} />
                  <div className="thumb-mini-line-1" />
                  <div className="thumb-mini-line-2" />
                  <div className="thumb-mini-btn" />
                </div>
              </div>

              <div className="gallery-card-content">
                <h3>{tpl.num} &bull; {tpl.name}</h3>
                <p className="gallery-card-desc">{tpl.desc}</p>

                <div className="gallery-traits">
                  {tpl.traits.map((tr, idx) => (
                    <span key={idx} className="gallery-trait-pill">{tr}</span>
                  ))}
                </div>
              </div>
            </div>

            <Link to={tpl.route} className="btn-glass-primary gallery-launch-btn">
              <span>LAUNCH TEMPLATE {tpl.num} PREVIEW</span>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="5" y1="12" x2="19" y2="12" />
                <polyline points="12 5 19 12 12 19" />
              </svg>
            </Link>
          </div>
        ))}
      </main>

      {/* Comparative Matrix Table */}
      <section className="gallery-matrix-section">
        <div className="gallery-matrix-card glass-tile-card">
          <div className="gallery-matrix-header">
            <h3>Material &amp; Optical Comparison Matrix</h3>
            <p>Direct technical comparison of optical blur parameters, surface refraction, and lighting characteristics across the five templates.</p>
          </div>

          <div className="gallery-matrix-table-wrap">
            <table className="gallery-matrix-table">
              <thead>
                <tr>
                  <th>Template</th>
                  <th>Glass Material Treatment</th>
                  <th>Backdrop Blur</th>
                  <th>Border &amp; Specular Highlight</th>
                  <th>Accent Palette</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {templates.map((t) => (
                  <tr key={t.id}>
                    <td style={{ fontWeight: 800 }}>{t.num} &bull; {t.name}</td>
                    <td>{t.material}</td>
                    <td><code>{t.blur}</code></td>
                    <td>{t.traits[1]}</td>
                    <td>{t.accents}</td>
                    <td>
                      <Link to={t.route} className="btn-glass-pill" style={{ textDecoration: 'none' }}>
                        Preview →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
