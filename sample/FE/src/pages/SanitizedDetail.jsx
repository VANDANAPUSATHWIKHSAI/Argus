import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import ProfileModal from '../components/ProfileModal';

const syntaxHighlight = (json) => {
  if (typeof json === 'string') {
    try {
      json = JSON.parse(json);
    } catch(e) {}
  }
  if (typeof json !== 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"\n])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'var(--text-main)';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'var(--blue)'; // Key
      } else {
        cls = 'var(--orange)'; // String
      }
    } else if (/true|false/.test(match)) {
      cls = 'var(--teal)'; // boolean
    } else if (/null/.test(match)) {
      cls = 'var(--red)'; // null
    } else {
      cls = 'var(--green)'; // number
    }
    return '<span style="color:' + cls + '">' + match + '</span>';
  });
};

const SeverityBadge = ({ severity }) => {
  const styles = {
    critical: { bg: '#fee2e2', text: '#ef4444' },
    high: { bg: '#fef3c7', text: '#f59e0b' },
    medium: { bg: '#e0f2fe', text: '#0ea5e9' },
    low: { bg: '#f1f5f9', text: '#64748b' }
  };
  const s = styles[severity?.toLowerCase()] || styles.low;
  return (
    <span style={{ backgroundColor: s.bg, color: s.text, padding: '4px 10px', borderRadius: 'var(--radius-full)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {severity}
    </span>
  );
};

const SanitizedDetail = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [detailTab, setDetailTab] = useState('overview');
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  
  const selected = location.state?.item;
  
  if (!selected) {
    return (
      <div style={{ display: 'flex', height: '100vh', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        No fact data found. <button onClick={() => navigate('/sanitized')} style={{ marginLeft: 8, color: 'var(--blue)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}>Go back</button>
      </div>
    );
  }

  return (
    <>
      <div id="app-shell">
        <Sidebar />
        <main className="main-content">
          <header className="topbar">
            <div className="search-container" style={{ flex: '0 1 400px' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: 8 }}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input type="text" id="global-search-input" placeholder="Search cases, evidence, or findings..." />
              <span className="search-shortcut">⌘ K</span>
            </div>
            
            <div className="topbar-actions" style={{ flex: 1, justifyContent: 'flex-end', display: 'flex' }}>
              <button className="btn btn-outline" onClick={() => navigate('/sanitized')} style={{ border: '1px solid var(--border-strong)', color: 'var(--text-main)', background: 'var(--bg-card)', padding: '8px 16px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                Back to List
              </button>
              
              <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
                <div className="avatar">A</div>
                <span style={{ fontWeight: 500 }}>Analyst</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
                {showUserDropdown && (
                  <div className="user-dropdown" style={{ display: 'block' }}>
                    <div className="user-dropdown-header">
                      <div className="ud-name">Analyst</div>
                      <div className="ud-role">Digital Forensics Investigator</div>
                    </div>
                    <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); setShowProfileModal(true); setShowUserDropdown(false); }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                      My Profile
                    </button>
                  </div>
                )}
              </div>
            </div>
          </header>

          <div className="dashboard-scroll">
            <div style={{ padding: '24px 24px 0 24px', flexShrink: 0 }}>
              <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-main)', marginBottom: 24 }}>Fact Details</h1>
            </div>

            <div className="main-grid" style={{ flexShrink: 0, padding: '0 24px 24px 24px', display: 'block' }}>
              <div className="panel-card" style={{ backgroundColor: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                <div style={{ padding: 32, display: 'flex', flexDirection: 'column', flex: 1 }}>
                  {/* Header */}
                  <div style={{ display: 'flex', gap: 20, marginBottom: 32 }}>
                    <div style={{ width: 64, height: 64, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, background: 'var(--blue-light)', color: 'var(--blue)', border: '2px solid var(--blue)' }}>
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <div style={{ flex: 1 }}>
                      <h2 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.3, marginBottom: 8 }}>{selected.ref}</h2>
                      <p style={{ fontSize: 14, color: 'var(--text-muted)', marginBottom: 12 }}>{selected.layer} Layer</p>
                      <SeverityBadge severity={selected.severity} />
                    </div>
                  </div>

                  {/* Tabs */}
                  <div style={{ display: 'flex', borderBottom: '1px solid var(--border-strong)', marginBottom: 32 }}>
                    {['overview', 'metadata', 'json'].map(tab => (
                      <div key={tab} onClick={() => setDetailTab(tab)} style={{ padding: '12px 24px', fontSize: 15, fontWeight: 600, cursor: 'pointer', color: detailTab === tab ? 'var(--blue)' : 'var(--text-muted)', borderBottom: detailTab === tab ? '2px solid var(--blue)' : 'none', textTransform: 'capitalize' }}>{tab}</div>
                    ))}
                  </div>

                  {detailTab === 'overview' && (
                    <>
                      <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-main)', marginBottom: 12 }}>Sanitized Fact</div>
                      <div style={{ fontSize: 15, fontFamily: 'monospace', color: 'var(--text-main)', lineHeight: 1.6, marginBottom: 32, background: 'var(--bg-surface)', padding: 24, borderRadius: 8, border: '1px solid var(--border-strong)', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'normal', overflowWrap: 'break-word' }}>
                        {selected.fact}
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
                        {[
                          { label: 'Evidence Ref', value: selected.ref },
                          { label: 'Layer', value: selected.layer },
                          { label: 'Timestamp', value: selected.timestamp },
                          { label: 'Confidence', value: `${selected.confidence}%` },
                          { label: 'Severity', value: selected.severity.charAt(0).toUpperCase() + selected.severity.slice(1) },
                        ].map(row => (
                          <div key={row.label} style={{ display: 'flex', flexDirection: 'column', fontSize: 14, paddingBottom: 16, borderBottom: '1px dashed var(--border-subtle)' }}>
                            <span style={{ color: 'var(--text-muted)', marginBottom: 4 }}>{row.label}</span>
                            <span style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: 15 }}>{row.value}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}

                  {detailTab === 'metadata' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
                      {[
                        { label: 'Evidence Ref', value: selected.evidenceRef || 'N/A' },
                        { label: 'Injection Flag', value: selected.injectionFlagged ? 'Yes' : 'No' },
                        { label: 'Injection Score', value: `${((selected.injectionScore || 0) * 100).toFixed(1)}%` },
                        { label: 'Actions Applied', value: selected.sanitizationActions?.join(', ') || 'None' },
                        { label: 'MITRE Mapping', value: selected.mitreMapping || 'None' },
                      ].map(row => (
                        <div key={row.label} style={{ display: 'flex', flexDirection: 'column', fontSize: 14, paddingBottom: 16, borderBottom: '1px dashed var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-muted)', marginBottom: 4 }}>{row.label}</span>
                          <span style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: 15 }}>{row.value}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {detailTab === 'json' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Sanitized Context (stored JSON)
                      </div>
                      <pre 
                        style={{ whiteSpace: 'pre-wrap', fontFamily: '"Courier New", monospace', fontSize: '15px', background: 'var(--bg-app)', padding: 24, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', overflowY: 'visible', color: 'var(--text-main)', lineHeight: 1.8 }}
                        dangerouslySetInnerHTML={{ __html: syntaxHighlight(selected.sanitizedContext || {}) }}
                      />
                    </div>
                  )}

                </div>
              </div>
            </div>
          </div>
        </main>
      </div>

      <ProfileModal isOpen={showProfileModal} onClose={() => setShowProfileModal(false)} />
    </>
  );
};

export default SanitizedDetail;
