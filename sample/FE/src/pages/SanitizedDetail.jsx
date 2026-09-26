import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import ProfileModal from '../components/ProfileModal';

const SEVERITY_STYLES = {
  critical: { bg: '#fee2e2', color: '#dc2626' },
  high:     { bg: '#fef3c7', color: '#d97706' },
  medium:   { bg: '#dbeafe', color: '#2563eb' },
  low:      { bg: '#d1fae5', color: '#059669' },
};

const SeverityBadge = ({ severity }) => {
  const s = SEVERITY_STYLES[severity?.toLowerCase()] || SEVERITY_STYLES.low;
  return (
    <span style={{ background: s.bg, color: s.color, padding: '4px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {severity}
    </span>
  );
};

const Field = ({ label, value, mono = false, full = false }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, gridColumn: full ? '1 / -1' : undefined }}>
    <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{label}</span>
    <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)', fontFamily: mono ? '"Courier New", monospace' : undefined }}>
      {value ?? '—'}
    </span>
  </div>
);

const TABS = [
  { id: 'output',    label: 'Sanitized Output' },
  { id: 'redaction', label: 'Redaction Details' },
  { id: 'evidence',  label: 'Evidence Block' },
  { id: 'metadata',  label: 'Metadata' },
];

const SanitizedDetail = () => {
  const location  = useLocation();
  const navigate  = useNavigate();
  const [tab, setTab] = useState('output');
  const [showProfileModal, setShowProfileModal] = useState(false);

  const item = location.state?.item;

  if (!item) {
    return (
      <div style={{ display: 'flex', height: '100vh', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, color: 'var(--text-muted)' }}>
        <span>No fact data found.</span>
        <button onClick={() => navigate('/sanitized')} style={{ color: 'var(--blue)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', fontSize: 14 }}>
          Back to Sanitized Output
        </button>
      </div>
    );
  }

  const redactionMap  = item.redactionMetadata || {};
  const actions       = item.sanitizationActions || [];
  const xmlBlock      = item.xmlEvidenceBlock || null;
  const severityStyle = SEVERITY_STYLES[item.severity?.toLowerCase()] || SEVERITY_STYLES.low;

  return (
    <>
      <div id="app-shell">
        <Sidebar />
        <main className="main-content">
          <header className="topbar">
            <div style={{ flex: 1 }} />
            <div className="topbar-actions" style={{ justifyContent: 'flex-end', display: 'flex' }}>
              <button onClick={() => navigate('/sanitized')} style={{ border: '1px solid var(--border-strong)', color: 'var(--text-main)', background: 'var(--bg-card)', padding: '8px 16px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
                Back
              </button>
              <div className="user-profile" onClick={() => setShowProfileModal(true)}>
                <div className="avatar">A</div>
                <span style={{ fontWeight: 500 }}>Analyst</span>
              </div>
            </div>
          </header>

          <div className="dashboard-scroll" style={{ padding: '32px 40px' }}>

            {/* Header Card */}
            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 12, padding: '24px 28px', marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 20, flexShrink: 0 }}>
              <div style={{ width: 52, height: 52, borderRadius: 12, background: severityStyle.bg, color: severityStyle.color, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: '"Courier New", monospace', fontWeight: 700, fontSize: 18, color: 'var(--text-main)' }}>{item.ref}</span>
                  <SeverityBadge severity={item.severity} />
                  {item.injectionFlagged && (
                    <span style={{ background: '#fee2e2', color: '#dc2626', padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>INJECTION FLAGGED</span>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 24, fontSize: 13, color: 'var(--text-muted)', flexWrap: 'wrap' }}>
                  <span><strong style={{ color: 'var(--text-main)' }}>Layer:</strong> {item.layer}</span>
                  <span><strong style={{ color: 'var(--text-main)' }}>Timestamp:</strong> {item.timestamp}</span>
                  <span><strong style={{ color: 'var(--text-main)' }}>Confidence:</strong> {item.confidence}%</span>
                  {item.mitreMapping && <span><strong style={{ color: 'var(--text-main)' }}>MITRE:</strong> {item.mitreMapping}</span>}
                </div>
              </div>
            </div>

            {/* Tab Bar */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border-strong)', marginBottom: 24, flexShrink: 0 }}>
              {TABS.map(t => (
                <button key={t.id} onClick={() => setTab(t.id)} style={{ background: 'none', border: 'none', borderBottom: tab === t.id ? '2px solid var(--blue)' : '2px solid transparent', color: tab === t.id ? 'var(--blue)' : 'var(--text-muted)', fontWeight: 600, fontSize: 14, padding: '12px 20px', cursor: 'pointer', transition: 'color 0.2s', marginBottom: -1 }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Sanitized Output Tab */}
            {tab === 'output' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20, flexShrink: 0 }}>
                <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 12, overflow: 'hidden' }}>
                  <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-card-alt)' }}>
                    <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>Sanitized Fact</span>
                  </div>
                  <div style={{ padding: '24px 28px', fontSize: 15, lineHeight: 1.8, color: 'var(--text-main)', fontWeight: 500 }}>
                    {item.fact}
                  </div>
                </div>
                {actions.length > 0 && (
                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 12, overflow: 'hidden' }}>
                    <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-card-alt)' }}>
                      <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>Sanitization Actions Applied</span>
                    </div>
                    <div style={{ padding: '20px 24px', display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                      {actions.map((a, i) => (
                        <span key={i} style={{ background: 'var(--blue-light)', color: 'var(--blue)', padding: '6px 16px', borderRadius: 20, fontSize: 13, fontWeight: 600 }}>
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Redaction Details Tab */}
            {tab === 'redaction' && (
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 12, overflow: 'hidden', flexShrink: 0 }}>
                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-card-alt)' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>Redacted Fields</span>
                </div>
                {Object.keys(redactionMap).length === 0 ? (
                  <div style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>No redactions were applied to this finding.</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-app)' }}>
                        <th style={{ padding: '12px 24px', fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'left' }}>Field</th>
                        <th style={{ padding: '12px 24px', fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'left' }}>Redacted Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(redactionMap).map(([key, val]) => (
                        <tr key={key} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '14px 24px', fontSize: 13, fontWeight: 600, color: 'var(--text-main)', textTransform: 'capitalize' }}>{key.replace(/_/g, ' ')}</td>
                          <td style={{ padding: '14px 24px' }}>
                            <code style={{ background: '#fee2e2', color: '#dc2626', padding: '4px 12px', borderRadius: 6, fontSize: 13, fontFamily: '"Courier New", monospace', fontWeight: 700 }}>{val}</code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* Evidence Block Tab */}
            {tab === 'evidence' && (
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 12, overflow: 'hidden', flexShrink: 0 }}>
                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-card-alt)' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>Raw Evidence Block (XML)</span>
                </div>
                {xmlBlock ? (
                  <pre style={{ margin: 0, padding: '28px 32px', fontFamily: '"Courier New", monospace', fontSize: 13, color: 'var(--text-main)', lineHeight: 1.9, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: 'var(--bg-app)' }}>{xmlBlock}</pre>
                ) : (
                  <div style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>No XML evidence block available for this finding.</div>
                )}
              </div>
            )}

            {/* Metadata Tab */}
            {tab === 'metadata' && (
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 12, padding: '28px 32px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px 48px', flexShrink: 0 }}>
                <Field label="Evidence Reference" value={item.ref} mono />
                <Field label="Layer" value={item.layer} />
                <Field label="Timestamp" value={item.timestamp} />
                <Field label="Confidence" value={`${item.confidence}%`} />
                <Field label="Severity" value={item.severity?.charAt(0).toUpperCase() + item.severity?.slice(1)} />
                <Field label="MITRE Mapping" value={item.mitreMapping} mono />
                <Field label="Injection Flagged" value={item.injectionFlagged ? 'Yes' : 'No'} />
                <Field label="Injection Score" value={`${((item.injectionScore || 0) * 100).toFixed(1)}%`} />
                <Field label="Actions Applied" value={actions.join(', ') || 'None'} full />
              </div>
            )}

          </div>
        </main>
      </div>
      <ProfileModal isOpen={showProfileModal} onClose={() => setShowProfileModal(false)} />
    </>
  );
};

export default SanitizedDetail;
