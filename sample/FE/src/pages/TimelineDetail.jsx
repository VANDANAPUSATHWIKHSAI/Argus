import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import NotificationMenu from '../components/NotificationMenu';
import { fetchFindings } from '../js/api';

const STATIC_FALLBACK_TIMELINE = [
  {
    id: 'T-001',
    time: 'Oct 24, 2026 - 14:00:00',
    category: 'Investigation',
    severity: 'low',
    title: 'Case Initialized',
    desc: 'New investigation case initialized in response to suspicious network activity alerts from the SOC.',
    source: 'System Audit',
    details: 'Status: Active Investigation'
  },
  {
    id: 'T-002',
    time: 'Oct 24, 2026 - 14:15:30',
    category: 'Evidence',
    severity: 'low',
    title: 'Evidence Ingested',
    desc: 'Digital evidence artifacts ingested for forensic processing.',
    source: 'System Intake',
    details: 'Status: Ingestion & Parser Routing Complete'
  }
];

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b'
};

const TimelineDetail = () => {
  const navigate = useNavigate();
  const activeCaseId = localStorage.getItem('active_case_id');
  const activeCaseName = localStorage.getItem('active_case_name') || 'Current Case';

  const [filter, setFilter] = useState('all');
  const [timelineData, setTimelineData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadTimeline = async () => {
      if (!activeCaseId) {
        setTimelineData(STATIC_FALLBACK_TIMELINE);
        setLoading(false);
        return;
      }

      setLoading(true);
      try {
        const res = await fetchFindings(activeCaseId);
        const dataList = Array.isArray(res) ? res : (res.data || []);
        
        if (dataList.length > 0) {
          const mapped = dataList.map((f, idx) => {
            const timeStr = f.timestamp ? new Date(f.timestamp).toLocaleString() : `Event #${idx + 1}`;
            return {
              id: f.finding_id || `TL-${idx}`,
              time: timeStr,
              category: f.layer ? f.layer.toUpperCase() : 'FORENSIC FINDING',
              severity: (f.severity || 'medium').toLowerCase(),
              title: f.finding_id || `Finding #${idx + 1}`,
              desc: f.sanitized_fact || f.fact,
              source: f.layer || 'FIR Repository',
              details: f.mitre_mapping ? `MITRE ATT&CK: ${f.mitre_mapping}` : `Ref: ${Array.isArray(f.evidence_reference) ? f.evidence_reference.join(', ') : f.evidence_reference || 'N/A'}`
            };
          });

          // Sort chronologically if valid timestamps exist
          mapped.sort((a, b) => new Date(a.time) - new Date(b.time));
          setTimelineData(mapped);
        } else {
          setTimelineData(STATIC_FALLBACK_TIMELINE);
        }
      } catch (err) {
        console.error('Error fetching timeline findings:', err);
        setTimelineData(STATIC_FALLBACK_TIMELINE);
      } finally {
        setLoading(false);
      }
    };

    loadTimeline();
  }, [activeCaseId]);

  const filteredData = filter === 'all' 
    ? timelineData 
    : timelineData.filter(d => (d.severity || '').toLowerCase() === filter);

  return (
    <div id="app-shell" style={{ display: 'flex', height: '100vh', background: 'var(--bg-app)', fontFamily: 'Inter, sans-serif' }}>
      <Sidebar active="timeline" />
      <main className="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        
        {/* Header */}
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 32px', background: 'var(--bg-card)', borderBottom: '1px solid var(--border-subtle)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '8px', borderRadius: '50%', display: 'flex' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            </button>
            <div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Timeline Reconstruction</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Case ID: {activeCaseId || 'None'} &mdash; {activeCaseName}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <NotificationMenu />
          </div>
        </header>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Controls Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-card)', padding: '12px 20px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 600 }}>Filter Severity:</span>
              <div style={{ display: 'flex', gap: '6px' }}>
                {['all', 'critical', 'high', 'medium', 'low'].map(s => (
                  <button
                    key={s}
                    onClick={() => setFilter(s)}
                    style={{
                      padding: '4px 12px',
                      borderRadius: '4px',
                      fontSize: '12px',
                      fontWeight: 600,
                      textTransform: 'capitalize',
                      border: 'none',
                      cursor: 'pointer',
                      background: filter === s ? (SEVERITY_COLORS[s] || 'var(--brand-blue)') : 'var(--bg-app)',
                      color: filter === s ? '#fff' : 'var(--text-muted)',
                      transition: 'all 0.2s'
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Showing {filteredData.length} timeline events
            </div>
          </div>

          {/* Timeline Feed */}
          {loading ? (
            <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <div className="spinner" style={{ margin: '0 auto 12px auto' }}></div>
              Loading timeline events for case {activeCaseId}...
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', position: 'relative', paddingLeft: '20px' }}>
              
              {/* Vertical Guide Line */}
              <div style={{ position: 'absolute', top: '12px', bottom: '12px', left: '29px', width: '2px', background: 'var(--border-subtle)', zIndex: 0 }} />

              {filteredData.map((item, idx) => {
                const color = SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.info;
                return (
                  <div key={item.id || idx} style={{ display: 'flex', gap: '20px', position: 'relative', zIndex: 1 }}>
                    
                    {/* Circle Node */}
                    <div style={{
                      width: '20px',
                      height: '20px',
                      borderRadius: '50%',
                      background: 'var(--bg-card)',
                      border: `3px solid ${color}`,
                      marginTop: '16px',
                      flexShrink: 0
                    }} />

                    {/* Card Content */}
                    <div style={{
                      flex: 1,
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border-subtle)',
                      borderLeft: `4px solid ${color}`,
                      borderRadius: '8px',
                      padding: '16px 20px',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)' }}>{item.title}</span>
                          <span style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', padding: '2px 8px', borderRadius: '4px', background: `${color}20`, color: color }}>
                            {item.category}
                          </span>
                        </div>
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{item.time}</span>
                      </div>

                      <div style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: '1.5', marginBottom: '12px' }}>
                        {item.desc}
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)', fontSize: '12px', color: 'var(--text-muted)' }}>
                        <span>Source: <strong>{item.source}</strong></span>
                        <span>{item.details}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default TimelineDetail;
