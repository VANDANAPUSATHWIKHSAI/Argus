import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import NotificationMenu from '../components/NotificationMenu';

const TIMELINE_DATA = [
  {
    id: 0,
    time: 'Oct 24, 2026 - 14:00:00',
    category: 'Investigation',
    severity: 'low',
    title: 'Case ARGUS-952 Created',
    desc: 'New investigation case initialized in response to suspicious network activity alerts from the SOC.',
    source: 'System Audit',
    details: 'Created by: Admin, Assigned to: Analyst'
  },
  {
    id: 0.1,
    time: 'Oct 24, 2026 - 14:15:30',
    category: 'Evidence',
    severity: 'low',
    title: 'Evidence Uploaded',
    desc: 'Multiple evidence files uploaded for analysis: PC-01-Security.evtx, network_traffic.pcap, firewall.log.',
    source: 'System Audit',
    details: 'Total size: 1.2 GB, Status: Processing started'
  },
  {
    id: 1,
    time: 'Oct 24, 2026 - 14:23:45',
    category: 'Initial Access',
    severity: 'critical',
    title: 'Suspicious Outbound Connection',
    desc: 'Internal host PC-WIN-04 initiated an unexpected outbound connection to known malicious IP 198.51.100.45 over port 443.',
    source: 'Firewall Log',
    details: 'Src: 10.0.1.45:49152, Dst: 198.51.100.45:443 (TLS/SSL)'
  },
  {
    id: 2,
    time: 'Oct 24, 2026 - 14:24:12',
    category: 'Execution',
    severity: 'high',
    title: 'Malicious Payload Dropped',
    desc: 'A suspicious executable "win_update_service.exe" was dropped into the C:\\Users\\Public\\Downloads directory and executed.',
    source: 'Endpoint EDR',
    details: 'Process ID: 4192, Hash: 8d1f2a...3c4b'
  },
  {
    id: 3,
    time: 'Oct 24, 2026 - 14:25:05',
    category: 'Persistence',
    severity: 'high',
    title: 'Registry Run Key Modification',
    desc: 'The dropped payload modified the HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key to ensure persistence across reboots.',
    source: 'Windows Event Log',
    details: 'Event ID 4657, Key Value: "WinUpdateSvc"'
  },
  {
    id: 3.5,
    time: 'Oct 24, 2026 - 14:28:00',
    category: 'Investigation',
    severity: 'medium',
    title: 'AI Analysis Completed',
    desc: 'ARGUS completed processing of the uploaded evidence and generated initial findings, classifying the incident as a Network Intrusion.',
    source: 'ARGUS Pipeline',
    details: '6 Findings Generated (2 Critical, 3 High, 1 Low)'
  },
  {
    id: 4,
    time: 'Oct 24, 2026 - 14:31:22',
    category: 'Privilege Escalation',
    severity: 'critical',
    title: 'Multiple Failed Logins (Brute Force)',
    desc: 'Detected 45 consecutive failed login attempts targeting the Administrator account originating from PC-WIN-04.',
    source: 'Active Directory',
    details: 'Event ID 4625 (Logon Failure)'
  },
  {
    id: 5,
    time: 'Oct 24, 2026 - 14:38:10',
    category: 'Command and Control',
    severity: 'high',
    title: 'C2 Beaconing Detected',
    desc: 'Periodic, consistent HTTP requests (beaconing) detected pointing to a newly registered domain (secure-update-svc[.]com).',
    source: 'Network PCAP / DNS',
    details: 'Beacon interval: 300s, Jitter: 5%'
  }
];

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b' // Added for non-malicious system events if needed
};

const TimelineDetail = () => {
  const navigate = useNavigate();
  const [filter, setFilter] = useState('all');

  const filteredData = filter === 'all' 
    ? TIMELINE_DATA 
    : TIMELINE_DATA.filter(d => d.severity === filter);

  return (
    <div id="app-shell" style={{ display: 'flex', height: '100vh', background: 'var(--bg-app)', fontFamily: 'Inter, sans-serif' }}>
      <Sidebar />
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
                Case ID: {localStorage.getItem('active_case_id') || 'Unknown'} &mdash; Attack Sequence
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <NotificationMenu />
          </div>
        </header>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '40px 48px' }}>
          <div style={{ maxWidth: '900px', margin: '0 auto' }}>
            
            {/* Controls */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px', background: 'var(--bg-card)', padding: '16px 24px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
              <div>
                <h2 style={{ margin: '0 0 4px 0', fontSize: '16px', fontWeight: 600, color: 'var(--text-main)' }}>Investigation Timeline</h2>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Chronological sequence of identified malicious activities.</div>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                {['all', 'critical', 'high'].map(lvl => (
                  <button 
                    key={lvl}
                    onClick={() => setFilter(lvl)}
                    style={{
                      padding: '6px 12px',
                      borderRadius: '6px',
                      border: `1px solid ${filter === lvl ? 'var(--blue)' : 'var(--border-strong)'}`,
                      background: filter === lvl ? 'rgba(59,130,246,0.1)' : 'transparent',
                      color: filter === lvl ? 'var(--blue)' : 'var(--text-main)',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      textTransform: 'capitalize'
                    }}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>

            {/* Timeline Stream */}
            <div style={{ position: 'relative', paddingLeft: '40px' }}>
              {/* Vertical Line */}
              <div style={{ position: 'absolute', top: 0, bottom: 0, left: '15px', width: '2px', background: 'var(--border-strong)' }}></div>

              {filteredData.map((item, index) => (
                <div key={item.id} style={{ position: 'relative', marginBottom: index === filteredData.length - 1 ? 0 : '40px' }}>
                  {/* Timeline Node */}
                  <div style={{ 
                    position: 'absolute', 
                    left: '-32.5px', 
                    top: '4px',
                    width: '16px', 
                    height: '16px', 
                    borderRadius: '50%', 
                    background: SEVERITY_COLORS[item.severity],
                    border: '4px solid var(--bg-app)',
                    boxShadow: `0 0 0 1px ${SEVERITY_COLORS[item.severity]}`
                  }}></div>

                  {/* Timestamp & Category */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                    <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-main)', fontFamily: 'monospace', background: 'var(--bg-card)', padding: '4px 10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      {item.time}
                    </div>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: SEVERITY_COLORS[item.severity], textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {item.category}
                    </div>
                  </div>

                  {/* Event Card */}
                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '20px', transition: 'all 0.2s', ':hover': { borderColor: 'var(--border-strong)' } }}>
                    <h3 style={{ margin: '0 0 8px 0', fontSize: '16px', fontWeight: 600, color: 'var(--text-main)' }}>{item.title}</h3>
                    <p style={{ margin: '0 0 16px 0', fontSize: '14px', color: 'var(--text-muted)', lineHeight: '1.5' }}>{item.desc}</p>
                    
                    <div style={{ display: 'flex', gap: '24px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>Source Evidence</div>
                        <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                          {item.source}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>Technical Details</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace', background: 'var(--bg-app)', padding: '4px 8px', borderRadius: '4px' }}>
                          {item.details}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ textAlign: 'center', marginTop: '60px' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--border-strong)', margin: '0 auto 12px' }}></div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>End of recorded timeline events.</div>
            </div>

          </div>
        </div>
      </main>
    </div>
  );
};

export default TimelineDetail;
