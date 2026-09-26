import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../css/style.css';
import NotificationMenu from '../components/NotificationMenu';
import { fetchEvidenceForCase, fetchCases } from '../js/api';

// Incident Templates
const INCIDENT_TEMPLATES = {
  'Network Intrusion': [
    { name: 'Firewall Logs',         type: 'Network Artifact',  expectedScope: 'Incident period' },
    { name: 'Network PCAP',          type: 'Network Capture',   expectedScope: 'Affected network' },
    { name: 'Windows Event Logs',    type: 'Host Artifact',     expectedScope: 'Affected endpoints' },
    { name: 'DNS Logs',              type: 'Network Artifact',  expectedScope: 'Incident period' },
    { name: 'Authentication Logs',   type: 'Host Artifact',     expectedScope: 'Domain controller' },
    { name: 'Endpoint Logs',         type: 'Host Artifact',     expectedScope: 'Affected endpoints' },
  ],
};

function mapStatus(s) {
  const st = (s || '').toLowerCase();
  if (st === 'completed' || st === 'processed' || st === 'analyzed') return 'Available';
  if (st === 'processing' || st === 'pending' || st === 'uploaded') return 'Processing';
  if (st === 'partial') return 'Partial';
  if (st === 'failed' || st === 'invalid' || st === 'error') return 'Failed';
  return 'Processing'; // Default for unclassified
}

function matchToTemplate(filename) {
  const f = (filename || '').toLowerCase();
  if (f.endsWith('.evtx') || (f.includes('event') && f.includes('log'))) return 'Windows Event Logs';
  if (f.endsWith('.pcap') || f.endsWith('.pcapng') || f.endsWith('.cap')) return 'Network PCAP';
  if (f.includes('firewall') || f.includes('fw_') || f.includes('pfsense') || f.includes('asa')) return 'Firewall Logs';
  if (f.includes('dns')) return 'DNS Logs';
  if (f.endsWith('.mem') || f.endsWith('.dmp') || f.endsWith('.raw') || f.endsWith('.bin')) return 'Memory Dump';
  if (f.includes('auth')) return 'Authentication Logs';
  if (f.includes('endpoint')) return 'Endpoint Logs';
  return 'Generic Artifact';
}

function formatBytes(bytes) {
  if (!+bytes) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

const STATUS_COLOR = {
  Available: '#22c55e', // Green
  Processing: '#3b82f6', // Blue
  Partial:   '#eab308', // Yellow
  Missing:   '#ef4444', // Red
  Failed:   '#a855f7', // Purple
};

const Dot = ({ status }) => (
  <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: STATUS_COLOR[status] || '#aaa', flexShrink: 0 }} />
);

export default function EvidenceCoverage() {
  const navigate = useNavigate();
  // State: 'analyzing' | 'classified'
  const [phase, setPhase] = useState('analyzing'); 
  const [loading, setLoading] = useState(true);
  const [submittedEvidence, setSubmittedEvidence] = useState([]);
  const [coverageItems, setCoverageItems] = useState([]);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [analystNote, setAnalystNote] = useState('');

  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const incidentType = 'Network Intrusion';

  useEffect(() => {
    loadEvidence();
  }, []);

  const loadEvidence = async () => {
    setLoading(true);
    try {
      const caseId = localStorage.getItem('active_case_id');
      
      // Authorization Check
      const casesRes = await fetchCases().catch(() => ({ data: [] }));
      const caseList = casesRes.data || [];
      const activeCase = caseList.find(c => c.case_id === caseId);

      let isAuthorized = false;
      const role = currentUser?.role || 'analyst';
      if (role === 'admin') {
        isAuthorized = true;
      } else if (activeCase && activeCase.assigned_to_you) {
        isAuthorized = true;
      }

      if (!isAuthorized && caseId) {
        setPhase('unauthorized');
        setLoading(false);
        return;
      }

      let evidenceList = [];
      if (caseId) {
        const raw = await fetchEvidenceForCase(caseId).catch(() => ({ data: [] }));
        evidenceList = raw.data || raw || [];
      } else {
        // Mock data if no case
        evidenceList = [
          { evidence_id: 1, filename: 'PC-01-Security.evtx', status: 'processing', metadata: { size_bytes: 125829120, sha256: 'a1b2c3d4e5f6' }, upload_timestamp: new Date().toISOString() },
          { evidence_id: 2, filename: 'network_traffic.pcap', status: 'completed', metadata: { size_bytes: 891289600, sha256: 'f1e2d3c4b5a6' }, upload_timestamp: new Date(Date.now() - 3600000).toISOString() },
          { evidence_id: 3, filename: 'firewall.log', status: 'processing', metadata: { size_bytes: 47185920, sha256: '9a8b7c6d5e4f' }, upload_timestamp: new Date().toISOString() },
          { evidence_id: 4, filename: 'memdump.raw', status: 'error', metadata: { size_bytes: 2576980377, sha256: '112233445566', error: 'Unsupported compression format' }, upload_timestamp: new Date(Date.now() - 7200000).toISOString() },
        ];
      }

      // Map submitted evidence
      const mappedSubmitted = evidenceList.map((item, idx) => {
        const status = mapStatus(item.status);
        const name = matchToTemplate(item.filename);
        let type = 'Generic Artifact';
        if (name.includes('Log')) type = 'Host Artifact';
        if (name.includes('PCAP') || name.includes('Firewall') || name.includes('DNS')) type = 'Network Artifact';
        if (name.includes('Dump')) type = 'Memory Artifact';
        
        return {
          id: item.evidence_id || idx,
          name: name,
          type: type,
          filename: item.filename || '--',
          size: item.metadata?.size_bytes ? formatBytes(item.metadata.size_bytes) : '--',
          status: status,
          submittedOn: item.upload_timestamp || new Date().toISOString(),
          submittedBy: item.uploaded_by || 'System',
          hash: item.metadata?.sha256 || item.metadata?.hash || '--',
          technicalError: item.metadata?.error || null,
          analystNotes: item.metadata?.notes || '',
        };
      });

      setSubmittedEvidence(mappedSubmitted);

      // Build Coverage items for classified state
      const template = INCIDENT_TEMPLATES[incidentType] || [];
      const matchedUploads = {};
      mappedSubmitted.forEach(item => {
        if (!matchedUploads[item.name]) matchedUploads[item.name] = item;
      });

      const coverageRows = template.map((tmpl, idx) => {
        const uploaded = matchedUploads[tmpl.name];
        if (uploaded) {
          // If expecting multiple logs but got partial, map it. (Simulate Partial for demo)
          let finalStatus = uploaded.status;
          if (tmpl.name === 'Windows Event Logs' && finalStatus === 'Available') finalStatus = 'Partial';

          return { ...uploaded, id: `cov-${idx}`, expectedScope: tmpl.expectedScope, status: finalStatus, isExpected: true };
        }
        return {
          id: `cov-${idx}`, name: tmpl.name, type: tmpl.type, expectedScope: tmpl.expectedScope,
          status: 'Missing', filename: '--', size: '--', hash: '--', submittedBy: '--', submittedOn: '--',
          technicalError: null, analystNotes: '', isExpected: true
        };
      });

      setCoverageItems(coverageRows);

    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('argus_token');
    localStorage.removeItem('argus_user');
    navigate('/login');
  };

  const simulateClassification = () => {
    setPhase('classified');
    setSelectedEvidence(null);
  };

  // Stats for Donut Charts
  const subAvailable = submittedEvidence.filter(i => i.status === 'Available').length;
  const subProcessing = submittedEvidence.filter(i => i.status === 'Processing').length;
  const subFailed = submittedEvidence.filter(i => i.status === 'Failed').length;
  const subTotal = submittedEvidence.length;

  const covAvailable = coverageItems.filter(i => i.status === 'Available').length;
  const covPartial = coverageItems.filter(i => i.status === 'Partial').length;
  const covProcessing = coverageItems.filter(i => i.status === 'Processing').length;
  const covFailed = coverageItems.filter(i => i.status === 'Failed').length;
  const covMissing = coverageItems.filter(i => i.status === 'Missing').length;
  const covTotal = coverageItems.length;

  const getActionBtn = (status) => {
    const base = { padding: '6px 14px', borderRadius: '4px', cursor: 'pointer', fontWeight: 600, fontSize: '12px', border: 'none' };
    if (status === 'Available') return <button style={{ ...base, background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)' }}>View</button>;
    if (status === 'Partial')   return <button style={{ ...base, background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)' }}>View Partial</button>;
    if (status === 'Processing')return <button style={{ ...base, background: '#eff6ff', border: '1px solid #3b82f6', color: '#1d4ed8' }}>Details</button>;
    if (status === 'Missing')   return <button style={{ ...base, background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)' }}>Upload</button>;
    if (status === 'Failed')    return <div style={{ display: 'flex', gap: '6px' }}><button style={{ ...base, background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)' }}>Error</button><button style={{ ...base, background: '#f3e8ff', border: '1px solid #a855f7', color: '#7e22ce' }}>Re-upload</button></div>;
    return null;
  };

  const Header = () => (
    <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 32px', background: 'var(--bg-card)', borderBottom: '1px solid var(--border-subtle)', flexShrink: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <button onClick={() => navigate(-1)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '8px', borderRadius: '50%', display: 'flex' }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
        </button>
        <div>
          <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)' }}>Evidence Coverage</div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Case ID: {localStorage.getItem('active_case_id') || 'Unknown'}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <NotificationMenu />
        <div style={{ position: 'relative' }}>
          <button onClick={() => setShowUserDropdown(!showUserDropdown)} style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'none', border: 'none', cursor: 'pointer' }}>
            <div style={{ width: '34px', height: '34px', borderRadius: '50%', background: 'var(--blue)', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '13px' }}>
              {currentUser?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div style={{ textAlign: 'left' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>{currentUser?.username || 'User'}</div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{currentUser?.role === 'senior_analyst' ? 'Senior Analyst' : 'Analyst'}</div>
            </div>
          </button>
          {showUserDropdown && (
            <div style={{ position: 'absolute', top: '100%', right: 0, background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '6px', minWidth: '160px', zIndex: 100, boxShadow: '0 4px 16px rgba(0,0,0,0.15)' }}>
              <button onClick={() => navigate('/settings')} style={{ width: '100%', padding: '9px 12px', textAlign: 'left', background: 'none', border: 'none', color: 'var(--text-main)', cursor: 'pointer', borderRadius: '4px', fontSize: '13px' }}>Settings</button>
              <button onClick={handleLogout} style={{ width: '100%', padding: '9px 12px', textAlign: 'left', background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', borderRadius: '4px', fontSize: '13px' }}>Logout</button>
            </div>
          )}
        </div>
      </div>
    </header>
  );

  const ProgressIndicator = () => (
    <div style={{ display: 'flex', alignItems: 'center', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '24px' }}>
      <span style={{ color: 'var(--text-main)' }}>Evidence Submitted</span>
      <svg style={{ margin: '0 8px' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
      <span style={{ color: phase === 'analyzing' ? 'var(--blue)' : 'var(--text-main)' }}>Analyzing Evidence</span>
      <svg style={{ margin: '0 8px' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
      <span style={{ color: phase === 'classified' ? 'var(--text-main)' : 'var(--text-muted)' }}>Identifying Incident Type</span>
      <svg style={{ margin: '0 8px' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
      <span style={{ color: phase === 'classified' ? 'var(--blue)' : 'var(--text-muted)' }}>Expected Evidence</span>
      <svg style={{ margin: '0 8px' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
      <span style={{ color: phase === 'classified' ? 'var(--blue)' : 'var(--text-muted)' }}>Coverage</span>
    </div>
  );

  const SimpleDonut = ({ segments, total }) => {
    const size = 120; const cx = 60; const cy = 60; const r = 44; const stroke = 16;
    const circ = 2 * Math.PI * r;
    let off = 0;
    return (
      <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border-subtle)" strokeWidth={stroke} />
          {total > 0 && segments.map(seg => {
            if (!seg.count) return null;
            const dashLen = (seg.count / total) * circ - 1;
            const el = (
              <circle key={seg.label} cx={cx} cy={cy} r={r} fill="none" stroke={seg.color}
                strokeWidth={stroke} strokeDasharray={`${dashLen} ${circ}`} strokeDashoffset={-off} />
            );
            off += (seg.count / total) * circ;
            return el;
          })}
        </svg>
      </div>
    );
  };

  const RightPanel = () => {
    if (!selectedEvidence) return null;
    return (
      <div style={{ width: '380px', background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '24px', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h3 style={{ margin: '0 0 8px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>{selectedEvidence.name}</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '13px', fontWeight: 600, color: STATUS_COLOR[selectedEvidence.status] }}>
              <Dot status={selectedEvidence.status} />{selectedEvidence.status}
            </div>
          </div>
          <button onClick={() => setSelectedEvidence(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Evidence Type</div>
            <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500 }}>{selectedEvidence.type}</div>
          </div>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>File Size</div>
            <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500 }}>{selectedEvidence.size}</div>
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>File Name</div>
            <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500, wordBreak: 'break-all' }}>{selectedEvidence.filename}</div>
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>SHA-256 Hash</div>
            <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500, fontFamily: 'monospace', wordBreak: 'break-all', background: 'var(--bg-app)', padding: '6px', borderRadius: '4px' }}>{selectedEvidence.hash}</div>
          </div>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Submitted By</div>
            <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500 }}>{selectedEvidence.submittedBy}</div>
          </div>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>Submitted On</div>
            <div style={{ fontSize: '13px', color: 'var(--text-main)', fontWeight: 500 }}>{selectedEvidence.submittedOn !== '--' ? new Date(selectedEvidence.submittedOn).toLocaleString() : '--'}</div>
          </div>
        </div>

        {selectedEvidence.status === 'Processing' && (
          <div style={{ border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '16px', marginTop: '8px' }}>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '12px' }}>Processing Pipeline</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-main)' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg> File received
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-main)' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg> Hash verification
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--blue)', fontWeight: 500 }}>
                <Dot status="Processing" /> Parsing and analysis — In progress
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)' }}>
                <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', border: '2px solid currentColor' }} /> Content analysis — Waiting
              </div>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '16px', fontStyle: 'italic' }}>Processing may take a few minutes. The status will update automatically.</div>
          </div>
        )}

        {selectedEvidence.status === 'Failed' && selectedEvidence.technicalError && (
          <div style={{ background: '#faf5ff', borderLeft: '3px solid #a855f7', padding: '12px', borderRadius: '4px' }}>
            <div style={{ fontSize: '12px', color: '#7e22ce', fontWeight: 700, marginBottom: 4 }}>Processing Error</div>
            <div style={{ fontSize: '13px', color: '#6b21a8' }}>{selectedEvidence.technicalError}</div>
          </div>
        )}

        <div style={{ marginTop: 'auto', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-main)', fontWeight: 600, marginBottom: 8 }}>Analyst Notes</div>
          <textarea 
            value={analystNote} 
            onChange={(e) => setAnalystNote(e.target.value)} 
            placeholder="Add a note about this evidence..."
            style={{ width: '100%', height: '80px', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-strong)', background: 'var(--bg-app)', color: 'var(--text-main)', fontSize: '13px', resize: 'none', fontFamily: 'inherit' }}
          />
        </div>
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-app)', fontFamily: 'Inter, sans-serif' }}>
      <Header />
      <main style={{ flex: 1, overflowY: 'auto', padding: '32px 48px' }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
          
          <ProgressIndicator />

          {phase === 'unauthorized' && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', textAlign: 'center' }}>
              <div style={{ width: '64px', height: '64px', background: 'rgba(239,68,68,0.1)', color: '#ef4444', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              </div>
              <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>Access Denied</h2>
              <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto 24px' }}>
                You do not have permission to view the evidence for this case. This information is restricted to the assigned analyst and senior personnel.
              </p>
              <button onClick={() => navigate('/')} style={{ background: 'var(--blue)', color: '#fff', border: 'none', padding: '10px 20px', borderRadius: '6px', fontWeight: 600, cursor: 'pointer' }}>
                Return to Dashboard
              </button>
            </div>
          )}

          {phase === 'analyzing' && (
            <>
              {/* Info Banner */}
              <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: '8px', padding: '16px 20px', display: 'flex', alignItems: 'flex-start', gap: '16px', marginBottom: '32px' }}>
                <svg style={{ color: '#3b82f6', marginTop: 2 }} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: '#1e3a8a', marginBottom: '4px' }}>ARGUS is analyzing the submitted evidence to identify the incident type.</div>
                  <div style={{ fontSize: '13px', color: '#1e40af' }}>Once the incident type is identified, the expected evidence checklist and coverage will be generated.</div>
                </div>
                <button onClick={simulateClassification} style={{ marginLeft: 'auto', background: '#3b82f6', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '6px', fontWeight: 600, fontSize: '12px', cursor: 'pointer' }}>Simulate Classification</button>
              </div>

              <div style={{ display: 'flex', gap: '24px', alignItems: 'flex-start' }}>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  
                  {/* Status Section */}
                  <div style={{ display: 'flex', gap: '24px', alignItems: 'center', background: 'var(--bg-card)', padding: '24px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                    <SimpleDonut 
                      segments={[
                        { label: 'Available', count: subAvailable, color: STATUS_COLOR['Available'] },
                        { label: 'Processing', count: subProcessing, color: STATUS_COLOR['Processing'] },
                        { label: 'Failed', count: subFailed, color: STATUS_COLOR['Failed'] }
                      ]} 
                      total={subTotal} 
                    />
                    <div>
                      <h2 style={{ margin: '0 0 16px 0', fontSize: '16px', fontWeight: 600, color: 'var(--text-main)' }}>Evidence Processing Status</h2>
                      <div style={{ display: 'flex', gap: '24px' }}>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Available</div>
                          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>{subAvailable}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Processing</div>
                          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>{subProcessing}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Failed</div>
                          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>{subFailed}</div>
                        </div>
                        <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '24px' }}>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Submitted</div>
                          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)' }}>{subTotal}</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Submitted Evidence Table */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <div>
                        <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Submitted Evidence</h2>
                        <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>Evidence submitted for this investigation is being validated and analyzed.</div>
                      </div>
                    </div>
                    
                    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', overflow: 'hidden' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-app)' }}>
                            {['Evidence', 'Type', 'File Name', 'Size', 'Status', 'Submitted On', 'Action'].map(h => (
                              <th key={h} style={{ padding: '14px 16px', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {submittedEvidence.map(ev => (
                            <tr key={ev.id} onClick={() => { setSelectedEvidence(ev); setAnalystNote(ev.analystNotes || ''); }}
                              style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', background: selectedEvidence?.id === ev.id ? 'var(--bg-app)' : 'transparent' }}
                            >
                              <td style={{ padding: '14px 16px', fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>{ev.name}</td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-muted)' }}>{ev.type}</td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-main)', fontFamily: 'monospace' }}>{ev.filename}</td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-muted)' }}>{ev.size}</td>
                              <td style={{ padding: '14px 16px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600, color: STATUS_COLOR[ev.status] }}>
                                  <Dot status={ev.status} />{ev.status}
                                </div>
                              </td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-muted)' }}>{ev.submittedOn !== '--' ? new Date(ev.submittedOn).toLocaleDateString() : '--'}</td>
                              <td style={{ padding: '14px 16px' }} onClick={e => e.stopPropagation()}>
                                {getActionBtn(ev.status)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>

                <RightPanel />
              </div>
            </>
          )}

          {phase === 'classified' && (
            <>
              {/* Classified Banner */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '32px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', background: 'var(--bg-card)', padding: '12px 20px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'rgba(59,130,246,0.1)', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Incident Type</div>
                    <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)' }}>{incidentType}</div>
                  </div>
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)', maxWidth: '600px' }}>
                  ARGUS has generated the expected evidence checklist based on the classified incident type. 
                  Compare the expected scope with the actual submitted evidence.
                </div>
                <button onClick={() => setPhase('analyzing')} style={{ marginLeft: 'auto', background: 'none', border: '1px solid var(--border-strong)', padding: '8px 16px', borderRadius: '6px', fontWeight: 600, fontSize: '12px', cursor: 'pointer', color: 'var(--text-main)' }}>Back</button>
              </div>

              <div style={{ display: 'flex', gap: '24px', alignItems: 'flex-start' }}>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  
                  {/* Coverage Section */}
                  <div style={{ display: 'flex', gap: '32px', alignItems: 'center', background: 'var(--bg-card)', padding: '32px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ position: 'relative', width: 140, height: 140 }}>
                      <SimpleDonut 
                        segments={[
                          { label: 'Available', count: covAvailable, color: STATUS_COLOR['Available'] },
                          { label: 'Partial', count: covPartial, color: STATUS_COLOR['Partial'] },
                          { label: 'Missing', count: covMissing, color: STATUS_COLOR['Missing'] },
                          { label: 'Processing', count: covProcessing, color: STATUS_COLOR['Processing'] },
                          { label: 'Failed', count: covFailed, color: STATUS_COLOR['Failed'] }
                        ]} 
                        total={covTotal} 
                      />
                      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                        <span style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1 }}>{covAvailable + covPartial} / {covTotal}</span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, marginTop: '4px' }}>Available</span>
                      </div>
                    </div>
                    <div>
                      <h2 style={{ margin: '0 0 4px 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-main)' }}>Evidence Coverage</h2>
                      <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '24px' }}>Expected evidence items for {incidentType} vs submitted.</div>
                      
                      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                        {[
                          { label: 'Available', count: covAvailable, color: STATUS_COLOR['Available'] },
                          { label: 'Partial', count: covPartial, color: STATUS_COLOR['Partial'] },
                          { label: 'Processing', count: covProcessing, color: STATUS_COLOR['Processing'] },
                          { label: 'Missing', count: covMissing, color: STATUS_COLOR['Missing'] },
                          { label: 'Failed', count: covFailed, color: STATUS_COLOR['Failed'] }
                        ].map(s => (
                          <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-app)', border: '1px solid var(--border-subtle)', padding: '8px 12px', borderRadius: '6px' }}>
                            <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.color }} />
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>{s.label}</div>
                            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-main)', marginLeft: '4px' }}>{s.count}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Expected Evidence Table */}
                  <div>
                    <h2 style={{ margin: '0 0 16px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>Expected Evidence Scope vs Actual Submitted Evidence</h2>
                    
                    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: '8px', overflow: 'hidden' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-app)' }}>
                            {['Evidence', 'Type', 'Expected Scope', 'Submitted File', 'Result', 'Action'].map(h => (
                              <th key={h} style={{ padding: '14px 16px', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {coverageItems.map(ev => (
                            <tr key={ev.id} onClick={() => { setSelectedEvidence(ev); setAnalystNote(ev.analystNotes || ''); }}
                              style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', background: selectedEvidence?.id === ev.id ? 'var(--bg-app)' : 'transparent' }}
                            >
                              <td style={{ padding: '14px 16px', fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>{ev.name}</td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-muted)' }}>{ev.type}</td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-muted)' }}>{ev.expectedScope}</td>
                              <td style={{ padding: '14px 16px', fontSize: '13px', color: 'var(--text-main)', fontFamily: 'monospace' }}>{ev.filename}</td>
                              <td style={{ padding: '14px 16px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 600, color: STATUS_COLOR[ev.status] }}>
                                  <Dot status={ev.status} />{ev.status}
                                </div>
                                {ev.status === 'Partial' && (
                                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Missing partial scope</div>
                                )}
                              </td>
                              <td style={{ padding: '14px 16px' }} onClick={e => e.stopPropagation()}>
                                {getActionBtn(ev.status)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>

                <RightPanel />
              </div>
            </>
          )}

        </div>
      </main>
    </div>
  );
}
