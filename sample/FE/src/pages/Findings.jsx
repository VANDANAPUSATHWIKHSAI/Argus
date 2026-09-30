import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import { fetchFindings } from '../js/api';
import '../css/style.css';

const SEVERITY_MAP = {
  critical: { color: '#ef4444', bg: '#fee2e2', label: 'CRITICAL' },
  high: { color: '#f97316', bg: '#ffedd5', label: 'HIGH' },
  medium: { color: '#3b82f6', bg: '#dbeafe', label: 'MEDIUM' },
  low: { color: '#10b981', bg: '#d1fae5', label: 'LOW' },
  info: { color: '#64748b', bg: '#f1f5f9', label: 'INFO' }
};

const SeverityBadge = ({ severity }) => {
  const s = SEVERITY_MAP[(severity || 'medium').toLowerCase()] || SEVERITY_MAP.medium;
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      padding: '4px 10px',
      borderRadius: '12px',
      fontSize: '11px',
      fontWeight: '700',
      letterSpacing: '0.5px'
    }}>
      {s.label}
    </span>
  );
};

const ConfidenceBar = ({ value }) => {
  const percent = Math.round((value > 1 ? value : value * 100) || 0);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 65, height: 6, background: 'var(--border-strong)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{
          width: `${percent}%`,
          height: '100%',
          background: percent >= 85 ? '#10b981' : percent >= 60 ? '#3b82f6' : '#f97316',
          borderRadius: 3,
          transition: 'width 0.4s'
        }} />
      </div>
      <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-main)' }}>{percent}%</span>
    </div>
  );
};

const Findings = () => {
  const navigate = useNavigate();
  const activeCaseId = localStorage.getItem('active_case_id');
  const activeCaseName = localStorage.getItem('active_case_name') || 'Current Case';

  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedFinding, setSelectedFinding] = useState(null);

  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });

  const closeAlert = () => setCustomAlert(prev => ({ ...prev, isOpen: false }));

  useEffect(() => {
    const loadFindings = async () => {
      if (!activeCaseId) {
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const result = await fetchFindings(activeCaseId);
        const dataList = Array.isArray(result) ? result : (result.data || []);
        setFindings(dataList);
        if (dataList.length > 0) {
          setSelectedFinding(dataList[0]);
        }
      } catch (err) {
        console.error('Failed to fetch findings:', err);
        setError(err.message || 'Failed to load case findings.');
      } finally {
        setLoading(false);
      }
    };

    loadFindings();
  }, [activeCaseId]);

  const filteredFindings = findings.filter(f => {
    const text = `${f.finding_id} ${f.fact} ${f.sanitized_fact || ''} ${f.mitre_mapping || ''} ${f.layer || ''}`.toLowerCase();
    const matchesSearch = !search || text.includes(search.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || (f.severity || '').toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'all' || (f.review_status || '').toLowerCase() === statusFilter.toLowerCase();
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const counts = {
    total: findings.length,
    critical: findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
    high: findings.filter(f => (f.severity || '').toLowerCase() === 'high').length,
    medium: findings.filter(f => (f.severity || '').toLowerCase() === 'medium').length,
    low: findings.filter(f => (f.severity || '').toLowerCase() === 'low').length,
    pending: findings.filter(f => !f.review_status || f.review_status === 'pending_review').length,
  };

  return (
    <div id="app-shell">
      <AlertModal 
        isOpen={customAlert.isOpen} 
        title={customAlert.title} 
        message={customAlert.message} 
        type={customAlert.type} 
        onClose={closeAlert} 
      />
      <Sidebar active="findings" />

      <main className="main-content">
        {/* TOPBAR */}
        <header className="topbar">
          <div className="search-container">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: 8 }}>
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <input 
              type="text" 
              placeholder="Filter findings by ID, fact text, or MITRE technique..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="topbar-actions" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <NotificationMenu />
            <div className="user-profile-badge" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-main)' }}>
                {activeCaseId ? `${activeCaseName} (${activeCaseId})` : 'No Active Case'}
              </span>
            </div>
          </div>
        </header>

        {/* PAGE CONTENT */}
        <div style={{ padding: '32px 40px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
            <div>
              <h1 style={{ fontSize: '26px', fontWeight: '700', color: 'var(--text-main)', margin: '0 0 6px 0' }}>
                Forensic Findings & FIR Record
              </h1>
              <p style={{ fontSize: '14px', color: 'var(--text-muted)', margin: 0 }}>
                Authoritative findings generated by deterministic analysis and AI reasoning for case <strong>{activeCaseId || 'N/A'}</strong>.
              </p>
            </div>
          </div>

          {/* STATS CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginBottom: 28 }}>
            <div className="card-panel" style={{ padding: '16px 20px', background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px' }}>
              <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Findings</span>
              <div style={{ fontSize: '24px', fontWeight: '800', color: 'var(--text-main)', marginTop: 4 }}>{counts.total}</div>
            </div>
            <div className="card-panel" style={{ padding: '16px 20px', background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px' }}>
              <span style={{ fontSize: '12px', fontWeight: '600', color: '#ef4444', textTransform: 'uppercase' }}>Critical</span>
              <div style={{ fontSize: '24px', fontWeight: '800', color: '#ef4444', marginTop: 4 }}>{counts.critical}</div>
            </div>
            <div className="card-panel" style={{ padding: '16px 20px', background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px' }}>
              <span style={{ fontSize: '12px', fontWeight: '600', color: '#f97316', textTransform: 'uppercase' }}>High</span>
              <div style={{ fontSize: '24px', fontWeight: '800', color: '#f97316', marginTop: 4 }}>{counts.high}</div>
            </div>
            <div className="card-panel" style={{ padding: '16px 20px', background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px' }}>
              <span style={{ fontSize: '12px', fontWeight: '600', color: '#3b82f6', textTransform: 'uppercase' }}>Medium</span>
              <div style={{ fontSize: '24px', fontWeight: '800', color: '#3b82f6', marginTop: 4 }}>{counts.medium}</div>
            </div>
            <div className="card-panel" style={{ padding: '16px 20px', background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px' }}>
              <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Pending Review</span>
              <div style={{ fontSize: '24px', fontWeight: '800', color: 'var(--text-main)', marginTop: 4 }}>{counts.pending}</div>
            </div>
          </div>

          {/* FILTERS */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <label style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-muted)' }}>Severity:</label>
              <select 
                value={severityFilter} 
                onChange={(e) => setSeverityFilter(e.target.value)}
                style={{ background: 'var(--bg-card)', color: 'var(--text-main)', border: '1px solid var(--border-color)', padding: '6px 12px', borderRadius: '8px', fontSize: '13px' }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <label style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-muted)' }}>Review Status:</label>
              <select 
                value={statusFilter} 
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{ background: 'var(--bg-card)', color: 'var(--text-main)', border: '1px solid var(--border-color)', padding: '6px 12px', borderRadius: '8px', fontSize: '13px' }}
              >
                <option value="all">All Statuses</option>
                <option value="pending_review">Pending Review</option>
                <option value="analyst_confirmed">Analyst Confirmed</option>
                <option value="analyst_rejected">Analyst Rejected</option>
              </select>
            </div>
          </div>

          {/* MAIN CONTENT AREA */}
          {!activeCaseId ? (
            <div className="card-panel" style={{ padding: '48px', textAlign: 'center', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5" style={{ marginBottom: 12 }}>
                <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                <polyline points="13 2 13 9 20 9"></polyline>
              </svg>
              <h3 style={{ fontSize: '18px', fontWeight: '600', color: 'var(--text-main)', margin: '0 0 8px 0' }}>No Active Case Selected</h3>
              <p style={{ fontSize: '14px', color: 'var(--text-muted)', margin: '0 0 20px 0' }}>Please select or create an active investigation case from the Dashboard to view findings.</p>
              <button onClick={() => navigate('/dashboard')} className="btn-primary" style={{ padding: '8px 20px', borderRadius: '8px', cursor: 'pointer' }}>
                Go to Dashboard
              </button>
            </div>
          ) : loading ? (
            <div className="card-panel" style={{ padding: '48px', textAlign: 'center', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
              <div className="spinner" style={{ margin: '0 auto 16px auto' }}></div>
              <p style={{ color: 'var(--text-muted)', margin: 0 }}>Loading findings for case {activeCaseId}...</p>
            </div>
          ) : error ? (
            <div className="card-panel" style={{ padding: '32px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '12px', color: '#ef4444' }}>
              <h4 style={{ margin: '0 0 6px 0', fontSize: '16px' }}>Error Loading Findings</h4>
              <p style={{ margin: 0, fontSize: '14px' }}>{error}</p>
            </div>
          ) : filteredFindings.length === 0 ? (
            <div className="card-panel" style={{ padding: '48px', textAlign: 'center', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
              <p style={{ color: 'var(--text-muted)', fontSize: '15px', margin: 0 }}>
                {findings.length === 0 ? 'No forensic findings recorded for this case yet.' : 'No findings match the current filter criteria.'}
              </p>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: selectedFinding ? '1fr 380px' : '1fr', gap: 24 }}>
              {/* FINDINGS TABLE */}
              <div className="card-panel" style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                  <thead>
                    <tr style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '14px 16px', color: 'var(--text-muted)', fontWeight: '600' }}>Finding ID</th>
                      <th style={{ padding: '14px 16px', color: 'var(--text-muted)', fontWeight: '600' }}>Severity</th>
                      <th style={{ padding: '14px 16px', color: 'var(--text-muted)', fontWeight: '600' }}>Fact</th>
                      <th style={{ padding: '14px 16px', color: 'var(--text-muted)', fontWeight: '600' }}>Confidence</th>
                      <th style={{ padding: '14px 16px', color: 'var(--text-muted)', fontWeight: '600' }}>Engine Layer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((f) => {
                      const isSelected = selectedFinding && selectedFinding.finding_id === f.finding_id;
                      return (
                        <tr 
                          key={f.finding_id}
                          onClick={() => setSelectedFinding(f)}
                          style={{
                            borderBottom: '1px solid var(--border-color)',
                            cursor: 'pointer',
                            background: isSelected ? 'rgba(59, 130, 246, 0.08)' : 'transparent',
                            transition: 'background 0.2s'
                          }}
                        >
                          <td style={{ padding: '14px 16px', fontWeight: '600', color: 'var(--brand-blue)' }}>{f.finding_id}</td>
                          <td style={{ padding: '14px 16px' }}><SeverityBadge severity={f.severity} /></td>
                          <td style={{ padding: '14px 16px', color: 'var(--text-main)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {f.sanitized_fact || f.fact}
                          </td>
                          <td style={{ padding: '14px 16px' }}><ConfidenceBar value={f.confidence} /></td>
                          <td style={{ padding: '14px 16px', color: 'var(--text-muted)' }}>{f.layer || 'forensic'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* FINDING DETAIL SIDE PANEL */}
              {selectedFinding && (
                <div className="card-panel" style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-color)', padding: '24px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                    <span style={{ fontSize: '18px', fontWeight: '700', color: 'var(--brand-blue)' }}>{selectedFinding.finding_id}</span>
                    <SeverityBadge severity={selectedFinding.severity} />
                  </div>

                  <div style={{ marginBottom: 20 }}>
                    <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Finding Fact</label>
                    <p style={{ fontSize: '14px', color: 'var(--text-main)', background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)', marginTop: 6, lineHeight: '1.5' }}>
                      {selectedFinding.sanitized_fact || selectedFinding.fact}
                    </p>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
                    <div>
                      <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Confidence Score</label>
                      <div style={{ marginTop: 6 }}>
                        <ConfidenceBar value={selectedFinding.confidence} />
                      </div>
                    </div>
                    <div>
                      <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Analysis Engine Layer</label>
                      <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-main)', marginTop: 6 }}>{selectedFinding.layer || 'forensic'}</div>
                    </div>
                  </div>

                  {selectedFinding.mitre_mapping && (
                    <div style={{ marginBottom: 20 }}>
                      <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>MITRE ATT&CK Mapping</label>
                      <div style={{ marginTop: 6, display: 'inline-block', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--brand-blue)', border: '1px solid var(--brand-blue)', padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: '600' }}>
                        {selectedFinding.mitre_mapping}
                      </div>
                    </div>
                  )}

                  <div style={{ marginBottom: 20 }}>
                    <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Evidence References</label>
                    <div style={{ fontSize: '13px', color: 'var(--text-main)', marginTop: 6 }}>
                      {Array.isArray(selectedFinding.evidence_reference) ? selectedFinding.evidence_reference.join(', ') : (selectedFinding.evidence_reference || 'N/A')}
                    </div>
                  </div>

                  {selectedFinding.source_artifact_id && (
                    <div style={{ marginBottom: 20 }}>
                      <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Source Artifact ID</label>
                      <div style={{ fontSize: '13px', color: 'var(--text-main)', marginTop: 6, fontFamily: 'monospace' }}>
                        {selectedFinding.source_artifact_id}
                      </div>
                    </div>
                  )}

                  <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: 16 }}>
                    <label style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Analyst Review Status</label>
                    <div style={{ fontSize: '13px', fontWeight: '600', color: selectedFinding.review_status === 'analyst_confirmed' ? '#10b981' : selectedFinding.review_status === 'analyst_rejected' ? '#ef4444' : '#f97316', marginTop: 6 }}>
                      {(selectedFinding.review_status || 'PENDING_REVIEW').toUpperCase()}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default Findings;
