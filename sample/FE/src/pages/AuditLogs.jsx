import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import SearchableSelect from '../components/SearchableSelect';
import '../css/style.css';
import { fetchActivity } from '../js/api';

const formatDate = (isoStr) => {
  try {
    const d = new Date(isoStr);
    const m = d.toLocaleString('en-US', { month: 'short' });
    const day = String(d.getDate()).padStart(2, '0');
    const y = d.getFullYear();
    const h = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${day} ${m} ${y}, ${h}:${min}:${s}`;
  } catch (e) {
    return isoStr;
  }
};

const getActionDetails = (action, details, case_id, user_name) => {
  let source = 'Web';
  let resource = details || '-';

  const lower = action.toLowerCase();
  
  if (lower.includes('evidence')) {
    resource = details || 'Evidence File';
  } else if (lower.includes('finding')) {
    resource = 'Finding';
  } else if (lower.includes('created case')) {
    resource = user_name || 'Admin';
  } else if (lower.includes('case')) {
    resource = case_id || '-';
  } else if (lower.includes('updated user') || lower.includes('role')) {
    resource = details || 'User';
  }

  if (lower.includes('system') || lower.includes('validated') || lower.includes('hash')) {
    source = 'System';
  }

  return { source, resource };
};

const AuditLogs = () => {
  const navigate = useNavigate();
  const activeCaseId = localStorage.getItem('active_case_id');

  const [logs, setLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterUser, setFilterUser] = useState('');
  
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(25);
  const [selectedLog, setSelectedLog] = useState(null);

  const [stats, setStats] = useState({ total: 0, today: 0, users: 0, system: 0 });

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, filterUser, itemsPerPage, activeCaseId]);

  const loadData = async () => {
    try {
      const res = await fetchActivity();
      if (res.status === 'SUCCESS' && res.data) {
        const now = new Date();
        
        // 1. IMPORTANT — Audit Logs are for ONE CASE ONLY
        const caseLogs = activeCaseId ? res.data.filter(item => item.case_id === activeCaseId) : [];

        let tTotal = caseLogs.length;
        let tToday = 0;
        let tUsers = 0;
        let tSystem = 0;

        const formatted = caseLogs.map((item, idx) => {
          const { source, resource } = getActionDetails(item.action, item.details, item.case_id, item.created_by);
          
          const dt = new Date(item.created_at);
          if (dt.toDateString() === now.toDateString()) tToday++;
          if (source === 'System') tSystem++;
          else tUsers++;

          return {
            id: item.id || (idx + 1000),
            event_id: item.event_id || 'Not recorded',
            timestamp_raw: dt,
            timestamp: formatDate(item.created_at),
            user: { name: item.created_by || 'System', id: item.created_by_id || '', role: item.created_by === 'System' ? 'System' : 'Analyst' },
            action: item.action,
            details: item.details,
            case_id: item.case_id,
            resource,
            source,
            hash: item.sha256_hash || (source === 'System' || item.action.toLowerCase().includes('evidence') ? 'Unavailable' : null)
          };
        });
        
        setLogs(formatted);
        setStats({ total: tTotal, today: tToday, users: tUsers, system: tSystem });
      }
    } catch (e) {
      console.error("Failed to fetch activity:", e);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeCaseId]);

  
  const exportLogs = () => {
    if (filteredLogs.length === 0) return;
    
    // Create CSV header
    const headers = ['Event ID', 'Timestamp', 'User', 'User ID', 'Role', 'Action', 'Resource', 'Case ID', 'Source'];
    
    // Create CSV rows
    const rows = filteredLogs.map(log => [
      log.event_id,
      `"${log.timestamp}"`,
      `"${log.user.name}"`,
      `"${log.user.id}"`,
      log.user.role,
      `"${log.action}"`,
      `"${log.resource}"`,
      log.case_id || '-',
      log.source
    ]);
    
    const csvContent = "data:text/csv;charset=utf-8," 
      + headers.join(',') + "\n" 
      + rows.map(e => e.join(',')).join("\n");
      
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `argus_audit_logs_${activeCaseId || 'all'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const clearFilters = () => {
    setSearchTerm('');
    setFilterUser('');
  };

  const filteredLogs = logs.filter(log => {
    if (filterUser && log.user.name !== filterUser) return false;

    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      if (!log.user.name.toLowerCase().includes(q) && 
          !log.action.toLowerCase().includes(q) && 
          !log.resource.toLowerCase().includes(q)) {
        return false;
      }
    }
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / itemsPerPage));
  const currentLogs = filteredLogs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

const uniqueUsers = Array.from(
    new Map(logs.map(l => [l.user.name, l.user])).values()
  );
  const userOptions = [
    { label: 'All Users', value: '' },
    ...uniqueUsers.map(u => ({ label: `${u.name} ${u.id ? `(${u.id})` : ''}`, value: u.name }))
  ];

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div className="audit-logs-container" style={{ padding: '0' }}>
          
          <div className="audit-header" style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', marginBottom: '24px' }}>
            <div className="header-title">
              <div>
                <h2 style={{ fontSize: '24px', margin: '0 0 8px 0', color: 'var(--text-main)' }}>
                  Audit Logs
                </h2>
                {activeCaseId ? (
                  <p style={{ margin: 0, color: 'var(--blue)', fontWeight: 600 }}>Current Case: {activeCaseId}</p>
                ) : (
                  <p style={{ margin: 0, color: 'var(--text-muted)' }}>No active case selected.</p>
                )}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)', background: 'var(--bg-card)', padding: '6px 12px', borderRadius: '16px', border: '1px solid var(--border-strong)' }}>
                {stats.total.toLocaleString()} Events
              </div>

              <button className="btn-export" onClick={exportLogs} style={{ background: 'var(--blue)', border: 'none', padding: '8px 16px', borderRadius: '6px', color: '#fff', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 600 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Export Logs
              </button>
            </div>
          </div>

          <div style={{ padding: '0 48px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px', marginBottom: '32px' }}>
              <div style={{ background: 'var(--bg-card)', borderRadius: '16px', padding: '24px', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Total Events</div>
                <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--text-main)' }}>{stats.total}</div>
              </div>
              <div style={{ background: 'var(--bg-card)', borderRadius: '16px', padding: '24px', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Today</div>
                <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--text-main)' }}>{stats.today}</div>
              </div>
              <div style={{ background: 'var(--bg-card)', borderRadius: '16px', padding: '24px', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>User Actions</div>
                <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--text-main)' }}>{stats.users}</div>
              </div>
              <div style={{ background: 'var(--bg-card)', borderRadius: '16px', padding: '24px', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>System Events</div>
                <div style={{ fontSize: '32px', fontWeight: 700, color: 'var(--text-main)' }}>{stats.system}</div>
              </div>
            </div>

            <div style={{ background: 'var(--bg-card)', borderRadius: '16px', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', overflow: 'hidden', marginBottom: '24px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-strong)', background: 'var(--bg-surface)' }}>
                    <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Timestamp</th>
                    <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>User</th>
                    <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Action</th>
                    <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Resource</th>
                    <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Case ID</th>
                    <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px', textAlign: 'right' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {currentLogs.length > 0 ? currentLogs.map((log) => (
                    <tr key={log.id} onClick={() => setSelectedLog(log)} style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', transition: 'background 0.2s' }} onMouseOver={e => e.currentTarget.style.background='var(--bg-surface)'} onMouseOut={e => e.currentTarget.style.background='transparent'}>
                      <td style={{ padding: '16px 24px', whiteSpace: 'nowrap', fontSize: '13px', color: 'var(--text-main)' }}>{log.timestamp}</td>
                      <td style={{ padding: '16px 24px', fontWeight: 500, color: 'var(--text-main)' }}>{log.user.name}</td>
                      <td style={{ padding: '16px 24px' }}>
                        <span style={{ padding: '4px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 500, background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6' }}>
                          {log.action}
                        </span>
                      </td>
                      <td style={{ padding: '16px 24px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-muted)', fontSize: '13px' }}>{log.resource}</td>
                      <td style={{ padding: '16px 24px', color: 'var(--text-muted)', fontSize: '13px' }}>{log.case_id || '-'}</td>
                      <td style={{ padding: '16px 24px', textAlign: 'right', color: 'var(--blue)', fontSize: '13px', fontWeight: 600 }}>View</td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan="6" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                        {activeCaseId ? "No audit events match the search." : "No active case selected. Create or open a case to view its audit logs."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="audit-footer" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: 'var(--text-muted)', fontSize: '13px' }}>
                <span>Showing {filteredLogs.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0} to {Math.min(currentPage * itemsPerPage, filteredLogs.length)} of {filteredLogs.length} events</span>
                <select value={itemsPerPage} onChange={e => {setItemsPerPage(Number(e.target.value)); setCurrentPage(1);}} style={{ background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '4px 8px', borderRadius: '4px' }}>
                  <option value={25}>25 per page</option>
                  <option value={50}>50 per page</option>
                  <option value={100}>100 per page</option>
                </select>
              </div>
              <div className="pagination" style={{ display: 'flex', gap: '4px' }}>
                <button className="btn-page" style={{ width: 'auto', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', opacity: currentPage === 1 ? 0.5 : 1 }} onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))} disabled={currentPage === 1}>Previous</button>
                <button className="btn-page" style={{ width: 'auto', background: 'var(--bg-app)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', opacity: currentPage === totalPages || totalPages === 0 ? 0.5 : 1 }} onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))} disabled={currentPage === totalPages || totalPages === 0}>Next</button>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Side Drawer */}
      {selectedLog && (
        <div className="drawer-overlay" onClick={() => setSelectedLog(null)}>
          <div className="audit-drawer" onClick={e => e.stopPropagation()}>
            <div className="drawer-header">
              <h3>Event Details</h3>
              <button className="close-btn" onClick={() => setSelectedLog(null)}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <div className="drawer-content">
              <div className="drawer-section">
                <h4>Event Information</h4>
                <div className="detail-row">
                  <div className="detail-label">Event ID</div>
                  <div className="detail-value">{selectedLog.event_id}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-label">Timestamp</div>
                  <div className="detail-value">{selectedLog.timestamp}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-label">Action</div>
                  <div className="detail-value">{selectedLog.action}</div>
                </div>
              </div>

              <div className="drawer-section">
                <h4>Actor</h4>
                <div className="detail-row">
                  <div className="detail-label">User</div>
                  <div className="detail-value">{selectedLog.user.name}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-label">Role</div>
                  <div className="detail-value">{selectedLog.user.role}</div>
                </div>
              </div>

              <div className="drawer-section">
                <h4>Target Resource</h4>
                <div className="detail-row">
                  <div className="detail-label">Case ID</div>
                  <div className="detail-value">{selectedLog.case_id || 'N/A'}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-label">Resource</div>
                  <div className="detail-value">{selectedLog.resource}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-label">Description</div>
                  <div className="detail-value">{selectedLog.details}</div>
                </div>
                
                {selectedLog.hash && (
                  <>
                    <div className="detail-row" style={{ marginTop: '16px' }}>
                      <div className="detail-label">Hash Algo</div>
                      <div className="detail-value">SHA-256</div>
                    </div>
                    <div className="detail-row">
                      <div className="detail-label">Evidence Hash</div>
                      <div className="detail-value" style={{ fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all', background: 'rgba(255,255,255,0.05)', padding: '8px', borderRadius: '4px' }}>
                        {selectedLog.hash.split('sha256: ')[1]}
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
            
            <div className="drawer-footer">
              {selectedLog.case_id && (
                <button className="btn-drawer-action btn-drawer-primary" onClick={() => {
                    localStorage.setItem('active_case_id', selectedLog.case_id);
                    navigate('/dashboard');
                }}>
                  View Related Case
                </button>
              )}
              {selectedLog.hash && (
                <button className="btn-drawer-action" onClick={() => navigate('/evidence')}>
                  View Evidence
                </button>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default AuditLogs;
