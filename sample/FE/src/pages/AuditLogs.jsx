import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import SearchableSelect from '../components/SearchableSelect';
import '../css/style.css';
import { fetchActivity } from '../js/api';
import { setActiveCase } from '../js/caseEvents';

import { safeFormatDateTime } from '../js/dateUtils';

const formatDate = (isoStr) => {
  return safeFormatDateTime(isoStr, '-');
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
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const queryCaseId = queryParams.get('case_id') || '';
  const [activeCaseId, setActiveCaseId] = useState(queryCaseId || localStorage.getItem('active_case_id') || '');

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

  useEffect(() => {
    const cid = queryCaseId || localStorage.getItem('active_case_id') || '';
    setActiveCaseId(cid);
    if (queryCaseId && queryCaseId !== localStorage.getItem('active_case_id')) {
      setActiveCase(queryCaseId);
    }
  }, [location.search, queryCaseId]);

  const loadData = async (targetId) => {
    try {
      const caseToFetch = targetId !== undefined ? targetId : activeCaseId;
      const res = await fetchActivity(caseToFetch);
      if (res.status === 'SUCCESS' && res.data) {
        const now = new Date();
        
        // Audit Logs filtered for active case, or all logs if none specified
        const caseLogs = caseToFetch ? res.data.filter(item => item.case_id === caseToFetch) : res.data;

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
    loadData(activeCaseId);
  }, [activeCaseId, location.search]);

  
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
        <header className="glass-topbar-capsule topbar">
          <div className="glass-topbar-left">
            <h2 className="glass-welcome-title">Audit Logs</h2>
            <p className="glass-welcome-sub">
              {activeCaseId ? (
                <>
                  Case: <strong style={{ color: 'var(--blue)' }}>{activeCaseId}</strong>
                  <button
                    onClick={() => {
                      navigate('/audit-logs');
                      setActiveCaseId('');
                    }}
                    style={{
                      marginLeft: '12px',
                      background: 'rgba(59, 130, 246, 0.1)',
                      border: '1px solid rgba(59, 130, 246, 0.3)',
                      color: '#3b82f6',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    View All Cases
                  </button>
                </>
              ) : 'Viewing All System Audit Events'}
            </p>
          </div>
          <div className="glass-topbar-right topbar-actions">
            <div style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--glass-dash-text-main)', background: 'var(--glass-dash-surface-nested)', padding: '6px 14px', borderRadius: '12px', border: '1px solid var(--glass-dash-border-subtle)' }}>
              {stats.total.toLocaleString()} Events
            </div>

            <button className="btn-primary" onClick={exportLogs} style={{ fontSize: '13px', padding: '8px 16px' }}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export Logs
            </button>
          </div>
        </header>

        <div className="dashboard-scroll">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px' }}>
            <div className="stat-card" style={{ padding: '24px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--glass-dash-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Total Events</div>
              <div style={{ fontSize: '32px', fontWeight: 800, color: 'var(--glass-dash-text-main)' }}>{stats.total}</div>
            </div>
            <div className="stat-card" style={{ padding: '24px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--glass-dash-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>Today</div>
              <div style={{ fontSize: '32px', fontWeight: 800, color: 'var(--glass-dash-text-main)' }}>{stats.today}</div>
            </div>
            <div className="stat-card" style={{ padding: '24px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--glass-dash-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>User Actions</div>
              <div style={{ fontSize: '32px', fontWeight: 800, color: 'var(--glass-dash-text-main)' }}>{stats.users}</div>
            </div>
            <div className="stat-card" style={{ padding: '24px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--glass-dash-text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>System Events</div>
              <div style={{ fontSize: '32px', fontWeight: 800, color: 'var(--glass-dash-text-main)' }}>{stats.system}</div>
            </div>
          </div>

          <div className="panel-card" style={{ overflow: 'hidden', borderRadius: '16px', border: '1px solid var(--border-subtle)', background: 'var(--bg-card)', boxShadow: '0 4px 20px rgba(0, 0, 0, 0.06)' }}>
            {/* Table Toolbar & Filters */}
            <div style={{
              padding: '16px 24px',
              borderBottom: '1px solid var(--border-subtle)',
              background: 'var(--bg-card)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '240px', maxWidth: '440px' }}>
                <div style={{ position: 'relative', width: '100%', display: 'flex', alignItems: 'center' }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" style={{ position: 'absolute', left: '12px', color: 'var(--text-muted)', pointerEvents: 'none' }}>
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    placeholder="Search action, resource, or actor..."
                    style={{
                      width: '100%',
                      padding: '8px 12px 8px 36px',
                      borderRadius: '8px',
                      background: 'var(--bg-app)',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-main)',
                      fontSize: '13px',
                      outline: 'none'
                    }}
                  />
                  {searchTerm && (
                    <button
                      onClick={() => setSearchTerm('')}
                      style={{
                        position: 'absolute',
                        right: '8px',
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        padding: '4px',
                        display: 'flex',
                        alignItems: 'center'
                      }}
                      title="Clear search"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                  )}
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <div style={{ minWidth: 160 }}>
                  <SearchableSelect
                    value={filterUser}
                    onChange={setFilterUser}
                    options={userOptions}
                    placeholder="All Users"
                    size="small"
                  />
                </div>

                {(searchTerm || filterUser) && (
                  <button
                    onClick={clearFilters}
                    style={{
                      padding: '7px 12px',
                      borderRadius: '8px',
                      background: 'transparent',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-muted)',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    Clear Filters
                  </button>
                )}
              </div>
            </div>

            {/* Table */}
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--glass-dash-surface-nested, var(--bg-surface))' }}>
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
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', transition: 'background 0.15s ease' }}
                      onMouseOver={e => e.currentTarget.style.background='var(--bg-surface)'}
                      onMouseOut={e => e.currentTarget.style.background='transparent'}
                    >
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

            {/* Pagination Footer — INSIDE panel-card */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '14px 24px',
              borderTop: '1px solid var(--border-subtle)',
              background: 'var(--glass-dash-surface-nested, var(--bg-surface))',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', color: 'var(--text-muted)', fontSize: '13px' }}>
                <span>
                  Showing <strong style={{ color: 'var(--text-main)' }}>{filteredLogs.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0}</strong> to <strong style={{ color: 'var(--text-main)' }}>{Math.min(currentPage * itemsPerPage, filteredLogs.length)}</strong> of <strong style={{ color: 'var(--text-main)' }}>{filteredLogs.length}</strong> events
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Show:</span>
                  <select
                    value={itemsPerPage}
                    onChange={e => { setItemsPerPage(Number(e.target.value)); setCurrentPage(1); }}
                    style={{
                      background: 'var(--bg-card, #ffffff)',
                      border: '1px solid var(--border-subtle, #cbd5e1)',
                      color: 'var(--text-main)',
                      padding: '4px 8px',
                      borderRadius: '6px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      outline: 'none'
                    }}
                  >
                    <option value={10}>10 per page</option>
                    <option value={25}>25 per page</option>
                    <option value={50}>50 per page</option>
                    <option value={100}>100 per page</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <button
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: 'var(--bg-card, #ffffff)',
                    border: '1px solid var(--border-subtle, #e2e8f0)',
                    color: 'var(--text-main)',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                    opacity: currentPage === 1 ? 0.45 : 1,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="15 18 9 12 15 6" /></svg>
                  Previous
                </button>

                {totalPages > 1 ? (
                  Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                    <button
                      key={p}
                      onClick={() => setCurrentPage(p)}
                      style={{
                        minWidth: '30px',
                        height: '30px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: 700,
                        cursor: 'pointer',
                        background: p === currentPage ? 'var(--blue, #2563eb)' : 'var(--bg-card, #ffffff)',
                        color: p === currentPage ? '#ffffff' : 'var(--text-main)',
                        border: p === currentPage ? '1px solid var(--blue, #2563eb)' : '1px solid var(--border-subtle, #e2e8f0)',
                        boxShadow: p === currentPage ? '0 2px 6px rgba(37, 99, 235, 0.3)' : 'none',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      {p}
                    </button>
                  ))
                ) : (
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', padding: '0 6px' }}>
                    Page 1 of 1
                  </span>
                )}

                <button
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={currentPage >= totalPages || totalPages === 0}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    background: 'var(--bg-card, #ffffff)',
                    border: '1px solid var(--border-subtle, #e2e8f0)',
                    color: 'var(--text-main)',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: (currentPage >= totalPages || totalPages === 0) ? 'not-allowed' : 'pointer',
                    opacity: (currentPage >= totalPages || totalPages === 0) ? 0.45 : 1,
                    transition: 'all 0.15s ease'
                  }}
                >
                  Next
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="9 18 15 12 9 6" /></svg>
                </button>
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
