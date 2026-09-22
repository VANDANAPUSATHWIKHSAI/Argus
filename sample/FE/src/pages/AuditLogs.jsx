import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import '../css/style.css';
import { fetchActivity } from '../js/api';

const ActionIcon = ({ type }) => {
  switch (type) {
    case 'upload':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>;
    case 'edit':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>;
    case 'file':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>;
    case 'alert':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>;
    case 'download':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>;
    case 'login':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>;
    case 'trash':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>;
    case 'eye':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>;
    case 'clock':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>;
    case 'logout':
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>;
    default:
      return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/></svg>;
  }
};

const formatDate = (isoStr) => {
  try {
    const d = new Date(isoStr);
    const m = d.toLocaleString('en-US', { month: 'short' });
    const day = String(d.getDate()).padStart(2, '0');
    const y = d.getFullYear();
    const h = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${m} ${day}, ${y} ${h}:${min}:${s}`;
  } catch (e) {
    return isoStr;
  }
};

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterUser, setFilterUser] = useState('All Users');
  const [filterAction, setFilterAction] = useState('All Actions');

  useEffect(() => {
    const loadData = async () => {
      try {
        const res = await fetchActivity();
        if (res.status === 'SUCCESS' && res.data) {
          const formatted = res.data.map((item, idx) => {
            let icon = 'alert';
            if (item.action === 'Created Case') icon = 'file';
            else if (item.action === 'Uploaded Evidence') icon = 'upload';
            else if (item.action === 'Closed Case') icon = 'trash';

            return {
              id: idx,
              timestamp: formatDate(item.created_at),
              user: { name: item.created_by || 'System', role: '' },
              action: item.action,
              details: item.details,
              icon: icon
            };
          });
          setLogs(formatted);
        }
      } catch (e) {
        console.error("Failed to fetch activity:", e);
      }
    };
    loadData();
  }, []);

  // Filter logs based on state
  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.details.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.action.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.user.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesUser = filterUser === 'All Users' || log.user.name === filterUser || (filterUser === 'System' && log.user.name === 'System');
    const matchesAction = filterAction === 'All Actions' || log.action === filterAction;
    return matchesSearch && matchesUser && matchesAction;
  });

  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div className="audit-logs-container">
          
          <div className="audit-header">
            <div className="header-title">
              <div className="icon-container">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <path d="M9 12l2 2 4-4"/>
                </svg>
              </div>
              <div>
                <h2>Audit Logs</h2>
                <p>Track user activities and system events for security and compliance.</p>
              </div>
            </div>
            <button className="btn-export">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export Logs
            </button>
          </div>

          <div className="audit-filters">
            <div className="filter-group">
              <div className="filter-dropdown date-range">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                <span>Sep 10, 2026 - Sep 16, 2026</span>
                <span className="caret">▾</span>
              </div>
              <select className="filter-dropdown" value={filterUser} onChange={e => setFilterUser(e.target.value)}>
                <option value="All Users">All Users</option>
                <option value="Vandana S.">Vandana S.</option>
                <option value="Rahul K.">Rahul K.</option>
                <option value="Meera P.">Meera P.</option>
                <option value="Amit R.">Amit R.</option>
                <option value="System">System</option>
              </select>
              <select className="filter-dropdown" value={filterAction} onChange={e => setFilterAction(e.target.value)}>
                <option value="All Actions">All Actions</option>
                <option value="Uploaded Evidence">Uploaded Evidence</option>
                <option value="Updated User">Updated User</option>
                <option value="Viewed Report">Viewed Report</option>
                <option value="Generated Alert">Generated Alert</option>
                <option value="Login">Login</option>
                <option value="Deleted File">Deleted File</option>
              </select>
            </div>
            <div className="search-box">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input type="text" placeholder="Search logs..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} />
            </div>
          </div>

          <div className="table-container">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Details</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map(log => (
                  <tr key={log.id}>
                    <td>
                      <div className="td-timestamp">
                        <ActionIcon type={log.icon} />
                        {log.timestamp}
                      </div>
                    </td>
                    <td>
                      <div className="td-user">
                        {log.user.name === 'System' ? (
                          <div className="avatar system-avatar">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                          </div>
                        ) : (
                          <div className={`avatar ${log.user.role.toLowerCase()}-avatar`}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                          </div>
                        )}
                        <div>
                          <div className="user-name">{log.user.name}</div>
                          {log.user.role && <div className="user-role">{log.user.role}</div>}
                        </div>
                      </div>
                    </td>
                    <td>
                      <div className="td-action">
                        {log.action}
                      </div>
                    </td>
                    <td>{log.details}</td>
                    <td className="actions-cell">
                      <button className="btn-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="1"/><circle cx="12" cy="5" r="1"/><circle cx="12" cy="19" r="1"/></svg>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="audit-footer">
            <span>Showing 1 to {filteredLogs.length} of 124 logs</span>
            <div className="pagination">
              <button className="btn-page">&lt;</button>
              <button className="btn-page active">1</button>
              <button className="btn-page">2</button>
              <button className="btn-page">3</button>
              <button className="btn-page">4</button>
              <button className="btn-page">5</button>
              <button className="btn-page">&gt;</button>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default AuditLogs;
