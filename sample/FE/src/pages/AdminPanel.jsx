import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import { API_BASE_URL } from '../js/api';

const AdminPanel = () => {
  const [employees, setEmployees] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newEmp, setNewEmp] = useState({ userid: '', name: '', email: '', role: 'analyst' });
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });
  const navigate = useNavigate();
  const [theme, setTheme] = useState(localStorage.getItem('argus_theme') || 'dark');

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('argus_theme', nextTheme);
  };

  const closeAlert = () => setCustomAlert({ ...customAlert, isOpen: false });

  const fetchEmployees = async () => {
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/auth/employees`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.status === 401 || res.status === 403) {
        navigate('/dashboard');
        return;
      }
      if (!res.ok) throw new Error('Failed to fetch employees');
      const data = await res.json();
      setEmployees(data);
    } catch (err) {
      console.error(err);
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message, type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmployees();
  }, []);

  const handleAddEmployee = async (e) => {
    e.preventDefault();
    if (!newEmp.userid || !newEmp.name || !newEmp.email) {
      setCustomAlert({ isOpen: true, title: 'Validation', message: 'All fields are required.', type: 'warning' });
      return;
    }
    
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/auth/employees`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify(newEmp)
      });
      
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Failed to add employee');
      }
      
      setShowAddModal(false);
      setNewEmp({ userid: '', name: '', email: '', role: 'analyst' });
      fetchEmployees();
    } catch (err) {
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message, type: 'error' });
    }
  };

  const handleDeleteEmployee = async (userid) => {
    if (!window.confirm(`Are you sure you want to delete employee ${userid}?`)) return;
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/auth/employees/${userid}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Failed to delete employee');
      }
      
      fetchEmployees();
    } catch (err) {
      setCustomAlert({ isOpen: true, title: 'Error', message: err.message, type: 'error' });
    }
  };

  return (
    <div id="app-shell">
      <AlertModal {...customAlert} onClose={closeAlert} />
      <Sidebar />
      <main className="main-content">
        <header className="topbar">
          <div className="search-container">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-muted)', marginRight: '8px' }}><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input type="text" placeholder="Search employees..." />
          </div>
          <div className="topbar-actions">
            <button
              onClick={() => setShowAddModal(true)}
              style={{ background: 'var(--blue)', color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontSize: '13px' }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
              Add Employee
            </button>
            <button className="icon-btn" onClick={toggleTheme} title="Toggle Theme" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              {theme === 'dark' ? (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
              ) : (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
              )}
            </button>
            <div className="user-profile">
              <div className="avatar">A</div>
              <span style={{ fontWeight: 500 }}>Admin</span>
            </div>
          </div>
        </header>

        <div className="dashboard-scroll" style={{ padding: '32px 40px' }}>
          <div style={{ marginBottom: '24px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 'bold', margin: '0 0 8px' }}>Admin Panel - Employee Management</h1>
            <p style={{ color: 'var(--text-muted)', margin: 0 }}>View, add, and remove access for team members.</p>
          </div>

          <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'var(--bg-card-alt)', borderBottom: '1px solid var(--border-subtle)' }}>
                  <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Employee</th>
                  <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>User ID</th>
                  <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Role</th>
                  <th style={{ padding: '16px 24px', fontWeight: 600, color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>Loading...</td></tr>
                ) : employees.length === 0 ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>No employees found.</td></tr>
                ) : (
                  employees.map((emp) => (
                    <tr key={emp.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '16px 24px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: 'var(--blue-light)', color: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 'bold' }}>
                            {emp.name.charAt(0)}
                          </div>
                          <div>
                            <div style={{ fontWeight: 500, color: 'var(--text-main)' }}>{emp.name}</div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{emp.email}</div>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '16px 24px', color: 'var(--text-muted)' }}>{emp.id}</td>
                      <td style={{ padding: '16px 24px' }}>
                        <span style={{ padding: '4px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 500, background: emp.role === 'admin' ? 'rgba(139, 92, 246, 0.1)' : 'rgba(59, 130, 246, 0.1)', color: emp.role === 'admin' ? '#8b5cf6' : '#3b82f6', textTransform: 'capitalize' }}>
                          {emp.role}
                        </span>
                      </td>
                      <td style={{ padding: '16px 24px', textAlign: 'right' }}>
                        <button 
                          onClick={() => handleDeleteEmployee(emp.id)}
                          style={{ background: '#ef4444', border: 'none', color: '#fff', padding: '6px 14px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 600 }}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* Add Employee Modal */}
      {showAddModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'transparent' }}>
          <div style={{ background: 'var(--bg-card)', width: '100%', maxWidth: '400px', borderRadius: '12px', boxShadow: '0 10px 25px rgba(0,0,0,0.5)', border: '1px solid var(--border-strong)', overflow: 'hidden' }}>
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 600 }}>Add New Employee</h2>
              <button onClick={() => setShowAddModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleAddEmployee} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>User ID</label>
                <input type="text" value={newEmp.userid} onChange={e => setNewEmp({...newEmp, userid: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-strong)', background: 'var(--bg-input)', color: 'var(--text-main)', outline: 'none' }} placeholder="e.g., u-1234" required />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Full Name</label>
                <input type="text" value={newEmp.name} onChange={e => setNewEmp({...newEmp, name: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-strong)', background: 'var(--bg-input)', color: 'var(--text-main)', outline: 'none' }} placeholder="Jane Doe" required />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Email Address</label>
                <input type="email" value={newEmp.email} onChange={e => setNewEmp({...newEmp, email: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-strong)', background: 'var(--bg-input)', color: 'var(--text-main)', outline: 'none' }} placeholder="jane@agency.gov" required />
              </div>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Role</label>
                <select value={newEmp.role} onChange={e => setNewEmp({...newEmp, role: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-strong)', background: 'var(--bg-input)', color: 'var(--text-main)', outline: 'none' }}>
                  <option value="analyst">Analyst</option>
                  <option value="senior analyst">Senior Analyst</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button type="button" onClick={() => setShowAddModal(false)} style={{ flex: 1, padding: '10px', background: 'var(--bg-card-alt)', border: '1px solid var(--border-strong)', borderRadius: '8px', color: 'var(--text-main)', fontWeight: 500, cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ flex: 1, padding: '10px', background: 'var(--blue)', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 500, cursor: 'pointer' }}>Add Employee</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminPanel;
