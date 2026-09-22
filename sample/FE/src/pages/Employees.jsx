import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import { API_BASE_URL } from '../js/api';

const Employees = () => {
  const [employees, setEmployees] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [newEmp, setNewEmp] = useState({ userid: '', name: '', email: '', role: 'analyst', phone: '', doj: '' });
  const [editEmp, setEditEmp] = useState(null);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning' });
  const navigate = useNavigate();

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
      const message = err.message === 'Failed to fetch' 
        ? 'Backend server is not reachable. Please ensure the server is running on port 8000.' 
        : err.message;
      setCustomAlert({ isOpen: true, title: 'Error', message, type: 'error' });
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
      setCustomAlert({ isOpen: true, title: 'Validation', message: 'User ID, Full Name, and Email are required.', type: 'warning' });
      return;
    }
    
    try {
      const token = localStorage.getItem('argus_token');
      // Send null instead of empty strings for optional fields
      const payload = {
        ...newEmp,
        phone: newEmp.phone || null,
        doj: newEmp.doj || null,
      };
      const res = await fetch(`${API_BASE_URL}/auth/employees`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) {
        let errMsg = 'Failed to add employee';
        try {
          const errData = await res.json();
          errMsg = errData.detail || errMsg;
        } catch (_) {}
        throw new Error(errMsg);
      }
      
      setShowAddModal(false);
      setNewEmp({ userid: '', name: '', email: '', role: 'analyst', phone: '', doj: '' });
      fetchEmployees();
      setCustomAlert({ isOpen: true, title: 'Success', message: 'Employee added successfully!', type: 'success' });
    } catch (err) {
      const message = err.message === 'Failed to fetch' 
        ? 'Backend server is not reachable. Please ensure the server is running on port 8000.' 
        : err.message;
      setCustomAlert({ isOpen: true, title: 'Error', message, type: 'error' });
    }
  };

  const handleEditEmployee = async (e) => {
    e.preventDefault();
    if (!editEmp.name || !editEmp.email) {
      setCustomAlert({ isOpen: true, title: 'Validation', message: 'Full Name and Email are required.', type: 'warning' });
      return;
    }
    
    try {
      const token = localStorage.getItem('argus_token');
      const payload = {
        name: editEmp.name,
        email: editEmp.email,
        role: editEmp.role,
        phone: editEmp.phone || null,
        doj: editEmp.doj || null,
      };
      
      const res = await fetch(`${API_BASE_URL}/auth/employees/${editEmp.id}`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) {
        let errMsg = 'Failed to update employee';
        try {
          const errData = await res.json();
          errMsg = errData.detail || errMsg;
        } catch (_) {}
        throw new Error(errMsg);
      }
      
      setShowEditModal(false);
      setEditEmp(null);
      fetchEmployees();
      setCustomAlert({ isOpen: true, title: 'Success', message: 'Employee updated successfully!', type: 'success' });
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
              style={{ background: 'linear-gradient(135deg, #3b82f6, #2563eb)', color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontSize: '13px' }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
              Add Employee
            </button>
            <div className="user-profile">
              <div className="avatar">A</div>
              <span style={{ fontWeight: 500 }}>Admin</span>
            </div>
          </div>
        </header>

        <div className="dashboard-scroll" style={{ padding: '32px 40px' }}>
          <div style={{ marginBottom: '24px' }}>
            <h1 style={{ fontSize: '24px', fontWeight: 'bold', margin: '0 0 8px' }}>Employee Management</h1>
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
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          <button 
                            onClick={() => { setEditEmp(emp); setShowEditModal(true); }}
                            style={{ background: 'none', border: '1px solid var(--border-strong)', color: 'var(--text-main)', padding: '6px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 500 }}
                          >
                            Edit
                          </button>
                          <button 
                            onClick={() => handleDeleteEmployee(emp.id)}
                            style={{ background: 'none', border: '1px solid var(--border-strong)', color: 'var(--danger)', padding: '6px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 500 }}
                          >
                            Delete
                          </button>
                        </div>
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
        <div style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)' }}>
          <div style={{ background: 'var(--bg-card-modal)', width: '100%', maxWidth: '420px', borderRadius: '16px', boxShadow: '0 20px 40px rgba(0,0,0,0.4)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: 'var(--text-main)' }}>Add New Employee</h2>
              <button onClick={() => setShowAddModal(false)} style={{ background: 'var(--bg-surface)', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', borderRadius: '50%', padding: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.2s' }} onMouseOver={(e) => { e.currentTarget.style.background = 'var(--bg-surface-2)'; e.currentTarget.style.color = 'var(--text-main)'; }} onMouseOut={(e) => { e.currentTarget.style.background = 'var(--bg-surface)'; e.currentTarget.style.color = 'var(--text-muted)'; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleAddEmployee} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>User ID</label>
                <input type="text" value={newEmp.userid} onChange={e => setNewEmp({...newEmp, userid: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none', transition: 'border-color 0.2s' }} placeholder="e.g., u-1234" required />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Full Name</label>
                <input type="text" value={newEmp.name} onChange={e => setNewEmp({...newEmp, name: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none' }} placeholder="Jane Doe" required />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Email Address</label>
                <input type="email" value={newEmp.email} onChange={e => setNewEmp({...newEmp, email: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none' }} placeholder="jane@agency.gov" required />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Phone Number</label>
                  <input type="tel" value={newEmp.phone} onChange={e => setNewEmp({...newEmp, phone: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none', boxSizing: 'border-box' }} placeholder="+1 (555) 000-0000" />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Date of Joining</label>
                  <input type="date" value={newEmp.doj} onChange={e => setNewEmp({...newEmp, doj: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none', boxSizing: 'border-box' }} />
                </div>
              </div>
              <div style={{ marginBottom: '32px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Role</label>
                <select value={newEmp.role} onChange={e => setNewEmp({...newEmp, role: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none' }}>
                  <option value="analyst">Analyst</option>
                  <option value="senior_analyst">Senior Analyst</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button type="button" onClick={() => setShowAddModal(false)} style={{ flex: 1, padding: '12px', background: 'transparent', border: '1px solid var(--border-subtle)', borderRadius: '8px', color: 'var(--text-muted)', fontWeight: 600, cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ flex: 1, padding: '12px', background: 'var(--primary)', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 600, cursor: 'pointer', boxShadow: '0 4px 12px rgba(59,130,246,0.3)', transition: 'transform 0.2s' }} onMouseOver={(e) => e.currentTarget.style.background = 'var(--primary-hover)'} onMouseOut={(e) => e.currentTarget.style.background = 'var(--primary)'}>Add Employee</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Employee Modal */}
      {showEditModal && editEmp && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)' }}>
          <div style={{ background: 'var(--bg-card-modal)', width: '100%', maxWidth: '420px', borderRadius: '16px', boxShadow: '0 20px 40px rgba(0,0,0,0.4)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: 'var(--text-main)' }}>Edit Employee</h2>
              <button onClick={() => { setShowEditModal(false); setEditEmp(null); }} style={{ background: 'var(--bg-surface)', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', borderRadius: '50%', padding: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.2s' }} onMouseOver={(e) => { e.currentTarget.style.background = 'var(--bg-surface-2)'; e.currentTarget.style.color = 'var(--text-main)'; }} onMouseOut={(e) => { e.currentTarget.style.background = 'var(--bg-surface)'; e.currentTarget.style.color = 'var(--text-muted)'; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleEditEmployee} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>User ID</label>
                <input type="text" value={editEmp.id} readOnly style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-2)', color: 'var(--text-muted)', outline: 'none', cursor: 'not-allowed' }} />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Full Name</label>
                <input type="text" value={editEmp.name} onChange={e => setEditEmp({...editEmp, name: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none' }} required />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Email Address</label>
                <input type="email" value={editEmp.email} onChange={e => setEditEmp({...editEmp, email: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none' }} required />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Phone Number</label>
                  <input type="tel" value={editEmp.phone || ''} onChange={e => setEditEmp({...editEmp, phone: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none', boxSizing: 'border-box' }} />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Date of Joining</label>
                  <input type="date" value={editEmp.doj || ''} onChange={e => setEditEmp({...editEmp, doj: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none', boxSizing: 'border-box' }} />
                </div>
              </div>
              <div style={{ marginBottom: '32px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Role</label>
                <select value={editEmp.role} onChange={e => setEditEmp({...editEmp, role: e.target.value})} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface)', color: 'var(--text-main)', outline: 'none' }}>
                  <option value="analyst">Analyst</option>
                  <option value="senior_analyst">Senior Analyst</option>
                  {editEmp.role === 'admin' && <option value="admin">Admin</option>}
                  {editEmp.role !== 'admin' && <option value="admin">Admin</option>}
                </select>
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button type="button" onClick={() => { setShowEditModal(false); setEditEmp(null); }} style={{ flex: 1, padding: '12px', background: 'transparent', border: '1px solid var(--border-subtle)', borderRadius: '8px', color: 'var(--text-muted)', fontWeight: 600, cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ flex: 1, padding: '12px', background: 'var(--primary)', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 600, cursor: 'pointer', boxShadow: '0 4px 12px rgba(59,130,246,0.3)', transition: 'transform 0.2s' }} onMouseOver={(e) => e.currentTarget.style.background = 'var(--primary-hover)'} onMouseOut={(e) => e.currentTarget.style.background = 'var(--primary)'}>Save Changes</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Employees;
