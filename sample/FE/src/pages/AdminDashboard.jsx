import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../js/api';
import SearchableSelect from '../components/SearchableSelect';
import '../css/style.css';
import AlertModal from '../components/AlertModal';

const AdminDashboard = () => {
  const navigate = useNavigate();
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };

  const [totalEmployees, setTotalEmployees] = useState(0);
  const [employees, setEmployees] = useState([]);
  const [casesSolved, setCasesSolved] = useState(0);
  const [currentCase, setCurrentCase] = useState(null);
  const [recentActivity, setRecentActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hasOpenCase, setHasOpenCase] = useState(false);

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseAnalyst, setNewCaseAnalyst] = useState('');
  const [newCaseSeniorAnalyst, setNewCaseSeniorAnalyst] = useState('');
  const [creating, setCreating] = useState(false);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;
    if (!newCaseAnalyst) {
      setCustomAlert({ isOpen: true, title: 'Validation Error', message: 'Please assign an Analyst to the case.', type: 'warning' });
      return;
    }

    setCreating(true);
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/cases/`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': 'dev-team'
        },
        body: JSON.stringify({ 
          name: newCaseName, 
          analyst: 'Admin', 
          analyst_id: newCaseAnalyst || null,
          senior_analyst_id: newCaseSeniorAnalyst || null
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      const createdId = data.case_id || data.id;
      localStorage.setItem('active_case_id', createdId);
      localStorage.setItem('active_case_name', newCaseName);
      
      setShowCreateModal(false);
      setNewCaseName('');
      setNewCaseAnalyst('');
      setNewCaseSeniorAnalyst('');
      setCustomAlert({
        isOpen: true,
        title: 'Success',
        message: 'Case created and assigned successfully.',
        type: 'success',
        onClose: () => window.location.reload()
      });
    } catch (err) {
      console.error(err);
      setCustomAlert({
        isOpen: true,
        title: 'Error',
        message: 'Failed to create case',
        type: 'error'
      });
    } finally {
      setCreating(false);
    }
  };

  const handleCloseCase = async () => {
    if (!currentCase) return;
    try {
      const token = localStorage.getItem('argus_token');
      const res = await fetch(`${API_BASE_URL}/cases/${currentCase.case_id}/close`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': 'dev-team'
        }
      });
      if (res.ok) {
        localStorage.removeItem('active_case_id');
        localStorage.removeItem('active_case_name');
        localStorage.removeItem('active_case_desc');
        setCustomAlert({
          isOpen: true,
          title: 'Success',
          message: 'Case closed successfully.',
          type: 'success',
          onClose: () => window.location.reload()
        });
      } else {
        setCustomAlert({
          isOpen: true,
          title: 'Error',
          message: 'Failed to close case.',
          type: 'error'
        });
      }
    } catch (e) {
      console.error(e);
      setCustomAlert({
        isOpen: true,
        title: 'Error',
        message: 'An error occurred.',
        type: 'error'
      });
    }
  };

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const token = localStorage.getItem('argus_token');
        const headers = {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-ID': 'dev-team'
        };

        // Fetch Employees first, build a lookup map by id
        let employeeMap = {};
        const empRes = await fetch(`${API_BASE_URL}/auth/employees`, { headers });
        if (empRes.ok) {
          const empData = await empRes.json();
          setTotalEmployees(empData.length || 0);
          setEmployees(empData || []);
          // Build a fast id -> employee lookup (handle both string and int ids)
          empData.forEach(emp => {
            employeeMap[String(emp.id)] = emp;
          });
        }

        // Fetch Cases
        const caseRes = await fetch(`${API_BASE_URL}/cases/`, { headers });
        if (caseRes.ok) {
          const caseData = await caseRes.json();
          const cases = caseData.data || [];
          setCasesSolved(cases.length || 0);
          
          if (cases.length > 0) {
            // Enrich each case with resolved analyst and senior analyst names
            const enriched = cases.map(c => ({
              ...c,
              analyst_name: c.analyst_id ? (employeeMap[String(c.analyst_id)]?.name || c.analyst_id) : null,
              senior_analyst_name: c.senior_analyst_id ? (employeeMap[String(c.senior_analyst_id)]?.name || c.senior_analyst_id) : null,
            }));

            // Sort newest first (reverse for created_at ascending)
            const sorted = enriched.reverse();
            
            // Prefer any open case as the current case
            const activeId = localStorage.getItem('active_case_id');
            let active = sorted.find(c => c.case_id === activeId && (c.status === 'open' || c.status === 'in_progress'));
            if (!active) active = sorted.find(c => c.status === 'open' || c.status === 'in_progress');
            if (!active) active = sorted[0]; // fallback to most recent
            setCurrentCase(active);

            setHasOpenCase(sorted.some(c => c.status === 'open' || c.status === 'in_progress'));
          } else {
            setCurrentCase(null);
            setHasOpenCase(false);
          }
        }
        
        // Fetch Recent Activity (Cases & Evidence Uploads)
        const actRes = await fetch(`${API_BASE_URL}/cases/activity`, { headers });
        if (actRes.ok) {
          const actData = await actRes.json();
          setRecentActivity(actData.data || []);
        }
      } catch (e) {
        console.error('Error fetching admin dashboard data:', e);
      } finally {
        setLoading(false);
      }
    };
    
    fetchDashboardData();
    const intervalId = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(intervalId);
  }, []);

  return (
    <div style={{ padding: '32px 40px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <AlertModal 
        isOpen={customAlert.isOpen} 
        title={customAlert.title} 
        message={customAlert.message} 
        type={customAlert.type} 
        onClose={closeAlert} 
      />
      
      {/* HEADER */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 'bold', margin: '0 0 8px', color: 'var(--text-main)' }}>Dashboard</h1>
          <p style={{ color: 'var(--text-muted)', margin: 0 }}>Overview of your organization and current case.</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: '14px', display: 'flex', gap: '16px' }}>
            <span>{new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })}</span>
            <span>{new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: 'numeric' })}</span>
          </div>
          <button
            onClick={() => {
              if (hasOpenCase) {
                setCustomAlert({
                  isOpen: true,
                  title: 'Notice',
                  message: 'An active case is currently open. You cannot create a new case until the active case is closed.',
                  type: 'warning'
                });
              } else {
                setShowCreateModal(true);
              }
            }}
            style={{ background: 'linear-gradient(135deg, #3b82f6, #2563eb)', color: '#fff', border: 'none', padding: '10px 20px', borderRadius: '8px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', cursor: hasOpenCase ? 'not-allowed' : 'pointer', fontSize: '14px', boxShadow: '0 4px 12px rgba(59,130,246,0.35)', opacity: hasOpenCase ? 0.6 : 1 }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Create Case
          </button>
        </div>
      </div>

      {/* STATS ROW */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
        {/* Total Employees */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ width: '64px', height: '64px', borderRadius: '16px', background: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6' }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '4px' }}>{loading ? '-' : totalEmployees}</div>
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>Total Employees</div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Active team members</div>
          </div>
        </div>

        {/* Cases Solved */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ width: '64px', height: '64px', borderRadius: '16px', background: 'rgba(16, 185, 129, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981' }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '4px' }}>{loading ? '-' : casesSolved}</div>
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>Cases Solved</div>
            <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Completed successfully</div>
          </div>
        </div>

        {/* Audit Logs */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', transition: 'all 0.2s' }} onMouseOver={e => e.currentTarget.style.transform = 'translateY(-2px)'} onMouseOut={e => e.currentTarget.style.transform = 'translateY(0)'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div style={{ width: '64px', height: '64px', borderRadius: '16px', background: 'rgba(139, 92, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8b5cf6' }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
            </div>
            <div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '4px' }}>Audit Logs</div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>View all activities</div>
            </div>
          </div>
          <div style={{ color: 'var(--text-muted)' }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>
        </div>
      </div>

      {/* ROW 2: Current Case & Recent Activity */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        
        {/* Current Case */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '16px', border: '1px solid var(--border-subtle)', padding: '32px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '32px' }}>
            <div>
              <h2 style={{ fontSize: '20px', fontWeight: 'bold', margin: '0 0 24px 0', color: 'var(--text-main)' }}>Current Case</h2>
              <div style={{ display: 'flex', gap: '20px' }}>
                <div style={{ width: '64px', height: '64px', borderRadius: '16px', background: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3b82f6' }}>
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  <div style={{ fontSize: '20px', fontWeight: 'bold', color: 'var(--text-main)', marginBottom: '4px' }}>{currentCase ? currentCase.case_id : 'No Active Case'}</div>
                  <div style={{ fontSize: '15px', color: 'var(--text-muted)' }}>{currentCase ? currentCase.name : 'Create a case to get started'}</div>
                </div>
              </div>
            </div>
            
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <span style={{ background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', padding: '6px 12px', borderRadius: '8px', fontSize: '13px', fontWeight: 600 }}>
                {currentCase ? (currentCase.status === 'open' || currentCase.status === 'in_progress' ? 'Under Review' : 'Closed') : 'No Active Cases'}
              </span>
              {currentCase && (currentCase.status === 'open' || currentCase.status === 'in_progress') && (
                <button 
                  onClick={handleCloseCase}
                  style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: 'none', padding: '6px 12px', borderRadius: '8px', fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'background 0.2s' }}
                  onMouseOver={e => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)'}
                  onMouseOut={e => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"></path></svg>
                  Close
                </button>
              )}
            </div>
          </div>

          {/* Progress Timeline */}
          <div style={{ position: 'relative', marginBottom: '48px', padding: '0 24px', marginTop: '16px' }}>
            <div style={{ position: 'absolute', top: '10px', left: '32px', right: '32px', height: '2px', background: 'var(--border-strong)', zIndex: 0 }}></div>
            <div style={{ position: 'absolute', top: '10px', left: '32px', width: '33%', height: '2px', background: '#3b82f6', zIndex: 1 }}></div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', zIndex: 2 }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '20px', height: '20px', borderRadius: '50%', background: '#3b82f6', border: '4px solid var(--bg-card)', boxShadow: '0 0 0 2px #3b82f6' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>Investigation</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>(Analyst)</div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '20px', height: '20px', borderRadius: '50%', background: '#3b82f6', border: '4px solid var(--bg-card)', boxShadow: '0 0 0 2px #3b82f6' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>Review</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>(Senior Analyst)</div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '20px', height: '20px', borderRadius: '50%', background: 'var(--bg-card)', border: '2px solid var(--border-strong)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)' }}>Audit</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>(Not Assigned)</div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '20px', height: '20px', borderRadius: '50%', background: 'var(--bg-card)', border: '2px solid var(--border-strong)' }}></div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)' }}>Closed</div>
                </div>
              </div>
            </div>
          </div>

          {/* Personnel */}
          <div style={{ background: 'var(--bg-app)', borderRadius: '12px', padding: '24px', display: 'flex', justifyContent: 'space-between', marginBottom: '32px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ color: 'var(--text-muted)' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '2px' }}>Analyst</div>
                <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>
                  {currentCase ? (currentCase.analyst_name || currentCase.analyst_id || currentCase.created_by || '-') : '-'}
                </div>
              </div>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ color: 'var(--text-muted)' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '2px' }}>Senior Analyst</div>
                <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>
                  {currentCase ? (currentCase.senior_analyst_name || currentCase.senior_analyst_id || 'Not Assigned') : '-'}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ color: 'var(--text-muted)', opacity: 0.5 }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '2px' }}>Auditor</div>
                <div style={{ fontSize: '15px', fontWeight: 500, color: 'var(--text-muted)' }}>Not Assigned</div>
              </div>
            </div>
          </div>

          {/* Dates */}
          <div style={{ display: 'flex', gap: '48px', paddingTop: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ color: 'var(--text-muted)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '2px' }}>Created On</div>
                <div style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-main)' }}>{currentCase && currentCase.created_at ? new Date(currentCase.created_at).toLocaleDateString('en-US', {month: 'short', day: 'numeric', year: 'numeric'}) : '-'}</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ color: 'var(--text-muted)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '2px' }}>Last Updated</div>
                <div style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-main)' }}>{currentCase && currentCase.created_at ? new Date(currentCase.created_at).toLocaleString('en-US', {month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit'}) : '-'}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div style={{ background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)', padding: '24px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 'bold', margin: 0, color: 'var(--text-main)' }}>Recent Activity</h2>
            <span style={{ color: '#3b82f6', fontSize: '14px', fontWeight: 500, cursor: 'pointer' }}>View All</span>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <th style={{ paddingBottom: '12px', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>Date & Time</th>
                <th style={{ paddingBottom: '12px', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>User</th>
                <th style={{ paddingBottom: '12px', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>Action</th>
                <th style={{ paddingBottom: '12px', fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {recentActivity.length > 0 ? recentActivity.map((activity, idx) => (
                <tr key={idx} style={{ borderBottom: idx === recentActivity.length - 1 ? 'none' : '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '16px 0', fontSize: '13px', color: 'var(--text-muted)' }}>
                    {activity.created_at ? new Date(activity.created_at).toLocaleDateString() : '-'}<br/>
                    {activity.created_at ? new Date(activity.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : ''}
                  </td>
                  <td style={{ padding: '16px 0' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: activity.created_by === 'admin' ? '#4b5563' : '#3b82f6', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: 'bold', textTransform: 'uppercase' }}>
                        {activity.created_by ? activity.created_by.charAt(0) : 'U'}
                      </div>
                      <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-main)', textTransform: 'capitalize' }}>{activity.created_by || 'Unknown'}</span>
                    </div>
                  </td>
                  <td style={{ padding: '16px 0', fontSize: '13px', color: 'var(--text-main)' }}>{activity.action || 'Unknown Action'}</td>
                  <td style={{ padding: '16px 0', fontSize: '13px', color: 'var(--text-muted)' }}>
                    {activity.action === 'Created Case' 
                      ? (activity.details ? activity.details.split('-')[0].substring(0, 12) + '...' : '-') 
                      : (activity.details || '-')}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="4" style={{ padding: '16px 0', fontSize: '13px', color: 'var(--text-muted)', textAlign: 'center' }}>No recent activity</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Admin Create Case Modal */}
      {showCreateModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)' }}>
          <div style={{ background: 'var(--bg-card)', width: '100%', maxWidth: '400px', borderRadius: '12px', boxShadow: '0 10px 25px rgba(0,0,0,0.2)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 600 }}>Create New Case</h2>
              <button onClick={() => setShowCreateModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              </button>
            </div>
            <form onSubmit={handleCreateCase} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Case Name</label>
                <input type="text" value={newCaseName} onChange={e => setNewCaseName(e.target.value)} style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid var(--border-strong)', background: 'var(--bg-input)', color: 'var(--text-main)', outline: 'none' }} placeholder="e.g., Operation Dark Web" required />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Assign Analyst</label>
                <SearchableSelect 
                  value={newCaseAnalyst} 
                  onChange={setNewCaseAnalyst} 
                  placeholder="Select Analyst"
                  options={employees.filter(e => e.role === 'analyst').map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }))}
                />
              </div>
              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px', color: 'var(--text-muted)' }}>Assign Senior Analyst</label>
                <SearchableSelect 
                  value={newCaseSeniorAnalyst} 
                  onChange={setNewCaseSeniorAnalyst} 
                  placeholder="Select Senior Analyst (Optional)"
                  options={employees.filter(e => e.role === 'senior_analyst').map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }))}
                />
              </div>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button type="button" onClick={() => setShowCreateModal(false)} style={{ flex: 1, padding: '10px', background: 'var(--bg-card-alt)', border: '1px solid var(--border-strong)', borderRadius: '8px', color: 'var(--text-main)', fontWeight: 500, cursor: 'pointer' }}>Cancel</button>
                <button type="submit" disabled={creating} style={{ flex: 1, padding: '10px', background: 'var(--blue)', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 500, cursor: 'pointer', opacity: creating ? 0.7 : 1 }}>
                  {creating ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
