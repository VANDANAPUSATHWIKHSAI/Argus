import React, { useState, useEffect, useMemo, useRef } from 'react';
import '../css/style.css';
import '../css/evidence.css';
import { fetchEvidenceForCase, closeCase, fetchCases } from '../js/api';
import { Link, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import SearchableSelect from '../components/SearchableSelect';
import { safeFormatDateOnly, formatEvidenceId } from '../js/dateUtils';
import { getActiveCaseId, getActiveCaseName, setActiveCase, subscribeToActiveCase } from '../js/caseEvents';

const Evidence = () => {
  const formatBytes = (bytes, decimals = 2) => {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  };

  const [evidenceData, setEvidenceData] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [selectedItem, setSelectedItem] = useState(null);
  const filterRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (filterRef.current && !filterRef.current.contains(event.target)) {
        setShowAdvancedFilters(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [filterRef]);
  const [_loading, setLoading] = useState(true);
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [_showProfileModal, _setShowProfileModal] = useState(false);
  const [customAlert, setCustomAlert] = useState({ isOpen: false, title: '', message: '', type: 'warning', onClose: null });
  const navigate = useNavigate();

  const [casesList, setCasesList] = useState([]);
  const [activeCaseId, setActiveCaseId] = useState(getActiveCaseId());
  const [activeCaseName, setActiveCaseName] = useState(getActiveCaseName());

  useEffect(() => {
    const getCases = async () => {
      try {
        const res = await fetchCases();
        const list = res?.data || res || [];
        setCasesList(Array.isArray(list) ? list : []);
        const currentSavedId = getActiveCaseId();
        const foundSaved = list.find(c => c.case_id === currentSavedId);
        if (foundSaved && (foundSaved.status === 'open' || foundSaved.status === 'in_progress')) {
          setActiveCaseId(foundSaved.case_id);
          setActiveCaseName(foundSaved.name || foundSaved.case_id);
        }
      } catch (err) {
        console.error('Failed to load cases in Evidence:', err);
      }
    };
    getCases();
  }, []);

  const handleSelectCase = (cId) => {
    if (!cId) {
      setActiveCase('', '');
      setActiveCaseId('');
      setActiveCaseName('');
      return;
    }
    const selected = casesList.find(c => c.case_id === cId);
    if (selected) {
      setActiveCase(selected.case_id, selected.name || selected.case_id);
      setActiveCaseId(selected.case_id);
      setActiveCaseName(selected.name || selected.case_id);
    }
  };

  // Synchronize active case across tabs and components
  useEffect(() => {
    return subscribeToActiveCase(({ caseId, caseName }) => {
      setActiveCaseId(caseId);
      setActiveCaseName(caseName);
    });
  }, []);

  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const isAdmin = currentUser?.role === 'admin';

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };
  
  useEffect(() => {
    let isMounted = true;
    const loadEvidence = async () => {
      try {
        setLoading(true);
        if (!activeCaseId) {
          if (isMounted) {
            setEvidenceData([]);
            setLoading(false);
          }
          return;
        }

        const rawData = await fetchEvidenceForCase(activeCaseId);
        if (!isMounted) return;

        const fetchedList = rawData.data || rawData || [];
        
        const mappedData = (Array.isArray(fetchedList) ? fetchedList : []).map((item, index) => {
          const f = (item.filename || '').toLowerCase();
          let type = 'File';
          if (f.endsWith('.ps1') || f.endsWith('.sh') || f.endsWith('.bat') || f.endsWith('.cmd') || f.endsWith('.py')) type = 'Script';
          else if (f.endsWith('.zip') || f.endsWith('.tar') || f.endsWith('.gz') || f.endsWith('.rar') || f.endsWith('.7z')) type = 'Archive';
          else if (f.endsWith('.evtx')) type = 'EVTX';
          else if (f.endsWith('.log') || f.endsWith('.txt') || f.endsWith('.syslog') || f.endsWith('.csv')) type = 'Log';
          else if (f.endsWith('.pcap') || f.endsWith('.pcapng') || f.endsWith('.cap')) type = 'PCAP';
          else if (f.includes('ntuser') || f.includes('sam') || f.includes('system') || f.includes('software') || f.endsWith('.dat') || f.endsWith('.hiv')) type = 'Registry';
          else if (f.endsWith('.e01') || f.endsWith('.raw') || f.endsWith('.img') || f.endsWith('.dd') || f.endsWith('.vmdk') || f.endsWith('.vhd')) type = 'Disk Image';
          else if (f.endsWith('.mem') || f.endsWith('.dmp') || f.endsWith('.bin')) type = 'Memory';

          const displayId = formatEvidenceId(item.evidence_id, index + 1);

          // Preserve authentic backend processing status
          const rawStatus = (item.status || '').toLowerCase();
          let normalizedStatus = 'Unknown';
          if (rawStatus.includes('fail') || rawStatus === 'error' || rawStatus === 'rejected' || Boolean(item.metadata?.error || item.error)) {
            normalizedStatus = 'Failed';
          } else if (rawStatus === 'processing' || rawStatus === 'uploaded' || rawStatus === 'sandboxed' || rawStatus === 'hashed' || rawStatus === 'metadata_extracted') {
            normalizedStatus = 'Processing';
          } else if (rawStatus === 'queued' || rawStatus === 'pending') {
            normalizedStatus = 'Queued';
          } else if (rawStatus === 'completed' || rawStatus === 'analyzed') {
            normalizedStatus = 'Analyzed';
          } else if (rawStatus === 'stored' || rawStatus === 'ingested') {
            normalizedStatus = 'Stored';
          } else if (item.status) {
            normalizedStatus = item.status.charAt(0).toUpperCase() + item.status.slice(1).toLowerCase();
          }

          // Authentic ingestion timestamp: never invent current date
          const authenticTimestamp = item.upload_timestamp || item.created_at || item.metadata?.ingested_at || null;

          // Authentic risk: only present authoritative backend score or Unassessed
          const authenticRisk = item.risk || item.metadata?.risk || (normalizedStatus === 'Failed' ? 'High' : 'Unassessed');

          return {
            id: item.evidence_id,
            displayId: displayId,
            name: item.filename,
            type: type,
            source: item.metadata?.host_id || item.uploaded_by || 'Unknown',
            size: item.metadata?.size_bytes || 0,
            status: normalizedStatus,
            rawStatus: item.status,
            error: item.metadata?.error || item.error || null,
            ingested_at: authenticTimestamp,
            risk: authenticRisk
          };
        });
        
        setEvidenceData(mappedData);
      } catch (err) {
        if (isMounted) {
          console.error("Failed to fetch evidence", err);
          setCustomAlert({ isOpen: true, title: 'Error Fetching Data', message: err.message || String(err), type: 'warning' });
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    loadEvidence();
    return () => {
      isMounted = false;
    };
  }, [activeCaseId]);

  const ingestedCount = useMemo(() => {
    return evidenceData.filter(e => e.status === 'Stored').length;
  }, [evidenceData]);

  const processingCount = useMemo(() => {
    return evidenceData.filter(e => e.status === 'Processing').length;
  }, [evidenceData]);

  const failedCount = useMemo(() => {
    return evidenceData.filter(e => e.status === 'Failed').length;
  }, [evidenceData]);

  const totalBytes = useMemo(() => {
    return evidenceData.reduce((acc, curr) => acc + (curr.size || 0), 0);
  }, [evidenceData]);

  const filteredData = useMemo(() => {
    return evidenceData.filter(item => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase().trim();
        const matchName = item.name && item.name.toLowerCase().includes(q);
        const matchSource = item.source && item.source.toLowerCase().includes(q);
        const matchId = item.id && item.id.toLowerCase().includes(q);
        const matchDisplayId = item.displayId && item.displayId.toLowerCase().includes(q);
        const matchStatus = item.status && item.status.toLowerCase().includes(q);
        if (!matchName && !matchSource && !matchId && !matchDisplayId && !matchStatus) return false;
      }
      if (typeFilter && item.type !== typeFilter) return false;
      if (statusFilter && item.status !== statusFilter) return false;
      if (sourceFilter && item.source !== sourceFilter) return false;
      if (riskFilter && item.risk !== riskFilter) return false;
      return true;
    });
  }, [evidenceData, searchQuery, typeFilter, statusFilter, sourceFilter, riskFilter]);

  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = filteredData.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(filteredData.length / itemsPerPage);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const handleOpenCreateCase = () => {
    const activeCaseId = localStorage.getItem('active_case_id');
    const activeCaseName = localStorage.getItem('active_case_name');
    if (activeCaseId && activeCaseId !== '00000000-0000-0000-0000-000000000001' && activeCaseName && activeCaseName !== 'Case 00000000') {
      setCustomAlert({ isOpen: true, title: 'Notice', message: `An active case "${activeCaseName}" is currently open. Please close the active case before creating a new case.`, type: 'warning' });
      return;
    }
    navigate('/dashboard');
  };

  const handleCloseCase = async () => {
    const activeCaseName = getActiveCaseName();
    const activeCaseId = getActiveCaseId();
    if (!activeCaseId && !activeCaseName) {
      setCustomAlert({ isOpen: true, title: 'Notice', message: "There is no active case currently open.", type: 'warning' });
      return;
    }
    try {
      if (activeCaseId) {
        await closeCase(activeCaseId);
      }
    } catch (e) {
      console.error("Failed to close case:", e);
    }
    setActiveCase('', '');
    try {
      localStorage.removeItem('active_case_desc');
    } catch (_e) {}
    setCustomAlert({
       isOpen: true,
       title: 'Success',
       message: `${activeCaseName || activeCaseId} has been closed successfully.`,
       type: 'success',
       onClose: () => window.location.reload()
    });
  };

  return (
    <>
      <div id="app-shell">
        <AlertModal 
          isOpen={customAlert.isOpen} 
          title={customAlert.title} 
          message={customAlert.message} 
          type={customAlert.type} 
          onClose={closeAlert} 
        />
  {/* SIDEBAR */}
  <Sidebar />

  {/* MAIN AREA */}
  <main className="main-content">
    
    {/* TOPBAR */}
    <header className="glass-topbar-capsule topbar">
      <div className="search-container">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{color: 'var(--glass-dash-text-muted)', marginRight: '8px'}}><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <input type="text" placeholder="Search cases, evidence, or findings..." />
        <span className="search-shortcut">⌘ K</span>
      </div>
      <div className="glass-topbar-right topbar-actions">
        {casesList.length > 0 && (
          <select
            id="evidence-topbar-case-select"
            value={activeCaseId || ''}
            onChange={(e) => handleSelectCase(e.target.value)}
            style={{
              background: 'var(--bg-card)',
              color: 'var(--text-main)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 20,
              padding: '6px 14px',
              fontSize: 13,
              fontWeight: 500,
              cursor: 'pointer',
              outline: 'none'
            }}
          >
            <option value="">-- Switch Case --</option>
            {casesList.filter(c => c.status === 'open' || c.status === 'in_progress').map(c => (
              <option key={c.case_id} value={c.case_id}>
                {c.case_id} — {c.name || 'Unnamed'}
              </option>
            ))}
          </select>
        )}
        <button
          id="btn-topbar-upload"
          className="btn btn-primary"
          onClick={() => navigate('/upload')}
          style={{ padding: '8px 16px', borderRadius: 'var(--radius-full)', fontSize: '13px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', background: 'var(--blue)', color: '#fff', border: 'none' }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
          Upload Evidence
        </button>
        {isAdmin && activeCaseId && (
          <button
            type="button"
            onClick={handleCloseCase}
            className="btn-outline"
            style={{ fontSize: '13px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '6px', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.08)', cursor: 'pointer' }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"></path></svg>
            Close Case
          </button>
        )}
        {isAdmin && (
          <button
            type="button"
            onClick={handleOpenCreateCase}
            className="btn-primary"
            style={{ fontSize: '13px', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Create Case
          </button>
        )}
        {localStorage.getItem('active_case_id') && <div className="badge-live"><div className="live-dot"></div> Live Analysis</div>}
        <NotificationMenu />
        <div className="glass-profile-pill user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
          <div className="glass-profile-avatar-dark avatar">{currentUser?.name ? currentUser.name.charAt(0).toUpperCase() : 'S'}</div>
          <span className="glass-profile-name" style={{textTransform: 'capitalize'}}>{currentUser?.name || 'sathwik'}</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          {showUserDropdown && (
            <div className="user-dropdown" style={{ display: 'block' }}>
              <div className="user-dropdown-header">
                <div className="ud-name" style={{ textTransform: 'capitalize' }}>{currentUser?.name || 'sathwik'}</div>
                <div className="ud-role">{currentUser?.role?.replace('_', ' ') || 'Digital Forensics Investigator'}</div>
              </div>
              <button className="user-dropdown-item" onClick={(e) => { e.stopPropagation(); setShowProfileModal(true); setShowUserDropdown(false); }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                My Profile
              </button>
            </div>
          )}
        </div>
      </div>
    </header>

    {/* DASHBOARD SCROLL AREA */}
    <div className="dashboard-scroll">
      
      {!activeCaseId ? (
        <div id="evidence-empty-state" style={{ display: 'block', textAlign: 'center', padding: '80px 20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', margin: '24px', border: '1px dashed var(--border-strong)' }}>
          <div style={{ width: '64px', height: '64px', background: 'var(--blue-light)', color: 'var(--blue)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>No Active Case Selected</h2>
          <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '440px', margin: '0 auto 20px' }}>Select an open case from the dropdown below or upload new evidence to begin your investigation.</p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            {casesList.length > 0 && (
              <select
                id="evidence-empty-case-select"
                value={activeCaseId || ''}
                onChange={(e) => handleSelectCase(e.target.value)}
                style={{
                  background: 'var(--bg-app)',
                  color: 'var(--text-main)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: 20,
                  padding: '8px 16px',
                  fontSize: 14,
                  fontWeight: 500,
                  cursor: 'pointer',
                  outline: 'none'
                }}
              >
                <option value="">-- Select an Open Case to View Evidence --</option>
                {casesList.filter(c => c.status === 'open' || c.status === 'in_progress').map(c => (
                  <option key={c.case_id} value={c.case_id}>
                    {c.case_id} — {c.name || 'Unnamed'}
                  </option>
                ))}
              </select>
            )}
            <button
              id="btn-empty-upload"
              className="btn btn-primary"
              onClick={() => navigate('/upload')}
              style={{ padding: '8px 18px', fontSize: 14, borderRadius: 'var(--radius-full)', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', background: 'var(--blue)', color: '#fff', border: 'none' }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
              Upload Evidence
            </button>
            {isAdmin && (
              <button
                className="btn btn-outline"
                onClick={handleOpenCreateCase}
                style={{ padding: '8px 18px', fontSize: 14, borderRadius: 'var(--radius-full)', cursor: 'pointer' }}
              >
                Create New Case
              </button>
            )}
          </div>
        </div>
      ) : (
        <>
          {/* Case Header */}
          <div className="header-card" style={{flexShrink: '0'}}>
            <div className="header-info-wrap">
          <div className="header-id">
            <h1>EVIDENCE</h1>
          </div>
          <div className="header-details">
            <h2 style={{fontSize: '16px', fontWeight: '500', color: 'var(--text-muted)'}}>Review, filter and investigate digital artifacts collected for this case.</h2>
            <div className="header-meta" style={{marginTop: '12px', gap: '12px'}}>
              <div className="meta-item" style={{color: 'var(--text-main)'}}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2" ry="2"></rect><path d="M10 4v4"></path><path d="M14 4v4"></path><path d="M2 8h20"></path></svg>
                <div>
                  <span style={{fontSize: '11px', textTransform: 'uppercase'}}>{localStorage.getItem('active_case_id') || 'UNKNOWN ID'}</span>
                  <strong style={{fontSize: '14px', marginTop: '2px'}}>{localStorage.getItem('active_case_name') || 'Unnamed Case'}</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="header-quote">
          <p>"From digital traces to real answers."</p>
          <span>— ARGUS</span>
        </div>
      </div>      {/* Stats Grid */}
      <div className="stats-grid evidence-stats" style={{flexShrink: '0', gridTemplateColumns: 'repeat(5, 1fr)'}}>
        <div 
          className="stat-card" 
          role="button"
          tabIndex={0}
          aria-pressed={statusFilter === ''}
          onClick={() => setStatusFilter('')} 
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setStatusFilter(''); } }}
          title="Click to view all evidence items"
          style={{ cursor: 'pointer', transition: 'all 0.2s', border: statusFilter === '' ? '2px solid var(--blue)' : '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}
        >
          <div className="stat-icon" style={{backgroundColor: 'var(--blue-light)', color: 'var(--blue)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
          </div>
          <div className="stat-info">
            <h2>{evidenceData.length}</h2>
            <h4>Total Items</h4>
            <p>Collected for this case</p>
          </div>
        </div>
        <div 
          className="stat-card" 
          role="button"
          tabIndex={0}
          aria-pressed={statusFilter === 'Stored'}
          onClick={() => setStatusFilter(prev => prev === 'Stored' ? '' : 'Stored')} 
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setStatusFilter(prev => prev === 'Stored' ? '' : 'Stored'); } }}
          title="Click to filter by Ingested"
          style={{ cursor: 'pointer', transition: 'all 0.2s', border: statusFilter === 'Stored' ? '2px solid var(--green, #10b981)' : '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}
        >
          <div className="stat-icon" style={{backgroundColor: 'var(--green-light, #e6f6ec)', color: 'var(--green, #10b981)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
          </div>
          <div className="stat-info">
            <h2>{ingestedCount}</h2>
            <h4>Ingested</h4>
            <p>Ready for analysis</p>
          </div>
        </div>
        <div 
          className="stat-card" 
          role="button"
          tabIndex={0}
          aria-pressed={statusFilter === 'Processing'}
          onClick={() => setStatusFilter(prev => prev === 'Processing' ? '' : 'Processing')} 
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setStatusFilter(prev => prev === 'Processing' ? '' : 'Processing'); } }}
          title="Click to filter by Processing"
          style={{ cursor: 'pointer', transition: 'all 0.2s', border: statusFilter === 'Processing' ? '2px solid var(--orange, #f59e0b)' : '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}
        >
          <div className="stat-icon" style={{backgroundColor: 'var(--orange-light)', color: 'var(--orange)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
          </div>
          <div className="stat-info">
            <h2>{processingCount}</h2>
            <h4>Processing</h4>
            <p>Currently analyzing</p>
          </div>
        </div>
        <div 
          className="stat-card" 
          role="button"
          tabIndex={0}
          aria-pressed={statusFilter === 'Failed'}
          onClick={() => setStatusFilter(prev => prev === 'Failed' ? '' : 'Failed')} 
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setStatusFilter(prev => prev === 'Failed' ? '' : 'Failed'); } }}
          title="Click to filter by Failed items"
          style={{ cursor: 'pointer', transition: 'all 0.2s', border: statusFilter === 'Failed' ? '2px solid var(--red, #ef4444)' : '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}
        >
          <div className="stat-icon" style={{backgroundColor: 'var(--red-light, #fee2e2)', color: 'var(--red, #ef4444)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          </div>
          <div className="stat-info">
            <h2 style={{ color: failedCount > 0 ? 'var(--red, #ef4444)' : 'inherit' }}>{failedCount}</h2>
            <h4>Failed</h4>
            <p style={{ color: failedCount > 0 ? 'var(--red, #ef4444)' : 'var(--text-muted)', fontWeight: failedCount > 0 ? 600 : 'normal' }}>
              {failedCount === 0 ? 'No errors detected' : `${failedCount} error${failedCount > 1 ? 's' : ''} require attention`}
            </p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{backgroundColor: 'var(--blue-light)', color: 'var(--blue)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>
          </div>
          <div className="stat-info">
            <h2>{totalBytes > 0 ? (totalBytes / (1024*1024)).toFixed(2) + ' MB' : '0 B'}</h2>
            <h4>Total Size</h4>
            <p>Across all evidence</p>
          </div>
        </div>
      </div>

      {/* Main Panels */}
      <div className="main-grid" id="main-grid" style={{flexShrink: '0', minHeight: '800px', display: 'grid', gridTemplateColumns: '1fr', gap: '24px', transition: 'all 0.3s ease'}}>
        
        {/* Evidence Workspace */}
        <div className="panel-card evidence-workspace" style={{display: 'flex', flexDirection: 'column', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', boxShadow: 'var(--shadow-card)', overflow: 'hidden'}}>
          
          {/* Navigation Tabs */}
          <div className="evidence-tabs" style={{display: 'flex', borderBottom: '1px solid var(--border-strong)', padding: '0 24px', background: 'var(--bg-app)'}}>
            <div className="evidence-tab active" style={{padding: '16px 20px', fontWeight: '600', fontSize: '14px', color: 'var(--blue)', borderBottom: '2px solid var(--blue)', cursor: 'pointer'}}>Evidence Items</div>
            <div id="tab-upload-evidence" className="evidence-tab" onClick={() => navigate('/upload')} style={{padding: '16px 20px', fontWeight: '500', fontSize: '14px', color: 'var(--text-muted)', cursor: 'pointer'}}>Upload Evidence</div>
          </div>

          {/* Search & Filters */}
          <div className="evidence-toolbar" style={{display: 'flex', justifyContent: 'space-between', padding: '16px 24px', borderBottom: '1px solid var(--border-strong)', alignItems: 'center', position: 'relative', zIndex: 100}}>
            <div className="toolbar-left" style={{display: 'flex', gap: '16px', alignItems: 'center'}}>
              <div className="search-container" style={{ width: '280px' }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <input type="text" placeholder="Search evidence..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
              </div>
            </div>
            <div className="toolbar-right" style={{display: 'flex', gap: '12px', alignItems: 'center'}}>
              <div style={{ width: '130px', position: 'relative' }}>
                <SearchableSelect 
                  value={typeFilter} 
                  onChange={setTypeFilter} 
                  placeholder="All Sources" 
                  noSearch 
                  size="small"
                   options={[
                    { label: "All Sources", value: "" },
                    { label: "Disk Image", value: "Disk Image" },
                    { label: "Memory Dump", value: "Memory" },
                    { label: "Network Capture", value: "PCAP" },
                    { label: "Windows Event Log", value: "EVTX" },
                    { label: "Linux Log", value: "Log" },
                    { label: "Registry Hive", value: "Registry" },
                    { label: "Script", value: "Script" },
                    { label: "File / Document", value: "File" },
                    { label: "Archive", value: "Archive" },
                  ]}
                />
              </div>
              <div style={{ width: '130px', position: 'relative' }}>
                <SearchableSelect 
                  value={statusFilter} 
                  onChange={setStatusFilter} 
                  placeholder="All Status" 
                  noSearch 
                  size="small"
                  options={[
                    { label: "All Status", value: "" },
                    { label: "Stored", value: "Stored" },
                    { label: "Processing", value: "Processing" },
                    { label: "Failed", value: "Failed" }
                  ]}
                />
              </div>
              <div style={{ position: 'relative' }} ref={filterRef}>
                <button 
                  className={`btn ${showAdvancedFilters ? 'btn-primary' : 'btn-outline'}`} 
                  onClick={() => setShowAdvancedFilters(!showAdvancedFilters)} 
                  style={{fontSize: '12px', padding: '6px 12px', gap: '4px', border: showAdvancedFilters ? 'none' : '1px solid var(--border-strong)'}}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line><line x1="1" y1="14" x2="7" y2="14"></line><line x1="9" y1="8" x2="15" y2="8"></line><line x1="17" y1="16" x2="23" y2="16"></line></svg> Filters
                </button>
                {showAdvancedFilters && (
                  <div style={{
                    position: 'absolute', top: '100%', right: 0, marginTop: '8px',
                    width: '280px', background: 'var(--bg-card)', border: '1px solid var(--border-strong)',
                    borderRadius: '8px', padding: '16px', zIndex: 1000,
                    boxShadow: 'var(--shadow-card)', display: 'flex', flexDirection: 'column', gap: '16px'
                  }}>
                    <h4 style={{ margin: 0, fontSize: '14px', color: 'var(--text-main)', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>Advanced Filters</h4>
                    
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Original Source Host</label>
                      <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)} style={{ padding: '8px', borderRadius: '6px', background: 'var(--bg-input)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', fontSize: '13px', outline: 'none' }}>
                        <option value="">All Hosts</option>
                        {Array.from(new Set(evidenceData.map(e => e.source))).filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Risk Level</label>
                      <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} style={{ padding: '8px', borderRadius: '6px', background: 'var(--bg-input)', border: '1px solid var(--border-strong)', color: 'var(--text-main)', fontSize: '13px', outline: 'none' }}>
                        <option value="">Any Risk</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                      </select>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
                      <button onClick={() => { setSourceFilter(''); setRiskFilter(''); setTypeFilter(''); setStatusFilter(''); }} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '12px', padding: '6px 12px' }}>Clear All Filters</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Evidence Table */}
          <div className="table-container" style={{flex: '1', overflowY: 'auto'}}>
            <table className="evidence-table" style={{width: '100%', borderCollapse: 'collapse', textAlign: 'left'}}>
              <thead>
                <tr style={{borderBottom: '1px solid var(--border-strong)', fontSize: '12px', color: 'var(--text-muted)', fontWeight: '600'}}>
                  <th style={{padding: '16px 24px', width: '40px'}}><input type="checkbox" onClick={(e) => { e.stopPropagation(); setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Bulk selection is not yet implemented in this prototype.', type: 'info'}) }} /></th>
                  <th style={{padding: '16px 12px'}}>Evidence ID</th>
                  <th style={{padding: '16px 12px'}}>Evidence Name</th>
                  <th style={{padding: '16px 12px'}}>Type</th>
                  <th style={{padding: '16px 12px'}}>Source</th>
                  <th style={{padding: '16px 12px'}}>Size</th>
                  <th style={{padding: '16px 12px'}}>Status</th>
                  <th style={{padding: '16px 12px'}}>Added On</th>
                  <th style={{padding: '16px 12px'}}>Risk</th>
                  <th style={{padding: '16px 24px', textAlign: 'right'}}>Actions</th>
                </tr>
              </thead>
              
                <tbody id="evidence-tbody">
                  {currentItems.length === 0 ? (
                    <tr>
                      <td colSpan="10" style={{textAlign: 'center', padding: '40px', color: 'var(--text-muted)'}}>
                        No evidence files found matching your criteria.
                      </td>
                    </tr>
                  ) : (
                    currentItems.map(item => (
                      <tr key={item.id} className={`ev-row ${selectedItem?.id === item.id ? 'selected' : ''}`} onClick={() => setSelectedItem(item)}>
                        <td style={{padding: '16px 24px'}}>
                          <input 
                            type="checkbox" 
                            aria-label={`Select evidence item ${item.displayId || item.id}`}
                            onClick={(e) => { e.stopPropagation(); setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Item selection is not yet implemented in this prototype.', type: 'info'}) }} 
                          />
                        </td>
                        <td style={{padding: '16px 12px'}}>
                          <span 
                            title={`Evidence ID: ${item.displayId || item.id}\nRaw ID: ${item.id}\nClick to copy`}
                            onClick={(e) => {
                              e.stopPropagation();
                              if (navigator.clipboard) {
                                navigator.clipboard.writeText(item.displayId || formatEvidenceId(item.id));
                              }
                            }}
                            style={{ 
                              fontFamily: 'monospace', 
                              fontSize: '12px', 
                              fontWeight: 600, 
                              color: 'var(--blue)', 
                              background: 'var(--blue-light, #eff6ff)', 
                              border: '1px solid #dbeafe', 
                              padding: '3px 8px', 
                              borderRadius: '6px',
                              whiteSpace: 'nowrap',
                              cursor: 'pointer',
                              display: 'inline-block'
                            }}
                          >
                            {item.displayId || formatEvidenceId(item.id)}
                          </span>
                        </td>
                        <td>
                          <div className="ev-name-cell" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <svg className="ev-file-icon" style={{ flexShrink: 0, color: 'var(--blue)' }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                              <polyline points="14 2 14 8 20 8" />
                            </svg>
                            <span style={{ fontWeight: '500', color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.name}</span>
                          </div>
                        </td>
                        <td><span className="ev-type-badge" style={{ background: 'var(--bg-app)', padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: '500', color: 'var(--text-muted)' }}>{item.type}</span></td>
                        <td>{item.source}</td>
                        <td>{formatBytes(item.size)}</td>
                        <td>
                          <span 
                            className={`status-pill status-${(item.status || '').toLowerCase()}`} 
                            title={item.error ? `Error: ${item.error}` : undefined}
                            style={{ 
                              display: 'inline-flex', 
                              alignItems: 'center', 
                              padding: '4px 10px', 
                              borderRadius: '12px', 
                              fontSize: '11px', 
                              fontWeight: '600', 
                              backgroundColor: item.status === 'Stored' ? 'var(--green-light, #e6f6ec)' : item.status === 'Failed' ? 'var(--red-light, #fee2e2)' : 'var(--orange-light, #fef3c7)', 
                              color: item.status === 'Stored' ? 'var(--green, #10b981)' : item.status === 'Failed' ? 'var(--red, #ef4444)' : 'var(--orange, #f59e0b)' 
                            }}
                          >
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'currentColor', marginRight: '6px' }}></span>
                            {item.status}
                          </span>
                        </td>
                        <td>{safeFormatDateOnly(item.ingested_at)}</td>
                        <td>
                           <span style={{ color: item.risk === 'High' ? 'var(--red)' : item.risk === 'Medium' ? 'var(--orange)' : 'var(--text-muted)' }}>{item.risk || 'Unassessed'}</span>
                        </td>
                        <td style={{ textAlign: 'right', padding: '16px 24px' }}>
                          <button 
                            aria-label={`Actions for evidence ${item.displayId || item.id}`}
                            onClick={(e) => { e.stopPropagation(); setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Item actions are not yet implemented in this prototype.', type: 'info'}) }} 
                            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
                          >
                             <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle><circle cx="5" cy="12" r="1"></circle></svg>
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>

            </table>
          </div>

          {/* Pagination Controls */}
          {totalPages > 0 && (
            <div className="pagination" style={{padding: '16px 24px', borderTop: '1px solid var(--border-strong)', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
              <span style={{fontSize: '13px', color: 'var(--text-muted)'}}>
                Showing {indexOfFirstItem + 1}–{Math.min(indexOfLastItem, filteredData.length)} of {filteredData.length} evidence items
              </span>
              <div style={{display: 'flex', gap: '8px', alignItems: 'center'}}>
                <button 
                  className="btn-icon" 
                  aria-label="Previous page"
                  onClick={() => paginate(currentPage - 1)} 
                  disabled={currentPage === 1}
                  style={{width: '32px', height: '32px', cursor: currentPage === 1 ? 'not-allowed' : 'pointer', opacity: currentPage === 1 ? 0.5 : 1}}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"></polyline></svg>
                </button>
                {Array.from({ length: totalPages }, (_, i) => (
                  <button 
                    key={i + 1} 
                    className="btn-icon" 
                    aria-label={`Page ${i + 1}`}
                    onClick={() => paginate(i + 1)}
                    style={{width: '32px', height: '32px', cursor: 'pointer', background: currentPage === i + 1 ? 'var(--blue)' : 'var(--bg-app)', color: currentPage === i + 1 ? '#fff' : 'var(--text-main)', borderColor: currentPage === i + 1 ? 'var(--blue)' : 'var(--border-strong)'}}
                  >
                    {i + 1}
                  </button>
                ))}
                <button 
                  className="btn-icon" 
                  aria-label="Next page"
                  onClick={() => paginate(currentPage + 1)} 
                  disabled={currentPage === totalPages}
                  style={{width: '32px', height: '32px', cursor: currentPage === totalPages ? 'not-allowed' : 'pointer', opacity: currentPage === totalPages ? 0.5 : 1}}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Evidence Details Modal */}
        {selectedItem && (
          <div 
            style={{ display: 'flex', position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)', zIndex: 1000, alignItems: 'center', justifyContent: 'center' }}
            onClick={() => setSelectedItem(null)}
          >
            <div 
              style={{ background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', width: 560, maxWidth: '90vw', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}
              onClick={e => e.stopPropagation()}
            >
              <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-app)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'var(--blue-light)', color: 'var(--blue)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                  </div>
                  <div>
                    <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>{selectedItem.name}</h3>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{selectedItem.displayId || selectedItem.id}</div>
                  </div>
                </div>
                <button 
                  onClick={() => setSelectedItem(null)} 
                  style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
                >
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              </div>

              <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <div style={{ background: 'var(--bg-app)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Status</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: selectedItem.status === 'Stored' ? '#10b981' : selectedItem.status === 'Failed' ? '#ef4444' : '#f59e0b', marginTop: 4 }}>
                      {selectedItem.status}
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-app)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Artifact Type</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)', marginTop: 4 }}>{selectedItem.type}</div>
                  </div>
                  <div style={{ background: 'var(--bg-app)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>File Size</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)', marginTop: 4 }}>{formatBytes(selectedItem.size)}</div>
                  </div>
                  <div style={{ background: 'var(--bg-app)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Risk Verdict</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: selectedItem.risk === 'High' ? '#ef4444' : 'var(--text-main)', marginTop: 4 }}>
                      {selectedItem.risk || 'Unassessed'}
                    </div>
                  </div>
                </div>

                <div style={{ background: 'var(--bg-app)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Source Device / Host</div>
                  <div style={{ fontSize: 13, color: 'var(--text-main)', marginTop: 4, fontFamily: 'monospace' }}>{selectedItem.source || 'Unknown Host'}</div>
                </div>

                <div style={{ background: 'var(--bg-app)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Ingestion Timestamp</div>
                  <div style={{ fontSize: 13, color: 'var(--text-main)', marginTop: 4 }}>{safeFormatDateOnly(selectedItem.ingested_at) || 'Not recorded'}</div>
                </div>

                {selectedItem.error && (
                  <div style={{ background: 'rgba(239, 68, 68, 0.08)', padding: '12px 16px', borderRadius: 'var(--radius-md)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#ef4444', fontSize: 12 }}>
                    <strong>Error:</strong> {selectedItem.error}
                  </div>
                )}
              </div>

              <div style={{ padding: '16px 24px', background: 'var(--bg-app)', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                <button 
                  className="btn btn-outline" 
                  onClick={() => setSelectedItem(null)}
                  style={{ padding: '8px 18px', borderRadius: 'var(--radius-md)', fontSize: 13, cursor: 'pointer' }}
                >
                  Close
                </button>
                <button 
                  className="btn btn-primary" 
                  onClick={() => {
                    navigate('/sanitized');
                  }}
                  style={{ padding: '8px 18px', borderRadius: 'var(--radius-md)', fontSize: 13, cursor: 'pointer', background: 'var(--blue)', color: '#fff', border: 'none' }}
                >
                  View Sanitized Output →
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
        </>
      )}
    </div>
  </main>
</div>




    </>
  );
};

export default Evidence;
