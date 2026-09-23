import React, { useState, useEffect, useMemo, useRef } from 'react';
import '../css/style.css';
import '../css/evidence.css';
import { fetchEvidenceForCase } from '../js/api';
import { Link, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import AlertModal from '../components/AlertModal';
import NotificationMenu from '../components/NotificationMenu';
import SearchableSelect from '../components/SearchableSelect';

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

  const currentUserStr = localStorage.getItem('argus_user');
  const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;
  const isAdmin = currentUser?.role === 'admin';

  const closeAlert = () => {
    if (customAlert.onClose) customAlert.onClose();
    setCustomAlert(prev => ({ ...prev, isOpen: false, onClose: null }));
  };
  
  useEffect(() => {
    const loadEvidence = async () => {
      try {
        let caseId = localStorage.getItem('active_case_id');
        
        if (!caseId) {
          setEvidenceData([]);
          setLoading(false);
          return;
        }

        const rawData = await fetchEvidenceForCase(caseId);
        const fetchedList = rawData.data || rawData || [];
        
        const mappedData = fetchedList.map(item => {
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

          return {
            id: item.evidence_id,
            name: item.filename,
            type: type,
            source: item.metadata?.host_id || item.uploaded_by || 'Unknown',
            size: item.metadata?.size_bytes || 0,
            status: item.status ? item.status.charAt(0).toUpperCase() + item.status.slice(1).toLowerCase() : 'Unknown',
            ingested_at: item.upload_timestamp || new Date().toISOString(),
            risk: 'Medium'
          };
        });
        
        setEvidenceData(mappedData);
      } catch (err) {
        console.error("Failed to fetch evidence", err);
        setCustomAlert({ isOpen: true, title: 'Error Fetching Data', message: err.message || String(err), type: 'warning' });
      } finally {
        setLoading(false);
      }
    };
    loadEvidence();
  }, []);

  const filteredData = useMemo(() => {
    return evidenceData.filter(item => {
      if (searchQuery && !item.name.toLowerCase().includes(searchQuery.toLowerCase()) && !item.source.toLowerCase().includes(searchQuery.toLowerCase())) return false;
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

  const handleCloseCase = () => {
    const activeCaseName = localStorage.getItem('active_case_name') || 'Current case';
    const activeCaseId = localStorage.getItem('active_case_id');
    if (!activeCaseId && !localStorage.getItem('active_case_name')) {
      setCustomAlert({ isOpen: true, title: 'Notice', message: "There is no active case currently open.", type: 'warning' });
      return;
    }
    localStorage.removeItem('active_case_id');
    localStorage.removeItem('active_case_name');
    localStorage.removeItem('active_case_desc');
    setCustomAlert({
       isOpen: true,
       title: 'Success',
       message: `${activeCaseName} has been closed successfully.`,
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
    <header className="topbar">
      <div className="search-container">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style={{color: 'var(--text-muted)', marginRight: '8px'}}><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <input type="text" placeholder="Search cases, evidence, or findings..." />
        <span className="search-shortcut">⌘ K</span>
      </div>
      <div className="topbar-actions">
        {isAdmin && (
          <button
            type="button"
            onClick={handleCloseCase}
            className="btn btn-outline"
            style={{ border: '1px solid var(--border-strong)', color: 'var(--text-main)', background: 'var(--bg-card)', padding: '8px 16px', borderRadius: 'var(--radius-full)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontSize: '13px', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"></path></svg>
            Close Case
          </button>
        )}
        {isAdmin && (
          <button
            type="button"
            onClick={handleOpenCreateCase}
            className="btn btn-primary"
            style={{background: 'var(--blue)', border: 'none', padding: '8px 16px', borderRadius: 'var(--radius-full)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: '#fff'}}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
            Create Case
          </button>
        )}
        {localStorage.getItem('active_case_id') && <div className="badge-live"><div className="live-dot"></div> Live Analysis</div>}
        <NotificationMenu />
        <div className="user-profile" onClick={() => setShowUserDropdown(!showUserDropdown)}>
          <div className="avatar">A</div>
          <span style={{fontWeight: '500'}}>Analyst</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
          {showUserDropdown && (
            <div className="user-dropdown" style={{ display: 'block' }}>
              <div className="user-dropdown-header">
                <div className="ud-name">Analyst</div>
                <div className="ud-role">Digital Forensics Investigator</div>
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
      
      {!localStorage.getItem('active_case_id') ? (
        <div id="evidence-empty-state" style={{ display: 'block', textAlign: 'center', padding: '100px 20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', margin: '24px', border: '1px dashed var(--border-strong)' }}>
          <div style={{ width: '64px', height: '64px', background: 'var(--blue-light)', color: 'var(--blue)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '8px' }}>No Active Case Selected</h2>
          <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>Select an existing case or create a new one to begin your investigation and view evidence.</p>
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
      </div>

      {/* Stats Grid */}
      <div className="stats-grid evidence-stats" style={{flexShrink: '0', gridTemplateColumns: 'repeat(5, 1fr)'}}>
        <div className="stat-card">
          <div className="stat-icon" style={{backgroundColor: 'var(--blue-light)', color: 'var(--blue)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
          </div>
          <div className="stat-info">
            <h2>{evidenceData.length}</h2>
            <h4>Total Items</h4>
            <p>Collected for this case</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{backgroundColor: 'var(--green-light, #e6f6ec)', color: 'var(--green, #10b981)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
          </div>
          <div className="stat-info">
            <h2>{evidenceData.filter(e => e.status?.toLowerCase() === 'stored' || e.status?.toLowerCase() === 'analyzed').length}</h2>
            <h4>Ingested</h4>
            <p>Ready for analysis</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{backgroundColor: 'var(--orange-light)', color: 'var(--orange)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
          </div>
          <div className="stat-info">
            <h2>{evidenceData.filter(e => e.status?.toLowerCase() === 'processing').length}</h2>
            <h4>Processing</h4>
            <p>Currently analyzing</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{backgroundColor: 'var(--red-light)', color: 'var(--red)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          </div>
          <div className="stat-info">
            <h2>{evidenceData.filter(e => e.status?.toLowerCase() === 'failed').length}</h2>
            <h4>Failed</h4>
            <p>No errors</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon" style={{backgroundColor: 'var(--blue-light)', color: 'var(--blue)'}}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>
          </div>
          <div className="stat-info">
            <h2>{evidenceData.reduce((acc, curr) => acc + (curr.size || 0), 0) > 0 ? (evidenceData.reduce((acc, curr) => acc + (curr.size || 0), 0) / (1024*1024)).toFixed(2) + ' MB' : '0 B'}</h2>
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
            <Link to="/upload" className="evidence-tab" style={{padding: '16px 20px', fontWeight: '500', fontSize: '14px', color: 'var(--text-muted)', textDecoration: 'none'}}>Upload Evidence</Link>
            <div className="evidence-tab" onClick={() => setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Coverage view is not yet implemented in this prototype.', type: 'info'})} style={{padding: '16px 20px', fontWeight: '500', fontSize: '14px', color: 'var(--text-muted)', cursor: 'pointer'}}>Coverage</div>
          </div>

          {/* Search & Filters */}
          <div className="evidence-toolbar" style={{display: 'flex', justifyContent: 'space-between', padding: '16px 24px', borderBottom: '1px solid var(--border-strong)', alignItems: 'center', position: 'relative', zIndex: 100}}>
            <div className="toolbar-left" style={{display: 'flex', gap: '16px', alignItems: 'center'}}>
              <div className="search-container" style={{background: 'var(--bg-app)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-strong)', padding: '6px 12px', width: '250px'}}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{color: 'var(--text-muted)'}}><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <input type="text" placeholder="Search evidence..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} style={{border: 'none', background: 'transparent', outline: 'none', marginLeft: '8px', fontSize: '13px', color: 'var(--text-main)', width: '80%'}} />
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
                    { label: "Parsed", value: "Parsed" },
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
                      <td colSpan="9" style={{textAlign: 'center', padding: '40px', color: 'var(--text-muted)'}}>
                        No evidence files found matching your criteria.
                      </td>
                    </tr>
                  ) : (
                    currentItems.map(item => (
                      <tr key={item.id} className={`ev-row ${selectedItem?.id === item.id ? 'selected' : ''}`} onClick={() => setSelectedItem(item)}>
                        <td style={{padding: '16px 24px'}}><input type="checkbox" onClick={(e) => { e.stopPropagation(); setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Item selection is not yet implemented in this prototype.', type: 'info'}) }} /></td>
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
                          <span className={`status-pill status-${(item.status||'').toLowerCase()}`} style={{ display: 'inline-flex', alignItems: 'center', padding: '4px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: '600', backgroundColor: item.status?.toLowerCase() === 'stored' ? 'var(--green-light, #e6f6ec)' : 'var(--orange-light, #fef3c7)', color: item.status?.toLowerCase() === 'stored' ? 'var(--green, #10b981)' : 'var(--orange, #f59e0b)' }}>
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'currentColor', marginRight: '6px' }}></span>
                            {item.status}
                          </span>
                        </td>
                        <td>{new Date(item.ingested_at).toLocaleDateString()}</td>
                        <td>
                           <span style={{ color: item.risk === 'High' ? 'var(--red)' : item.risk === 'Medium' ? 'var(--orange)' : 'var(--text-muted)' }}>{item.risk || 'Low'}</span>
                        </td>
                        <td style={{ textAlign: 'right', padding: '16px 24px' }}>
                          <button onClick={(e) => { e.stopPropagation(); setCustomAlert({isOpen: true, title: 'Coming Soon', message: 'Item actions are not yet implemented in this prototype.', type: 'info'}) }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
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
                    onClick={() => paginate(i + 1)}
                    style={{width: '32px', height: '32px', cursor: 'pointer', background: currentPage === i + 1 ? 'var(--blue)' : 'var(--bg-app)', color: currentPage === i + 1 ? '#fff' : 'var(--text-main)', borderColor: currentPage === i + 1 ? 'var(--blue)' : 'var(--border-strong)'}}
                  >
                    {i + 1}
                  </button>
                ))}
                <button 
                  className="btn-icon" 
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

        {/* Node Details Panel */}
        
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
