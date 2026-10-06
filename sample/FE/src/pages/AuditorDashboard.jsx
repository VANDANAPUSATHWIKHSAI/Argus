import React, { useState, useEffect } from 'react';
import { fetchAuditorStats } from '../js/api';

export default function AuditorDashboard() {
  const currentUser = JSON.parse(localStorage.getItem('argus_user') || '{}');
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [hoveredCase, setHoveredCase] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [caseLimit, setCaseLimit] = useState(8);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    fetchAuditorStats()
      .then(res => {
        if (isMounted && res) {
          setStats(res);
        }
      })
      .catch(err => {
        console.error("Failed to load auditor stats:", err);
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });
    return () => { isMounted = false; };
  }, []);

  const rawCases = stats?.previous_cases || [];

  // Filter cases based on severity filter if selected
  const severityFiltered = rawCases.filter(c => {
    if (severityFilter === 'ALL') return true;
    return c.severity?.toUpperCase() === severityFilter.toUpperCase();
  });

  // Limit to most recent past cases (default 8)
  const filteredCases = severityFiltered.slice(-caseLimit);

  const getSeverityColor = (sev) => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return { bg: '#ef4444', gradient: 'linear-gradient(180deg, #f87171 0%, #dc2626 100%)', light: '#fef2f2', text: '#b91c1c', badgeBg: '#fee2e2' };
    if (s === 'high') return { bg: '#f97316', gradient: 'linear-gradient(180deg, #fb923c 0%, #ea580c 100%)', light: '#fff7ed', text: '#c2410c', badgeBg: '#ffedd5' };
    if (s === 'medium') return { bg: '#f59e0b', gradient: 'linear-gradient(180deg, #fbbf24 0%, #d97706 100%)', light: '#fffbeb', text: '#b45309', badgeBg: '#fef3c7' };
    return { bg: '#10b981', gradient: 'linear-gradient(180deg, #34d399 0%, #059669 100%)', light: '#ecfdf5', text: '#047857', badgeBg: '#d1fae5' };
  };

  const totalFindings = stats?.total_findings ?? 0;
  const highSeverity = stats?.high_severity ?? 0;
  const mediumSeverity = stats?.medium_severity ?? 0;
  const lowSeverity = stats?.low_severity ?? 0;

  return (
    <div style={{ padding: '32px 48px', backgroundColor: '#f8fafc', minHeight: '100vh', boxSizing: 'border-box', color: '#1e293b' }}>
      {/* Header Section */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
            Auditor Dashboard
          </div>
          <h1 style={{ fontSize: '28px', fontWeight: 700, margin: '0 0 6px 0', color: '#0f172a' }}>
            Welcome, {currentUser?.name || 'Auditor'}
          </h1>
          <p style={{ color: '#64748b', fontSize: '14px', margin: 0 }}>
            Review AI findings, verify evidence and audit the investigation.
          </p>
        </div>
        <button style={{ 
          display: 'flex', alignItems: 'center', gap: '8px', 
          backgroundColor: '#3b82f6', color: '#fff', 
          padding: '10px 18px', borderRadius: '8px', 
          border: 'none', fontSize: '14px', fontWeight: 600, cursor: 'pointer',
          boxShadow: '0 4px 12px rgba(59, 130, 246, 0.25)',
          transition: 'all 0.2s ease'
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
          View Full Report 
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
        </button>
      </div>

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '28px' }}>
        <SummaryCard icon="file" title="Total Findings" value={totalFindings} subtitle="Total findings" color="#3b82f6" bg="#eff6ff" />
        <SummaryCard icon="alert" title="High Severity" value={highSeverity} subtitle="Require priority review" color="#ef4444" bg="#fef2f2" />
        <SummaryCard icon="warning" title="Medium Severity" value={mediumSeverity} subtitle="Require verification" color="#f59e0b" bg="#fffbeb" />
        <SummaryCard icon="check" title="Low Severity" value={lowSeverity} subtitle="Routine findings" color="#10b981" bg="#ecfdf5" />
      </div>

      {/* Main Graph Card */}
      <div style={{ 
        backgroundColor: '#ffffff', borderRadius: '16px', padding: '28px 32px', 
        border: '1px solid #e2e8f0', boxShadow: '0 4px 20px rgba(0, 0, 0, 0.03)',
        display: 'flex', flexDirection: 'column', gap: '24px'
      }}>
        {/* Header inside the card */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#0f172a' }}>
                Previous Cases – Severity & Confidence
              </h2>
              <span style={{ backgroundColor: '#eff6ff', color: '#2563eb', padding: '2px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: 600 }}>
                {filteredCases.length} {filteredCases.length === 1 ? 'Case' : 'Cases'}
              </span>
            </div>
            <p style={{ margin: 0, fontSize: '14px', color: '#64748b' }}>
              Shows severity classification and AI confidence score for recent completed cases in the past year.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <select 
              value={caseLimit} 
              onChange={(e) => setCaseLimit(Number(e.target.value))}
              style={{ padding: '7px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', color: '#334155', backgroundColor: '#fff', cursor: 'pointer', outline: 'none', fontWeight: 500 }}
            >
              <option value={8}>Recent 8 Cases</option>
              <option value={12}>Recent 12 Cases</option>
              <option value={20}>All Past Cases</option>
            </select>

            <select 
              value={severityFilter} 
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{ padding: '7px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', color: '#334155', backgroundColor: '#fff', cursor: 'pointer', outline: 'none', fontWeight: 500 }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical Severity Only</option>
              <option value="HIGH">High Severity Only</option>
              <option value="MEDIUM">Medium Severity Only</option>
              <option value="LOW">Low Severity Only</option>
            </select>
          </div>
        </div>

        {/* Loading State */}
        {loading && (
          <div style={{ padding: '60px', textAlign: 'center', color: '#94a3b8', fontSize: '14px' }}>
            Loading previous case metrics...
          </div>
        )}

        {/* Empty State */}
        {!loading && filteredCases.length === 0 && (
          <div style={{ textAlign: 'center', padding: '54px 20px', backgroundColor: '#f8fafc', borderRadius: '12px', border: '1px dashed #cbd5e1', margin: '12px 0' }}>
            <div style={{ width: '52px', height: '52px', borderRadius: '50%', backgroundColor: '#eff6ff', color: '#3b82f6', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px' }}>
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
            </div>
            <h3 style={{ margin: '0 0 4px 0', fontSize: '16px', fontWeight: 600, color: '#0f172a' }}>No previous cases available</h3>
            <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Completed investigation cases will appear here automatically.</p>
          </div>
        )}

        {/* Dynamic Graph Content */}
        {!loading && filteredCases.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            
            {/* Chart Area Container */}
            <div style={{ position: 'relative', width: '100%', overflowX: 'auto', paddingBottom: '24px' }}>
              <div style={{ position: 'relative', minWidth: `${Math.max(640, filteredCases.length * 76)}px`, height: '270px', paddingTop: '48px', boxSizing: 'border-box' }}>
                
                {/* Y-Axis Grid Lines & Tick Labels */}
                <div style={{ position: 'absolute', top: '48px', left: 0, right: 0, bottom: '40px', pointerEvents: 'none' }}>
                  {[100, 75, 50, 25, 0].map((val, i) => (
                    <div key={val} style={{ position: 'absolute', top: `${(i / 4) * 100}%`, left: 0, right: 0, borderTop: i < 4 ? '1px dashed #e2e8f0' : '1.5px solid #cbd5e1', width: '100%' }}>
                      <span style={{ position: 'absolute', left: '0px', top: '-9px', fontSize: '11px', color: '#94a3b8', fontWeight: 600 }}>
                        {val}%
                      </span>
                    </div>
                  ))}
                </div>

                {/* Plot Bars Row */}
                <div style={{ 
                  position: 'absolute', top: '48px', left: '52px', right: '20px', bottom: '40px', 
                  display: 'flex', justifyContent: 'space-around', alignItems: 'flex-end', zIndex: 2 
                }}>
                  {filteredCases.map((c) => {
                    const sevStyles = getSeverityColor(c.severity);
                    const confVal = Math.min(100, Math.max(0, c.confidence || 0));
                    const isHovered = hoveredCase?.case_id === c.case_id;
                    const displayId = c.case_id.length > 10 ? `${c.case_id.substring(0, 8)}..` : c.case_id;

                    return (
                      <div 
                        key={c.case_id}
                        onMouseEnter={() => setHoveredCase(c)}
                        onMouseLeave={() => setHoveredCase(null)}
                        style={{ 
                          position: 'relative', 
                          display: 'flex', 
                          flexDirection: 'column', 
                          alignItems: 'center', 
                          height: '100%', 
                          justifyContent: 'flex-end',
                          width: '56px',
                          cursor: 'pointer'
                        }}
                      >
                        {/* Numerical Confidence Pill Badge — Generous 12px headroom prevents box overlap */}
                        <div style={{ 
                          position: 'absolute', 
                          bottom: `calc(${confVal}% + 8px)`, 
                          backgroundColor: isHovered ? sevStyles.bg : sevStyles.badgeBg,
                          color: isHovered ? '#ffffff' : sevStyles.text,
                          padding: '2px 6px',
                          borderRadius: '10px',
                          fontSize: '11px', 
                          fontWeight: 700, 
                          whiteSpace: 'nowrap',
                          transition: 'all 0.2s ease',
                          boxShadow: isHovered ? `0 2px 8px ${sevStyles.bg}55` : 'none'
                        }}>
                          {confVal}%
                        </div>

                        {/* Bar */}
                        <div style={{ 
                          width: '28px', 
                          height: `${confVal}%`, 
                          background: sevStyles.gradient, 
                          borderRadius: '8px 8px 0 0',
                          transition: 'height 0.4s ease, transform 0.2s ease, box-shadow 0.2s ease',
                          transform: isHovered ? 'scaleY(1.02) translateY(-4px)' : 'none',
                          boxShadow: isHovered ? `0 6px 16px ${sevStyles.bg}55` : '0 2px 4px rgba(0,0,0,0.05)'
                        }} />

                        {/* X-Axis Case Label */}
                        <div style={{ 
                          position: 'absolute', 
                          top: '100%', 
                          marginTop: '10px', 
                          textAlign: 'center', 
                          whiteSpace: 'nowrap' 
                        }}>
                          <div style={{ fontSize: '11px', fontWeight: 700, color: '#0f172a' }}>{displayId}</div>
                          <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 500 }}>{c.date_formatted}</div>
                        </div>

                        {/* Glassmorphic Hover Tooltip Popup */}
                        {isHovered && (
                          <div style={{ 
                            position: 'absolute', 
                            bottom: `calc(${confVal}% + 34px)`, 
                            left: '50%', 
                            transform: 'translateX(-50%)', 
                            backgroundColor: 'rgba(15, 23, 42, 0.95)', 
                            backdropFilter: 'blur(8px)',
                            color: '#fff', 
                            padding: '12px 16px', 
                            borderRadius: '10px', 
                            fontSize: '12px', 
                            boxShadow: '0 12px 30px rgba(15, 23, 42, 0.4)', 
                            border: '1px solid rgba(255, 255, 255, 0.1)',
                            zIndex: 20,
                            whiteSpace: 'nowrap',
                            pointerEvents: 'none'
                          }}>
                            <div style={{ fontWeight: 700, fontSize: '13px', marginBottom: '4px', color: '#38bdf8' }}>
                              {c.name && c.name !== c.case_id ? c.name : c.case_id}
                            </div>
                            <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '8px' }}>
                              ID: {c.case_id} • {c.full_date_formatted}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                              <span style={{ color: '#94a3b8' }}>Severity:</span>
                              <span style={{ 
                                backgroundColor: sevStyles.bg, 
                                color: '#ffffff', 
                                padding: '2px 8px', 
                                borderRadius: '4px', 
                                fontWeight: 700, 
                                fontSize: '10px',
                                textTransform: 'uppercase',
                                letterSpacing: '0.03em'
                              }}>
                                {c.severity}
                              </span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                              <span style={{ color: '#94a3b8' }}>AI Confidence:</span>
                              <span style={{ fontWeight: 700, color: '#38bdf8' }}>{c.confidence}%</span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{ color: '#94a3b8' }}>Findings:</span>
                              <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{c.total_findings} recorded</span>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Severity Legend */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: '32px', borderTop: '1px solid #f1f5f9', paddingTop: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#475569', fontWeight: 500 }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#ef4444' }}></div>
                Critical Severity
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#475569', fontWeight: 500 }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#f97316' }}></div>
                High Severity
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#475569', fontWeight: 500 }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#f59e0b' }}></div>
                Medium Severity
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#475569', fontWeight: 500 }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#10b981' }}></div>
                Low Severity
              </div>
            </div>

          </div>
        )}
      </div>
    </div>
  );
}

function SummaryCard({ icon, title, value, subtitle, color, bg }) {
  const getIcon = () => {
    if (icon === 'file') return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>;
    if (icon === 'alert') return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>;
    if (icon === 'warning') return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>;
    if (icon === 'check') return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>;
  };

  return (
    <div style={{ backgroundColor: bg, border: `1px solid ${color}33`, borderRadius: '12px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: color }}>
        {getIcon()}
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#475569' }}>{title}</span>
      </div>
      <div>
        <div style={{ fontSize: '36px', fontWeight: 700, color: '#0f172a', lineHeight: '1', marginBottom: '4px' }}>{value}</div>
        <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 500 }}>{subtitle}</div>
      </div>
    </div>
  );
}
