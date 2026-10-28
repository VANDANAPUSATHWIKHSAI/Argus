import React, { useState, useRef, useEffect } from 'react';

/**
 * CaseSwitcher
 * Glassmorphic custom dropdown for switching active forensic cases.
 * Replaces ugly native OS <select> with a sleek, themed glass capsule and dropdown.
 */
const CaseSwitcher = ({
  cases = [],
  activeCaseId = '',
  onSelectCase,
  id = 'evidence-topbar-case-select',
  placeholder = '-- Switch Case --',
  style = {},
  buttonStyle = {},
  align = 'right',
  loading = false
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const wrapperRef = useRef(null);
  const searchInputRef = useRef(null);

  // Close when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  // Focus search input on open
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      setTimeout(() => searchInputRef.current?.focus(), 50);
    } else {
      setSearchTerm('');
    }
  }, [isOpen]);

  const activeCase = cases.find((c) => c.case_id === activeCaseId);

  const filteredCases = cases.filter((c) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      (c.case_id || '').toLowerCase().includes(term) ||
      (c.name || '').toLowerCase().includes(term)
    );
  });

  const handleSelect = (caseId) => {
    if (onSelectCase) {
      onSelectCase(caseId);
    }
    setIsOpen(false);
  };

  return (
    <div
      ref={wrapperRef}
      id={id}
      style={{
        position: 'relative',
        display: 'inline-block',
        ...style
      }}
    >
      {/* Trigger Capsule Pill */}
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        onClick={() => setIsOpen((prev) => !prev)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          background: 'var(--glass-dash-surface-nested, var(--bg-card, rgba(255, 255, 255, 0.08)))',
          color: 'var(--text-main, #f8fafc)',
          border: `1px solid ${
            isOpen
              ? 'var(--glass-dash-blue, #2563eb)'
              : 'var(--glass-dash-border-subtle, var(--border-subtle, rgba(255, 255, 255, 0.12)))'
          }`,
          borderRadius: '20px',
          padding: '6px 14px',
          fontSize: '13px',
          fontWeight: 500,
          cursor: 'pointer',
          outline: 'none',
          boxShadow: isOpen
            ? '0 0 0 2px var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.25))'
            : 'none',
          transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          maxWidth: '440px',
          minWidth: 'fit-content',
          whiteSpace: 'nowrap',
          ...buttonStyle
        }}
      >
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            minWidth: 0
          }}
        >
          {activeCase ? (
            <>
              <span
                style={{
                  fontFamily: 'var(--glass-dash-mono, monospace)',
                  fontWeight: 700,
                  color: 'var(--glass-dash-blue, #3b82f6)',
                  flexShrink: 0
                }}
              >
                {activeCase.case_id}
              </span>
              <span style={{ color: 'var(--text-muted, #94a3b8)', flexShrink: 0 }}>—</span>
              <span
                style={{
                  color: 'var(--text-main, #f8fafc)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '280px'
                }}
                title={activeCase.name || activeCase.case_id}
              >
                {activeCase.name || 'Unnamed'}
              </span>
            </>
          ) : loading ? (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted, #94a3b8)' }}>
              <span className="spinner" style={{ width: '12px', height: '12px', borderWidth: '1.5px' }}></span>
              Loading cases...
            </span>
          ) : (
            <span style={{ color: 'var(--text-main, #f8fafc)' }}>{placeholder}</span>
          )}
        </span>
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.4"
          style={{
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s ease',
            flexShrink: 0,
            color: 'var(--text-muted, #94a3b8)'
          }}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {/* Glassmorphic Dropdown Menu */}
      {isOpen && (
        <div
          role="listbox"
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            [align === 'right' ? 'right' : 'left']: 0,
            minWidth: '100%',
            width: 'max-content',
            maxWidth: '380px',
            maxHeight: '400px',
            background: 'var(--glass-dash-surface-gradient, var(--bg-card-modal, #181a20))',
            backdropFilter: 'blur(32px) saturate(200%)',
            WebkitBackdropFilter: 'blur(32px) saturate(200%)',
            border: '1px solid var(--glass-dash-border, var(--border-strong, rgba(255, 255, 255, 0.16)))',
            borderRadius: '16px',
            boxShadow: 'var(--glass-dash-shadow-card, 0 20px 48px -12px rgba(0, 0, 0, 0.55), 0 4px 16px rgba(0, 0, 0, 0.35))',
            zIndex: 1050,
            padding: '8px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
            animation: 'dropdownFade 0.15s cubic-bezier(0.16, 1, 0.3, 1)'
          }}
        >
          {/* Header */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '6px 8px 8px',
              borderBottom: '1px solid var(--glass-dash-border-subtle, var(--border-subtle, rgba(255, 255, 255, 0.08)))'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: 'var(--text-muted, #94a3b8)'
                }}
              >
                Switch Case
              </span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '1px 6px',
                  borderRadius: '9999px',
                  background: 'var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.12))',
                  color: 'var(--glass-dash-blue, #3b82f6)'
                }}
              >
                {cases.length}
              </span>
            </div>
            {activeCaseId && (
              <button
                type="button"
                onClick={() => handleSelect('')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--glass-dash-blue, #3b82f6)',
                  fontSize: '11px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  padding: '2px 4px'
                }}
              >
                Clear selection
              </button>
            )}
          </div>

          {/* Quick Search filter if cases > 3 */}
          {cases.length > 3 && (
            <div style={{ padding: '2px 4px 4px' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'var(--glass-dash-surface-nested, rgba(255, 255, 255, 0.04))',
                  border: '1px solid var(--glass-dash-border-subtle, rgba(255, 255, 255, 0.08))',
                  borderRadius: '8px',
                  padding: '4px 8px'
                }}
              >
                <svg
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  style={{ color: 'var(--text-muted, #94a3b8)' }}
                >
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
                <input
                  ref={searchInputRef}
                  type="text"
                  placeholder="Filter cases..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    fontSize: '12px',
                    color: 'var(--text-main, #f8fafc)'
                  }}
                />
                {searchTerm && (
                  <button
                    type="button"
                    onClick={() => setSearchTerm('')}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-muted, #94a3b8)',
                      cursor: 'pointer',
                      padding: 0,
                      fontSize: '12px'
                    }}
                  >
                    ×
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Cases List */}
          <div
            style={{
              maxHeight: '260px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '2px'
            }}
          >
            {/* Default / Deselect Option */}
            <div
              role="option"
              aria-selected={!activeCaseId}
              onClick={() => handleSelect('')}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '8px 10px',
                borderRadius: '10px',
                cursor: 'pointer',
                fontSize: '12px',
                color: !activeCaseId ? 'var(--glass-dash-blue, #3b82f6)' : 'var(--text-muted, #94a3b8)',
                background: !activeCaseId ? 'var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.1))' : 'transparent',
                transition: 'background 0.15s ease'
              }}
              onMouseEnter={(e) => {
                if (activeCaseId) {
                  e.currentTarget.style.background = 'var(--glass-dash-surface-nested, rgba(255, 255, 255, 0.05))';
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = !activeCaseId
                  ? 'var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.1))'
                  : 'transparent';
              }}
            >
              <span style={{ fontStyle: 'italic' }}>{placeholder}</span>
              {!activeCaseId && (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              )}
            </div>

            {/* Case Items */}
            {filteredCases.length > 0 ? (
              filteredCases.map((c) => {
                const isSelected = c.case_id === activeCaseId;
                return (
                  <div
                    key={c.case_id}
                    role="option"
                    aria-selected={isSelected}
                    onClick={() => handleSelect(c.case_id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 10px',
                      borderRadius: '10px',
                      cursor: 'pointer',
                      background: isSelected
                        ? 'var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.14))'
                        : 'transparent',
                      border: isSelected
                        ? '1px solid var(--glass-dash-blue-border, rgba(37, 99, 235, 0.3))'
                        : '1px solid transparent',
                      transition: 'all 0.15s ease'
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected) {
                        e.currentTarget.style.background =
                          'var(--glass-dash-surface-nested, rgba(255, 255, 255, 0.06))';
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected) {
                        e.currentTarget.style.background = 'transparent';
                      }
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span
                        style={{
                          width: '6px',
                          height: '6px',
                          borderRadius: '50%',
                          background: 'var(--glass-dash-green, #10b981)',
                          boxShadow: '0 0 6px var(--glass-dash-green, #10b981)',
                          flexShrink: 0
                        }}
                      />
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          minWidth: 0,
                          textAlign: 'left'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span
                            style={{
                              fontFamily: 'var(--glass-dash-mono, monospace)',
                              fontWeight: 700,
                              fontSize: '12px',
                              color: isSelected
                                ? 'var(--glass-dash-blue, #3b82f6)'
                                : 'var(--text-main, #f8fafc)'
                            }}
                          >
                            {c.case_id}
                          </span>
                        </div>
                        <span
                          style={{
                            fontSize: '11px',
                            color: 'var(--text-muted, #94a3b8)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            maxWidth: '220px'
                          }}
                        >
                          {c.name || 'Unnamed Case'}
                        </span>
                      </div>
                    </div>
                    {isSelected && (
                      <svg
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="var(--glass-dash-blue, #3b82f6)"
                        strokeWidth="2.5"
                        style={{ flexShrink: 0, marginLeft: '6px' }}
                      >
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    )}
                  </div>
                );
              })
            ) : (
              <div
                style={{
                  padding: '16px',
                  textAlign: 'center',
                  fontSize: '12px',
                  color: 'var(--text-muted, #94a3b8)'
                }}
              >
                No cases match &quot;{searchTerm}&quot;
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default CaseSwitcher;
