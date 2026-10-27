import React, { useState, useRef, useEffect } from 'react';

/**
 * SearchableSelect
 * Premium glassmorphic dropdown with optional search filter,
 * smooth chevron rotation, text truncation, and responsive menu width.
 */
const SearchableSelect = ({
  options = [],
  value,
  onChange,
  placeholder = 'Select...',
  noSearch = false,
  size = 'medium',
  style = {},
  align = 'left'
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState('');
  const wrapperRef = useRef(null);
  const searchInputRef = useRef(null);

  // Close when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen]);

  // Handle escape key
  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  // Focus search input when opened
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      setTimeout(() => searchInputRef.current?.focus(), 40);
    } else {
      setSearch('');
    }
  }, [isOpen]);

  // Normalize options to { value, label } format
  const normalizedOptions = (options || []).map((opt) =>
    typeof opt === 'object' && opt !== null ? opt : { value: opt, label: String(opt) }
  );

  const filteredOptions = normalizedOptions.filter((opt) =>
    (opt.label || '').toLowerCase().includes(search.toLowerCase())
  );

  const selectedOption = normalizedOptions.find((opt) => opt.value === value);

  const isSmall = size === 'small';

  return (
    <div
      ref={wrapperRef}
      style={{
        position: 'relative',
        width: '100%',
        ...style
      }}
    >
      {/* Trigger Pill */}
      <div
        role="button"
        tabIndex={0}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setIsOpen(!isOpen);
          }
        }}
        style={{
          width: '100%',
          padding: isSmall ? '6px 12px' : '9px 14px',
          borderRadius: isSmall ? '10px' : '12px',
          fontSize: isSmall ? '12px' : '13px',
          fontWeight: 500,
          border: `1px solid ${
            isOpen
              ? 'var(--glass-dash-blue, #2563eb)'
              : 'var(--glass-dash-border-subtle, var(--border-subtle, rgba(255, 255, 255, 0.12)))'
          }`,
          background: 'var(--glass-dash-surface-nested, var(--bg-card, rgba(255, 255, 255, 0.08)))',
          color: selectedOption
            ? 'var(--text-main, #f8fafc)'
            : 'var(--text-muted, #94a3b8)',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '8px',
          boxSizing: 'border-box',
          boxShadow: isOpen
            ? '0 0 0 2px var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.25))'
            : 'none',
          transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          userSelect: 'none'
        }}
      >
        <span
          style={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            flex: 1,
            textAlign: 'left'
          }}
          title={selectedOption ? selectedOption.label : placeholder}
        >
          {selectedOption ? selectedOption.label : placeholder}
        </span>
        <svg
          width={isSmall ? 13 : 14}
          height={isSmall ? 13 : 14}
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
      </div>

      {/* Glassmorphic Dropdown Menu */}
      {isOpen && (
        <div
          role="listbox"
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            [align === 'right' ? 'right' : 'left']: 0,
            minWidth: '100%',
            width: 'max-content',
            maxWidth: '280px',
            background: 'var(--glass-dash-surface-gradient, var(--bg-card-modal, #181a20))',
            backdropFilter: 'blur(32px) saturate(200%)',
            WebkitBackdropFilter: 'blur(32px) saturate(200%)',
            border: '1px solid var(--glass-dash-border, var(--border-strong, rgba(255, 255, 255, 0.16)))',
            borderRadius: '14px',
            boxShadow: 'var(--glass-dash-shadow-card, 0 16px 40px rgba(0, 0, 0, 0.35))',
            zIndex: 1100,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            animation: 'dropdownFade 0.15s cubic-bezier(0.16, 1, 0.3, 1)',
            padding: '6px'
          }}
        >
          {!noSearch && (
            <div style={{ padding: '2px 4px 6px' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'var(--glass-dash-surface-nested, rgba(255, 255, 255, 0.05))',
                  border: '1px solid var(--glass-dash-border-subtle, rgba(255, 255, 255, 0.1))',
                  borderRadius: '8px',
                  padding: '5px 8px'
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
                  placeholder="Filter..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    width: '100%',
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    fontSize: '12px',
                    color: 'var(--text-main, #f8fafc)',
                    boxSizing: 'border-box'
                  }}
                />
              </div>
            </div>
          )}

          <div
            style={{
              overflowY: 'auto',
              maxHeight: '220px',
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
              padding: '2px'
            }}
          >
            {filteredOptions.length > 0 ? (
              filteredOptions.map((opt) => {
                const isSelected = opt.value === value;
                return (
                  <div
                    key={String(opt.value)}
                    role="option"
                    aria-selected={isSelected}
                    onClick={() => {
                      onChange(opt.value);
                      setIsOpen(false);
                      setSearch('');
                    }}
                    style={{
                      padding: isSmall ? '6px 10px' : '8px 12px',
                      fontSize: isSmall ? '12px' : '13px',
                      fontWeight: isSelected ? 600 : 400,
                      borderRadius: '8px',
                      cursor: 'pointer',
                      color: isSelected
                        ? 'var(--glass-dash-blue, #3b82f6)'
                        : 'var(--text-main, #f8fafc)',
                      background: isSelected
                        ? 'var(--glass-dash-blue-soft, rgba(37, 99, 235, 0.12))'
                        : 'transparent',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
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
                    <span
                      style={{
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}
                    >
                      {opt.label}
                    </span>
                    {isSelected && (
                      <svg
                        width="13"
                        height="13"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2.5"
                        style={{ flexShrink: 0 }}
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
                  padding: '12px',
                  textAlign: 'center',
                  color: 'var(--text-muted, #94a3b8)',
                  fontSize: '12px'
                }}
              >
                No matches found
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchableSelect;
