import React from 'react';

const ArgusLogo = ({ size = 36, className = '' }) => {
  return (
    <svg 
      width={size} 
      height={size} 
      viewBox="0 0 36 36" 
      fill="none" 
      xmlns="http://www.w3.org/2000/svg"
      className={`argus-logo-svg ${className}`}
      style={{ flexShrink: 0, display: 'block' }}
    >
      <rect 
        x="0.5" 
        y="0.5" 
        width="35" 
        height="35" 
        rx="9" 
        className="argus-logo-bg"
      />
      {/* Outer Shield */}
      <path 
        d="M18 7.5L26.5 11.5V17.5C26.5 22.8 22.8 26.8 18 28.5C13.2 26.8 9.5 22.8 9.5 17.5V11.5L18 7.5Z" 
        className="argus-logo-shield"
        strokeWidth="1.8" 
        strokeLinejoin="round" 
      />
      {/* Forensic Scanning Iris */}
      <path 
        d="M13 18C13 18 15.2 14.8 18 14.8C20.8 14.8 23 18 23 18C23 18 20.8 21.2 18 21.2C15.2 21.2 13 18 13 18Z" 
        className="argus-logo-iris"
        strokeWidth="1.5" 
        strokeLinecap="round" 
        strokeLinejoin="round" 
      />
      {/* Central Focal Lens Dot */}
      <circle cx="18" cy="18" r="1.8" className="argus-logo-dot" />
    </svg>
  );
};

export default ArgusLogo;
