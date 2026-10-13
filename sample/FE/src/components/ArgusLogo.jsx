import React from 'react';

const ArgusLogo = ({ size = 36, className = '' }) => {
  return (
    <svg 
      width={size} 
      height={size} 
      viewBox="0 0 48 48" 
      fill="none" 
      xmlns="http://www.w3.org/2000/svg"
      className={`argus-logo-svg ${className}`}
      style={{ flexShrink: 0, display: 'block' }}
    >
      {/* Minimalist Precision Shield Outline */}
      <path 
        d="M24 6L38.5 11V23.5C38.5 32.5 30.8 39.5 24 42.5C17.2 39.5 9.5 32.5 9.5 23.5V11L24 6Z" 
        stroke="var(--emblem-shield, #38bdf8)" 
        strokeWidth="1.85" 
        strokeLinecap="round" 
        strokeLinejoin="round" 
        className="argus-logo-shield"
      />
      {/* Minimalist Forensic Eye Scanning Contour */}
      <path 
        d="M17.5 24C19.5 19.8 28.5 19.8 30.5 24C28.5 28.2 19.5 28.2 17.5 24Z" 
        stroke="var(--emblem-eye, #22d3ee)" 
        strokeWidth="1.6" 
        strokeLinecap="round" 
        strokeLinejoin="round" 
        className="argus-logo-iris"
      />
      {/* Centered Optical Pupil Focal Point */}
      <circle 
        cx="24" 
        cy="24" 
        r="2.2" 
        fill="var(--emblem-shield, #38bdf8)" 
        className="argus-logo-dot"
      />
    </svg>
  );
};

export default ArgusLogo;
