import React from 'react';
import Sidebar from '../components/Sidebar';

const Findings = () => {
  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div style={{ padding: '32px 40px' }}>
          <h2>All AI Findings</h2>
          <p>Review findings in detail.</p>
        </div>
      </main>
    </div>
  );
};

export default Findings;
