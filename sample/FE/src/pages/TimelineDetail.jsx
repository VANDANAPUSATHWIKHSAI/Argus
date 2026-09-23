import React from 'react';
import Sidebar from '../components/Sidebar';

const TimelineDetail = () => {
  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div style={{ padding: '32px 40px' }}>
          <h2>Full Timeline</h2>
          <p>Chronological detailed view of events.</p>
        </div>
      </main>
    </div>
  );
};

export default TimelineDetail;
