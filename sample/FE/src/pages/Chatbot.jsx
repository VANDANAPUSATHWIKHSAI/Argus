import React from 'react';
import Sidebar from '../components/Sidebar';

const Chatbot = () => {
  return (
    <div id="app-shell">
      <Sidebar />
      <main className="main-content">
        <div style={{ padding: '32px 40px' }}>
          <h2>Investigation Assistant</h2>
          <p>Chat with AI about this case.</p>
        </div>
      </main>
    </div>
  );
};

export default Chatbot;
