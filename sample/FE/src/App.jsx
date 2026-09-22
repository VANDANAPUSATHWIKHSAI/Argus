import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Evidence from './pages/Evidence';
import Settings from './pages/Settings';
import Upload from './pages/Upload';
import Sanitized from './pages/Sanitized';
import Employees from './pages/Employees';

// Global styles for the app (can also just import individual ones in components)
import './App.css';

function App() {
  React.useEffect(() => {
    const savedTheme = localStorage.getItem('argus_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/employees" element={<Employees />} />
        <Route path="/index.html" element={<Navigate to="/dashboard" replace />} />
        <Route path="/evidence" element={<Evidence />} />
        <Route path="/evidence.html" element={<Navigate to="/evidence" replace />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/settings.html" element={<Navigate to="/settings" replace />} />
        <Route path="/upload" element={<Upload />} />
        <Route path="/upload.html" element={<Navigate to="/upload" replace />} />
        <Route path="/sanitized" element={<Sanitized />} />
        <Route path="/sanitized.html" element={<Navigate to="/sanitized" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
