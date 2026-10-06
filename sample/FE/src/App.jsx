import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Evidence from './pages/Evidence';
import Settings from './pages/Settings';
import Upload from './pages/Upload';
import Sanitized from './pages/Sanitized';
import SanitizedDetail from './pages/SanitizedDetail';
import Employees from './pages/Employees';
import AuditLogs from './pages/AuditLogs';
import CaseNotes from './pages/CaseNotes';
import Chatbot from './pages/Chatbot';
import Findings from './pages/Findings';
import TimelineDetail from './pages/TimelineDetail';
import EvidenceCoverage from './pages/EvidenceCoverage';
import Notifications from './pages/Notifications';
import ProtectedRoute from './components/ProtectedRoute';// Global styles for the app (can also just import individual ones in components)
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
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/employees" element={<ProtectedRoute><Employees /></ProtectedRoute>} />
        <Route path="/audit-logs" element={<ProtectedRoute><AuditLogs /></ProtectedRoute>} />
        <Route path="/case-notes" element={<ProtectedRoute><CaseNotes /></ProtectedRoute>} />
        <Route path="/chatbot" element={<ProtectedRoute><Chatbot /></ProtectedRoute>} />
        <Route path="/findings" element={<ProtectedRoute><Findings /></ProtectedRoute>} />
        <Route path="/timeline" element={<ProtectedRoute><TimelineDetail /></ProtectedRoute>} />
        <Route path="/evidence-coverage" element={<ProtectedRoute><EvidenceCoverage /></ProtectedRoute>} />
        <Route path="/index.html" element={<Navigate to="/dashboard" replace />} />
        <Route path="/evidence" element={<ProtectedRoute><Evidence /></ProtectedRoute>} />
        <Route path="/evidence.html" element={<Navigate to="/evidence" replace />} />
        <Route path="/notifications" element={<ProtectedRoute><Notifications /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
        <Route path="/settings.html" element={<Navigate to="/settings" replace />} />
        <Route path="/upload" element={<ProtectedRoute><Upload /></ProtectedRoute>} />
        <Route path="/upload.html" element={<Navigate to="/upload" replace />} />
        <Route path="/sanitized" element={<ProtectedRoute><Sanitized /></ProtectedRoute>} />
        <Route path="/sanitized/:id" element={<ProtectedRoute><SanitizedDetail /></ProtectedRoute>} />
        <Route path="/sanitized.html" element={<Navigate to="/sanitized" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
