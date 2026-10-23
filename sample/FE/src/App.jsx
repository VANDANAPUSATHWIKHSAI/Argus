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
import Notifications from './pages/Notifications';
import Cases from './pages/Cases';
import Agents from './pages/Agents';
import Report from './pages/Report';
import ProtectedRoute from './components/ProtectedRoute';// Global styles for the app (can also just import individual ones in components)
import './App.css';

import SessionManager from './components/SessionManager';
import DevRoleSwitcher from './components/DevRoleSwitcher';
import TemplateHub from './templates/TemplateHub';
import TechnicalMinimalTemplate from './templates/TechnicalMinimalTemplate';
import ModernWorkspaceTemplate from './templates/ModernWorkspaceTemplate';
import TechnicalMinimalCompactTemplate from './templates/TechnicalMinimalCompactTemplate';
import TechnicalMinimalAdvancedTemplate from './templates/TechnicalMinimalAdvancedTemplate';
import ModernWorkspaceDetailedTemplate from './templates/ModernWorkspaceDetailedTemplate';
import ModernWorkspaceSplitTemplate from './templates/ModernWorkspaceSplitTemplate';
import TechnicalWorkstationV2 from './templates_v2/TechnicalWorkstationV2';
import GlassDashboardTemplate from './templates/GlassDashboardTemplate';

function App() {
  React.useEffect(() => {
    const savedTheme = localStorage.getItem('argus_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // Validate "Keep session active" policy on app boot:
    // If user logged in without "Keep session active" (argus_keep_active === 'false'),
    // their session is tab-scoped via sessionStorage.
    // If sessionStorage is empty (e.g. browser or tab was reopened), clear persistent tokens!
    const keepActive = localStorage.getItem('argus_keep_active');
    if (keepActive === 'false') {
      const sessionToken = sessionStorage.getItem('argus_token');
      if (!sessionToken) {
        localStorage.removeItem('argus_token');
        localStorage.removeItem('argus_user');
      } else {
        localStorage.setItem('argus_token', sessionToken);
        const sessionUser = sessionStorage.getItem('argus_user');
        if (sessionUser) localStorage.setItem('argus_user', sessionUser);
      }
    }
  }, []);

  return (
    <Router>
      <SessionManager />
      <DevRoleSwitcher />
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/cases" element={<ProtectedRoute><Cases /></ProtectedRoute>} />
        <Route path="/agents" element={<ProtectedRoute><Agents /></ProtectedRoute>} />
        <Route path="/report" element={<ProtectedRoute><Report /></ProtectedRoute>} />
        <Route path="/reports" element={<ProtectedRoute><Report /></ProtectedRoute>} />
        <Route path="/employees" element={<ProtectedRoute><Employees /></ProtectedRoute>} />
        <Route path="/audit-logs" element={<ProtectedRoute><AuditLogs /></ProtectedRoute>} />
        <Route path="/case-notes" element={<ProtectedRoute><CaseNotes /></ProtectedRoute>} />
        <Route path="/chatbot" element={<ProtectedRoute><Chatbot /></ProtectedRoute>} />
        <Route path="/findings" element={<ProtectedRoute><Findings /></ProtectedRoute>} />
        <Route path="/timeline" element={<ProtectedRoute><TimelineDetail /></ProtectedRoute>} />
        <Route path="/evidence-coverage" element={<Navigate to="/evidence" replace />} />
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

        {/* ARGUS Approved-Direction Design Exploration Suite (6 Templates) */}
        <Route path="/templates" element={<TemplateHub />} />
        <Route path="/templates/glass-dashboard" element={<GlassDashboardTemplate />} />
        <Route path="/templates/technical-minimal" element={<TechnicalMinimalTemplate />} />
        <Route path="/templates/modern-workspace" element={<ModernWorkspaceTemplate />} />
        <Route path="/templates/technical-minimal-compact" element={<TechnicalMinimalCompactTemplate />} />
        <Route path="/templates/technical-minimal-advanced" element={<TechnicalMinimalAdvancedTemplate />} />
        <Route path="/templates/modern-workspace-detailed" element={<ModernWorkspaceDetailedTemplate />} />
        <Route path="/templates/modern-workspace-split" element={<ModernWorkspaceSplitTemplate />} />
        <Route path="/templates/v2-technical" element={<TechnicalWorkstationV2 />} />
      </Routes>
    </Router>
  );
}

export default App;
