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
import ProtectedRoute from './components/ProtectedRoute';
import './App.css';

import SessionManager from './components/SessionManager';
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
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        
        {/* Role-governed Routes */}
        <Route path="/dashboard" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Dashboard /></ProtectedRoute>} />
        <Route path="/cases" element={<ProtectedRoute allowedRoles={['admin']}><Cases /></ProtectedRoute>} />
        <Route path="/agents" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Agents /></ProtectedRoute>} />
        <Route path="/report" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst', 'auditor']}><Report /></ProtectedRoute>} />
        <Route path="/reports" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst', 'auditor']}><Report /></ProtectedRoute>} />
        <Route path="/employees" element={<ProtectedRoute allowedRoles={['admin']}><Employees /></ProtectedRoute>} />
        <Route path="/audit-logs" element={<ProtectedRoute allowedRoles={['admin']}><AuditLogs /></ProtectedRoute>} />
        <Route path="/case-notes" element={<ProtectedRoute allowedRoles={['analyst', 'senior_analyst']}><CaseNotes /></ProtectedRoute>} />
        <Route path="/chatbot" element={<ProtectedRoute allowedRoles={['analyst', 'senior_analyst']}><Chatbot /></ProtectedRoute>} />
        <Route path="/findings" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst']}><Findings /></ProtectedRoute>} />
        <Route path="/timeline" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst']}><TimelineDetail /></ProtectedRoute>} />
        <Route path="/evidence" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Evidence /></ProtectedRoute>} />
        <Route path="/upload" element={<ProtectedRoute allowedRoles={['admin', 'analyst']}><Upload /></ProtectedRoute>} />
        <Route path="/sanitized" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Sanitized /></ProtectedRoute>} />
        <Route path="/sanitized/:id" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><SanitizedDetail /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst', 'auditor']}><Settings /></ProtectedRoute>} />
        <Route path="/notifications" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst', 'auditor']}><Notifications /></ProtectedRoute>} />

        {/* Legacy redirect aliases */}
        <Route path="/evidence-coverage" element={<Navigate to="/evidence" replace />} />
        <Route path="/index.html" element={<Navigate to="/dashboard" replace />} />
        <Route path="/evidence.html" element={<Navigate to="/evidence" replace />} />
        <Route path="/settings.html" element={<Navigate to="/settings" replace />} />
        <Route path="/upload.html" element={<Navigate to="/upload" replace />} />
        <Route path="/sanitized.html" element={<Navigate to="/sanitized" replace />} />

        {/* Internal Design Exploration Suite (Restricted to authenticated staff) */}
        <Route path="/templates" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><TemplateHub /></ProtectedRoute>} />
        <Route path="/templates/glass-dashboard" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><GlassDashboardTemplate /></ProtectedRoute>} />
        <Route path="/templates/technical-minimal" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><TechnicalMinimalTemplate /></ProtectedRoute>} />
        <Route path="/templates/modern-workspace" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><ModernWorkspaceTemplate /></ProtectedRoute>} />
        <Route path="/templates/technical-minimal-compact" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><TechnicalMinimalCompactTemplate /></ProtectedRoute>} />
        <Route path="/templates/technical-minimal-advanced" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><TechnicalMinimalAdvancedTemplate /></ProtectedRoute>} />
        <Route path="/templates/modern-workspace-detailed" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><ModernWorkspaceDetailedTemplate /></ProtectedRoute>} />
        <Route path="/templates/modern-workspace-split" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><ModernWorkspaceSplitTemplate /></ProtectedRoute>} />
        <Route path="/templates/v2-technical" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><TechnicalWorkstationV2 /></ProtectedRoute>} />
      </Routes>
    </Router>
  );
}

export default App;
