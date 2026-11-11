import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import ProtectedRoute from './components/ProtectedRoute';
import './App.css';

import SessionManager from './components/SessionManager';
import DevTools from './components/DevTools';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const Evidence = lazy(() => import('./pages/Evidence'));
const Settings = lazy(() => import('./pages/Settings'));
const Upload = lazy(() => import('./pages/Upload'));
const Sanitized = lazy(() => import('./pages/Sanitized'));
const SanitizedDetail = lazy(() => import('./pages/SanitizedDetail'));
const Employees = lazy(() => import('./pages/Employees'));
const AuditLogs = lazy(() => import('./pages/AuditLogs'));
const CaseNotes = lazy(() => import('./pages/CaseNotes'));
const Chatbot = lazy(() => import('./pages/Chatbot'));
const Findings = lazy(() => import('./pages/Findings'));
const TimelineDetail = lazy(() => import('./pages/TimelineDetail'));
const Notifications = lazy(() => import('./pages/Notifications'));
const Cases = lazy(() => import('./pages/Cases'));
const Agents = lazy(() => import('./pages/Agents'));
const Report = lazy(() => import('./pages/Report'));
const Profile = lazy(() => import('./pages/Profile'));

const TemplateHub = lazy(() => import('./templates/TemplateHub'));
const TechnicalMinimalTemplate = lazy(() => import('./templates/TechnicalMinimalTemplate'));
const ModernWorkspaceTemplate = lazy(() => import('./templates/ModernWorkspaceTemplate'));
const TechnicalMinimalCompactTemplate = lazy(() => import('./templates/TechnicalMinimalCompactTemplate'));
const TechnicalMinimalAdvancedTemplate = lazy(() => import('./templates/TechnicalMinimalAdvancedTemplate'));
const ModernWorkspaceDetailedTemplate = lazy(() => import('./templates/ModernWorkspaceDetailedTemplate'));
const ModernWorkspaceSplitTemplate = lazy(() => import('./templates/ModernWorkspaceSplitTemplate'));
const TechnicalWorkstationV2 = lazy(() => import('./templates_v2/TechnicalWorkstationV2'));
const GlassDashboardTemplate = lazy(() => import('./templates/GlassDashboardTemplate'));

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
      <div className="glass-dash-ambient-grid" aria-hidden="true" />
      <div className="glass-dash-neutral-glow-1" aria-hidden="true" />
      <div className="glass-dash-neutral-glow-2" aria-hidden="true" />
      <SessionManager />
      <DevTools />
      <Suspense fallback={<div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted, #94a3b8)', fontSize: '14px' }}>Loading workspace...</div>}>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        
        {/* Role-governed Routes */}
        <Route path="/dashboard" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Dashboard /></ProtectedRoute>} />
        <Route path="/cases" element={<ProtectedRoute allowedRoles={['admin']}><Cases /></ProtectedRoute>} />
        <Route path="/agents" element={<ProtectedRoute allowedRoles={['analyst', 'senior_analyst']}><Agents /></ProtectedRoute>} />
        <Route path="/report" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst', 'auditor']}><Report /></ProtectedRoute>} />
        <Route path="/reports" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst', 'auditor']}><Report /></ProtectedRoute>} />
        <Route path="/employees" element={<ProtectedRoute allowedRoles={['admin']}><Employees /></ProtectedRoute>} />
        <Route path="/audit-logs" element={<ProtectedRoute allowedRoles={['admin', 'auditor']}><AuditLogs /></ProtectedRoute>} />
        <Route path="/case-notes" element={<ProtectedRoute allowedRoles={['analyst', 'senior_analyst']}><CaseNotes /></ProtectedRoute>} />
        <Route path="/chatbot" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'auditor']}><Chatbot /></ProtectedRoute>} />
        <Route path="/findings" element={<ProtectedRoute allowedRoles={['admin', 'senior_analyst']}><Findings /></ProtectedRoute>} />
        <Route path="/timeline" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><TimelineDetail /></ProtectedRoute>} />
        <Route path="/evidence" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Evidence /></ProtectedRoute>} />
        <Route path="/upload" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Upload /></ProtectedRoute>} />
        <Route path="/sanitized" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><Sanitized /></ProtectedRoute>} />
        <Route path="/sanitized/:id" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst']}><SanitizedDetail /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst', 'auditor']}><Settings /></ProtectedRoute>} />
        <Route path="/notifications" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst', 'auditor']}><Notifications /></ProtectedRoute>} />
        <Route path="/profile" element={<ProtectedRoute allowedRoles={['admin', 'analyst', 'senior_analyst', 'auditor']}><Profile /></ProtectedRoute>} />

        {/* Legacy redirect aliases */}
        <Route path="/profile.html" element={<Navigate to="/profile" replace />} />
        <Route path="/evidence-coverage" element={<Navigate to="/evidence" replace />} />
        <Route path="/index.html" element={<Navigate to="/dashboard" replace />} />
        <Route path="/evidence.html" element={<Navigate to="/evidence" replace />} />
        <Route path="/settings.html" element={<Navigate to="/settings" replace />} />
        <Route path="/upload.html" element={<Navigate to="/upload" replace />} />
        <Route path="/sanitized.html" element={<Navigate to="/sanitized" replace />} />

        {/* ARGUS Design Exploration Suite & Template Previews */}
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
      </Suspense>
    </Router>
  );
}

export default App;
