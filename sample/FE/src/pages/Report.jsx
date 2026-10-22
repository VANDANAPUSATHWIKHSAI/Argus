import React from 'react';
import { Navigate } from 'react-router-dom';
import AuditorReportWorkspace from './AuditorReportWorkspace';

export default function Report() {
  let user = null;
  try {
    user = JSON.parse(localStorage.getItem('argus_user'));
  } catch (e) {}

  // Analyst role does not have access to Report page; redirect to Dashboard
  if (user?.role === 'analyst') {
    return <Navigate to="/dashboard" replace />;
  }

  return <AuditorReportWorkspace />;
}
