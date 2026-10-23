import React from 'react';
import { Navigate } from 'react-router-dom';
import { isTokenExpired, clearSession, getAuthToken, getAuthUser } from '../js/authSession';

/**
 * Route protection component with role-aware authorization
 * @param {React.ReactNode} children - Target component to render if authorized
 * @param {string[]} [allowedRoles] - Optional list of authorized roles for this route
 */
const ProtectedRoute = ({ children, allowedRoles }) => {
  const token = getAuthToken();
  const user = getAuthUser();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (isTokenExpired(token) || !user || !user.role) {
    clearSession();
    return <Navigate to="/login?reason=session_expired" replace />;
  }

  // Enforce role-based access if route specifies allowedRoles
  if (allowedRoles && allowedRoles.length > 0) {
    const userRole = (user.role || '').toLowerCase();
    const isAuthorized = allowedRoles.map(r => r.toLowerCase()).includes(userRole);

    if (!isAuthorized) {
      // Auditor is restricted to report view
      if (userRole === 'auditor') {
        return <Navigate to="/report" replace />;
      }
      // Other roles navigate back to authorized dashboard
      return <Navigate to="/dashboard" replace />;
    }
  }

  return children;
};

export default ProtectedRoute;
