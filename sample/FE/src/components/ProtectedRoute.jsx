import React from 'react';
import { Navigate } from 'react-router-dom';
import { isTokenExpired, clearSession, getAuthToken } from '../js/authSession';

const ProtectedRoute = ({ children }) => {
  const token = getAuthToken();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (isTokenExpired(token)) {
    clearSession();
    return <Navigate to="/login?reason=session_expired" replace />;
  }

  return children;
};

export default ProtectedRoute;
