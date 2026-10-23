import test from 'node:test';
import assert from 'node:assert/strict';

// Role permission mapping from App.jsx
const ROUTE_PERMISSIONS = {
  '/dashboard': ['admin', 'analyst', 'senior_analyst'],
  '/cases': ['admin'],
  '/agents': ['admin', 'analyst', 'senior_analyst'],
  '/report': ['admin', 'auditor', 'senior_analyst'],
  '/employees': ['admin'],
  '/audit-logs': ['admin', 'auditor'],
  '/case-notes': ['admin', 'analyst', 'senior_analyst'],
  '/chatbot': ['admin', 'analyst', 'senior_analyst', 'auditor'],
  '/findings': ['admin'],
  '/timeline': ['admin', 'analyst', 'senior_analyst'],
  '/evidence': ['admin', 'analyst', 'senior_analyst'],
  '/upload': ['admin', 'analyst', 'senior_analyst'],
  '/sanitized': ['admin', 'analyst', 'senior_analyst'],
  '/settings': ['admin', 'analyst', 'senior_analyst', 'auditor'],
  '/notifications': ['admin', 'analyst', 'senior_analyst', 'auditor']
};

const checkRouteAccess = ({ path, userRole, isExpired }) => {
  if (isExpired || !userRole) {
    return { allowed: false, redirectTo: '/login' };
  }
  const allowedRoles = ROUTE_PERMISSIONS[path];
  if (!allowedRoles) {
    return { allowed: true };
  }
  if (!allowedRoles.includes(userRole)) {
    const redirectTo = userRole === 'auditor' ? '/report' : '/dashboard';
    return { allowed: false, redirectTo };
  }
  return { allowed: true };
};

test('routeProtection: unauthenticated or expired sessions fail closed to /login', () => {
  assert.deepEqual(checkRouteAccess({ path: '/dashboard', userRole: null, isExpired: true }), {
    allowed: false,
    redirectTo: '/login'
  });
  assert.deepEqual(checkRouteAccess({ path: '/report', userRole: 'auditor', isExpired: true }), {
    allowed: false,
    redirectTo: '/login'
  });
});

test('routeProtection: auditor cannot access analyst or admin routes and is redirected to /report', () => {
  assert.deepEqual(checkRouteAccess({ path: '/dashboard', userRole: 'auditor', isExpired: false }), {
    allowed: false,
    redirectTo: '/report'
  });
  assert.deepEqual(checkRouteAccess({ path: '/cases', userRole: 'auditor', isExpired: false }), {
    allowed: false,
    redirectTo: '/report'
  });
  assert.deepEqual(checkRouteAccess({ path: '/evidence', userRole: 'auditor', isExpired: false }), {
    allowed: false,
    redirectTo: '/report'
  });
  assert.deepEqual(checkRouteAccess({ path: '/report', userRole: 'auditor', isExpired: false }), {
    allowed: true
  });
});

test('routeProtection: analyst cannot access auditor reports or case management directly', () => {
  assert.deepEqual(checkRouteAccess({ path: '/cases', userRole: 'analyst', isExpired: false }), {
    allowed: false,
    redirectTo: '/dashboard'
  });
  assert.deepEqual(checkRouteAccess({ path: '/findings', userRole: 'analyst', isExpired: false }), {
    allowed: false,
    redirectTo: '/dashboard'
  });
  assert.deepEqual(checkRouteAccess({ path: '/report', userRole: 'analyst', isExpired: false }), {
    allowed: false,
    redirectTo: '/dashboard'
  });
  assert.deepEqual(checkRouteAccess({ path: '/dashboard', userRole: 'analyst', isExpired: false }), {
    allowed: true
  });
});

test('routeProtection: admin role has full access across all operations', () => {
  for (const path of Object.keys(ROUTE_PERMISSIONS)) {
    assert.deepEqual(
      checkRouteAccess({ path, userRole: 'admin', isExpired: false }),
      { allowed: true },
      `Admin must have access to ${path}`
    );
  }
});
