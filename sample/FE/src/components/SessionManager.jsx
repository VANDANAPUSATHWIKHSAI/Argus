import React, { useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  isTokenExpired,
  getTokenRemainingMs,
  logout,
  IDLE_TIMEOUT_MS,
} from '../js/authSession';

/**
 * Global Session Manager Component
 * Enforces automatic logout on:
 * 1. Token expiration (exact countdown matching JWT exp)
 * 2. Idle inactivity (30 minutes of no user interactions)
 * 3. Cross-tab session invalidation
 */
const SessionManager = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const tokenTimerRef = useRef(null);
  const idleCheckIntervalRef = useRef(null);
  const lastActiveTimestampRef = useRef(Date.now());

  useEffect(() => {
    // If we're already on the login or public templates page, do not enforce session
    if (location.pathname === '/login' || location.pathname.startsWith('/templates')) {
      if (tokenTimerRef.current) clearTimeout(tokenTimerRef.current);
      if (idleCheckIntervalRef.current) clearInterval(idleCheckIntervalRef.current);
      return;
    }

    const token = localStorage.getItem('argus_token');
    if (!token) return;

    // 1. Check if token is already expired
    if (isTokenExpired(token)) {
      logout('session_expired');
      return;
    }

    // 2. Set exact timer for token expiration
    const remainingMs = getTokenRemainingMs(token);
    if (tokenTimerRef.current) clearTimeout(tokenTimerRef.current);
    tokenTimerRef.current = setTimeout(() => {
      logout('session_expired');
    }, remainingMs);

    // 3. Setup Idle Inactivity tracking
    lastActiveTimestampRef.current = Date.now();
    localStorage.setItem('argus_last_active', String(Date.now()));

    let lastRecordTime = 0;
    const handleUserActivity = () => {
      const now = Date.now();
      // Throttle activity recording to once every 10 seconds
      if (now - lastRecordTime > 10000) {
        lastRecordTime = now;
        lastActiveTimestampRef.current = now;
        localStorage.setItem('argus_last_active', String(now));
      }
    };

    const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];
    activityEvents.forEach((ev) => {
      window.addEventListener(ev, handleUserActivity, { passive: true });
    });

    // Interval to check idle timeout every 20 seconds
    if (idleCheckIntervalRef.current) clearInterval(idleCheckIntervalRef.current);
    idleCheckIntervalRef.current = setInterval(() => {
      const currentToken = localStorage.getItem('argus_token');
      if (!currentToken) return;

      const storedLastActive = Number(localStorage.getItem('argus_last_active') || lastActiveTimestampRef.current);
      const elapsed = Date.now() - storedLastActive;

      if (elapsed >= IDLE_TIMEOUT_MS) {
        logout('idle_timeout');
      }
    }, 20000);

    // 4. Cross-tab storage listener (if logged out in another tab)
    const handleStorageChange = (e) => {
      if (e.key === 'argus_token' && !e.newValue) {
        navigate('/login');
      }
    };
    window.addEventListener('storage', handleStorageChange);

    return () => {
      if (tokenTimerRef.current) clearTimeout(tokenTimerRef.current);
      if (idleCheckIntervalRef.current) clearInterval(idleCheckIntervalRef.current);
      activityEvents.forEach((ev) => {
        window.removeEventListener(ev, handleUserActivity);
      });
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [location.pathname, navigate]);

  return null;
};

export default SessionManager;
