import React from 'react';
import DevRoleSwitcher from './DevRoleSwitcher';

/**
 * DevTools wrapper: Isolates dev-only UI utilities such that App.jsx remains clean
 * and compliant with production safety audits.
 */
export default function DevTools() {
  if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.DEV) {
    return <DevRoleSwitcher />;
  }
  return null;
}
