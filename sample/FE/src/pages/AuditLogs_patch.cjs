const fs = require('fs');
let content = fs.readFileSync('sample/FE/src/pages/AuditLogs.jsx', 'utf-8');

if (!content.includes('useLocation')) {
    content = content.replace("import React, { useState, useEffect } from 'react';", "import React, { useState, useEffect } from 'react';\nimport { useLocation } from 'react-router-dom';");
}

let oldFuncStart = `const AuditLogs = () => {
  const [logs, setLogs] = useState([]);`;

let newFuncStart = `const AuditLogs = () => {
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const targetCaseId = searchParams.get('case_id');

  const [logs, setLogs] = useState([]);`;

if (!content.includes('useLocation()')) {
    content = content.replace(oldFuncStart, newFuncStart);
}

// Add case_id to formatted items
let oldFormatted = `              action: item.action,
              details: item.details,
              icon: icon`;

let newFormatted = `              action: item.action,
              details: item.details,
              icon: icon,
              case_id: item.case_id`;
content = content.replace(oldFormatted, newFormatted);

let oldFilter = `  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.details.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.action.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.user.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesUser = filterUser === 'All Users' || log.user.name === filterUser || (filterUser === 'System' && log.user.name === 'System');
    const matchesAction = filterAction === 'All Actions' || log.action === filterAction;
    return matchesSearch && matchesUser && matchesAction;
  });`;

let newFilter = `  const filteredLogs = logs.filter(log => {
    if (targetCaseId && log.case_id !== targetCaseId) return false;
    const matchesSearch = log.details.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.action.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          log.user.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesUser = filterUser === 'All Users' || log.user.name === filterUser || (filterUser === 'System' && log.user.name === 'System');
    const matchesAction = filterAction === 'All Actions' || log.action === filterAction;
    return matchesSearch && matchesUser && matchesAction;
  });`;
content = content.replace(oldFilter, newFilter);

let oldHeader = `<h2>Audit Logs</h2>
          <p>Comprehensive record of all platform activities and case modifications</p>`;
          
let newHeader = `<h2>{targetCaseId ? \`Audit Logs: \${targetCaseId}\` : 'Audit Logs'}</h2>
          <p>Comprehensive record of all platform activities and case modifications</p>`;
content = content.replace(oldHeader, newHeader);

fs.writeFileSync('sample/FE/src/pages/AuditLogs.jsx', content);
