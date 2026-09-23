import re

# 1. Update cases.py
cases_path = "api/routes/cases.py"
with open(cases_path, "r", encoding="utf-8") as f:
    cases_code = f.read()

# Add created_by_id for Case Creation
cases_code = cases_code.replace(
    '"created_by": mapped_name,',
    '"created_by": mapped_name,\n                "created_by_id": c_by,'
)

# Add created_by_id for Closed Case
cases_code = cases_code.replace(
    '"created_by": c_by_name,',
    '"created_by": c_by_name,\n                    "created_by_id": closed_by if closed_by else c_by,'
)

# Add created_by_id for Uploaded Evidence
cases_code = cases_code.replace(
    '"created_by": user_map.get(u_by, u_by),',
    '"created_by": user_map.get(u_by, u_by),\n                "created_by_id": u_by,'
)

# Add created_by_id for Analyst Findings
cases_code = cases_code.replace(
    '"created_by": user_name,',
    '"created_by": user_name,\n                        "created_by_id": reviewed_by if reviewed_by else "system",'
)

with open(cases_path, "w", encoding="utf-8") as f:
    f.write(cases_code)


# 2. Update AuditLogs.jsx
audit_path = "sample/FE/src/pages/AuditLogs.jsx"
with open(audit_path, "r", encoding="utf-8") as f:
    audit_code = f.read()

# Update mapped log object to include user id
audit_code = audit_code.replace(
    "user: { name: item.created_by || 'System', role: item.created_by === 'System' ? 'System' : 'Analyst' },",
    "user: { name: item.created_by || 'System', id: item.created_by_id || '', role: item.created_by === 'System' ? 'System' : 'Analyst' },"
)

# Implement Export Logs function
export_func = """
  const exportLogs = () => {
    if (filteredLogs.length === 0) return;
    
    // Create CSV header
    const headers = ['Event ID', 'Timestamp', 'User', 'User ID', 'Role', 'Action', 'Resource', 'Case ID', 'Source'];
    
    // Create CSV rows
    const rows = filteredLogs.map(log => [
      log.event_id,
      `"${log.timestamp}"`,
      `"${log.user.name}"`,
      `"${log.user.id}"`,
      log.user.role,
      `"${log.action}"`,
      `"${log.resource}"`,
      log.case_id || '-',
      log.source
    ]);
    
    const csvContent = "data:text/csv;charset=utf-8," 
      + headers.join(',') + "\\n" 
      + rows.map(e => e.join(',')).join("\\n");
      
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `argus_audit_logs_${activeCaseId || 'all'}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };
"""

audit_code = audit_code.replace("const clearFilters = () => {", export_func + "\n  const clearFilters = () => {")

# Attach to button
audit_code = audit_code.replace(
    '<button className="btn-export" style={{ background: \'var(--blue)\', border: \'none\', padding: \'8px 16px\', borderRadius: \'6px\', color: \'#fff\', cursor: \'pointer\', display: \'flex\', alignItems: \'center\', gap: \'8px\', fontSize: \'13px\', fontWeight: 600 }}>',
    '<button className="btn-export" onClick={exportLogs} style={{ background: \'var(--blue)\', border: \'none\', padding: \'8px 16px\', borderRadius: \'6px\', color: \'#fff\', cursor: \'pointer\', display: \'flex\', alignItems: \'center\', gap: \'8px\', fontSize: \'13px\', fontWeight: 600 }}>'
)

# Update uniqueUsers array to use objects with name and ID for SearchableSelect
user_options_replacement = """
  const uniqueUsers = Array.from(
    new Map(logs.map(l => [l.user.name, l.user])).values()
  );
  const userOptions = [
    { label: 'All Users', value: '' },
    ...uniqueUsers.map(u => ({ label: `${u.name} ${u.id ? `(${u.id})` : ''}`, value: u.name }))
  ];
"""
audit_code = audit_code.replace("""  const uniqueUsers = Array.from(new Set(logs.map(l => l.user.name)));
  const userOptions = [
    { label: 'All Users', value: '' },
    ...uniqueUsers.map(u => ({ label: u, value: u }))
  ];""", user_options_replacement.strip())

with open(audit_path, "w", encoding="utf-8") as f:
    f.write(audit_code)
