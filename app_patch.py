path = "sample/FE/src/App.jsx"
with open(path, "r", encoding="utf-8") as f:
    code = f.read()

code = code.replace(
    "import AuditLogs from './pages/AuditLogs';",
    "import AuditLogs from './pages/AuditLogs';\nimport CaseNotes from './pages/CaseNotes';"
)

code = code.replace(
    '<Route path="/audit-logs" element={<ProtectedRoute><AuditLogs /></ProtectedRoute>} />',
    '<Route path="/audit-logs" element={<ProtectedRoute><AuditLogs /></ProtectedRoute>} />\n        <Route path="/case-notes" element={<ProtectedRoute><CaseNotes /></ProtectedRoute>} />'
)

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
