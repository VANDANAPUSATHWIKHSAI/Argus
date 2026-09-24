path = "sample/FE/src/components/Sidebar.jsx"
with open(path, "r", encoding="utf-8") as f:
    code = f.read()

# Find the place to insert Case Notes. Under Timeline or before Audit Logs.
# Let's insert it before Audit Logs, but only for Analyst roles, wait... "For the Analyst role: Allowed: Create notes, View notes".
# I'll put it right after AI Findings / Timeline
link = """
        <Link to="/case-notes" className={`nav-item ${currentPath === '/case-notes' ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
          <span>Case Notes</span>
        </Link>
"""

code = code.replace(
    '<Link to="/sanitized" className={`nav-item ${currentPath === \'/sanitized\' ? \'active\' : \'\'}`}>',
    link.strip() + '\n        <Link to="/sanitized" className={`nav-item ${currentPath === \'/sanitized\' ? \'active\' : \'\'}`}>'
)

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
