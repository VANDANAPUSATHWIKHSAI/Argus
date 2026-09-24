import re

path = "sample/FE/src/components/Sidebar.jsx"
with open(path, "r", encoding="utf-8") as f:
    code = f.read()

# Fix the JSX element nesting issue in Sidebar.jsx

code = code.replace(
"""        {user?.role === 'senior_analyst' && (
          <>
            {user?.role !== 'senior_analyst' && (
          <Link to="/dashboard" className={`nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <span>Case Review</span>
            </Link>""",
"""        {user?.role === 'senior_analyst' && (
          <>
            <Link to="/dashboard" className={`nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <span>Case Review</span>
            </Link>"""
)

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
