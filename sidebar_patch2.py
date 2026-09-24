import re

path = "sample/FE/src/components/Sidebar.jsx"
with open(path, "r", encoding="utf-8") as f:
    code = f.read()

# Separate Analyst and Senior Analyst
code = code.replace(
    "{(user?.role === 'analyst' || user?.role === 'senior_analyst') && (",
    "{(user?.role === 'analyst') && ("
)

# Insert Senior Analyst links before Audit Logs
senior_links = """
        {user?.role === 'senior_analyst' && (
          <>
            <Link to="/dashboard" className={`nav-item ${currentPath === '/dashboard' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <span>Case Review</span>
            </Link>
            <Link to="/report-review" className={`nav-item ${currentPath === '/report-review' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              <span>Report Review</span>
            </Link>
            <Link to="/review-notes" className={`nav-item ${currentPath === '/review-notes' ? 'active' : ''}`}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><polyline points="9 15 11 17 15 13"></polyline></svg>
              <span>Review Notes</span>
            </Link>
          </>
        )}
"""

code = code.replace(
    '<Link to="/audit-logs" className={`nav-item ${currentPath === \'/audit-logs\' ? \'active\' : \'\'}`}>',
    senior_links.strip() + '\n\n        <Link to="/audit-logs" className={`nav-item ${currentPath === \'/audit-logs\' ? \'active\' : \'\'}`}>'
)

# Only show top-level "Dashboard" for non-senior
code = code.replace(
    '<Link to="/dashboard" className={`nav-item ${currentPath === \'/dashboard\' ? \'active\' : \'\'}`}>',
    '{user?.role !== \'senior_analyst\' && (\n          <Link to="/dashboard" className={`nav-item ${currentPath === \'/dashboard\' ? \'active\' : \'\'}`}>'
)
code = code.replace(
    '<span>Dashboard</span>\n        </Link>',
    '<span>Dashboard</span>\n          </Link>\n        )}'
)

# Update the footer graphic
footer_replacement = """      <div className="sidebar-footer" style={{ 
        marginTop: 'auto', 
        width: '100%', 
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'flex-end',
        position: 'relative'
      }}>
        {user?.role === 'senior_analyst' ? (
          <div style={{ position: 'relative', width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            {/* Simple CSS Mountain Silhouette */}
            <svg width="100%" height="80" viewBox="0 0 300 80" preserveAspectRatio="none" style={{ position: 'absolute', bottom: '0', zIndex: 0, opacity: 0.15 }}>
              <path d="M0,80 L50,40 L90,60 L140,20 L190,55 L240,10 L300,70 L300,80 Z" fill="#ffffff"/>
              <path d="M30,80 L70,50 L110,65 L160,30 L210,60 L260,20 L300,75 L300,80 Z" fill="#ffffff" opacity="0.5"/>
            </svg>
            <div style={{ zIndex: 1, padding: '24px 32px 32px 32px', textAlign: 'left', width: '100%' }}>
              <p style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', margin: '0 0 4px 0', letterSpacing: '1px', textTransform: 'uppercase' }}>
                Truth<br/>Through<br/>Evidence
              </p>
            </div>
          </div>
        ) : (
          <div style={{ padding: '24px 32px', width: '100%', textAlign: 'left' }}>
            <p style={{ fontSize: '13px', fontStyle: 'italic', color: 'var(--text-muted)', marginBottom: '8px' }}>
              "From digital traces<br />to real answers."
            </p>
            <p style={{ fontSize: '14px', fontWeight: 'bold', color: 'var(--text-main)', margin: 0, letterSpacing: '1px' }}>
              ARGUS
            </p>
            <div style={{ width: '20px', height: '1px', backgroundColor: 'var(--border-strong)', marginTop: '8px' }}></div>
          </div>
        )}
      </div>"""

# replace entire sidebar-footer div
start_footer = code.find('<div className="sidebar-footer"')
end_footer = code.find('</aside>')
code = code[:start_footer] + footer_replacement + "\n    " + code[end_footer:]

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
