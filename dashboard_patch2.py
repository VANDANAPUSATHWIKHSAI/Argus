import re

path = "sample/FE/src/pages/Dashboard.jsx"
with open(path, "r", encoding="utf-8") as f:
    code = f.read()

code = code.replace(
    "import AdminDashboard from './AdminDashboard';",
    "import AdminDashboard from './AdminDashboard';\nimport SeniorDashboard from './SeniorDashboard';"
)

code = code.replace(
    "const isAdmin = currentUser?.role === 'admin';",
    "const isAdmin = currentUser?.role === 'admin';\n  const isSeniorAnalyst = currentUser?.role === 'senior_analyst';"
)

render_conditional = """    <>
      <div id="app-shell">
        <AlertModal 
          isOpen={customAlert.isOpen} 
          title={customAlert.title} 
          message={customAlert.message} 
          type={customAlert.type} 
          onClose={closeAlert} 
        />

        {/* -- SIDEBAR -- */}
        <Sidebar />

        {/* -- MAIN CONTENT -- */}
        <main className="main-content" style={{ padding: isSeniorAnalyst ? 0 : undefined }}>
          {isSeniorAnalyst ? (
            <SeniorDashboard />
          ) : isAdmin ? ("""

code = code.replace(
    """    <>
      <div id="app-shell">
        <AlertModal 
          isOpen={customAlert.isOpen} 
          title={customAlert.title} 
          message={customAlert.message} 
          type={customAlert.type} 
          onClose={closeAlert} 
        />

        {/* -- SIDEBAR -- */}
        <Sidebar />

        {/* -- MAIN CONTENT -- */}
        <main className="main-content">
          {isAdmin ? (""",
    render_conditional
)

code = code.replace(
    """          </div>
            </>
          )}
        </main>
      </div>""",
    """          </div>
            </>
          )}
        </main>
      </div>"""
)

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
