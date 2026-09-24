import re

path = "sample/FE/src/pages/AdminDashboard.jsx"
with open(path, "r", encoding="utf-8") as f:
    code = f.read()

# 1. Add state variable
code = code.replace(
    "const [newCaseAnalyst, setNewCaseAnalyst] = useState('');",
    "const [newCaseAnalyst, setNewCaseAnalyst] = useState('');\n  const [newCaseSeniorAnalyst, setNewCaseSeniorAnalyst] = useState('');"
)

# 2. Add to POST payload
code = code.replace(
    "analyst_id: newCaseAnalyst || null,",
    "analyst_id: newCaseAnalyst || null,\n          senior_analyst_id: newCaseSeniorAnalyst || null,"
)

# 3. Add UI select dropdown
senior_select_ui = """
              <div style={{ marginBottom: '32px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-main)' }}>Assign Senior Analyst (Optional)</label>
                <SearchableSelect 
                  value={newCaseSeniorAnalyst} 
                  onChange={setNewCaseSeniorAnalyst} 
                  placeholder="Select Senior Analyst"
                  options={employees.filter(e => e.role === 'senior_analyst').map(emp => ({ value: emp.id, label: `${emp.name} (${emp.id})` }))}
                />
              </div>
"""

# Replace the text "Senior Analyst can be assigned after the case is created." with the new SearchableSelect component.
code = code.replace(
    "<div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: 6 }}>Senior Analyst can be assigned after the case is created.</div>\n              </div>",
    "</div>\n" + senior_select_ui
)

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
