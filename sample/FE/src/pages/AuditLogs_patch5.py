audit_path = "sample/FE/src/pages/AuditLogs.jsx"
with open(audit_path, "r", encoding="utf-8") as f:
    audit_code = f.read()

audit_code = audit_code.replace(
    '<button className="btn-page" style={{ background: \'var(--bg-app)\', border: \'1px solid var(--border-strong)\', color: \'var(--text-main)\', padding: \'6px 12px\', borderRadius: \'4px\', cursor: \'pointer\', opacity: currentPage === 1 ? 0.5 : 1 }} onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))} disabled={currentPage === 1}>Previous</button>',
    '<button className="btn-page" style={{ width: \'auto\', background: \'var(--bg-app)\', border: \'1px solid var(--border-strong)\', color: \'var(--text-main)\', padding: \'6px 12px\', borderRadius: \'4px\', cursor: \'pointer\', opacity: currentPage === 1 ? 0.5 : 1 }} onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))} disabled={currentPage === 1}>Previous</button>'
)

audit_code = audit_code.replace(
    '<button className="btn-page" style={{ background: \'var(--bg-app)\', border: \'1px solid var(--border-strong)\', color: \'var(--text-main)\', padding: \'6px 12px\', borderRadius: \'4px\', cursor: \'pointer\', opacity: currentPage === totalPages || totalPages === 0 ? 0.5 : 1 }} onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))} disabled={currentPage === totalPages || totalPages === 0}>Next</button>',
    '<button className="btn-page" style={{ width: \'auto\', background: \'var(--bg-app)\', border: \'1px solid var(--border-strong)\', color: \'var(--text-main)\', padding: \'6px 12px\', borderRadius: \'4px\', cursor: \'pointer\', opacity: currentPage === totalPages || totalPages === 0 ? 0.5 : 1 }} onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))} disabled={currentPage === totalPages || totalPages === 0}>Next</button>'
)

with open(audit_path, "w", encoding="utf-8") as f:
    f.write(audit_code)
