import psycopg2
from psycopg2.extras import RealDictCursor

def audit_source_artifacts():
    conn = psycopg2.connect(
        host="localhost",
        port=5433,
        dbname="argus",
        user="argus_user",
        password="argus_dev"
    )
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT source_artifact_id, COUNT(*) as finding_count
        FROM fir_findings
        WHERE case_id = 'CASE-FINAL-DEMO-2026'
        GROUP BY source_artifact_id;
    """)
    rows = cur.fetchall()
    print("======================================================================")
    print("SOURCE ARTIFACT ID DISTRIBUTION IN POSTGRESQL FOR CASE-FINAL-DEMO-2026:")
    print("======================================================================")
    for r in rows:
        print(f"  source_artifact_id: {r['source_artifact_id']} | finding_count: {r['finding_count']}")
        
    cur.execute("""
        SELECT COUNT(DISTINCT source_artifact_id) as distinct_artifacts, COUNT(*) as total_findings
        FROM fir_findings
        WHERE case_id = 'CASE-FINAL-DEMO-2026';
    """)
    summary = cur.fetchone()
    print("\nSummary:")
    print(f"  Distinct source_artifact_id count: {summary['distinct_artifacts']}")
    print(f"  Total findings count              : {summary['total_findings']}")
    
    # Check evidence table as well
    cur.execute("SELECT id, case_id, filename, file_type, sha256 FROM evidence WHERE case_id = 'CASE-FINAL-DEMO-2026';")
    ev_rows = cur.fetchall()
    print(f"\nEvidence records in 'evidence' table for CASE-FINAL-DEMO-2026 (Count: {len(ev_rows)}):")
    for ev in ev_rows:
        print(f"  ID: {ev['id']} | Filename: {ev['filename']} | FileType: {ev['file_type']} | SHA256: {ev['sha256'][:16]}...")

    conn.close()

if __name__ == "__main__":
    audit_source_artifacts()
