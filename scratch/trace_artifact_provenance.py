import psycopg2
from psycopg2.extras import RealDictCursor
import json

def inspect_all_findings():
    conn = psycopg2.connect(
        host="localhost",
        port=5433,
        dbname="argus",
        user="argus_user",
        password="argus_dev"
    )
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT finding_id, layer, severity, confidence, source_artifact_id, evidence_reference, finding_fingerprint, LEFT(sanitized_fact, 100) as fact_snippet
        FROM fir_findings
        WHERE case_id = 'CASE-FINAL-DEMO-2026';
    """)
    rows = cur.fetchall()
    conn.close()
    
    print(f"Total findings in CASE-FINAL-DEMO-2026: {len(rows)}")
    layer_counts = {}
    artifact_ids = set()
    for i, r in enumerate(rows, 1):
        layer_counts[r['layer']] = layer_counts.get(r['layer'], 0) + 1
        artifact_ids.add(r['source_artifact_id'])
        print(f"{i:02d}. ID: {r['finding_id']} | Layer: {r['layer']} | Sev: {r['severity']} | ArtifactID: {r['source_artifact_id']} | EvRefs: {r['evidence_reference']} | Fact: {r['fact_snippet']}...")

    print("\nLayer Distribution:", layer_counts)
    print("Distinct Source Artifact IDs:", artifact_ids)

if __name__ == "__main__":
    inspect_all_findings()
