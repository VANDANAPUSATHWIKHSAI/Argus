import subprocess
import sys
import json
import psycopg2
from psycopg2.extras import RealDictCursor

def run_audit_iteration(run_id: int):
    print(f"\n--- RUNNING AUDIT ITERATION {run_id} ---")
    proc = subprocess.run(
        [sys.executable, "scratch/downstream_generalization_audit.py"],
        capture_output=True,
        text=True
    )
    assert proc.returncode == 0, f"Run {run_id} failed: {proc.stderr}"
    
    conn = psycopg2.connect(host="localhost", port=5433, dbname="argus", user="argus_user", password="argus_dev")
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT finding_id, case_id, tenant_id, severity, confidence, mitre_mapping, sanitized_fact, finding_fingerprint, layer
        FROM fir_findings
        WHERE case_id = 'CASE-GENERALIZATION-001'
        ORDER BY finding_fingerprint, layer;
    """)
    rows = cur.fetchall()
    conn.close()
    return rows

def test_determinism():
    print("======================================================================")
    print("ARGUS — PHASE 11: DETERMINISM & REPEATABILITY AUDIT")
    print("======================================================================")
    
    rows_run1 = run_audit_iteration(1)
    rows_run2 = run_audit_iteration(2)

    print(f"\nRun 1 Row Count: {len(rows_run1)}")
    print(f"Run 2 Row Count: {len(rows_run2)}")
    assert len(rows_run1) == len(rows_run2), "Row count mismatch between runs!"

    fingerprints_run1 = set(r["finding_fingerprint"] for r in rows_run1)
    fingerprints_run2 = set(r["finding_fingerprint"] for r in rows_run2)
    
    fp_match = fingerprints_run1 == fingerprints_run2
    print(f"Fingerprint Set Equality across runs: {fp_match}")
    assert fp_match, f"Fingerprint set mismatch between runs! Diff: {fingerprints_run1 ^ fingerprints_run2}"

    mismatches = []
    for r1, r2 in zip(rows_run1, rows_run2):
        for k in ("severity", "confidence", "mitre_mapping", "sanitized_fact", "finding_fingerprint", "layer", "case_id", "tenant_id"):
            if r1[k] != r2[k]:
                mismatches.append(f"Mismatch in {k} for fingerprint {r1['finding_fingerprint']}: Run1='{r1[k]}' vs Run2='{r2[k]}'")

    print(f"Field Mismatches across runs: {len(mismatches)}")
    assert len(mismatches) == 0, f"Determinism failure: {mismatches}"

    print("\n======================================================================")
    print("DETERMINISM AUDIT PASSED (100% LOGICAL & OUTPUT DETERMINISM VERIFIED)")
    print("======================================================================")

if __name__ == "__main__":
    test_determinism()
