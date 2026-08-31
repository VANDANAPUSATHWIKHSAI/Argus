"""
PostgreSQL Real Evidence Verification & Report Query Script
============================================================
Runs the nps-2009-ntfs1 pipeline once into an isolated test case in PostgreSQL
and outputs all required database statistics and discrepancy analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from config.settings import settings

import psycopg2
from psycopg2.extras import RealDictCursor

from scratch.audit_phase_a4_e2e import run_phase_a4_e2e
from fir.repository import FIRRepository
from forensic_analysis.schemas import finding_to_fir

logging.basicConfig(level=logging.INFO)


def run_pg_nps_verification():
    print("=" * 70)
    print("ARGUS — POSTGRESQL REAL EVIDENCE VERIFICATION")
    print("=" * 70)

    # 1. Connect to PostgreSQL
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        connect_timeout=3
    )
    cur = conn.cursor(cursor_factory=RealDictCursor)

    target_case_id = "CASE-NPS-2009-NTFS1"

    # 2. Clear previous test rows for this dedicated case
    cur.execute("DELETE FROM fir_findings WHERE case_id = %s;", (target_case_id,))
    conn.commit()

    fir_repo = FIRRepository()
    fir_repo.clear()

    # 3. Run real evidence pipeline exactly once
    print(f"\n[1] Running real evidence pipeline for case '{target_case_id}'...")
    run_phase_a4_e2e()

    pipeline_findings = list(fir_repo.findings.values())
    print(f"  Pipeline generated {len(pipeline_findings)} in-memory FIR findings.")

    # 4. Insert findings into PostgreSQL via FIRRepository logic
    for item in pipeline_findings:
        item.case_id = target_case_id
        fir_repo.insert(item)

    # 5. Execute PostgreSQL Queries
    print("\n[2] QUERYING POSTGRESQL DATABASE FOR VERIFICATION METRICS...")

    # Total rows in table
    cur.execute("SELECT COUNT(*) AS total_rows FROM fir_findings;")
    total_rows = cur.fetchone()["total_rows"]

    # Rows for target case
    cur.execute("SELECT COUNT(*) AS case_rows FROM fir_findings WHERE case_id = %s;", (target_case_id,))
    case_rows = cur.fetchone()["case_rows"]

    # Unique finding fingerprints
    cur.execute("SELECT COUNT(DISTINCT finding_fingerprint) AS unique_fp FROM fir_findings WHERE case_id = %s;", (target_case_id,))
    unique_fp = cur.fetchone()["unique_fp"]

    # Duplicate fingerprints (fingerprints with count > 1)
    cur.execute("""
        SELECT finding_fingerprint, COUNT(*) AS cnt 
        FROM fir_findings 
        WHERE case_id = %s AND finding_fingerprint IS NOT NULL
        GROUP BY finding_fingerprint 
        HAVING COUNT(*) > 1;
    """, (target_case_id,))
    dup_fps = cur.fetchall()
    dup_count = len(dup_fps)

    # Sanitized findings count
    cur.execute("SELECT COUNT(*) AS sanitized_cnt FROM fir_findings WHERE case_id = %s AND sanitized_fact IS NOT NULL;", (target_case_id,))
    sanitized_cnt = cur.fetchone()["sanitized_cnt"]

    # Review status breakdown
    cur.execute("SELECT review_status, COUNT(*) AS cnt FROM fir_findings WHERE case_id = %s GROUP BY review_status;", (target_case_id,))
    review_status_breakdown = {row["review_status"]: row["cnt"] for row in cur.fetchall()}

    print("\n" + "=" * 70)
    print("POSTGRESQL AUDIT METRICS REPORT:")
    print("=" * 70)
    print(f"  1. Total Rows in fir_findings Table : {total_rows}")
    print(f"  2. Rows for CASE-NPS-2009-NTFS1     : {case_rows}")
    print(f"  3. Unique Finding Fingerprints       : {unique_fp}")
    print(f"  4. Duplicate Fingerprints Count      : {dup_count}")
    print(f"  5. Sanitized Findings Count          : {sanitized_cnt}")
    print(f"  6. Review-Status Breakdown           : {review_status_breakdown}")
    print("=" * 70)

    conn.close()

if __name__ == "__main__":
    run_pg_nps_verification()
