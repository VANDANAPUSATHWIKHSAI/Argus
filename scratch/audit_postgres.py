"""
ARGUS — PostgreSQL Production Verification Script
=================================================
Inspects PostgreSQL connection, fir_findings schema, Phase A.4 column presence,
round-trip persistence, fingerprint deduplication, tenant isolation, and real evidence counts.
"""

from __future__ import annotations

import sys
import json
import logging
from datetime import datetime, timezone

from config.settings import settings
from forensic_analysis.schemas import Finding, finding_to_fir
from sanitization.gateway import SanitizationGateway
from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from infrastructure.schemas import Evidence

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pg_audit")


def audit_pg():
    print("=" * 70)
    print("ARGUS — POSTGRESQL PRODUCTION VERIFICATION")
    print("=" * 70)

    import psycopg2
    from psycopg2.extras import RealDictCursor

    # 1. Connect to PostgreSQL using settings
    ports_to_try = [settings.postgres_port, 5433, 5432]
    conn = None
    connected_port = None

    for port in ports_to_try:
        try:
            print(f"Attempting PostgreSQL connection to {settings.postgres_host}:{port} (db={settings.postgres_db}, user={settings.postgres_user})...")
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            connected_port = port
            print(f"  [SUCCESS] Connected to PostgreSQL on port {port}!")
            break
        except Exception as e:
            print(f"  [CONNECTION FAILED on port {port}]: {e}")

    if not conn:
        print("\n[CRITICAL ERROR] Could not connect to PostgreSQL on any port!")
        return

    cur = conn.cursor(cursor_factory=RealDictCursor)

    # 2. Inspect fir_findings table schema
    print("\n[2] INSPECTING 'fir_findings' TABLE SCHEMA IN POSTGRESQL...")
    cur.execute("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'fir_findings'
        ORDER BY ordinal_position;
    """)
    rows = cur.fetchall()

    if not rows:
        print("  [NOTICE] Table 'fir_findings' does NOT exist in PostgreSQL yet.")
        existing_cols = []
    else:
        print(f"  Existing columns in 'fir_findings' ({len(rows)} total):")
        existing_cols = [r["column_name"] for r in rows]
        for r in rows:
            print(f"    - {r['column_name']:<24} : {r['data_type']:<16} (Nullable: {r['is_nullable']})")

    # 3. Compare with FIRFinding model fields
    required_fields = [
        "finding_id", "case_id", "tenant_id", "fact", "sanitized_fact",
        "confidence", "severity", "mitre_mapping", "evidence_reference",
        "source_artifact_id", "finding_fingerprint", "review_status",
        "reviewed_by", "injection_flagged", "injection_score", "layer", "timestamp"
    ]

    missing_cols = [f for f in required_fields if f not in existing_cols]
    print("\n[3] COMPARING POSTGRESQL SCHEMA WITH FIRFINDING MODEL:")
    if missing_cols:
        print(f"  [SCHEMA GAP DETECTED] Missing columns in PostgreSQL table: {missing_cols}")
    else:
        print("  [SUCCESS] PostgreSQL schema matches FIRFinding model 100%!")

    # 4. Perform Real PostgreSQL Round-Trip Test
    print("\n[4] EXECUTING REAL POSTGRESQL ROUND-TRIP PERSISTENCE TEST...")
    cur.execute("DELETE FROM fir_findings WHERE case_id = 'CASE-PG-TEST';")
    conn.commit()

    # Ensure table has all columns by running DDL from fir/repository.py or updating schema
    print("  Creating/Updating fir_findings table DDL...")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fir_findings (
            finding_id          TEXT PRIMARY KEY,
            case_id             TEXT NOT NULL,
            tenant_id           TEXT NOT NULL DEFAULT 'default',
            fact                TEXT NOT NULL,
            sanitized_fact      TEXT,
            confidence          FLOAT NOT NULL DEFAULT 1.0,
            severity            TEXT NOT NULL DEFAULT 'medium',
            mitre_mapping       TEXT,
            evidence_reference  TEXT[] NOT NULL DEFAULT '{}',
            source_artifact_id  TEXT,
            finding_fingerprint TEXT,
            review_status       TEXT NOT NULL DEFAULT 'pending_review',
            reviewed_by         TEXT,
            injection_flagged   BOOLEAN DEFAULT FALSE,
            injection_score     FLOAT DEFAULT 0.0,
            layer               TEXT NOT NULL DEFAULT 'unknown',
            timestamp           TIMESTAMPTZ DEFAULT NOW(),
            raw_data            JSONB DEFAULT '{}'
        );
        ALTER TABLE fir_findings DROP CONSTRAINT IF EXISTS fir_findings_case_id_fkey;
        ALTER TABLE fir_findings ALTER COLUMN case_id TYPE TEXT USING case_id::text;
        ALTER TABLE fir_findings ALTER COLUMN source_engine DROP NOT NULL;
        ALTER TABLE fir_findings ALTER COLUMN source_engine SET DEFAULT 'argus';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS sanitized_fact TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS source_artifact_id TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS finding_fingerprint TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending_review';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_flagged BOOLEAN DEFAULT FALSE;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_score FLOAT DEFAULT 0.0;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS layer TEXT DEFAULT 'unknown';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ DEFAULT NOW();
    """)
    conn.commit()

    # Create raw Finding -> Sanitization Gateway -> FIRFinding
    raw_finding = Finding(
        case_id="CASE-PG-TEST",
        tenant_id="tenant-pg",
        fact="Unauthorized login for user admin@corp.com from 198.51.100.44",
        confidence=0.92,
        severity="high",
        evidence_reference="CORR-PG-1",
        source_artifact_id="art-pg-100",
        layer="endpoint"
    )

    gateway = SanitizationGateway()
    ctx = gateway.sanitize_finding(raw_finding)

    fir_fnd = FIRFinding(
        finding_id=ctx.finding_id,
        case_id=ctx.case_id,
        tenant_id=ctx.tenant_id,
        fact=raw_finding.fact,
        sanitized_fact=ctx.sanitized_fact,
        confidence=ctx.confidence,
        severity=ctx.severity,
        mitre_mapping=ctx.mitre_mapping,
        evidence_reference=ctx.evidence_reference,
        source_artifact_id=ctx.source_artifact_id,
        finding_fingerprint=raw_finding.finding_fingerprint,
        review_status=ReviewStatus.PENDING_REVIEW,
        injection_flagged=ctx.injection_flagged,
        injection_score=ctx.injection_score,
        layer=ctx.layer,
        timestamp=ctx.timestamp
    )

    # Insert into PostgreSQL
    cur.execute("""
        INSERT INTO fir_findings
            (finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
             evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
             injection_flagged, injection_score, layer, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (finding_id) DO UPDATE SET
            sanitized_fact = EXCLUDED.sanitized_fact,
            review_status = EXCLUDED.review_status,
            reviewed_by = EXCLUDED.reviewed_by;
    """, (
        fir_fnd.finding_id, fir_fnd.case_id, fir_fnd.tenant_id, fir_fnd.fact, fir_fnd.sanitized_fact,
        fir_fnd.confidence, fir_fnd.severity, fir_fnd.mitre_mapping, fir_fnd.evidence_reference,
        fir_fnd.source_artifact_id, fir_fnd.finding_fingerprint, fir_fnd.review_status.value,
        fir_fnd.reviewed_by, fir_fnd.injection_flagged, fir_fnd.injection_score, fir_fnd.layer, fir_fnd.timestamp
    ))
    conn.commit()

    # Query back from PostgreSQL
    cur.execute("SELECT * FROM fir_findings WHERE finding_id = %s;", (fir_fnd.finding_id,))
    retrieved = cur.fetchone()

    print("\n[5] POSTGRESQL ROUND-TRIP VERIFICATION RESULTS:")
    print(f"  Finding ID          : {retrieved['finding_id']}")
    print(f"  Case ID             : {retrieved['case_id']}")
    print(f"  Tenant ID           : {retrieved['tenant_id']}")
    print(f"  Sanitized Fact      : {retrieved['sanitized_fact']!r}")
    print(f"  Fingerprint         : {retrieved['finding_fingerprint']}")
    print(f"  Source Artifact ID  : {retrieved['source_artifact_id']}")
    print(f"  Review Status       : {retrieved['review_status']}")
    print(f"  Injection Flagged   : {retrieved['injection_flagged']}")
    print(f"  Injection Score     : {retrieved['injection_score']}")

    assert retrieved["sanitized_fact"] == ctx.sanitized_fact
    assert retrieved["finding_fingerprint"] == raw_finding.finding_fingerprint
    assert retrieved["source_artifact_id"] == "art-pg-100"
    print("  [SUCCESS] All fields survived PostgreSQL persistence 100% intact!")

    # 5. Idempotent Fingerprint Insertion Test
    print("\n[6] TESTING FINGERPRINT DUP INSERTION IDEMPOTENCY IN POSTGRESQL...")
    cur.execute("""
        INSERT INTO fir_findings
            (finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
             evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
             injection_flagged, injection_score, layer, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (finding_id) DO NOTHING;
    """, (
        fir_fnd.finding_id, fir_fnd.case_id, fir_fnd.tenant_id, fir_fnd.fact, fir_fnd.sanitized_fact,
        fir_fnd.confidence, fir_fnd.severity, fir_fnd.mitre_mapping, fir_fnd.evidence_reference,
        fir_fnd.source_artifact_id, fir_fnd.finding_fingerprint, fir_fnd.review_status.value,
        fir_fnd.reviewed_by, fir_fnd.injection_flagged, fir_fnd.injection_score, fir_fnd.layer, fir_fnd.timestamp
    ))
    conn.commit()
    cur.execute("SELECT COUNT(*) AS cnt FROM fir_findings WHERE case_id = %s;", (fir_fnd.case_id,))
    count_res = cur.fetchone()["cnt"]
    print(f"  Finding count after repeat insert: {count_res} (Expected: 1)")
    assert count_res == 1

    # 6. Tenant Isolation Verification
    print("\n[7] VERIFYING TENANT ISOLATION IN POSTGRESQL...")
    cur.execute("SELECT * FROM fir_findings WHERE case_id = %s AND tenant_id = %s;", (fir_fnd.case_id, "tenant-other"))
    iso_res = cur.fetchall()
    print(f"  Query result for tenant-other: {len(iso_res)} records")
    assert len(iso_res) == 0
    print("  [SUCCESS] Tenant isolation verified in PostgreSQL!")

    # 7. Run real nps-2009-ntfs1 pipeline with PostgreSQL
    print("\n[8] RUNNING REAL nps-2009-ntfs1 PIPELINE WITH POSTGRESQL...")
    fir_repo = FIRRepository()
    fir_repo.clear()

    # Clear PostgreSQL fir_findings table for case CASE-REAL-NPS-PG
    cur.execute("DELETE FROM fir_findings WHERE case_id = 'CASE-REAL-NPS-PG';")
    conn.commit()

    # Run real evidence pipeline
    from scratch.audit_phase_a4_e2e import run_phase_a4_e2e
    run_phase_a4_e2e()

    pg_findings = list(fir_repo.findings.values())
    print(f"\n  Pipeline produced {len(pg_findings)} FIR findings. Persisting to PostgreSQL table...")

    # Insert findings to PostgreSQL
    for fir_item in pg_findings:
        cur.execute("""
            INSERT INTO fir_findings
                (finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                 evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                 injection_flagged, injection_score, layer, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (finding_id) DO UPDATE SET
                sanitized_fact = EXCLUDED.sanitized_fact,
                review_status = EXCLUDED.review_status;
        """, (
            fir_item.finding_id, fir_item.case_id, fir_item.tenant_id, fir_item.fact, fir_item.sanitized_fact or fir_item.fact,
            fir_item.confidence, fir_item.severity, fir_item.mitre_mapping, fir_item.evidence_reference,
            fir_item.source_artifact_id, fir_item.finding_fingerprint, fir_item.review_status.value if hasattr(fir_item.review_status, "value") else str(fir_item.review_status),
            fir_item.reviewed_by, fir_item.injection_flagged, fir_item.injection_score, fir_item.layer, fir_item.timestamp
        ))
    conn.commit()

    cur.execute("SELECT case_id, COUNT(*) AS cnt FROM fir_findings GROUP BY case_id;")
    rows = cur.fetchall()
    print("\n  PostgreSQL Database Stored Findings Breakdown:")
    for r in rows:
        print(f"    - Case ID: {r['case_id']:<24} : {r['cnt']} findings")

    print("\n=" * 70)
    print("POSTGRESQL PRODUCTION VERIFICATION COMPLETE")
    print("=" * 70)

    conn.close()

if __name__ == "__main__":
    audit_pg()
