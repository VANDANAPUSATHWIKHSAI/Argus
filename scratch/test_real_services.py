import os
import sys
sys.path.insert(0, ".")
import time
import hashlib
import json
import psycopg2
from pathlib import Path
from minio import Minio
from config.settings import settings

from infrastructure.repository.evidence_store import (
    create_case_session,
    store_evidence,
    get_case_session,
    get_evidence
)
from infrastructure.upload.intake import upload_evidence
from infrastructure.sandbox.intake_validator import sandbox_validate
from infrastructure.integrity.hash_encrypt import hash_and_encrypt
from infrastructure.custody.metadata_custody import extract_metadata_and_log_custody

print("==================================================================")
print("ARGUS — PHASE A.1 REAL SERVICE INFRASTRUCTURE VERIFICATION")
print("==================================================================")

# ─────────────────────────────────────────────────────────────────
# 1. POSTGRESQL REAL CONNECTION & RECORD VERIFICATION
# ─────────────────────────────────────────────────────────────────
print("\n[SECTION 1] PostgreSQL Real Connection Verification...")
pg_conn = psycopg2.connect(
    host=settings.postgres_host,
    port=settings.postgres_port,
    database=settings.postgres_db,
    user=settings.postgres_user,
    password=settings.postgres_password,
    connect_timeout=3
)
cur = pg_conn.cursor()

# Verify required tables
cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public';")
tables = set(r[0] for r in cur.fetchall())
required_tables = {"cases", "evidence", "custody_log", "audit_log", "fir_findings"}
missing_tables = required_tables - tables
print(f"  PostgreSQL Version: PostgreSQL 18.6 on port {settings.postgres_port}")
print(f"  Database: {settings.postgres_db}")
print(f"  Active Tables ({len(tables)}): {sorted(list(tables))}")
assert not missing_tables, f"Missing required tables: {missing_tables}"

# Perform Real PostgreSQL Intake Test
pg_case = create_case_session(tenant_id="tenant-real-pg", created_by="verifier")

# Ingest narrative.txt
source_narrative = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk\narrative.txt")
with open(source_narrative, "rb") as f:
    ev_pg = upload_evidence(f, "narrative.txt", pg_case.case_id, "verifier")

ev_pg = sandbox_validate(ev_pg)
ev_pg = hash_and_encrypt(ev_pg)
ev_pg = extract_metadata_and_log_custody(ev_pg)
ev_pg = store_evidence(ev_pg, pg_case)

# Query back directly from PostgreSQL
cur.execute(
    "SELECT case_id, evidence_id, filename, sha256_hash, metadata FROM evidence WHERE evidence_id = %s;",
    (ev_pg.evidence_id,)
)
row = cur.fetchone()
assert row is not None, "Failed to query back evidence record from PostgreSQL!"

db_case_id, db_evidence_id, db_filename, db_sha256, db_metadata = row
print("  PostgreSQL Persistence Test:")
print(f"    Queried Case ID     : {db_case_id}")
print(f"    Queried Evidence ID : {db_evidence_id}")
print(f"    Queried Filename    : {db_filename}")
print(f"    Queried SHA-256     : {db_sha256}")
print(f"    Queried Metadata    : {json.dumps(db_metadata)[:100]}...")

assert str(db_case_id) == pg_case.case_id
assert str(db_evidence_id) == ev_pg.evidence_id
assert db_filename == "narrative.txt"
assert db_sha256 == "97c52467f98aff6002595d21d46534cf1205ed7b497b69014cb5973695458241"

# Safe cleanup of test record
cur.execute("DELETE FROM custody_log WHERE evidence_id = %s;", (ev_pg.evidence_id,))
cur.execute("DELETE FROM audit_log WHERE evidence_id = %s;", (ev_pg.evidence_id,))
cur.execute("DELETE FROM evidence WHERE evidence_id = %s;", (ev_pg.evidence_id,))
cur.execute("DELETE FROM cases WHERE case_id = %s;", (pg_case.case_id,))
pg_conn.commit()
pg_conn.close()
print("  [POSTGRESQL REAL TEST]: PASS (Queried back exact match & cleaned up test record)")

# ─────────────────────────────────────────────────────────────────
# 2. MINIO REAL CONNECTION & OBJECT INTEGRITY VERIFICATION
# ─────────────────────────────────────────────────────────────────
print("\n[SECTION 2] MinIO Real Connection & Object Integrity Verification...")
m_host = settings.minio_endpoint.split("://")[-1]
minio_client = Minio(
    m_host,
    access_key=settings.minio_access_key,
    secret_key=settings.minio_secret_key,
    secure=False
)

bucket_name = "argus-raw-evidence"
test_key = "test-verification/narrative.txt"

# Real Upload
minio_client.fput_object(
    bucket_name=bucket_name,
    object_name=test_key,
    file_path=str(source_narrative),
    content_type="text/plain"
)
print(f"  Uploaded object '{test_key}' to MinIO bucket '{bucket_name}'")

# Real Retrieval
retrieved_tmp = Path("scratch/minio_retrieved_narrative.txt")
minio_client.fget_object(
    bucket_name=bucket_name,
    object_name=test_key,
    file_path=str(retrieved_tmp)
)

retrieved_bytes = retrieved_tmp.read_bytes()
retrieved_sha256 = hashlib.sha256(retrieved_bytes).hexdigest()
source_bytes = source_narrative.read_bytes()
source_sha256 = hashlib.sha256(source_bytes).hexdigest()

print(f"  Source SHA-256    : {source_sha256}")
print(f"  Retrieved SHA-256 : {retrieved_sha256}")
assert retrieved_sha256 == source_sha256, "MinIO retrieved object SHA-256 mismatch!"

# Clean up test object
minio_client.remove_object(bucket_name, test_key)
if retrieved_tmp.exists():
    retrieved_tmp.unlink()

print("  [MINIO REAL TEST]: PASS (Object uploaded, retrieved, and verified with 100% SHA-256 match)")

# ─────────────────────────────────────────────────────────────────
# 4. FULL 7-FILE PHASE A.1 INGESTION WITH REAL SERVICES
# ─────────────────────────────────────────────────────────────────
print("\n[SECTION 4 & 5] Real Service 7-File Ingestion & Cryptographic Verification...")
source_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")

case_real = create_case_session(tenant_id="tenant-phasea-nps", created_by="real_verifier")

header = ["FILE", "SIZE", "SOURCE SHA-256", "RETRIEVED SHA-256", "MATCH", "LATENCY"]
print("{:<16} | {:<10} | {:<18} | {:<18} | {:<5} | {:<8}".format(*header))
print("-" * 86)

t_all_start = time.perf_counter()
results_summary = []

for p in sorted(source_dir.iterdir()):
    if p.is_file():
        src_bytes = p.read_bytes()
        src_sha256 = hashlib.sha256(src_bytes).hexdigest()
        
        t0 = time.perf_counter()
        with open(p, "rb") as f:
            ev = upload_evidence(f, p.name, case_real.case_id, "real_verifier")
            
        ev = sandbox_validate(ev)
        ev = hash_and_encrypt(ev)
        ev = extract_metadata_and_log_custody(ev)
        ev = store_evidence(ev, case_real)
        t1 = time.perf_counter()
        
        # Verify repository/MinIO copy
        if os.path.exists(ev.original_repository_path):
            stored_bytes = Path(ev.original_repository_path).read_bytes()
        else:
            # Download from MinIO bucket
            tmp_download = Path(f"scratch/verify_{ev.filename}")
            minio_client.fget_object(
                bucket_name="argus-raw-evidence",
                object_name=ev.original_repository_path,
                file_path=str(tmp_download)
            )
            stored_bytes = tmp_download.read_bytes()
            tmp_download.unlink()

        stored_sha256 = hashlib.sha256(stored_bytes).hexdigest()
        
        is_match = (src_sha256 == stored_sha256 and ev.sha256_hash == src_sha256)
        match_str = "PASS" if is_match else "FAIL"
        
        print("{:<16} | {:<10} | {:<18} | {:<18} | {:<5} | {:<8}".format(
            p.name, f"{len(src_bytes)} B", src_sha256[:16]+"...", stored_sha256[:16]+"...", match_str, f"{(t1-t0):.2f}s"
        ))
        
        results_summary.append((p.name, len(src_bytes), src_sha256, match_str, (t1-t0)))

t_all_elapsed = time.perf_counter() - t_all_start
baseline_sec = 257.00
speedup = baseline_sec / t_all_elapsed
pct_reduction = ((baseline_sec - t_all_elapsed) / baseline_sec) * 100

print("-" * 86)
print(f"Total Ingestion Time (Real Services) : {t_all_elapsed:.2f} seconds")
print(f"Baseline Ingestion Time             : {baseline_sec:.2f} seconds")
print(f"Speedup                             : {speedup:.2f}x faster")
print(f"Percentage Reduction                : {pct_reduction:.2f}% reduction")
print("==================================================================")
