"""
Live Integration Tests for Adversarial Security Audit
======================================================
Exercises LIVE MinIO S3 object storage (port 9000) and LIVE PostgreSQL (port 5433).
Never mocked. Confirms production readiness.
"""

import os
import uuid
import hashlib
import psycopg2
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from databases.minio_client import minio_store, S3Error
from config.settings import settings
from infrastructure.schemas import Evidence, EvidenceStatus
from infrastructure.repository.evidence_store import _should_attempt_postgres, _should_attempt_minio
from api.routes.auth import get_current_user

client = TestClient(app)


@pytest.fixture(scope="module")
def check_live_services():
    """Verify live PostgreSQL and live MinIO are up, skipping if either is unavailable."""
    if not _should_attempt_postgres():
        pytest.skip("Live PostgreSQL service unavailable on port 5433")
    if not _should_attempt_minio():
        pytest.skip("Live MinIO service unavailable on port 9000")


@pytest.fixture(autouse=True)
def clean_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def test_live_minio_and_postgres_end_to_end_verification(check_live_services):
    """
    Live End-to-End Production Storage Test:
    1. Generates 512KB binary evidence.
    2. Inserts canonical UUID evidence record directly into live PostgreSQL `evidence` table.
    3. Streams and uploads object directly to live MinIO bucket `argus-raw-evidence`.
    4. Executes POST /evidence/{evidence_id}/verify live without mocks.
    5. Asserts VERIFIED status, correct SHA-256 computation, and live audit record generation.
    6. Tamper check: overwrites object in MinIO with corrupted bytes, calls verify endpoint, asserts CORRUPTED.
    7. Cleans up PostgreSQL row and MinIO object.
    """
    tenant_id = f"tenant-live-{uuid.uuid4().hex[:6]}"
    case_id = f"CASE-LIVE-{uuid.uuid4().hex[:6]}"
    evidence_id = str(uuid.uuid4())
    raw_content = b"LIVE_FORENSIC_EVIDENCE_PRODUCTION_TEST_PAYLOAD_" * 10000  # ~470 KB
    sha256_hash = hashlib.sha256(raw_content).hexdigest()
    filename = "live_memory_dump.raw"
    obj_key = f"{tenant_id}/{case_id}/{evidence_id}/original/{filename}"

    # 1. Connect to Live PostgreSQL and insert Case and Evidence records
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password
    )
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO cases (case_id, tenant_id, created_by, status, name)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (case_id) DO NOTHING;
            """,
            (case_id, tenant_id, "auditor_live", "open", "Live Audit Case")
        )
        cur.execute(
            """
            INSERT INTO evidence (evidence_id, case_id, filename, uploaded_by, upload_timestamp, status, sha256_hash, repository_path, metadata)
            VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s, %s);
            """,
            (
                evidence_id,
                case_id,
                filename,
                "auditor_live",
                "stored",
                sha256_hash,
                obj_key,
                '{"tenant_id": "' + tenant_id + '", "storage_backend": "minio"}'
            )
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    # 2. Upload to Live MinIO
    import io
    minio_store.ensure_buckets()
    minio_store.client.put_object(
        bucket_name=minio_store.RAW_BUCKET,
        object_name=obj_key,
        data=io.BytesIO(raw_content),
        length=len(raw_content),
        content_type="application/octet-stream",
        metadata={"tenant_id": tenant_id, "sha256": sha256_hash}
    )

    try:
        # 3. Call Live Verification Endpoint
        app.dependency_overrides[get_current_user] = lambda: {
            "id": "live_senior_analyst",
            "role": "senior_analyst",
            "tenant_id": tenant_id
        }

        res = client.post(
            f"/evidence/{evidence_id}/verify",
            headers={"X-Tenant-ID": tenant_id}
        )

        assert res.status_code == 200, res.text
        data = res.json()
        assert data["status"] == "VERIFIED"
        assert data["digest_match"] is True
        assert data["calculated_sha256"] == sha256_hash
        assert data["expected_sha256"] == sha256_hash
        assert data["audit_chain_status"] == "VERIFIED"

        # 4. Adversarial Tamper Verification: Modify object in MinIO and re-verify
        tampered_content = b"TAMPERED_ADVERSARIAL_INJECTION" + raw_content[31:]
        minio_store.client.put_object(
            bucket_name=minio_store.RAW_BUCKET,
            object_name=obj_key,
            data=io.BytesIO(tampered_content),
            length=len(tampered_content),
            content_type="application/octet-stream"
        )

        res_tampered = client.post(
            f"/evidence/{evidence_id}/verify",
            headers={"X-Tenant-ID": tenant_id}
        )

        assert res_tampered.status_code == 200
        data_tampered = res_tampered.json()
        assert data_tampered["status"] == "CORRUPTED"
        assert data_tampered["digest_match"] is False
        assert data_tampered["calculated_sha256"] != sha256_hash
        assert "Cryptographic integrity failure" in data_tampered["failure_reason"]

    finally:
        # Cleanup live MinIO object
        try:
            minio_store.client.remove_object(minio_store.RAW_BUCKET, obj_key)
        except Exception:
            pass

        # Cleanup live PostgreSQL rows
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password
        )
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM evidence WHERE evidence_id = %s;", (evidence_id,))
            cur.execute("DELETE FROM cases WHERE case_id = %s;", (case_id,))
            conn.commit()
        finally:
            cur.close()
            conn.close()
