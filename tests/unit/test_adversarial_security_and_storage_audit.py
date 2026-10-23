"""
Adversarial Security Audit and Production Storage Validation Test Suite
=======================================================================
Covers:
- Audit 1: Review override policies, hierarchical role checks, justification enforcement,
           concurrency race elimination, and audit persistence failure rollback.
- Audit 2: Authoritative evidence selection, fail-closed 0-row DB handling, ID format
           validation, and strict tenant/case isolation without silent local fallback.
- Audit 3: MinIO/S3 streaming verification, bounded chunk memory safety, tamper detection,
           missing object handling, and no-fallback-to-local when MinIO is configured.
- Audit 4: Verification and audit-state consistency, separation of digest/timestamp/audit
           statuses, and concurrent verification safety.
- Audit 5: Canonical UUID identifier contract and schema safety.
"""

import os
import uuid
import hmac
import shutil
import hashlib
import threading
import concurrent.futures
from pathlib import Path
from typing import Optional
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from minio.error import S3Error

from api.main import app
from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository
from infrastructure.schemas import Evidence, EvidenceStatus, TimestampRecord
from infrastructure.repository.evidence_store import REPOSITORY_DIR
from api.routes.auth import get_current_user
from api.routes.evidence import EvidenceVerificationStatus

client = TestClient(app)
_repo = FIRRepository()


@pytest.fixture(autouse=True)
def clean_test_env():
    """Ensure clean dependency overrides and test environment."""
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


def _make_test_finding(
    finding_id: Optional[str] = None,
    case_id: str = "CASE-AUDIT-01",
    tenant_id: str = "tenant-audit",
    reviewed_by: Optional[str] = None,
    review_status: ReviewStatus = ReviewStatus.PENDING_REVIEW
) -> FIRFinding:
    f_id = finding_id or f"fnd-{uuid.uuid4().hex[:8]}"
    finding = FIRFinding(
        finding_id=f_id,
        case_id=case_id,
        tenant_id=tenant_id,
        fact="Adversarial persistence via suspicious scheduled task",
        confidence=0.95,
        severity="high",
        evidence_reference=["ev-ref-1"],
        layer="test",
        review_status=review_status,
        reviewed_by=reviewed_by
    )
    _repo.findings[f_id] = finding
    return finding


def _make_test_evidence(
    tenant_id: str = "tenant-audit",
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    content: bytes = b"AUTHORITATIVE_TEST_EVIDENCE_BYTES_SHA256"
) -> tuple[Evidence, Path]:
    c_id = case_id or f"CASE-EV-{uuid.uuid4().hex[:8]}"
    e_id = evidence_id or str(uuid.uuid4())
    actual_hash = hashlib.sha256(content).hexdigest()

    repo_base = Path(REPOSITORY_DIR) / c_id / e_id
    orig_dir = repo_base / "original"
    orig_dir.mkdir(parents=True, exist_ok=True)
    file_path = orig_dir / "artifact.bin"
    with open(file_path, "wb") as f:
        f.write(content)

    meta_dict = {
        "evidence_id": e_id,
        "case_id": c_id,
        "tenant_id": tenant_id,
        "filename": "artifact.bin",
        "file_path": str(file_path),
        "uploaded_by": "auditor",
        "status": "stored",
        "sha256_hash": actual_hash,
        "encrypted": False,
        "original_repository_path": str(file_path),
        "repository_path": str(file_path),
        "metadata": {"tenant_id": tenant_id, "sha256": actual_hash, "size_bytes": len(content)}
    }
    with open(repo_base / "metadata.json", "w", encoding="utf-8") as f:
        import json
        json.dump(meta_dict, f)

    return Evidence(**meta_dict), file_path


# =============================================================================
# AUDIT 1: Review Override, Hierarchical Roles, Justification & Rollback Tests
# =============================================================================

def test_override_requires_non_empty_justification_notes():
    """force=True must be rejected with 400 if notes justification is omitted or empty."""
    finding = _make_test_finding(
        review_status=ReviewStatus.ANALYST_CONFIRMED,
        reviewed_by="senior_01"
    )
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_02",
        "role": "senior_analyst"
    }

    # Pass force=True but empty notes
    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_rejected", "force": True, "notes": "   "},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 400
    assert "justification" in res.json()["detail"].lower()


def test_hierarchical_override_protection():
    """A senior analyst cannot override a review decision made by an administrator."""
    finding = _make_test_finding(
        review_status=ReviewStatus.ANALYST_CONFIRMED,
        reviewed_by="admin_root"
    )
    # Caller is senior_analyst trying to force override admin's decision
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_analyst_01",
        "role": "senior_analyst"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_rejected", "force": True, "notes": "I disagree with admin"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 403
    assert "cannot override" in res.json()["detail"].lower()


def test_audit_write_failure_rolls_back_review_and_returns_500():
    """A failed audit write rolls back the finding to its previous state and returns 500."""
    finding = _make_test_finding(
        review_status=ReviewStatus.PENDING_REVIEW,
        reviewed_by=None
    )
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    with patch("infrastructure.audit_logger.get_audit_logger") as mock_logger_getter:
        mock_logger = MagicMock()
        mock_logger.info.side_effect = IOError("Disk full: cannot write audit ledger")
        mock_logger_getter.return_value = mock_logger

        res = client.put(
            f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
            json={"status": "analyst_confirmed", "notes": "Valid finding"},
            headers={"X-Tenant-ID": finding.tenant_id}
        )

    # Must fail with 500
    assert res.status_code == 500
    assert "audit persistence failure" in res.json()["detail"].lower()

    # The finding MUST have been rolled back to PENDING_REVIEW
    updated = _repo.findings[finding.finding_id]
    assert updated.review_status == ReviewStatus.PENDING_REVIEW
    assert updated.reviewed_by is None


def test_concurrent_reviews_eliminated_by_thread_lock():
    """Concurrent review requests on an unreviewed finding cannot both pass without force=True."""
    finding = _make_test_finding(review_status=ReviewStatus.PENDING_REVIEW)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_concurrent",
        "role": "senior_analyst"
    }

    results = []
    def make_review(status_val):
        r = client.put(
            f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
            json={"status": status_val, "notes": f"Decision: {status_val}"},
            headers={"X-Tenant-ID": finding.tenant_id}
        )
        results.append(r.status_code)

    threads = [
        threading.Thread(target=make_review, args=("analyst_confirmed",)),
        threading.Thread(target=make_review, args=("analyst_rejected",))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one request must succeed (200), and the second must be rejected (409 Conflict)
    assert 200 in results
    assert 409 in results


# =============================================================================
# AUDIT 2: Authoritative Database Selection & Fail-Closed Fallback Tests
# =============================================================================

def test_database_empty_result_does_not_fall_back_to_local_disk():
    """
    When PostgreSQL is reachable, a 0-row database lookup must fail closed (return 404).
    It must NOT fall back to local disk and pick up an unauthenticated or orphaned artifact.
    """
    # Create an artifact only on local disk (not in PostgreSQL)
    ev, _ = _make_test_evidence()

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # Simulate reachable PostgreSQL that returns None (0 rows)
    with patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=True), \
         patch("psycopg2.connect") as mock_conn:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None  # 0 rows in DB
        mock_conn.return_value.cursor.return_value = mock_cursor

        res = client.post(
            f"/evidence/{ev.evidence_id}/verify",
            headers={"X-Tenant-ID": ev.tenant_id}
        )

    # Must return 404 Not Found, NOT 200 via local fallback!
    assert res.status_code == 404
    assert f"Evidence '{ev.evidence_id}' not found" in res.json()["detail"]


def test_postgres_uuid_format_mismatch_fails_closed():
    """
    If PostgreSQL encounters an ID format error (e.g. invalid UUID representation),
    it must fail closed (return 404), never silently fallback to an unrelated local file.
    """
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # Pass an ID that causes PostgreSQL syntax error
    with patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=True), \
         patch("psycopg2.connect") as mock_conn:
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("invalid input syntax for type uuid: 'invalid-id-xyz'")
        mock_conn.return_value.cursor.return_value = mock_cursor

        res = client.post(
            "/evidence/invalid-id-xyz/verify",
            headers={"X-Tenant-ID": "tenant-audit"}
        )

    assert res.status_code == 404


def test_cross_tenant_local_file_strictly_isolated():
    """Local fallback must never return or verify an artifact belonging to another tenant."""
    ev, _ = _make_test_evidence(tenant_id="tenant-alpha")

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_beta",
        "role": "senior_analyst",
        "tenant_id": "tenant-beta"
    }

    with patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=False):
        res = client.post(
            f"/evidence/{ev.evidence_id}/verify",
            headers={"X-Tenant-ID": "tenant-beta"}
        )

    # Cross-tenant must fail closed with 404
    assert res.status_code == 404


# =============================================================================
# AUDIT 3: Production MinIO/S3 Streaming Verification Tests
# =============================================================================

def test_minio_streaming_verification_success():
    """
    When MinIO is configured, stream bytes in bounded 64KB chunks and verify SHA-256
    without loading entire object into memory.
    """
    content = b"STREAMING_MINIO_EVIDENCE_PAYLOAD_CHUNKED_SAFE" * 2000
    expected_hash = hashlib.sha256(content).hexdigest()
    ev_id = str(uuid.uuid4())
    case_id = "CASE-MINIO-01"
    tenant_id = "tenant-minio"
    obj_key = f"{tenant_id}/{case_id}/{ev_id}/original/evidence.raw"

    ev = Evidence(
        evidence_id=ev_id,
        case_id=case_id,
        tenant_id=tenant_id,
        filename="evidence.raw",
        file_path="minio://raw/" + obj_key,
        uploaded_by="ingestion_pipeline",
        status=EvidenceStatus.STORED,
        sha256_hash=expected_hash,
        repository_path=obj_key,
        original_repository_path=obj_key,
        metadata={"tenant_id": tenant_id, "sha256": expected_hash}
    )

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # Mock MinIO streaming client
    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_client:

        mock_stat = MagicMock()
        mock_stat.metadata = {"sha256": expected_hash}
        mock_client.stat_object.return_value = mock_stat

        # Simulate streaming response with bounded chunks
        import io
        stream_chunks = [content[:32768], content[32768:]]
        mock_response = MagicMock()
        mock_response.read.side_effect = stream_chunks + [b""]
        mock_client.get_object.return_value = mock_response

        res = client.post(f"/evidence/{ev_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["calculated_sha256"] == expected_hash
    assert data["expected_sha256"] == expected_hash
    assert mock_response.read.call_count >= 2  # Proves bounded chunk streaming


def test_minio_tamper_detection_returns_corrupted():
    """When MinIO object bytes produce a different SHA-256, status must be CORRUPTED."""
    original_hash = hashlib.sha256(b"AUTHENTIC_EVIDENCE").hexdigest()
    tampered_bytes = b"TAMPERED_MALICIOUS_EVIDENCE"
    ev_id = str(uuid.uuid4())
    case_id = "CASE-MINIO-02"
    tenant_id = "tenant-minio"
    obj_key = f"{tenant_id}/{case_id}/{ev_id}/original/evidence.raw"

    ev = Evidence(
        evidence_id=ev_id,
        case_id=case_id,
        tenant_id=tenant_id,
        filename="evidence.raw",
        file_path="minio://raw/" + obj_key,
        uploaded_by="ingestion",
        status=EvidenceStatus.STORED,
        sha256_hash=original_hash,
        repository_path=obj_key,
        metadata={"tenant_id": tenant_id, "sha256": original_hash}
    )

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_client:

        mock_stat = MagicMock()
        mock_stat.metadata = {}
        mock_client.stat_object.return_value = mock_stat

        mock_response = MagicMock()
        mock_response.read.side_effect = [tampered_bytes, b""]
        mock_client.get_object.return_value = mock_response

        res = client.post(f"/evidence/{ev_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CORRUPTED"
    assert data["digest_match"] is False
    assert "Cryptographic integrity failure" in data["failure_reason"]


def test_minio_offline_returns_error_without_silent_local_fallback():
    """
    If MinIO is configured for the evidence artifact but the MinIO service is offline,
    it must return ERROR, never fall back to a local copy and report success.
    """
    ev_id = str(uuid.uuid4())
    case_id = "CASE-MINIO-03"
    tenant_id = "tenant-minio"
    obj_key = f"{tenant_id}/{case_id}/{ev_id}/original/evidence.raw"

    ev = Evidence(
        evidence_id=ev_id,
        case_id=case_id,
        tenant_id=tenant_id,
        filename="evidence.raw",
        file_path="minio://" + obj_key,
        uploaded_by="ingestion",
        status=EvidenceStatus.STORED,
        sha256_hash=hashlib.sha256(b"REAL").hexdigest(),
        repository_path=obj_key,
        metadata={"tenant_id": tenant_id, "sha256": hashlib.sha256(b"REAL").hexdigest()}
    )

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # Simulate MinIO unreachable
    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=False):

        res = client.post(f"/evidence/{ev_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ERROR"
    assert "MinIO object storage is offline" in data["failure_reason"]


# =============================================================================
# AUDIT 4: Verification and Audit-State Consistency Tests
# =============================================================================

def test_digest_match_with_timestamp_failure_independent():
    """
    A matching digest does not imply trusted RFC 3161 timestamp verification.
    The response must keep digest_match and timestamp_status completely independent.
    """
    content = b"EVIDENCE_WITH_CORRUPT_TIMESTAMP_TOKEN"
    ev, _ = _make_test_evidence(content=content)
    ev.rfc3161_timestamp = "INVALID_CORRUPT_BASE64_TOKEN"
    ev.timestamp_record = TimestampRecord(
        sha256_hash=ev.sha256_hash,
        timestamp_token="INVALID_TOKEN",
        tsa_url="https://freetsa.org/tsr",
        timestamp_source="freetsa",
        timestamp_verification_status="failed",
        evidence_id=ev.evidence_id,
        case_id=ev.case_id,
        tenant_id=ev.tenant_id
    )

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=False), \
         patch("infrastructure.integrity.timestamp_service.verify_rfc3161_timestamp", return_value=False):

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": ev.tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "VERIFIED"       # Byte digest matches
    assert data["digest_match"] is True       # Digest match is True
    assert data["timestamp_status"] == "FAILED" # Timestamp status is FAILED (Independent!)
    assert data["audit_chain_status"] == "VERIFIED"


def test_concurrent_verification_thread_safe():
    """Multiple concurrent verification requests do not corrupt metadata or custody log."""
    ev, _ = _make_test_evidence()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    statuses = []
    def run_verify():
        r = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": ev.tenant_id})
        statuses.append(r.status_code)

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=False):
        threads = [threading.Thread(target=run_verify) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert all(s == 200 for s in statuses)
    assert len(statuses) == 5
    assert len(ev.custody_log) == 5


# =============================================================================
# AUDIT 5: Canonical UUID Schema Contract Validation Tests
# =============================================================================

def test_evidence_model_generates_canonical_rfc4122_uuid():
    """Newly instantiated Evidence objects must generate valid RFC 4122 UUID identifiers."""
    ev = Evidence(
        case_id="CASE-UUID-01",
        filename="disk.raw",
        file_path="/tmp/disk.raw",
        uploaded_by="analyst"
    )

    # Must be valid UUID parseable by python uuid.UUID
    parsed = uuid.UUID(ev.evidence_id)
    assert str(parsed) == ev.evidence_id
    assert not ev.evidence_id.startswith("e-")
