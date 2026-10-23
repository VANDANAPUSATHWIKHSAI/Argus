"""
Unit Tests for Task B — Evidence Integrity Verification API
============================================================
POST /evidence/{evidence_id}/verify

Validates:
1. Correct digest -> VERIFIED with digest_match=True.
2. Tampered/corrupted evidence bytes -> CORRUPTED with digest_match=False and failure reason.
3. Missing storage artifact -> UNVERIFIABLE.
4. Missing or malformed recorded SHA-256 digest -> UNVERIFIABLE.
5. Inaccessible storage / I/O failure -> ERROR.
6. Role-based authorization: forensic roles (admin, senior_analyst, auditor, analyst) authorized; viewer/guest rejected (403); unauthenticated (401).
7. Strict tenant isolation: cross-tenant verification rejected without leaking evidence existence.
8. RFC 3161 timestamp handling: verified independently from byte integrity; distinct fields.
9. Append-only cryptographic audit logging for all verification attempts.
10. Audit persistence failure handling (500 without false success).
11. Read-only evidence semantics: original file bytes remain unaltered.
12. Streaming SHA-256 computation in 64KB chunks for large files.
13. Safe, idempotent repeated verification.
"""

from __future__ import annotations

import os
import io
import json
import uuid
import hmac
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from api.main import app
from infrastructure.schemas import Evidence, EvidenceStatus, TimestampRecord
from infrastructure.repository.evidence_store import REPOSITORY_DIR
from api.routes.auth import get_current_user
from api.routes.evidence import EvidenceVerificationStatus
from infrastructure.audit_logger import verify_chain, get_audit_logger

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_env():
    """Ensure clean dependency overrides and test environment (isolated to local store)."""
    app.dependency_overrides.clear()
    with patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=False):
        yield
    app.dependency_overrides.clear()


def _setup_test_evidence(
    tenant_id: str = "tenant-verify-suite",
    case_id: Optional[str] = None,
    evidence_id: Optional[str] = None,
    content: bytes = b"EXACT_EVIDENCE_BYTES_FOR_CRYPTO_VERIFICATION_TEST_12345",
    sha256_override: Optional[str] = None,
    with_timestamp: bool = False,
    create_physical_file: bool = True
) -> tuple[Evidence, Path]:
    c_id = case_id or f"CASE-VER-{uuid.uuid4().hex[:8]}"
    e_id = evidence_id or str(uuid.uuid4())

    actual_hash = hashlib.sha256(content).hexdigest()
    recorded_hash = sha256_override if sha256_override is not None else actual_hash

    # Create directory structure in REPOSITORY_DIR
    repo_base = Path(REPOSITORY_DIR) / c_id / e_id
    orig_dir = repo_base / "original"
    orig_dir.mkdir(parents=True, exist_ok=True)
    file_path = orig_dir / "disk_image.raw"

    if create_physical_file:
        with open(file_path, "wb") as f:
            f.write(content)

    ts_rec = None
    rfc_ts_str = None
    if with_timestamp:
        import base64
        mock_tok = f"MOCK_RFC3161_TOKEN:{recorded_hash}:{e_id}".encode("utf-8")
        token_b64 = base64.b64encode(mock_tok).decode("utf-8")
        ts_rec = TimestampRecord(
            sha256_hash=recorded_hash,
            timestamp_token=token_b64,
            tsa_url="https://freetsa.org/tsr",
            timestamp_source="local_fallback",
            timestamp_verification_status="verified",
            evidence_id=e_id,
            case_id=c_id,
            tenant_id=tenant_id
        )
        rfc_ts_str = token_b64

    meta = {
        "tenant_id": tenant_id,
        "sha256": recorded_hash,
        "original_repository_path": str(file_path) if create_physical_file else None,
        "size_bytes": len(content)
    }
    if ts_rec:
        meta["timestamp_record"] = ts_rec.model_dump(mode="json")

    meta_file = repo_base / "metadata.json"
    meta_dict = {
        "evidence_id": e_id,
        "case_id": c_id,
        "tenant_id": tenant_id,
        "filename": "disk_image.raw",
        "file_path": str(file_path) if create_physical_file else "",
        "uploaded_by": "forensic_analyst",
        "upload_timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "stored",
        "sha256_hash": recorded_hash,
        "encrypted": False,
        "rfc3161_timestamp": rfc_ts_str,
        "original_repository_path": str(file_path) if create_physical_file else None,
        "repository_path": str(file_path) if create_physical_file else None,
        "metadata": meta,
        "timestamp_record": ts_rec.model_dump(mode="json") if ts_rec else None,
        "custody_log": []
    }
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_dict, f, indent=2)

    ev = Evidence(
        evidence_id=e_id,
        case_id=c_id,
        tenant_id=tenant_id,
        filename="disk_image.raw",
        file_path=str(file_path) if create_physical_file else "",
        uploaded_by="forensic_analyst",
        upload_timestamp=datetime.now(timezone.utc),
        status=EvidenceStatus.STORED,
        sha256_hash=recorded_hash,
        original_repository_path=str(file_path) if create_physical_file else None,
        repository_path=str(file_path) if create_physical_file else None,
        rfc3161_timestamp=rfc_ts_str,
        timestamp_record=ts_rec,
        metadata=meta
    )
    return ev, file_path


# 1. Correct digest returns VERIFIED with digest_match=True
def test_verify_correct_digest_success():
    ev, file_path = _setup_test_evidence()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "verifier_senior",
        "role": "senior_analyst",
        "email": "senior@argus.local"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["evidence_id"] == ev.evidence_id
    assert data["case_id"] == ev.case_id
    assert data["tenant_id"] == ev.tenant_id
    assert data["expected_sha256"] == ev.sha256_hash
    assert data["calculated_sha256"] == ev.sha256_hash
    assert data["verified_by"] == "verifier_senior"
    assert data["failure_reason"] is None


# 2. Corrupted evidence bytes return CORRUPTED with digest_match=False
def test_verify_corrupted_evidence_tamper_detected():
    content = b"ORIGINAL_AUTHENTIC_EVIDENCE_BYTES"
    ev, file_path = _setup_test_evidence(content=content)

    # Tamper with the evidence on disk (simulate bit-flip or malicious alteration)
    with open(file_path, "wb") as f:
        f.write(b"TAMPERED_MODIFIED_EVIDENCE_BYTES")

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "verifier_auditor",
        "role": "auditor"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "CORRUPTED"
    assert data["digest_match"] is False
    assert data["calculated_sha256"] != data["expected_sha256"]
    assert "mismatch" in data["failure_reason"].lower() or "differs" in data["failure_reason"].lower()


# 3. Missing storage artifact returns UNVERIFIABLE
def test_verify_missing_storage_file():
    ev, file_path = _setup_test_evidence(create_physical_file=False)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "analyst_bob",
        "role": "analyst"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "UNVERIFIABLE"
    assert data["digest_match"] is False
    assert "not found" in data["failure_reason"].lower()


# 4. Missing or malformed recorded expected digest returns UNVERIFIABLE
def test_verify_missing_expected_digest():
    ev, file_path = _setup_test_evidence(sha256_override="")
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "admin_alice",
        "role": "admin"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "UNVERIFIABLE"
    assert "sha-256" in data["failure_reason"].lower()


# 5. Inaccessible storage / I/O read failure returns ERROR
def test_verify_storage_io_read_error():
    ev, file_path = _setup_test_evidence()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_analyst",
        "role": "senior_analyst"
    }

    orig_open = open
    def mock_open(file, *args, **kwargs):
        if "disk_image.raw" in str(file):
            raise PermissionError("EACCES: storage volume access denied")
        return orig_open(file, *args, **kwargs)

    with patch("builtins.open", side_effect=mock_open):
        res = client.post(
            f"/evidence/{ev.evidence_id}/verify",
            headers={"X-Tenant-ID": ev.tenant_id}
        )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ERROR"
    assert data["digest_match"] is False
    assert "read failure" in data["failure_reason"].lower() or "eacces" in data["failure_reason"].lower()


# 6. Unauthenticated caller rejected (401)
def test_verify_unauthenticated_rejected():
    ev, _ = _setup_test_evidence()
    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 401


# 7. Unauthorized role (e.g. viewer / guest) rejected with 403
def test_verify_unauthorized_role_rejected():
    ev, _ = _setup_test_evidence()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "viewer_01",
        "role": "viewer"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()


# 8. Cross-tenant access rejection (fails closed without leaking evidence existence)
def test_verify_cross_tenant_access_rejected():
    ev, _ = _setup_test_evidence(tenant_id="tenant-acme-corp")
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_foreign",
        "role": "senior_analyst",
        "tenant_id": "tenant-evil-corp"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": "tenant-evil-corp"}
    )
    # Must fail closed with 404 (not found in tenant-evil-corp) or 403
    assert res.status_code in (403, 404)


# 9. RFC 3161 timestamp verified separately from byte integrity
def test_verify_rfc3161_timestamp_separate_fields():
    ev, _ = _setup_test_evidence(with_timestamp=True)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_ts",
        "role": "senior_analyst"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["timestamp_status"] in ("VERIFIED", "LOCAL_TIMESTAMP_ONLY")


# 10. Missing RFC 3161 timestamp represented as NOT_PRESENT (does not invalidate byte match)
def test_verify_without_timestamp_represented_as_not_present():
    ev, _ = _setup_test_evidence(with_timestamp=False)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["timestamp_status"] == "NOT_PRESENT"


# 11. Immutable append-only audit event created for verification attempts
def test_audit_event_logged_and_tamper_evident():
    tenant_id = f"tenant-audit-ver-{uuid.uuid4().hex[:6]}"
    ev, _ = _setup_test_evidence(tenant_id=tenant_id)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_auditor",
        "role": "senior_analyst"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": tenant_id}
    )
    assert res.status_code == 200

    # Verify audit chain integrity
    chain_ver = verify_chain(tenant_id)
    assert chain_ver["ok"] is True
    assert chain_ver["entries_verified"] >= 1


# 12. Audit persistence failure returns 500 and prevents false success claim
def test_audit_write_failure_raises_500():
    ev, _ = _setup_test_evidence()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # Simulate audit logger disk full / permission crash
    with patch("infrastructure.audit_logger.get_audit_logger") as mock_logger_getter:
        mock_logger = MagicMock()
        mock_logger.info.side_effect = RuntimeError("Audit disk volume full")
        mock_logger_getter.return_value = mock_logger

        res = client.post(
            f"/evidence/{ev.evidence_id}/verify",
            headers={"X-Tenant-ID": ev.tenant_id}
        )
    assert res.status_code == 500
    assert "audit integrity failure" in res.json()["detail"].lower()


# 13. Read-only verification preserves exact original evidence bytes
def test_evidence_bytes_immutable_read_only():
    content = b"PRECIOUS_FORENSIC_EVIDENCE_BYTES_MUST_NOT_BE_MODIFIED"
    ev, file_path = _setup_test_evidence(content=content)
    stat_before = file_path.stat()

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200
    stat_after = file_path.stat()

    # Byte contents and size must remain identical
    with open(file_path, "rb") as f:
        assert f.read() == content
    assert stat_after.st_size == stat_before.st_size


# 14. Large-file streaming verification in 64KB chunks
def test_large_file_streaming_verification():
    # 2 MB synthetic evidence file (exercises multiple 64KB chunks)
    large_content = b"A" * (2 * 1024 * 1024 + 12345)
    ev, file_path = _setup_test_evidence(content=large_content)

    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res = client.post(
        f"/evidence/{ev.evidence_id}/verify",
        headers={"X-Tenant-ID": ev.tenant_id}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["calculated_sha256"] == hashlib.sha256(large_content).hexdigest()


# 15. Repeated verification is safe and idempotent
def test_repeated_verification_idempotent():
    ev, _ = _setup_test_evidence()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res1 = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": ev.tenant_id})
    res2 = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": ev.tenant_id})

    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res1.json()["status"] == res2.json()["status"] == "VERIFIED"
    assert res1.json()["calculated_sha256"] == res2.json()["calculated_sha256"]
