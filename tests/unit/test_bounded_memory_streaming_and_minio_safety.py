"""
ARGUS Bounded-Memory Streaming and MinIO Resource Safety Test Suite
==================================================================
Validates:
1. Bounded-memory streaming verification using tracemalloc to guarantee
   O(1) memory consumption (< 500 KB peak allocation) across multi-megabyte objects.
2. Digest correctness across chunk boundaries (0-byte empty, 64KB-1, 64KB, 64KB+1, 128KB, 300KB).
3. Safe resource cleanup: response.close() and response.release_conn() executed in finally blocks
   even under stream interruption, chunk read exceptions, and close() failures.
4. Detection and explicit surfacing of metadata conflicts between MinIO object metadata
   and authoritative database acquisition records (no silent trust of conflicting sources).
5. Strict tenant, case, and evidence ID boundaries on MinIO object keys.
"""

import os
import uuid
import hmac
import hashlib
import tracemalloc
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from infrastructure.schemas import Evidence, EvidenceStatus
from api.routes.auth import get_current_user
from api.routes.evidence import EvidenceVerificationStatus

client = TestClient(app)


class MockChunkedStream:
    """Simulates a chunked MinIO HTTPResponse stream yielding 64KB blocks."""
    def __init__(self, data: bytes, chunk_size: int = 64 * 1024, fail_at_chunk: int = -1, fail_close: bool = False):
        self.data = data
        self.chunk_size = chunk_size
        self.offset = 0
        self.chunk_count = 0
        self.fail_at_chunk = fail_at_chunk
        self.fail_close = fail_close
        self.is_closed = False
        self.conn_released = False

    def read(self, amt: int = -1):
        if self.is_closed:
            raise ValueError("I/O operation on closed stream")
        self.chunk_count += 1
        if self.fail_at_chunk > 0 and self.chunk_count == self.fail_at_chunk:
            raise IOError("Simulated network drop / socket timeout during chunk read")
        if self.offset >= len(self.data):
            return b""
        chunk = self.data[self.offset : self.offset + amt]
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.is_closed = True
        if self.fail_close:
            raise OSError("Simulated socket error during stream close")

    def release_conn(self):
        self.conn_released = True


@pytest.fixture(autouse=True)
def clean_auth():
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_memory_auditor",
        "role": "senior_analyst"
    }
    yield
    app.dependency_overrides.clear()


def _make_minio_evidence(content: bytes, metadata_sha: str = None, file_size: int = None):
    ev_id = str(uuid.uuid4())
    case_id = f"CASE-MEM-{uuid.uuid4().hex[:6]}"
    tenant_id = f"tenant-mem-{uuid.uuid4().hex[:6]}"
    obj_key = f"{tenant_id}/{case_id}/{ev_id}/original/evidence.raw"
    expected_hash = hashlib.sha256(content).hexdigest()

    ev = Evidence(
        evidence_id=ev_id,
        case_id=case_id,
        tenant_id=tenant_id,
        filename="evidence.raw",
        file_path="minio://raw/" + obj_key,
        uploaded_by="stream_tester",
        status=EvidenceStatus.STORED,
        sha256_hash=expected_hash,
        repository_path=obj_key,
        metadata={"tenant_id": tenant_id, "sha256": expected_hash, "file_size": file_size or len(content)}
    )
    return ev, obj_key, expected_hash, tenant_id


def test_bounded_memory_streaming_verification():
    """
    PROVES mathematically that the MinIO verification implementation streams in bounded
    memory and NEVER loads the entire multi-megabyte object into RAM.
    Measures peak memory using tracemalloc.
    """
    # 10 MB payload
    payload_size = 10 * 1024 * 1024
    chunk_pattern = b"0123456789ABCDEF" * 4096  # 64 KB pattern
    full_content = chunk_pattern * (payload_size // len(chunk_pattern))

    ev, obj_key, expected_hash, tenant_id = _make_minio_evidence(full_content)

    mock_stream = MockChunkedStream(full_content)

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_minio:

        mock_stat = MagicMock()
        mock_stat.metadata = {"sha256": expected_hash}
        mock_stat.size = len(full_content)
        mock_minio.stat_object.return_value = mock_stat
        mock_minio.get_object.return_value = mock_stream

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": tenant_id})

        snapshot_after = tracemalloc.take_snapshot()
        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["calculated_sha256"] == expected_hash

    # PROOF: Peak memory allocated during the 10 MB stream MUST stay bounded (< 500 KB)
    # If the file were loaded into memory, peak_ram would exceed 10 MB.
    assert peak_ram < 500 * 1024, f"Memory unbounded: peak allocation was {peak_ram / 1024:.2f} KB"
    assert mock_stream.is_closed is True
    assert mock_stream.conn_released is True


@pytest.mark.parametrize("payload_size,desc", [
    (0, "0-byte empty artifact"),
    (65535, "64KB - 1 byte boundary"),
    (65536, "Exact 64KB chunk boundary"),
    (65537, "64KB + 1 byte boundary"),
    (131072, "Exact 128KB (2 chunk) boundary"),
    (300000, "Fractional multi-chunk boundary")
])
def test_digest_correctness_across_chunk_boundaries(payload_size, desc):
    """
    Validates SHA-256 calculation correctness across exact 64KB chunk boundaries,
    fractional chunks, and 0-byte empty artifacts.
    """
    content = os.urandom(payload_size) if payload_size > 0 else b""
    expected_hash = hashlib.sha256(content).hexdigest()

    ev, obj_key, _, tenant_id = _make_minio_evidence(content)
    mock_stream = MockChunkedStream(content)

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_minio:

        mock_stat = MagicMock()
        mock_stat.metadata = {"sha256": expected_hash}
        mock_stat.size = len(content)
        mock_minio.stat_object.return_value = mock_stat
        mock_minio.get_object.return_value = mock_stream

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "VERIFIED"
    assert data["digest_match"] is True
    assert data["calculated_sha256"] == expected_hash
    if payload_size == 0:
        # Standard empty SHA-256 hash
        assert data["calculated_sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_interrupted_stream_cleanup_guarantee_and_error_status():
    """
    Simulates a streaming interruption / socket drop on chunk 2.
    Guarantees:
    - response.close() and response.release_conn() ARE called in finally.
    - Verification status is ERROR.
    - digest_match is False and calculated_sha256 is None (no partial hash reported as success).
    - Failure reason describes the stream interruption.
    """
    content = b"CHUNKS_OF_FORENSIC_BYTES" * 8000  # ~192 KB (3 chunks)
    ev, obj_key, expected_hash, tenant_id = _make_minio_evidence(content)

    mock_stream = MockChunkedStream(content, fail_at_chunk=2)

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_minio:

        mock_stat = MagicMock()
        mock_stat.metadata = {"sha256": expected_hash}
        mock_stat.size = len(content)
        mock_minio.stat_object.return_value = mock_stat
        mock_minio.get_object.return_value = mock_stream

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ERROR"
    assert data["digest_match"] is False
    assert data["calculated_sha256"] is None
    assert "Streaming read was interrupted" in data["failure_reason"] or "I/O read failure" in data["failure_reason"]

    # Resource safety verification: connections must be cleaned up in finally
    assert mock_stream.is_closed is True
    assert mock_stream.conn_released is True


def test_cleanup_failure_resilience_releases_connection():
    """
    Simulates an exception during response.close().
    Guarantees that response.release_conn() is still executed and does not raise 500.
    """
    content = b"FORENSIC_PAYLOAD_SAFE" * 500
    ev, obj_key, expected_hash, tenant_id = _make_minio_evidence(content)

    mock_stream = MockChunkedStream(content, fail_close=True)

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_minio:

        mock_stat = MagicMock()
        mock_stat.metadata = {"sha256": expected_hash}
        mock_stat.size = len(content)
        mock_minio.stat_object.return_value = mock_stat
        mock_minio.get_object.return_value = mock_stream

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    assert mock_stream.is_closed is True
    assert mock_stream.conn_released is True


def test_metadata_conflict_surfaces_corrupted_explicitly():
    """
    When MinIO object metadata (x-amz-meta-sha256) conflicts with the authoritative
    database recorded acquisition digest, the system surfaces CORRUPTED with an explicit
    failure reason rather than silently trusting one inconsistent source.
    """
    content = b"LEGITIMATE_BYTES"
    ev, obj_key, expected_hash, tenant_id = _make_minio_evidence(content)

    conflicting_metadata_hash = hashlib.sha256(b"CONFLICTING_TAMPERED_METADATA").hexdigest()

    mock_stream = MockChunkedStream(content)

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True), \
         patch("databases.minio_client.minio_store.client") as mock_minio:

        mock_stat = MagicMock()
        # MinIO metadata reports a different SHA-256 than the DB seal
        mock_stat.metadata = {"sha256": conflicting_metadata_hash}
        mock_stat.size = len(content)
        mock_minio.stat_object.return_value = mock_stat
        mock_minio.get_object.return_value = mock_stream

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CORRUPTED"
    assert data["digest_match"] is False
    assert "Metadata integrity conflict" in data["failure_reason"]
    assert conflicting_metadata_hash in data["failure_reason"]


def test_object_key_security_boundary_validation():
    """
    Validates that if a MinIO object key lacks the caller's tenant_id, case_id,
    or evidence_id in its path, it fails closed with UNVERIFIABLE without streaming.
    """
    content = b"TAMPERED_PATH_BYTES"
    ev, _, expected_hash, tenant_id = _make_minio_evidence(content)

    # Tampered key pointing to another tenant or case
    ev.original_repository_path = "different-tenant/other-case/fake-id/original/evil.bin"
    ev.repository_path = ev.original_repository_path

    with patch("api.routes.evidence.get_evidence", return_value=ev), \
         patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=True):

        res = client.post(f"/evidence/{ev.evidence_id}/verify", headers={"X-Tenant-ID": tenant_id})

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UNVERIFIABLE"
    assert "Security boundary or metadata mismatch" in data["failure_reason"]
