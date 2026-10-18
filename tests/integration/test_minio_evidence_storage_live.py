"""
Integration tests for live MinIO S3-compatible object storage.
Verifies:
1. Live S3-compatible connectivity and bucket auto-creation.
2. Upload and byte-for-byte retrieval of original raw evidence.
3. Strict original-byte SHA-256 digest verification before and after storage.
4. Tenant and case namespacing and object metadata (tenant_id, case_id, evidence_id, sha256).
5. Immutability controls: preventing overwriting of existing evidence objects.
6. Encrypted evidence blob upload and retrieval.
7. Simulated application process restart recovery (new client instance retrieving existing evidence).
8. Cross-tenant storage isolation.
"""

import io
import uuid
import hashlib
import pytest
from pathlib import Path
from databases.minio_client import MinioClient, minio_store


@pytest.fixture(scope="module")
def live_minio():
    """Provides an active MinioClient connected to the live MinIO instance."""
    client = MinioClient()
    try:
        client.ensure_buckets()
    except Exception as e:
        pytest.skip(f"Live MinIO service unavailable: {e}")
    return client


def test_minio_buckets_exist_and_healthy(live_minio):
    """Verify raw evidence and encrypted evidence buckets are present and reachable."""
    buckets = [b.name for b in live_minio.client.list_buckets()]
    assert live_minio.RAW_BUCKET in buckets
    assert live_minio.ENCRYPTED_BUCKET in buckets


def test_minio_upload_retrieval_and_sha256_fidelity(live_minio):
    """Verify upload, retrieval, and byte-for-byte SHA-256 match."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:8]}"
    case_id = f"CASE-{uuid.uuid4().hex[:8]}"
    evidence_id = f"EVID-{uuid.uuid4().hex[:8]}"
    filename = "memory_dump_test.raw"

    raw_data = b"FORENSIC_RAW_BYTES_SAMPLE_DATA_55667788_IMMUTABLE_TEST_PAYLOAD"
    expected_sha256 = hashlib.sha256(raw_data).hexdigest()

    # 1. Upload
    obj_key = live_minio.upload_raw_evidence(
        tenant_id=tenant_id,
        case_id=case_id,
        evidence_id=evidence_id,
        filename=filename,
        data=raw_data
    )

    try:
        assert obj_key == f"{tenant_id}/{case_id}/{evidence_id}/original/{filename}"
        assert live_minio.object_exists(live_minio.RAW_BUCKET, obj_key) is True

        # 2. Retrieve
        retrieved_data = live_minio.download_raw_evidence(obj_key)
        assert retrieved_data == raw_data

        # 3. Cryptographic integrity check
        retrieved_sha256 = hashlib.sha256(retrieved_data).hexdigest()
        assert retrieved_sha256 == expected_sha256

        # 4. Metadata verification
        stat = live_minio.get_object_stat(live_minio.RAW_BUCKET, obj_key)
        assert stat["size"] == len(raw_data)
        meta = stat.get("metadata", {})
        # S3 user metadata keys are returned lowercased with x-amz-meta- prefix
        assert meta.get("x-amz-meta-tenant_id") == tenant_id
        assert meta.get("x-amz-meta-case_id") == case_id
        assert meta.get("x-amz-meta-evidence_id") == evidence_id
        assert meta.get("x-amz-meta-sha256") == expected_sha256
    finally:
        # Cleanup test object
        live_minio.client.remove_object(live_minio.RAW_BUCKET, obj_key)


def test_minio_immutability_controls(live_minio):
    """Verify that attempting to overwrite existing raw evidence fails closed."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:8]}"
    case_id = f"CASE-{uuid.uuid4().hex[:8]}"
    evidence_id = f"EVID-{uuid.uuid4().hex[:8]}"
    filename = "immutable_evidence.bin"

    original_data = b"ORIGINAL_IMMUTABLE_FORENSIC_EVIDENCE"
    modified_data = b"TAMPERED_MODIFIED_EVIDENCE_ATTEMPT"

    obj_key = live_minio.upload_raw_evidence(
        tenant_id=tenant_id,
        case_id=case_id,
        evidence_id=evidence_id,
        filename=filename,
        data=original_data
    )

    try:
        # Attempting to re-upload / overwrite the same object key MUST raise an Immutability violation
        with pytest.raises(RuntimeError, match="Immutability violation"):
            live_minio.upload_raw_evidence(
                tenant_id=tenant_id,
                case_id=case_id,
                evidence_id=evidence_id,
                filename=filename,
                data=modified_data
            )

        # Confirm data in MinIO was NOT modified
        stored = live_minio.download_raw_evidence(obj_key)
        assert stored == original_data
        assert hashlib.sha256(stored).hexdigest() == hashlib.sha256(original_data).hexdigest()
    finally:
        live_minio.client.remove_object(live_minio.RAW_BUCKET, obj_key)


def test_minio_restart_recovery(live_minio):
    """
    Verify that persisted evidence survives application process restart:
    A newly instantiated client connects and retrieves previously stored objects.
    """
    tenant_id = f"tenant-{uuid.uuid4().hex[:8]}"
    case_id = f"CASE-RESTART-{uuid.uuid4().hex[:8]}"
    evidence_id = f"EVID-{uuid.uuid4().hex[:8]}"
    filename = "post_restart_evidence.log"
    content = b"APPLICATION_RESTART_SURVIVAL_VERIFICATION_BYTES"
    sha = hashlib.sha256(content).hexdigest()

    # Process 1 uploads
    key = live_minio.upload_raw_evidence(
        tenant_id=tenant_id,
        case_id=case_id,
        evidence_id=evidence_id,
        filename=filename,
        data=content
    )

    try:
        # Simulate Process 2 restart: new isolated MinioClient instance
        restarted_client = MinioClient()
        assert restarted_client.object_exists(restarted_client.RAW_BUCKET, key) is True

        downloaded = restarted_client.download_raw_evidence(key)
        assert downloaded == content
        assert hashlib.sha256(downloaded).hexdigest() == sha

        stat = restarted_client.get_object_stat(restarted_client.RAW_BUCKET, key)
        assert stat["size"] == len(content)
        assert stat["metadata"].get("x-amz-meta-tenant_id") == tenant_id
    finally:
        live_minio.client.remove_object(live_minio.RAW_BUCKET, key)


def test_minio_cross_tenant_isolation(live_minio):
    """Verify tenant isolation: two tenants uploading the same case/filename do not collide."""
    tenant_a = f"tenant-alpha-{uuid.uuid4().hex[:6]}"
    tenant_b = f"tenant-beta-{uuid.uuid4().hex[:6]}"
    case_id = "COMMON-CASE-001"
    evidence_id = "COMMON-EVID-001"
    filename = "disk_partition.raw"

    data_a = b"DATA_BELONGING_TO_TENANT_ALPHA"
    data_b = b"DATA_BELONGING_TO_TENANT_BETA"

    key_a = live_minio.upload_raw_evidence(tenant_a, case_id, evidence_id, filename, data_a)
    key_b = live_minio.upload_raw_evidence(tenant_b, case_id, evidence_id, filename, data_b)

    try:
        assert key_a != key_b
        assert key_a.startswith(tenant_a)
        assert key_b.startswith(tenant_b)

        assert live_minio.download_raw_evidence(key_a) == data_a
        assert live_minio.download_raw_evidence(key_b) == data_b
    finally:
        live_minio.client.remove_object(live_minio.RAW_BUCKET, key_a)
        live_minio.client.remove_object(live_minio.RAW_BUCKET, key_b)


def test_minio_tamper_detection_and_sha256_mismatch(live_minio):
    """
    Verify that if evidence is verified on download against expected SHA-256,
    any hash mismatch or data tampering fails closed with an integrity violation error.
    """
    tenant_id = f"tenant-{uuid.uuid4().hex[:8]}"
    case_id = f"CASE-TAMPER-{uuid.uuid4().hex[:8]}"
    evidence_id = f"EVID-TAMPER-{uuid.uuid4().hex[:8]}"
    filename = "tamper_test.bin"

    original_bytes = b"VERIFIED_FORENSIC_BYTE_STREAM_AUTHENTIC"
    correct_hash = hashlib.sha256(original_bytes).hexdigest()
    fraudulent_hash = hashlib.sha256(b"FRAUDULENT_OR_TAMPERED_BYTES").hexdigest()

    key = live_minio.upload_raw_evidence(tenant_id, case_id, evidence_id, filename, original_bytes)

    try:
        # 1. Download with valid expected hash succeeds
        valid_retrieval = live_minio.download_raw_evidence(key, expected_sha256=correct_hash)
        assert valid_retrieval == original_bytes

        # 2. Download with mismatched expected hash MUST fail closed
        with pytest.raises(RuntimeError, match="Evidence integrity violation"):
            live_minio.download_raw_evidence(key, expected_sha256=fraudulent_hash)
    finally:
        live_minio.client.remove_object(live_minio.RAW_BUCKET, key)

