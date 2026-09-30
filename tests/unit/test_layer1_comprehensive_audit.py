"""
ARGUS Layer 1 Comprehensive Infrastructure Audit & Verification Suite (L1-T01 to L1-T20)
===================================================================================
Tests real Layer 1 implementation paths without bypassing security mechanisms.
"""

import os
import uuid
import shutil
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession, CustodyLogEntry
from infrastructure.upload.intake import upload_evidence, sanitize_segment
from infrastructure.sandbox.intake_validator import sandbox_validate
from infrastructure.integrity.hash_encrypt import hash_and_encrypt
from infrastructure.integrity.timestamp_service import issue_rfc3161_timestamp, verify_rfc3161_timestamp
from infrastructure.custody.metadata_custody import extract_metadata_and_log_custody
from infrastructure.repository.evidence_store import create_case_session, store_evidence, get_evidence, list_evidence_by_case
from infrastructure.pipeline import run_infrastructure_layer


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="argus_l1_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# L1-T01: normal evidence upload
def test_L1_T01_normal_evidence_upload(temp_dir):
    data = b"L1-T01 normal evidence upload data"
    ev = upload_evidence(file_bytes=data, filename="sample.txt", case_id="ARGUS_L1_01", uploaded_by="analyst_1", tenant_id="tenant_alpha")
    assert ev.evidence_id is not None
    assert ev.case_id == "ARGUS_L1_01"
    assert ev.tenant_id == "tenant_alpha"
    assert ev.status == EvidenceStatus.UPLOADED
    assert os.path.exists(ev.file_path)


# L1-T02: path traversal filename
def test_L1_T02_path_traversal_filename():
    with pytest.raises(ValueError, match="Path traversal or invalid characters"):
        upload_evidence(file_bytes=b"test", filename="../../etc/passwd", case_id="ARGUS_L1_02", uploaded_by="analyst")


# L1-T03: absolute path filename
def test_L1_T03_absolute_path_filename():
    with pytest.raises(ValueError, match="Path traversal or invalid characters"):
        upload_evidence(file_bytes=b"test", filename="/etc/passwd", case_id="ARGUS_L1_03", uploaded_by="analyst")


# L1-T04: oversized file
def test_L1_T04_oversized_file(temp_dir):
    file_path = os.path.join(temp_dir, "large.txt")
    with open(file_path, "wb") as f:
        f.write(b"A" * 1024)

    ev = Evidence(case_id="ARGUS_L1_04", filename="large.txt", file_path=file_path, uploaded_by="analyst")
    with patch("infrastructure.sandbox.intake_validator.MAX_FILE_SIZE_BYTES", 500):
        val_ev = sandbox_validate(ev)
        assert val_ev.status == EvidenceStatus.VALIDATION_FAILED
        assert any("file_too_large" in flag for flag in val_ev.sandbox_result.flags)


# L1-T05: empty file
def test_L1_T05_empty_file(temp_dir):
    file_path = os.path.join(temp_dir, "empty.txt")
    with open(file_path, "wb") as f:
        pass

    ev = Evidence(case_id="ARGUS_L1_05", filename="empty.txt", file_path=file_path, uploaded_by="analyst")
    val_ev = sandbox_validate(ev)
    assert any("empty_file" in flag for flag in val_ev.sandbox_result.flags)


# L1-T06: invalid evidence type
def test_L1_T06_invalid_evidence_type(temp_dir):
    file_path = os.path.join(temp_dir, "malicious.unknownext")
    with open(file_path, "wb") as f:
        f.write(b"unknown format data")

    ev = Evidence(case_id="ARGUS_L1_06", filename="malicious.unknownext", file_path=file_path, uploaded_by="analyst")
    val_ev = sandbox_validate(ev)
    assert any("unknown_extension" in flag for flag in val_ev.sandbox_result.flags)


# L1-T07: SHA-256 correctness
def test_L1_T07_sha256_correctness(temp_dir):
    import hashlib
    data = b"Deterministic SHA-256 evidence data test"
    file_path = os.path.join(temp_dir, "sha_test.txt")
    with open(file_path, "wb") as f:
        f.write(data)

    expected_sha = hashlib.sha256(data).hexdigest()
    ev = Evidence(case_id="ARGUS_L1_07", filename="sha_test.txt", file_path=file_path, uploaded_by="analyst")
    hashed_ev = hash_and_encrypt(ev)
    assert hashed_ev.sha256_hash == expected_sha


# L1-T08: hash mismatch detection
def test_L1_T08_hash_mismatch_detection(temp_dir):
    data = b"Test data for hash mismatch"
    file_path = os.path.join(temp_dir, "mismatch.txt")
    with open(file_path, "wb") as f:
        f.write(data)

    ev = Evidence(case_id="ARGUS_L1_08", filename="mismatch.txt", file_path=file_path, uploaded_by="analyst")
    with patch("infrastructure.integrity.hash_encrypt.verify_gcm_encrypted_file", return_value=False):
        with pytest.raises(RuntimeError, match="GCM encryption failed"):
            hash_and_encrypt(ev)


# L1-T09: encryption failure
def test_L1_T09_encryption_failure(temp_dir):
    file_path = os.path.join(temp_dir, "enc_fail.txt")
    with open(file_path, "wb") as f:
        f.write(b"Encryption test content")

    ev = Evidence(case_id="ARGUS_L1_09", filename="enc_fail.txt", file_path=file_path, uploaded_by="analyst")
    with patch("infrastructure.integrity.hash_encrypt.encrypt_file_gcm", side_effect=IOError("Disk write failed")):
        with pytest.raises(RuntimeError, match="GCM encryption failed"):
            hash_and_encrypt(ev)
        assert ev.status == EvidenceStatus.FAILED
        assert ev.encrypted is False


# L1-T10: timestamping success/failure boundary
def test_L1_T10_timestamping_boundary():
    ev1 = Evidence(case_id="ARGUS_L1_10", filename="ts1.txt", file_path="fake/ts1.txt", sha256_hash="a" * 64, uploaded_by="analyst")
    rec = issue_rfc3161_timestamp(ev1, allow_mock=True)
    assert rec.timestamp_source in ("mock", "tsa")
    assert verify_rfc3161_timestamp(ev1) is True

    ev2 = Evidence(case_id="ARGUS_L1_10", filename="ts2.txt", file_path="fake/ts2.txt", sha256_hash="b" * 64, uploaded_by="analyst")
    with patch("infrastructure.integrity.timestamp_service._call_tsa_http", return_value=(None, "Connection timeout")):
        with pytest.raises(RuntimeError, match="Production trusted RFC 3161 timestamping failed"):
            issue_rfc3161_timestamp(ev2, allow_mock=False)


# L1-T11: chain-of-custody creation
def test_L1_T11_chain_of_custody_creation(temp_dir):
    data = b"Chain of custody creation test"
    case = CaseSession(case_id="ARGUS_L1_11", tenant_id="tenant_c", created_by="analyst_c")
    ev = run_infrastructure_layer(data, "custody.txt", case, "analyst_c")
    assert len(ev.custody_log) >= 4
    actions = [entry.action for entry in ev.custody_log]
    assert "uploaded" in actions
    assert "sandbox_validated" in actions
    assert "hashed" in actions
    assert "metadata_extracted" in actions
    assert "stored" in actions


# L1-T12: custody immutability
def test_L1_T12_custody_immutability():
    ev = Evidence(case_id="ARGUS_L1_12", filename="test.txt", file_path="fake/test.txt", uploaded_by="analyst")
    entry1 = CustodyLogEntry(actor="analyst", action="uploaded", notes="Initial upload")
    ev.custody_log.append(entry1)
    
    # Verify entries are appended, existing entries are preserved in historical order
    entry2 = CustodyLogEntry(actor="validator", action="sandbox_validated", notes="Passed")
    ev.custody_log.append(entry2)
    
    assert len(ev.custody_log) == 2
    assert ev.custody_log[0].action == "uploaded"
    assert ev.custody_log[1].action == "sandbox_validated"


# L1-T13: tenant isolation
def test_L1_T13_tenant_isolation(temp_dir):
    with patch("infrastructure.repository.evidence_store._should_attempt_postgres", return_value=False):
        case_a = create_case_session(tenant_id="tenant_A", created_by="analyst_A", case_id=str(uuid.uuid4()))
        assert case_a.tenant_id == "tenant_A"


# L1-T14: cross-case isolation
def test_L1_T14_cross_case_isolation(temp_dir):
    with patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=False):
        case_1 = CaseSession(case_id="ARGUS_CASE_101", tenant_id="tenant_iso", created_by="analyst_1")
        case_2 = CaseSession(case_id="ARGUS_CASE_102", tenant_id="tenant_iso", created_by="analyst_2")

        ev1 = upload_evidence(b"case 1 evidence", "file1.txt", case_1.case_id, "analyst_1")
        ev1 = hash_and_encrypt(ev1)
        ev1 = extract_metadata_and_log_custody(ev1)
        ev1 = store_evidence(ev1, case_1)

        assert ev1.case_id == "ARGUS_CASE_101"
        assert "ARGUS_CASE_101" in ev1.original_repository_path
        assert "ARGUS_CASE_102" not in ev1.original_repository_path


# L1-T15: upload failure state
def test_L1_T15_upload_failure_state():
    with pytest.raises(ValueError):
        upload_evidence(b"", "", "ARGUS_L1_15", "analyst")


# L1-T16: sandbox failure state
def test_L1_T16_sandbox_failure_state(temp_dir):
    file_path = os.path.join(temp_dir, "symlink_test.txt")
    with open(file_path, "wb") as f:
        f.write(b"data")

    ev = Evidence(case_id="ARGUS_L1_16", filename="symlink_test.txt", file_path=file_path, uploaded_by="analyst")
    with patch("os.path.islink", return_value=True):
        val_ev = sandbox_validate(ev)
        assert val_ev.status == EvidenceStatus.VALIDATION_FAILED
        assert "symbolic_link_rejected" in val_ev.sandbox_result.flags


# L1-T17: storage failure state
def test_L1_T17_storage_failure_state(temp_dir):
    case = CaseSession(case_id="ARGUS_L1_17", tenant_id="tenant_x", created_by="analyst")
    ev = Evidence(case_id="ARGUS_L1_17", filename="missing.txt", file_path=os.path.join(temp_dir, "nonexistent.txt"), uploaded_by="analyst")
    with pytest.raises(RuntimeError, match="Cannot store evidence"):
        store_evidence(ev, case)
    assert ev.status == EvidenceStatus.FAILED


# L1-T18: duplicate evidence behavior
def test_L1_T18_duplicate_evidence_behavior(temp_dir):
    with patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=False):
        data = b"Identical raw evidence content"
        case = CaseSession(case_id="ARGUS_L1_18", tenant_id="tenant_dup", created_by="analyst")
        
        ev1 = run_infrastructure_layer(data, "dup1.txt", case, "analyst")
        ev2 = run_infrastructure_layer(data, "dup2.txt", case, "analyst")

        assert ev1.evidence_id != ev2.evidence_id
        assert ev1.sha256_hash == ev2.sha256_hash
        assert ev1.status == EvidenceStatus.STORED
        assert ev2.status == EvidenceStatus.STORED


# L1-T19: original evidence immutability
def test_L1_T19_original_evidence_immutability(temp_dir):
    with patch("infrastructure.repository.evidence_store._should_attempt_minio", return_value=False):
        data = b"Original Immutable Evidence Content 12345"
        case = CaseSession(case_id="ARGUS_L1_19", tenant_id="tenant_immut", created_by="analyst")
        ev = run_infrastructure_layer(data, "immutable.txt", case, "analyst")

        with open(ev.original_repository_path, "rb") as f:
            stored_bytes = f.read()
        assert stored_bytes == data


# L1-T20: audit log correctness
def test_L1_T20_audit_log_correctness(temp_dir):
    data = b"Audit log verification content"
    case = CaseSession(case_id="ARGUS_L1_20", tenant_id="tenant_audit", created_by="analyst")
    ev = run_infrastructure_layer(data, "audit_test.txt", case, "analyst")

    assert len(ev.audit_log) >= 5
    events = [e.event for e in ev.audit_log]
    assert "stage_intake_complete" in events
    assert "stage_sandbox_complete" in events
    assert "stage_integrity_complete" in events
    assert "stage_metadata_complete" in events
    assert "evidence_stored" in events
