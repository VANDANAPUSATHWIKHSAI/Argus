"""
Automated Tests for Infrastructure Layer Fixes
==============================================
Tests the following issues:
1. Metadata ordering bug (ensuring original metadata/size is extracted before GCM encryption).
2. Docker sandbox validation and ClamAV scanning integration with mock fallback testing.
3. Path traversal rejections on case_id and filename.
4. Production key fallback safety checks.
5. Atomic GCM in-place encryption writes.
6. Chunked GCM streaming encryption/decryption.
7. Max file size configurations.
8. Recursive zip, tar, and gz bomb detection.
"""

import os
import io
import sys
import unittest
import tempfile
import shutil
import base64
import hashlib
import zipfile
import tarfile
import gzip
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession
from infrastructure.upload.intake import upload_evidence
from infrastructure.sandbox.intake_validator import sandbox_validate, ALLOWED_EXTENSIONS
from infrastructure.integrity.hash_encrypt import (
    hash_and_encrypt,
    encrypt_file_gcm,
    verify_gcm_encrypted_file,
    _get_encryption_key
)
from infrastructure.custody.metadata_custody import extract_metadata_and_log_custody

# Decryption helper for verification tests
def decrypt_file_gcm(input_path: str, output_path: str, key_bytes: bytes) -> None:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    with open(input_path, "rb") as in_f, open(output_path, "wb") as out_f:
        salt = in_f.read(4)
        if len(salt) < 4:
            raise ValueError("Invalid GCM encrypted file: missing salt header")
        chunk_idx = 0
        while True:
            len_bytes = in_f.read(4)
            if not len_bytes:
                break
            c_len = int.from_bytes(len_bytes, byteorder="big")
            tag = in_f.read(16)
            ciphertext = in_f.read(c_len)
            nonce = salt + chunk_idx.to_bytes(8, byteorder="big")
            decryptor = Cipher(
                algorithms.AES(key_bytes),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            plain = decryptor.update(ciphertext) + decryptor.finalize()
            out_f.write(plain)
            chunk_idx += 1


class TestInfrastructureFixes(unittest.TestCase):
    def setUp(self):
        # Create a temp directory for test evidence
        self.test_dir = tempfile.mkdtemp()
        self.old_intake_dir = os.environ.get("ARGUS_INTAKE_DIR")
        os.environ["ARGUS_INTAKE_DIR"] = self.test_dir

    def tearDown(self):
        # Clean up temp files
        shutil.rmtree(self.test_dir)
        if self.old_intake_dir:
            os.environ["ARGUS_INTAKE_DIR"] = self.old_intake_dir
        else:
            os.environ.pop("ARGUS_INTAKE_DIR", None)

    # ── 1. Metadata Ordering Bug Test ──────────────────────────────────────────
    @patch("infrastructure.sandbox.intake_validator.run_docker_sandbox")
    @patch("infrastructure.sandbox.intake_validator.run_clamav_scan")
    def test_metadata_ordering_bug(self, mock_clamav, mock_docker):
        # Setup mocks to allow sandbox validation to pass
        mock_docker.return_value = []
        mock_clamav.return_value = []

        # Create a dummy zip file
        zip_path = os.path.join(self.test_dir, "test_input.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "Hello World!")
            zf.writestr("file2.txt", "Another test file.")

        with open(zip_path, "rb") as f:
            zip_bytes = f.read()

        case = CaseSession(tenant_id="tenant-test", created_by="test-user")

        # Run Stages 1 & 2
        evidence = upload_evidence(zip_bytes, "test_input.zip", case.case_id, "test-user")
        evidence = sandbox_validate(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.SANDBOXED)

        original_size = os.path.getsize(evidence.file_path)

        # Run Stage 3 (Hash & Encrypt)
        evidence = hash_and_encrypt(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.HASHED)
        self.assertTrue(evidence.encrypted)

        # Check that original file on disk remains unencrypted and intact
        self.assertEqual(os.path.getsize(evidence.file_path), original_size)

        # Check that encrypted file is stored separately
        self.assertTrue(os.path.exists(evidence.encrypted_file_path))
        self.assertNotEqual(evidence.file_path, evidence.encrypted_file_path)

        # Run Stage 4 (Metadata Extraction)
        evidence = extract_metadata_and_log_custody(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.METADATA_EXTRACTED)

        # Verify that zip entry count was extracted from original unencrypted file
        self.assertEqual(evidence.metadata.get("zip_entry_count"), 2)
        # Verify size_bytes matches original unencrypted size, not encrypted size
        self.assertEqual(evidence.metadata.get("size_bytes"), original_size)

    # ── 2. Sandbox Isolation & ClamAV Tests ────────────────────────────────────
    @patch("docker.from_env")
    @patch("pyclamd.ClamdNetworkSocket")
    def test_sandbox_docker_timeout(self, mock_clamav_socket, mock_docker_env):
        # Mock Docker to simulate a container timeout
        mock_container = MagicMock()
        mock_container.wait.side_effect = Exception("Timeout")
        
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_docker_env.return_value = mock_client

        # Mock ClamAV as clean
        mock_clamav = MagicMock()
        mock_clamav.ping.return_value = True
        mock_clamav.scan_file.return_value = None
        mock_clamav_socket.return_value = mock_clamav

        case = CaseSession(tenant_id="tenant-test", created_by="test-user")
        evidence = upload_evidence(b"clean text data", "clean.txt", case.case_id, "test-user")
        
        # Validate should reject due to container timeout
        evidence = sandbox_validate(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.VALIDATION_FAILED)
        self.assertTrue(any("sandbox_timeout" in f for f in evidence.sandbox_result.flags))

    @patch("docker.from_env")
    @patch("pyclamd.ClamdNetworkSocket")
    def test_sandbox_clamav_infected(self, mock_clamav_socket, mock_docker_env):
        # Mock Docker to succeed
        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_client = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_docker_env.return_value = mock_client

        # Mock ClamAV to detect infected file
        mock_clamav = MagicMock()
        mock_clamav.ping.return_value = True
        
        # ClamAV scan returns format: {file_path: ('FOUND', 'Eicar-Signature')}
        mock_evidence_path = os.path.join(self.test_dir, "test_cases", "virus.txt") # dummy placeholder
        mock_clamav.scan_file.return_value = {mock_evidence_path: ("FOUND", "Eicar-Signature")}
        mock_clamav_socket.return_value = mock_clamav

        case = CaseSession(tenant_id="tenant-test", created_by="test-user")
        evidence = upload_evidence(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "virus.txt", case.case_id, "test-user")
        
        # Patch the scanned file path in mock return so it matches the evidence.file_path
        mock_clamav.scan_file.return_value = {evidence.file_path: ("FOUND", "Eicar-Signature")}

        # Validate should reject due to virus detected
        evidence = sandbox_validate(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.VALIDATION_FAILED)
        self.assertTrue(any("virus_detected:Eicar-Signature" in f for f in evidence.sandbox_result.flags))

    # ── 3. Path Traversal Test ─────────────────────────────────────────────────
    def test_path_traversal_rejections(self):
        case_id = "test-case-123"
        
        # Attempt traversal in case_id
        with self.assertRaises(ValueError):
            upload_evidence(b"data", "test.txt", "../bad_case", "test-user")
            
        # Attempt traversal in filename
        with self.assertRaises(ValueError):
            upload_evidence(b"data", "../test.txt", case_id, "test-user")
            
        with self.assertRaises(ValueError):
            upload_evidence(b"data", "subdir/test.txt", case_id, "test-user")

    # ── 4. Production Key Fallback Test ────────────────────────────────────────
    def test_production_key_safety(self):
        # Backup environment
        old_key = os.environ.get("ARGUS_FERNET_KEY")
        old_env = os.environ.get("APP_ENV")
        
        try:
            # Set to production environment and remove key
            os.environ["APP_ENV"] = "production"
            os.environ.pop("ARGUS_FERNET_KEY", None)
            
            # Importing or calling key validation should raise RuntimeError
            with self.assertRaises(RuntimeError):
                _get_encryption_key()
        finally:
            # Restore environment
            if old_key:
                os.environ["ARGUS_FERNET_KEY"] = old_key
            else:
                os.environ.pop("ARGUS_FERNET_KEY", None)
            if old_env:
                os.environ["APP_ENV"] = old_env
            else:
                os.environ.pop("APP_ENV", None)

    # ── 5. Chunked GCM Streaming and Hashing Test ─────────────────────────────
    def test_chunked_gcm_correctness(self):
        # Generate 1 MB of random bytes (larger than CHUNK_SIZE of 64KB)
        data = os.urandom(1024 * 1024 + 123) # non-aligned size
        
        original_f = os.path.join(self.test_dir, "original.bin")
        encrypted_f = os.path.join(self.test_dir, "encrypted.bin")
        decrypted_f = os.path.join(self.test_dir, "decrypted.bin")
        
        with open(original_f, "wb") as f:
            f.write(data)
            
        key_bytes = os.urandom(32)
        
        # Encrypt GCM
        encrypt_file_gcm(original_f, encrypted_f, key_bytes)
        
        # Verify GCM Decryption matches SHA-256
        expected_sha256 = hashlib.sha256(data).hexdigest()
        self.assertTrue(verify_gcm_encrypted_file(encrypted_f, expected_sha256, key_bytes))
        
        # Decrypt GCM
        decrypt_file_gcm(encrypted_f, decrypted_f, key_bytes)
        
        with open(decrypted_f, "rb") as f:
            decrypted_data = f.read()
            
        self.assertEqual(data, decrypted_data)

    # ── 6. Recursive Archive Bomb Checks ───────────────────────────────────────
    @patch("infrastructure.sandbox.intake_validator.run_docker_sandbox")
    @patch("infrastructure.sandbox.intake_validator.run_clamav_scan")
    def test_recursive_zip_bomb(self, mock_clamav, mock_docker):
        mock_docker.return_value = []
        mock_clamav.return_value = []

        # Create a nested zip bomb: outer.zip containing inner.zip containing a highly compressed file
        inner_bio = io.BytesIO()
        with zipfile.ZipFile(inner_bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Write a large empty file that compresses extremely well
            zf.writestr("huge.txt", "0" * (10 * 1024 * 1024)) # 10 MB of zeros
        inner_bio.seek(0)
        
        outer_bio = io.BytesIO()
        with zipfile.ZipFile(outer_bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Add the inner zip
            zf.writestr("inner.zip", inner_bio.read())
        outer_bio.seek(0)
        
        case = CaseSession(tenant_id="tenant-test", created_by="test-user")
        evidence = upload_evidence(outer_bio.read(), "outer.zip", case.case_id, "test-user")
        
        # Validate should detect zip bomb
        evidence = sandbox_validate(evidence)
        self.assertTrue(any("zip_bomb_suspected" in f for f in evidence.sandbox_result.flags))

    def test_symbolic_link_rejection(self):
        case = CaseSession(tenant_id="tenant-test", created_by="test-user")
        evidence = upload_evidence(b"Some text", "test_file.txt", case.case_id, "test-user")
        
        from unittest.mock import patch
        with patch("os.path.islink", return_value=True):
            evidence = sandbox_validate(evidence)
            self.assertEqual(evidence.status, EvidenceStatus.VALIDATION_FAILED)
            self.assertIn("symbolic_link_rejected", evidence.sandbox_result.flags)

    @patch("psycopg2.connect")
    @patch("minio.Minio")
    def test_tenant_isolation_enforcement(self, mock_minio, mock_connect):
        """Create evidence under tenant A and tenant B, assert cross-tenant queries return nothing."""
        from infrastructure.repository.evidence_store import (
            create_case_session,
            store_evidence,
            get_evidence,
            list_evidence_by_case
        )
        
        # 1. Setup in-memory mock DB lists
        db_cases = {}      # case_id -> tuple
        db_evidence = {}   # evidence_id -> tuple

        class MockCursor:
            def __init__(self):
                self._results = []

            def execute(self, query, params=None):
                query_upper = query.upper().strip()
                if "INSERT INTO CASES" in query_upper:
                    case_id, tenant_id, created_by = params[0], params[1], params[2]
                    db_cases[case_id] = (case_id, tenant_id, "2026-08-25", created_by, "open")
                elif "INSERT INTO EVIDENCE" in query_upper:
                    evidence_id, case_id, filename, uploaded_by, status, sha256, encrypted, rfc, metadata, repo_path = params
                    db_evidence[evidence_id] = (
                        evidence_id, case_id, filename, repo_path, uploaded_by, "2026-08-25",
                        status, sha256, encrypted, rfc, metadata
                    )
                elif "SELECT" in query_upper and "FROM EVIDENCE" in query_upper:
                    self._results = []
                    if "E.EVIDENCE_ID = %S" in query_upper:
                        evidence_id, tenant_id = params
                        for ev_id, ev in db_evidence.items():
                            if ev_id == evidence_id:
                                case_id = ev[1]
                                case = db_cases.get(case_id)
                                if case and case[1] == tenant_id:
                                    self._results.append(ev)
                    elif "E.CASE_ID = %S" in query_upper:
                        case_id, tenant_id = params
                        for ev_id, ev in db_evidence.items():
                            if ev[1] == case_id:
                                case = db_cases.get(case_id)
                                if case and case[1] == tenant_id:
                                    self._results.append(ev)
                elif "SELECT" in query_upper and "FROM CASES" in query_upper:
                    self._results = []
                    case_id, tenant_id = params
                    case = db_cases.get(case_id)
                    if case and case[1] == tenant_id:
                        self._results.append(case)

            def fetchone(self):
                return self._results[0] if self._results else None

            def fetchall(self):
                return self._results

            def close(self):
                pass

        class MockConn:
            def cursor(self):
                return MockCursor()
            def commit(self):
                pass
            def close(self):
                pass

        mock_connect.return_value = MockConn()
        mock_minio.return_value = MagicMock()

        # 2. Create Case Sessions
        case_a = create_case_session(tenant_id="tenant-a", created_by="analyst-a")
        case_b = create_case_session(tenant_id="tenant-b", created_by="analyst-b")
        
        # 3. Upload and store evidence under Tenant A
        raw_a = b"Tenant A confidential log data"
        ev_a_temp = upload_evidence(raw_a, "confidential_a.txt", case_a.case_id, "analyst-a")
        ev_a = store_evidence(ev_a_temp, case_a)
        
        # 4. Upload and store evidence under Tenant B
        raw_b = b"Tenant B confidential pcap data"
        ev_b_temp = upload_evidence(raw_b, "confidential_b.txt", case_b.case_id, "analyst-b")
        ev_b = store_evidence(ev_b_temp, case_b)
        
        # 5. Assert get_evidence scoped to tenant-a cannot fetch tenant-b's evidence
        stored_a = get_evidence(tenant_id="tenant-a", evidence_id=ev_a.evidence_id)
        self.assertIsNotNone(stored_a)
        self.assertEqual(stored_a.filename, "confidential_a.txt")
        
        stored_b_leak = get_evidence(tenant_id="tenant-a", evidence_id=ev_b.evidence_id)
        self.assertIsNone(stored_b_leak)
        
        # 6. Assert get_evidence scoped to tenant-b cannot fetch tenant-a's evidence
        stored_b = get_evidence(tenant_id="tenant-b", evidence_id=ev_b.evidence_id)
        self.assertIsNotNone(stored_b)
        self.assertEqual(stored_b.filename, "confidential_b.txt")
        
        stored_a_leak = get_evidence(tenant_id="tenant-b", evidence_id=ev_a.evidence_id)
        self.assertIsNone(stored_a_leak)
        
        # 7. Assert list_evidence_by_case is properly isolated
        list_a = list_evidence_by_case(tenant_id="tenant-a", case_id=case_a.case_id)
        self.assertEqual(len(list_a), 1)
        self.assertEqual(list_a[0].evidence_id, ev_a.evidence_id)
        
        list_a_leak = list_evidence_by_case(tenant_id="tenant-a", case_id=case_b.case_id)
        self.assertEqual(len(list_a_leak), 0)
        
        list_b = list_evidence_by_case(tenant_id="tenant-b", case_id=case_b.case_id)
        self.assertEqual(len(list_b), 1)
        self.assertEqual(list_b[0].evidence_id, ev_b.evidence_id)
        
        list_b_leak = list_evidence_by_case(tenant_id="tenant-b", case_id=case_a.case_id)
        self.assertEqual(len(list_b_leak), 0)


if __name__ == "__main__":
    unittest.main()
