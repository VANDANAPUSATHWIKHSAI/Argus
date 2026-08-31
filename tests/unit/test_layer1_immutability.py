"""
Unit Tests for Layer 1 Original Evidence Immutability + Storage Separation
===========================================================================
Proves that raw forensic evidence bytes remain byte-for-byte untouched during 
the entire Layer 1 lifecycle (Upload -> Sandbox -> Hash/Encrypt -> Metadata -> Store).
"""

import os
import shutil
import tempfile
import unittest
import hashlib
from unittest.mock import patch, MagicMock

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession
from infrastructure.upload.intake import upload_evidence
from infrastructure.sandbox.intake_validator import sandbox_validate
from infrastructure.integrity.hash_encrypt import (
    hash_and_encrypt,
    verify_gcm_encrypted_file,
    _get_encryption_key
)
from infrastructure.custody.metadata_custody import extract_metadata_and_log_custody
from infrastructure.repository.evidence_store import (
    store_evidence,
    get_evidence,
    list_evidence_by_case,
    create_case_session
)
from infrastructure.pipeline import run_infrastructure_layer
from test_infrastructure_fixes import decrypt_file_gcm


class TestLayer1Immutability(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.old_intake = os.environ.get("ARGUS_INTAKE_DIR")
        self.old_repo = os.environ.get("ARGUS_REPOSITORY_DIR")
        os.environ["ARGUS_INTAKE_DIR"] = os.path.join(self.test_dir, "intake")
        os.environ["ARGUS_REPOSITORY_DIR"] = os.path.join(self.test_dir, "repository")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if self.old_intake:
            os.environ["ARGUS_INTAKE_DIR"] = self.old_intake
        else:
            os.environ.pop("ARGUS_INTAKE_DIR", None)
        if self.old_repo:
            os.environ["ARGUS_REPOSITORY_DIR"] = self.old_repo
        else:
            os.environ.pop("ARGUS_REPOSITORY_DIR", None)

    @patch("infrastructure.sandbox.intake_validator.run_docker_sandbox", return_value=[])
    @patch("infrastructure.sandbox.intake_validator.run_clamav_scan", return_value=[])
    def test_original_evidence_immutability_and_decryption(self, mock_clamav, mock_docker):
        """
        Requirements 1 to 9:
        Upload known bytes -> calculate SHA-256 -> integrity & store -> verify:
        - Stored original is byte-for-byte identical to input
        - SHA-256 matches original bytes
        - Encrypted representation is distinct from original
        - Decrypting encrypted representation reproduces original bytes
        - Original file is never overwritten
        - Repository references distinguish original and encrypted paths
        """
        known_bytes = b"known forensic evidence - raw EVTX or memory payload 12345"
        expected_sha256 = hashlib.sha256(known_bytes).hexdigest()
        filename = "known_evidence.log"
        case = CaseSession(tenant_id="tenant-alpha", created_by="analyst-1")

        # 1. Intake Stage
        evidence = upload_evidence(known_bytes, filename, case.case_id, "analyst-1")
        self.assertEqual(evidence.status, EvidenceStatus.UPLOADED)
        intake_file_path = evidence.file_path

        # Verify raw intake bytes immediately
        with open(intake_file_path, "rb") as f:
            self.assertEqual(f.read(), known_bytes)

        # 2. Sandbox Validation Stage
        evidence = sandbox_validate(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.SANDBOXED)

        # 3. Hash & Encrypt Stage
        evidence = hash_and_encrypt(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.HASHED)
        self.assertEqual(evidence.sha256_hash, expected_sha256)

        # REQUIREMENT 8: Original evidence path is NOT overwritten
        self.assertTrue(os.path.exists(evidence.file_path))
        with open(evidence.file_path, "rb") as f:
            self.assertEqual(f.read(), known_bytes, "Original evidence file was modified/overwritten!")

        # REQUIREMENT 4 & 6: Encrypted representation is separate and different
        self.assertIsNotNone(evidence.encrypted_file_path)
        self.assertTrue(os.path.exists(evidence.encrypted_file_path))
        self.assertNotEqual(evidence.file_path, evidence.encrypted_file_path)

        with open(evidence.encrypted_file_path, "rb") as f:
            enc_bytes = f.read()
        self.assertNotEqual(known_bytes, enc_bytes, "Encrypted bytes must differ from original bytes!")

        # REQUIREMENT 7: Decrypting encrypted representation reproduces original bytes
        decrypted_out = os.path.join(self.test_dir, "decrypted_test.bin")
        key_bytes = _get_encryption_key()
        decrypt_file_gcm(evidence.encrypted_file_path, decrypted_out, key_bytes)

        with open(decrypted_out, "rb") as f:
            restored_bytes = f.read()
        self.assertEqual(known_bytes, restored_bytes, "Decrypted bytes must match original bytes exactly!")

        # 4. Metadata Extraction Stage
        evidence = extract_metadata_and_log_custody(evidence)
        self.assertEqual(evidence.status, EvidenceStatus.METADATA_EXTRACTED)

        # 5. Store Stage
        evidence = store_evidence(evidence, case)
        self.assertEqual(evidence.status, EvidenceStatus.STORED)

        # REQUIREMENT 4 & 9: Repository references distinguish original and encrypted
        self.assertIsNotNone(evidence.original_repository_path)
        self.assertIsNotNone(evidence.encrypted_repository_path)
        self.assertNotEqual(evidence.original_repository_path, evidence.encrypted_repository_path)

        # Verify stored ORIGINAL in repository is byte-for-byte identical
        orig_file_path = evidence.original_repository_path if os.path.exists(evidence.original_repository_path) else evidence.metadata.get("original_repository_path_local", os.path.join("data/repository", case.case_id, evidence.evidence_id, "original", evidence.filename))
        with open(orig_file_path, "rb") as f:
            stored_orig_bytes = f.read()
        self.assertEqual(known_bytes, stored_orig_bytes, "Repository original file differs from intake bytes!")

        # Verify stored ENCRYPTED in repository decrypts to original
        enc_file_path = evidence.encrypted_repository_path if os.path.exists(evidence.encrypted_repository_path) else evidence.metadata.get("encrypted_repository_path_local", os.path.join("data/repository", case.case_id, evidence.evidence_id, "encrypted", f"{evidence.filename}.enc"))
        decrypted_repo_out = os.path.join(self.test_dir, "decrypted_repo.bin")
        decrypt_file_gcm(enc_file_path, decrypted_repo_out, key_bytes)
        with open(decrypted_repo_out, "rb") as f:
            self.assertEqual(f.read(), known_bytes)

    @patch("infrastructure.sandbox.intake_validator.run_docker_sandbox", return_value=[])
    @patch("infrastructure.sandbox.intake_validator.run_clamav_scan", return_value=[])
    def test_storage_failure_semantics(self, mock_clamav, mock_docker):
        """
        REQUIREMENT 10:
        Verify that a storage failure does NOT result in status=STORED.
        """
        known_bytes = b"sample log data"
        case = CaseSession(tenant_id="tenant-fail", created_by="analyst-1")
        evidence = upload_evidence(known_bytes, "sample.log", case.case_id, "analyst-1")
        evidence = sandbox_validate(evidence)
        evidence = hash_and_encrypt(evidence)

        # Force a storage failure by making repository directory read-only / invalid
        with patch("shutil.copy2", side_effect=IOError("Disk full or permission error")):
            with self.assertRaises(RuntimeError):
                store_evidence(evidence, case)
            self.assertEqual(evidence.status, EvidenceStatus.FAILED)
            self.assertNotEqual(evidence.status, EvidenceStatus.STORED)

    @patch("psycopg2.connect")
    def test_tenant_isolation(self, mock_db_connect):
        """
        REQUIREMENT 11:
        Verify Tenant A cannot retrieve Tenant B's evidence.
        """
        db_cases = {}
        db_evidence = {}

        class MockCursor:
            def __init__(self):
                self._results = []

            def execute(self, query, params=None):
                q = query.upper().strip()
                if "INSERT INTO CASES" in q:
                    db_cases[params[0]] = (params[0], params[1], "2026-08-27", params[2], "open")
                elif "INSERT INTO EVIDENCE" in q:
                    db_evidence[params[0]] = (
                        params[0], params[1], params[2], params[9], params[3], "2026-08-27",
                        params[4], params[5], params[6], params[7], params[8]
                    )
                elif "SELECT" in q and "FROM EVIDENCE" in q:
                    self._results = []
                    if "E.EVIDENCE_ID = %S" in q:
                        eid, tid = params
                        ev = db_evidence.get(eid)
                        if ev:
                            cid = ev[1]
                            c = db_cases.get(cid)
                            if c and c[1] == tid:
                                self._results.append(ev)
                    elif "E.CASE_ID = %S" in q:
                        cid, tid = params
                        for ev in db_evidence.values():
                            if ev[1] == cid:
                                c = db_cases.get(cid)
                                if c and c[1] == tid:
                                    self._results.append(ev)

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

        mock_db_connect.return_value = MockConn()

        case_a = create_case_session(tenant_id="tenant-A", created_by="user-A")
        case_b = create_case_session(tenant_id="tenant-B", created_by="user-B")

        ev_a = store_evidence(upload_evidence(b"Tenant A secret", "a.txt", case_a.case_id, "user-A"), case_a)
        ev_b = store_evidence(upload_evidence(b"Tenant B secret", "b.txt", case_b.case_id, "user-B"), case_b)

        # Tenant A can fetch ev_a, but NOT ev_b
        self.assertIsNotNone(get_evidence("tenant-A", ev_a.evidence_id))
        self.assertIsNone(get_evidence("tenant-A", ev_b.evidence_id))

        # Tenant B can fetch ev_b, but NOT ev_a
        self.assertIsNotNone(get_evidence("tenant-B", ev_b.evidence_id))
        self.assertIsNone(get_evidence("tenant-B", ev_a.evidence_id))

    @patch("infrastructure.sandbox.intake_validator.run_docker_sandbox", return_value=[])
    @patch("infrastructure.sandbox.intake_validator.run_clamav_scan", return_value=[])
    def test_custody_log_chronological_ordering(self, mock_clamav, mock_docker):
        """
        REQUIREMENT 12:
        Verify custody entries preserve chronological order and include explicit events:
        UPLOADED -> SANDBOXED -> HASHED -> ORIGINAL_STORED / ENCRYPTED_STORED / STORED.
        """
        case = CaseSession(tenant_id="tenant-custody", created_by="analyst-c")
        evidence = run_infrastructure_layer(b"custody test bytes", "custody.txt", case, "analyst-c")

        actions = [entry.action for entry in evidence.custody_log]
        self.assertIn("uploaded", actions)
        self.assertIn("sandbox_validated", actions)
        self.assertIn("hashed", actions)
        self.assertIn("encrypted_stored", actions)
        self.assertIn("original_stored", actions)
        self.assertIn("stored", actions)

        # Check chronological timestamps
        timestamps = [entry.timestamp for entry in evidence.custody_log]
        for i in range(1, len(timestamps)):
            self.assertGreaterEqual(timestamps[i], timestamps[i-1])


if __name__ == "__main__":
    unittest.main()
