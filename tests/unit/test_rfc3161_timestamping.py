"""
Unit Tests for RFC 3161 Trusted Timestamping
=============================================
Verifies RFC 3161 request construction, TSA response handling, production fail-closed 
semantics, mock/dev mode distinction, token verification, and non-network test execution.
"""

import os
import shutil
import tempfile
import unittest
import hashlib
import base64
from unittest.mock import patch, MagicMock

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession, TimestampRecord
from infrastructure.upload.intake import upload_evidence
from infrastructure.sandbox.intake_validator import sandbox_validate
from infrastructure.integrity.hash_encrypt import hash_and_encrypt
from infrastructure.integrity.timestamp_service import (
    issue_rfc3161_timestamp,
    verify_rfc3161_timestamp,
    build_rfc3161_request_bytes,
    get_tsa_url
)
from infrastructure.repository.evidence_store import store_evidence


class TestRFC3161Timestamping(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.old_intake = os.environ.get("ARGUS_INTAKE_DIR")
        self.old_repo = os.environ.get("ARGUS_REPOSITORY_DIR")
        self.old_tsa_url = os.environ.get("ARGUS_TSA_URL")
        self.old_app_env = os.environ.get("APP_ENV")
        self.old_fernet_key = os.environ.get("ARGUS_FERNET_KEY")

        os.environ["ARGUS_INTAKE_DIR"] = os.path.join(self.test_dir, "intake")
        os.environ["ARGUS_REPOSITORY_DIR"] = os.path.join(self.test_dir, "repository")
        os.environ["ARGUS_TSA_URL"] = "https://mock.tsa.test/tsr"
        os.environ["APP_ENV"] = "development"

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
        if self.old_tsa_url:
            os.environ["ARGUS_TSA_URL"] = self.old_tsa_url
        else:
            os.environ.pop("ARGUS_TSA_URL", None)
        if self.old_app_env:
            os.environ["APP_ENV"] = self.old_app_env
        else:
            os.environ.pop("APP_ENV", None)
        if self.old_fernet_key:
            os.environ["ARGUS_FERNET_KEY"] = self.old_fernet_key
        else:
            os.environ.pop("ARGUS_FERNET_KEY", None)

    # 1 & 2. SHA-256 Digest & Request Message Imprint Test
    def test_sha256_and_message_imprint(self):
        known_data = b"forensic log raw evidence bytes 9999"
        expected_sha256 = hashlib.sha256(known_data).hexdigest()
        digest_bytes = bytes.fromhex(expected_sha256)

        req_bytes = build_rfc3161_request_bytes(expected_sha256)
        self.assertIsInstance(req_bytes, bytes)
        self.assertTrue(len(req_bytes) > 30)
        # Message imprint MUST contain the exact 32-byte digest of original evidence
        self.assertIn(digest_bytes, req_bytes)

    # 3, 4, 5, 6. Successful TSA Response & Evidence/Case/Tenant Association
    @patch("infrastructure.integrity.timestamp_service._call_tsa_http")
    def test_successful_tsa_response_association(self, mock_call_tsa):
        fake_der_token = b"\x30\x82\x01\x00MockTSADerResponseBytesPayload" + b"12345"
        mock_call_tsa.return_value = (fake_der_token, None)

        case = CaseSession(tenant_id="tenant-sec-1", created_by="analyst-9")
        evidence = upload_evidence(b"raw evidence data", "evidence.bin", case.case_id, "analyst-9")
        evidence = hash_and_encrypt(evidence)

        rec = evidence.timestamp_record
        self.assertIsNotNone(rec)
        self.assertEqual(rec.sha256_hash, evidence.sha256_hash)
        self.assertEqual(rec.evidence_id, evidence.evidence_id)
        self.assertEqual(rec.case_id, case.case_id)
        self.assertEqual(rec.timestamp_source, "tsa")
        self.assertEqual(rec.tsa_url, "https://mock.tsa.test/tsr")

    # 7. Configuration-driven TSA URL
    def test_configuration_driven_tsa_url(self):
        os.environ["ARGUS_TSA_URL"] = "https://custom-tsa.example.org/tsr"
        self.assertEqual(get_tsa_url(), "https://custom-tsa.example.org/tsr")

    # 8, 9, 10. Timestamp Verification (Success on match, Failure on mismatch)
    @patch("infrastructure.integrity.timestamp_service._call_tsa_http")
    def test_timestamp_verification(self, mock_call_tsa):
        case = CaseSession(tenant_id="tenant-sec-2", created_by="analyst-9")
        raw_bytes = b"verification test original bytes"
        sha256_orig = hashlib.sha256(raw_bytes).hexdigest()
        digest_bytes = bytes.fromhex(sha256_orig)

        fake_der_token = b"\x30\x40TSATokenHeader" + digest_bytes + b"TSATokenFooter"
        mock_call_tsa.return_value = (fake_der_token, None)

        evidence = upload_evidence(raw_bytes, "verify.log", case.case_id, "analyst-9")
        evidence = hash_and_encrypt(evidence)

        # Requirement 9: Verification succeeds when original SHA-256 is unchanged
        verified = verify_rfc3161_timestamp(evidence, expected_sha256=sha256_orig)
        self.assertTrue(verified)
        self.assertEqual(evidence.timestamp_record.timestamp_verification_status, "verified")

        # Requirement 10: Verification fails when a different SHA-256 is supplied
        tampered_hash = hashlib.sha256(b"tampered data").hexdigest()
        verified_tampered = verify_rfc3161_timestamp(evidence, expected_sha256=tampered_hash)
        self.assertFalse(verified_tampered)

    # 11 & 12. Production Failure Semantics (No Silent STORED)
    @patch("infrastructure.integrity.timestamp_service._call_tsa_http")
    def test_production_tsa_failure_fails_closed(self, mock_call_tsa):
        mock_call_tsa.return_value = (None, "TSA HTTP 503 Service Unavailable")
        os.environ["APP_ENV"] = "production"
        os.environ["ARGUS_FERNET_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()

        case = CaseSession(tenant_id="tenant-prod", created_by="sys-admin")
        evidence = upload_evidence(b"critical production log", "prod.log", case.case_id, "sys-admin")

        with self.assertRaises(RuntimeError) as cm:
            hash_and_encrypt(evidence)

        self.assertIn("Production trusted RFC 3161 timestamping failed", str(cm.exception))
        self.assertEqual(evidence.status, EvidenceStatus.FAILED)
        self.assertNotEqual(evidence.status, EvidenceStatus.STORED)
        self.assertNotEqual(evidence.status, EvidenceStatus.HASHED)

    # 13. Dev/Test Mock Mode Explicit Distinction
    @patch("infrastructure.integrity.timestamp_service._call_tsa_http")
    def test_dev_mock_mode_explicit_distinction(self, mock_call_tsa):
        mock_call_tsa.return_value = (None, "Offline TSA")
        os.environ["APP_ENV"] = "development"

        case = CaseSession(tenant_id="tenant-dev", created_by="dev-user")
        evidence = upload_evidence(b"dev log data", "dev.log", case.case_id, "dev-user")
        evidence = hash_and_encrypt(evidence)

        rec = evidence.timestamp_record
        self.assertIsNotNone(rec)
        self.assertEqual(rec.timestamp_source, "mock")
        self.assertTrue(rec.tsa_url.startswith("mock://"))

        decoded_token = base64.b64decode(rec.timestamp_token).decode("utf-8")
        self.assertTrue(decoded_token.startswith("MOCK_RFC3161_TOKEN:"))
        self.assertIn(evidence.sha256_hash, decoded_token)

    # 14 & 15. Immutability & Storage Separation Integration
    @patch("infrastructure.sandbox.intake_validator.run_docker_sandbox", return_value=[])
    @patch("infrastructure.sandbox.intake_validator.run_clamav_scan", return_value=[])
    @patch("infrastructure.integrity.timestamp_service._call_tsa_http")
    def test_full_pipeline_immutability_and_storage_separation(self, mock_tsa, mock_clamav, mock_docker):
        raw_evidence = b"Immutable original log bytes for full pipeline check"
        sha256_expected = hashlib.sha256(raw_evidence).hexdigest()
        fake_der = b"\x30\x40TSATokenHeader" + bytes.fromhex(sha256_expected) + b"Footer"
        mock_tsa.return_value = (fake_der, None)

        case = CaseSession(tenant_id="tenant-full", created_by="lead-analyst")
        evidence = upload_evidence(raw_evidence, "full.log", case.case_id, "lead-analyst")
        evidence = sandbox_validate(evidence)
        evidence = hash_and_encrypt(evidence)
        evidence = store_evidence(evidence, case)

        self.assertEqual(evidence.status, EvidenceStatus.STORED)
        self.assertEqual(evidence.sha256_hash, sha256_expected)

        # Original bytes intact in repository
        with open(evidence.original_repository_path, "rb") as f:
            self.assertEqual(f.read(), raw_evidence)

        # Encrypted representation exists separately
        self.assertTrue(os.path.exists(evidence.encrypted_repository_path))
        self.assertNotEqual(evidence.original_repository_path, evidence.encrypted_repository_path)

        # Timestamp record attached and verified
        self.assertIsNotNone(evidence.timestamp_record)
        self.assertTrue(verify_rfc3161_timestamp(evidence))

    # Optional Live TSA Integration Test (Skipped in normal test runs)
    @unittest.skipUnless(os.getenv("ARGUS_RUN_TSA_INTEGRATION_TESTS") == "1", "Live TSA integration test skipped unless ARGUS_RUN_TSA_INTEGRATION_TESTS=1")
    def test_live_tsa_integration(self):
        case = CaseSession(tenant_id="tenant-live", created_by="live-tester")
        evidence = upload_evidence(b"Live TSA test payload", "live.log", case.case_id, "live-tester")
        evidence = hash_and_encrypt(evidence)

        self.assertIsNotNone(evidence.timestamp_record)
        self.assertEqual(evidence.timestamp_record.timestamp_source, "tsa")
        self.assertTrue(verify_rfc3161_timestamp(evidence))


if __name__ == "__main__":
    unittest.main()
