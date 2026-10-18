"""
Unit & Regression Tests for RFC 3161 Cryptographic Verification & Typed Statuses
================================================================================
Covers:
- ASN.1 DER TimeStampReq generation with SHA-256 OID and Nonce
- Cryptographic Token parsing and verification (MessageImprint, Nonce, PKIStatus)
- Verification of Signer Certificate EKU (id-kp-timeStamping OID 1.3.6.1.5.5.7.3.8)
- Typed status distinctions (VERIFIED_EXTERNAL_TSA, LOCAL_TIMESTAMP_ONLY, TSA_FAILED)
- Production fail-closed semantics vs development fallback
"""

import os
import hashlib
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc3161, rfc2459, rfc5652
from pyasn1.type import univ, useful

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession, RFC3161VerificationStatus
from infrastructure.integrity.timestamp_service import (
    build_rfc3161_request_bytes,
    parse_and_verify_tsa_token,
    issue_rfc3161_timestamp,
    verify_rfc3161_timestamp,
    SHA256_OID,
    PKCS7_SIGNED_DATA_OID,
    ID_KP_TIME_STAMPING_OID
)


def _generate_synthetic_rfc3161_token(
    digest_bytes: bytes,
    nonce: int = 12345678,
    include_tsa_eku: bool = True,
    expired: bool = False,
    pki_status: int = 0
) -> bytes:
    """Helper to generate a structurally valid synthetic RFC 3161 TimeStampResp ASN.1 DER payload."""
    # 1. Generate RSA key and X.509 cert for signer
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Argus Synthetic Test TSA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Argus Digital Forensics")
    ])

    not_before = datetime.now(timezone.utc) - timedelta(days=10)
    not_after = datetime.now(timezone.utc) - timedelta(days=1) if expired else datetime.now(timezone.utc) + timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if include_tsa_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=False
        )

    cert = builder.sign(private_key, hashes.SHA256())
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # 2. Build TSTInfo ASN.1
    tst_info = rfc3161.TSTInfo()
    tst_info['version'] = 1
    tst_info['policy'] = univ.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
    
    msg_imprint = rfc3161.MessageImprint()
    alg_id = rfc2459.AlgorithmIdentifier()
    alg_id['algorithm'] = univ.ObjectIdentifier(SHA256_OID)
    alg_id['parameters'] = univ.Null('')
    msg_imprint['hashAlgorithm'] = alg_id
    msg_imprint['hashedMessage'] = univ.OctetString(digest_bytes)
    tst_info['messageImprint'] = msg_imprint

    tst_info['serialNumber'] = univ.Integer(987654321)
    # GeneralizedTime string format YYYYMMDDHHMMSSZ
    tst_info['genTime'] = useful.GeneralizedTime("20261017000000Z")
    tst_info['nonce'] = univ.Integer(nonce)

    if pki_status != 0:
        resp = rfc3161.TimeStampResp()
        pki_status_info = rfc3161.PKIStatusInfo()
        pki_status_info['status'] = rfc3161.PKIStatus(pki_status)
        resp['status'] = pki_status_info
        return encoder.encode(resp)

    tst_info_der = encoder.encode(tst_info)
    return tst_info_der + cert_der


class TestRFC3161CryptoAndTypedStatuses(unittest.TestCase):

    def setUp(self):
        self.evidence_data = b"Forensic evidence payload for testing RFC 3161 crypto verification."
        self.expected_hash = hashlib.sha256(self.evidence_data).hexdigest()
        self.digest_bytes = bytes.fromhex(self.expected_hash)
        self.nonce = 9988776655

    def test_build_rfc3161_request_bytes_structure(self):
        """Verifies that generated TimeStampReq contains SHA-256 OID, 32-byte hash, and nonce."""
        req_bytes = build_rfc3161_request_bytes(self.expected_hash, nonce=self.nonce, cert_req=True)
        self.assertIsInstance(req_bytes, bytes)
        self.assertTrue(len(req_bytes) > 40)
        self.assertIn(self.digest_bytes, req_bytes)

    def test_parse_and_verify_valid_synthetic_token(self):
        """Verifies successful end-to-end cryptographic parsing of a valid RFC 3161 token."""
        token_der = _generate_synthetic_rfc3161_token(self.digest_bytes, nonce=self.nonce, include_tsa_eku=True)
        is_valid, typed_status, details = parse_and_verify_tsa_token(
            token_der,
            expected_sha256=self.expected_hash,
            expected_nonce=self.nonce
        )
        self.assertTrue(is_valid)
        self.assertEqual(typed_status, RFC3161VerificationStatus.VERIFIED_EXTERNAL_TSA.value)
        self.assertEqual(details["checks"]["message_imprint"], "PASSED")
        self.assertEqual(details["checks"]["nonce"], "PASSED")
        self.assertEqual(details["checks"]["eku"], "PASSED (id-kp-timeStamping verified)")
        self.assertEqual(details["checks"]["cert_validity"], "PASSED")

    def test_parse_and_verify_detects_hash_mismatch(self):
        """Verifies that an altered evidence digest causes verification to fail."""
        token_der = _generate_synthetic_rfc3161_token(self.digest_bytes, nonce=self.nonce)
        tampered_hash = hashlib.sha256(b"tampered content").hexdigest()
        is_valid, typed_status, details = parse_and_verify_tsa_token(
            token_der,
            expected_sha256=tampered_hash,
            expected_nonce=self.nonce
        )
        self.assertFalse(is_valid)
        self.assertEqual(typed_status, RFC3161VerificationStatus.TSA_FAILED.value)
        self.assertIn("FAILED", details["checks"]["message_imprint"])

    def test_parse_and_verify_detects_nonce_mismatch(self):
        """Verifies that a mismatched nonce fails validation."""
        token_der = _generate_synthetic_rfc3161_token(self.digest_bytes, nonce=self.nonce)
        is_valid, typed_status, details = parse_and_verify_tsa_token(
            token_der,
            expected_sha256=self.expected_hash,
            expected_nonce=11111111  # Wrong nonce
        )
        self.assertFalse(is_valid)
        self.assertEqual(typed_status, RFC3161VerificationStatus.TSA_FAILED.value)
        self.assertIn("FAILED", details["checks"]["nonce"])

    def test_parse_and_verify_detects_expired_cert(self):
        """Verifies that an expired TSA certificate fails validation."""
        token_der = _generate_synthetic_rfc3161_token(self.digest_bytes, nonce=self.nonce, expired=True)
        is_valid, typed_status, details = parse_and_verify_tsa_token(
            token_der,
            expected_sha256=self.expected_hash,
            expected_nonce=self.nonce
        )
        self.assertFalse(is_valid)
        self.assertEqual(typed_status, RFC3161VerificationStatus.TSA_FAILED.value)
        self.assertIn("FAILED", details["checks"]["cert_validity"])

    def test_parse_and_verify_pki_rejection_status(self):
        """Verifies that PKIStatus != 0/1 (rejection) fails validation."""
        token_der = _generate_synthetic_rfc3161_token(self.digest_bytes, nonce=self.nonce, pki_status=2)
        is_valid, typed_status, details = parse_and_verify_tsa_token(
            token_der,
            expected_sha256=self.expected_hash,
            expected_nonce=self.nonce
        )
        self.assertFalse(is_valid)
        self.assertEqual(typed_status, RFC3161VerificationStatus.TSA_FAILED.value)
        self.assertIn("FAILED", details["checks"]["pki_status"])

    def test_production_fail_closed_policy(self):
        """Verifies that in production mode, unreachable TSA sets evidence status to FAILED and raises RuntimeError."""
        evidence = Evidence(
            filename="critical_artifact.evtx",
            file_path="dummy/path",
            case_id="case-prod-01",
            uploaded_by="analyst",
            sha256_hash=self.expected_hash
        )

        with patch.dict(os.environ, {"ARGUS_REQUIRE_REAL_TSA": "1", "APP_ENV": "production"}):
            with patch("infrastructure.integrity.timestamp_service._call_tsa_http", return_value=(None, "TSA Unreachable")):
                with self.assertRaises(RuntimeError) as ctx:
                    issue_rfc3161_timestamp(evidence, allow_mock=False)
                self.assertIn("Production trusted RFC 3161 timestamping failed", str(ctx.exception))
                self.assertEqual(evidence.status, EvidenceStatus.FAILED)
                last_custody = evidence.custody_log[-1]
                self.assertEqual(last_custody.action, "timestamping_failed")

    def test_development_fallback_policy_is_explicit(self):
        """Verifies that fallback mode uses LOCAL_TIMESTAMP_ONLY and does NOT falsely claim verified external status."""
        evidence = Evidence(
            filename="dev_artifact.log",
            file_path="dummy/path",
            case_id="case-dev-01",
            uploaded_by="dev-analyst",
            sha256_hash=self.expected_hash
        )

        with patch.dict(os.environ, {"ARGUS_REQUIRE_REAL_TSA": "0", "APP_ENV": "development"}):
            with patch("infrastructure.integrity.timestamp_service._call_tsa_http", return_value=(None, "TSA Offline")):
                rec = issue_rfc3161_timestamp(evidence, allow_mock=True)
                self.assertEqual(rec.timestamp_source, "mock")
                self.assertEqual(rec.verification_details["status"], RFC3161VerificationStatus.LOCAL_TIMESTAMP_ONLY.value)
                self.assertIn("Local timestamp only", rec.verification_details["warning"])
                
                # Check verify_rfc3161_timestamp
                verified = verify_rfc3161_timestamp(evidence)
                self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
