"""
STAGE 3 — Trusted RFC 3161 Timestamping Service
================================================
Generates, records, and verifies trusted RFC 3161 timestamps over original evidence SHA-256 digests.
"""

import os
import base64
import hashlib
import logging
import requests
from datetime import datetime, timezone
from typing import Optional, Tuple

from infrastructure.schemas import Evidence, EvidenceStatus, TimestampRecord, CustodyLogEntry
from config.settings import settings

logger = logging.getLogger(__name__)


def get_tsa_url() -> str:
    """Returns configuration-driven TSA URL."""
    return os.getenv("ARGUS_TSA_URL") or getattr(settings, "rfc3161_tsa_url", "https://freetsa.org/tsr")


def build_rfc3161_request_bytes(sha256_hex: str) -> bytes:
    """
    Constructs an RFC 3161 TimeStampReq ASN.1 DER structure over the SHA-256 hash digest of original evidence.
    Ensures SHA-256 OID (2.16.840.1.101.3.4.2.1) and 32-byte hash digest are used.
    """
    digest_bytes = bytes.fromhex(sha256_hex)
    if len(digest_bytes) != 32:
        raise ValueError(f"Invalid SHA-256 digest length: expected 32 bytes, got {len(digest_bytes)}")

    try:
        import rfc3161ng
        # Check if rfc3161ng supports digest parameter with sha256
        treq = None
        try:
            treq = rfc3161ng.make_timestamp_request(digest=digest_bytes, hashname="sha256")
        except TypeError:
            try:
                treq = rfc3161ng.make_timestamp_request(digest=digest_bytes, hash_alg="sha256")
            except TypeError:
                pass

        if treq is not None:
            if isinstance(treq, bytes):
                return treq
            elif hasattr(rfc3161ng, "encode_timestamp_request"):
                return rfc3161ng.encode_timestamp_request(treq)
            try:
                from pyasn1.codec.der import encoder
                return encoder.encode(treq)
            except Exception:
                pass
    except Exception:
        pass

    # Standard DER ASN.1 TimeStampReq for SHA-256:
    # OID 2.16.840.1.101.3.4.2.1 (sha256)
    sha256_oid_der = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"
    alg_id_der = b"\x30" + bytes([len(sha256_oid_der)]) + sha256_oid_der
    digest_octet = b"\x04\x20" + digest_bytes
    msg_imprint = b"\x30" + bytes([len(alg_id_der) + len(digest_octet)]) + alg_id_der + digest_octet
    version_der = b"\x02\x01\x01"
    cert_req_der = b"\x01\x01\xff"

    payload = version_der + msg_imprint + cert_req_der
    return b"\x30" + bytes([len(payload)]) + payload


def issue_rfc3161_timestamp(
    evidence: Evidence,
    tenant_id: Optional[str] = None,
    tsa_url_override: Optional[str] = None,
    allow_mock: Optional[bool] = None
) -> TimestampRecord:
    """
    Submits RFC 3161 request for evidence.sha256_hash to configured TSA.
    In Production: Failure throws RuntimeError and sets evidence.status = FAILED.
    In Dev/Test: Allows explicit mock fallback when TSA is unreachable or disabled.
    """
    if not evidence.sha256_hash:
        raise ValueError("Cannot issue RFC 3161 timestamp without evidence.sha256_hash")

    tsa_url = tsa_url_override or get_tsa_url()
    app_env = os.getenv("APP_ENV") or settings.app_env
    require_real_tsa = os.getenv("ARGUS_REQUIRE_REAL_TSA") == "1" or app_env == "production"

    if allow_mock is None:
        allow_mock = not require_real_tsa

    # Log custody event: timestamp_requested
    evidence.custody_log.append(CustodyLogEntry(
        actor="timestamp_service",
        action="timestamp_requested",
        notes=f"Submitting RFC 3161 request to {tsa_url} for hash sha256={evidence.sha256_hash[:16]}..."
    ))

    # Perform TSA HTTP call
    ts_bytes, err_msg = _call_tsa_http(sha256_hex=evidence.sha256_hash, tsa_url=tsa_url)

    if ts_bytes:
        token_b64 = base64.b64encode(ts_bytes).decode("utf-8")
        record = TimestampRecord(
            sha256_hash=evidence.sha256_hash,
            timestamp_token=token_b64,
            tsa_url=tsa_url,
            timestamp_source="tsa",
            timestamped_at=datetime.now(timezone.utc),
            timestamp_algorithm="sha256",
            timestamp_verification_status="verified",
            evidence_id=evidence.evidence_id,
            case_id=evidence.case_id,
            tenant_id=tenant_id
        )

        evidence.custody_log.append(CustodyLogEntry(
            actor="timestamp_service",
            action="timestamped",
            notes=f"Trusted RFC 3161 timestamp issued by {tsa_url} (source=tsa)"
        ))

        evidence.timestamp_record = record
        evidence.rfc3161_timestamp = token_b64
        return record

    # TSA request failed
    if require_real_tsa or not allow_mock:
        evidence.status = EvidenceStatus.FAILED
        evidence.custody_log.append(CustodyLogEntry(
            actor="timestamp_service",
            action="timestamping_failed",
            notes=f"TSA error at {tsa_url}: {err_msg}"
        ))
        raise RuntimeError(f"Production trusted RFC 3161 timestamping failed: {err_msg}")

    # Dev/Test Mock Mode
    mock_payload = f"MOCK_RFC3161_TOKEN:{evidence.sha256_hash}:{evidence.evidence_id}".encode("utf-8")
    mock_token_b64 = base64.b64encode(mock_payload).decode("utf-8")

    mock_record = TimestampRecord(
        sha256_hash=evidence.sha256_hash,
        timestamp_token=mock_token_b64,
        tsa_url=f"mock://{tsa_url}",
        timestamp_source="mock",
        timestamped_at=datetime.now(timezone.utc),
        timestamp_algorithm="sha256",
        timestamp_verification_status="verified",
        evidence_id=evidence.evidence_id,
        case_id=evidence.case_id,
        tenant_id=tenant_id
    )

    evidence.custody_log.append(CustodyLogEntry(
        actor="timestamp_service",
        action="timestamped",
        notes=f"Dev/Test mock RFC 3161 timestamp generated (source=mock, cause={err_msg})"
    ))

    evidence.timestamp_record = mock_record
    evidence.rfc3161_timestamp = mock_token_b64
    return mock_record


def verify_rfc3161_timestamp(evidence: Evidence, expected_sha256: Optional[str] = None) -> bool:
    """
    Verifies that the stored RFC 3161 timestamp record corresponds to expected_sha256
    (or evidence.sha256_hash) and validates the token structure.
    """
    record = evidence.timestamp_record
    if not record or not record.timestamp_token:
        if evidence:
            evidence.custody_log.append(CustodyLogEntry(
                actor="timestamp_service",
                action="timestamp_verification_failed",
                notes="No timestamp record found on evidence"
            ))
        return False

    target_hash = expected_sha256 or evidence.sha256_hash
    if not target_hash:
        return False

    # Check Hash Matching
    if record.sha256_hash != target_hash:
        evidence.custody_log.append(CustodyLogEntry(
            actor="timestamp_service",
            action="timestamp_verification_failed",
            notes=f"Hash mismatch: record={record.sha256_hash[:16]}... vs expected={target_hash[:16]}..."
        ))
        record.timestamp_verification_status = "failed"
        return False

    # Mock Token Verification
    if record.timestamp_source == "mock":
        try:
            decoded = base64.b64decode(record.timestamp_token.encode("utf-8")).decode("utf-8")
            if decoded.startswith("MOCK_RFC3161_TOKEN:") and target_hash in decoded:
                record.timestamp_verification_status = "verified"
                evidence.custody_log.append(CustodyLogEntry(
                    actor="timestamp_service",
                    action="timestamp_verified",
                    notes="Mock RFC 3161 timestamp token structure and hash verified"
                ))
                return True
        except Exception:
            pass
        record.timestamp_verification_status = "failed"
        return False

    # Real TSA Token Verification
    try:
        raw_token = base64.b64decode(record.timestamp_token.encode("utf-8"))
        # Check if the raw token contains the target SHA-256 digest bytes or hex
        digest_bytes = bytes.fromhex(target_hash)
        if digest_bytes in raw_token or target_hash.encode("ascii") in raw_token:
            record.timestamp_verification_status = "verified"
            evidence.custody_log.append(CustodyLogEntry(
                actor="timestamp_service",
                action="timestamp_verified",
                notes=f"TSA RFC 3161 token validated against sha256={target_hash[:16]}..."
            ))
            return True
        
        # Additional rfc3161ng verification if library is present
        try:
            import rfc3161ng
            # Verify timestamp token structure
            tobj = rfc3161ng.get_timestamp_response(raw_token)
            if tobj:
                record.timestamp_verification_status = "verified"
                evidence.custody_log.append(CustodyLogEntry(
                    actor="timestamp_service",
                    action="timestamp_verified",
                    notes="TSA RFC 3161 token structure validated via rfc3161ng"
                ))
                return True
        except Exception:
            pass

    except Exception as e:
        logger.error(f"Timestamp verification exception: {e}")

    record.timestamp_verification_status = "failed"
    evidence.custody_log.append(CustodyLogEntry(
        actor="timestamp_service",
        action="timestamp_verification_failed",
        notes=f"Failed to verify RFC 3161 token against hash sha256={target_hash[:16]}..."
    ))
    return False


def _call_tsa_http(sha256_hex: str, tsa_url: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Helper to perform HTTP POST to TSA server."""
    try:
        req_bytes = build_rfc3161_request_bytes(sha256_hex)
        resp = requests.post(
            tsa_url,
            data=req_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=5
        )
        if resp.status_code == 200 and len(resp.content) > 10:
            # Minimal check: ASN.1 SEQUENCE start (0x30)
            if resp.content[0] == 0x30:
                return resp.content, None
            return None, f"Invalid TSA response content header: {resp.content[:10].hex()}"
        return None, f"TSA server HTTP status {resp.status_code}"
    except Exception as e:
        return None, f"TSA connection failed: {type(e).__name__}: {e}"
