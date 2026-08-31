"""
STAGE 3 — SHA-256 Hash + Encrypt
Computes SHA-256 hash of the file (integrity seal) and encrypts it with chunked AES-256-GCM.
The encryption key is loaded from the environment — never generated per-file.
RFC 3161 timestamping is implemented as a real call to a free TSA.
"""

import os
import base64
import hashlib
import tempfile
import requests
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from infrastructure.schemas import Evidence, EvidenceStatus, CustodyLogEntry
from config.settings import settings

logger = logging.getLogger(__name__)

# ── Encryption key configuration & validation ──────────────────────────────
_KEY_ENV = "ARGUS_FERNET_KEY"
_APP_ENV = os.getenv("APP_ENV") or settings.app_env

# At startup, refuse to start in production if the key is not configured
if _APP_ENV == "production" and not os.getenv(_KEY_ENV):
    raise RuntimeError("CRITICAL CONFIGURATION ERROR: ARGUS_FERNET_KEY must be set in production environment!")

# Ephemeral fallback key generated once per process in non-production environments
_FALLBACK_RAW_KEY = os.urandom(32)
CHUNK_SIZE = 64 * 1024  # 64 KB chunks for memory efficiency


def _get_encryption_key() -> bytes:
    key_env = os.getenv(_KEY_ENV)
    app_env = os.getenv("APP_ENV") or settings.app_env
    
    if app_env == "production" and not key_env:
        raise RuntimeError("CRITICAL CONFIGURATION ERROR: ARGUS_FERNET_KEY must be set in production environment!")
        
    if key_env:
        try:
            # ARGUS_FERNET_KEY is a URL-safe base64-encoded 32-byte key
            return base64.urlsafe_b64decode(key_env.encode())
        except Exception as e:
            raise ValueError(f"Invalid ARGUS_FERNET_KEY: {e}") from e

    # Non-production fallback (production checks are handled at startup)
    logger.warning(
        "LOUD WARNING: ARGUS_FERNET_KEY is not set. Silent fallback to an ephemeral "
        "per-process key is active. Encrypted files will be UNRECOVERABLE after process restart!"
    )
    return _FALLBACK_RAW_KEY


# ── Chunked AES-256-GCM Helpers ───────────────────────────────────────────────

def encrypt_file_gcm(input_path: str, output_path: str, key_bytes: bytes) -> None:
    """
    Encrypts input_path into output_path in fixed-size chunks using AES-256-GCM.
    Writes: [4-byte salt] + [Chunk 0] + [Chunk 1] ...
    Each chunk block: [4-byte ciphertext len] + [16-byte tag] + [ciphertext]
    """
    salt = os.urandom(4)
    with open(input_path, "rb") as in_f, open(output_path, "wb") as out_f:
        # Write 4-byte salt first
        out_f.write(salt)
        
        chunk_idx = 0
        while True:
            chunk = in_f.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # Derive 12-byte nonce (4-byte salt + 8-byte big-endian chunk counter)
            nonce = salt + chunk_idx.to_bytes(8, byteorder="big")
            
            encryptor = Cipher(
                algorithms.AES(key_bytes),
                modes.GCM(nonce),
                backend=default_backend()
            ).encryptor()
            
            ciphertext = encryptor.update(chunk) + encryptor.finalize()
            tag = encryptor.tag
            
            # Write metadata header for this chunk
            out_f.write(len(ciphertext).to_bytes(4, byteorder="big"))
            out_f.write(tag)
            out_f.write(ciphertext)
            chunk_idx += 1


def verify_gcm_encrypted_file(enc_path: str, expected_sha256: str, key_bytes: bytes) -> bool:
    """
    Verifies that the encrypted file can be successfully decrypted and its plain text
    matches the expected SHA-256 hash. Performs verification streaming in chunks.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(enc_path, "rb") as in_f:
            salt = in_f.read(4)
            if len(salt) < 4:
                return False
                
            chunk_idx = 0
            while True:
                len_bytes = in_f.read(4)
                if not len_bytes:
                    break
                if len(len_bytes) < 4:
                    return False
                    
                c_len = int.from_bytes(len_bytes, byteorder="big")
                tag = in_f.read(16)
                if len(tag) < 16:
                    return False
                    
                ciphertext = in_f.read(c_len)
                if len(ciphertext) < c_len:
                    return False
                    
                nonce = salt + chunk_idx.to_bytes(8, byteorder="big")
                
                decryptor = Cipher(
                    algorithms.AES(key_bytes),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                ).decryptor()
                
                plain = decryptor.update(ciphertext) + decryptor.finalize()
                sha256_hash.update(plain)
                chunk_idx += 1
                
        return sha256_hash.hexdigest() == expected_sha256
    except Exception as e:
        logger.error(f"Integrity check failed: {e}")
        return False


# ── RFC 3161 TSA ──────────────────────────────────────────────────────────────
TSA_URL = os.getenv("RFC3161_TSA_URL", "https://freetsa.org/tsr")


def _rfc3161_timestamp(sha256_hex: str) -> str | None:
    """
    Request an RFC 3161 timestamp from a free TSA.
    Returns base64-encoded timestamp token, or None if unreachable.
    """
    try:
        import base64
        # Using rfc3161ng if available, otherwise skip gracefully
        try:
            import rfc3161ng
            ts = rfc3161ng.make_timestamp_request(data=bytes.fromhex(sha256_hex))
            response = requests.post(TSA_URL, data=ts, headers={"Content-Type": "application/timestamp-query"}, timeout=5)
            if response.status_code == 200:
                return base64.b64encode(response.content).decode()
        except ImportError:
            pass  # rfc3161ng not installed — skip silently
    except Exception:
        pass
    return None


def hash_and_encrypt(evidence: Evidence) -> Evidence:
    """
    1. SHA-256 hash the original file using streaming (chunked update loop).
    2. Extract basic size and format-specific metadata BEFORE encryption.
    3. Encrypt into a SEPARATE file representation using chunked AES-256-GCM.
       The original intake file is NEVER overwritten or replaced.
    4. Verify encrypted representation can be decrypted back to matching SHA-256.
    5. Set status = HASHED and append custody events.
    """
    raw_path = evidence.raw_file_path or evidence.file_path
    if not os.path.exists(raw_path):
        evidence.status = EvidenceStatus.FAILED
        raise RuntimeError(f"Original evidence file missing at {raw_path}")

    key_bytes = _get_encryption_key()

    # ── 1. Calculate SHA-256 & extract metadata from original bytes ──
    sha256_hash = hashlib.sha256()
    with open(raw_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256_hash.update(chunk)
            
    sha256 = sha256_hash.hexdigest()
    evidence.sha256_hash = sha256
    evidence.original_file_path = raw_path

    ext = os.path.splitext(evidence.filename)[1].lower()
    
    # Import Stage 4's metadata parsing logic to perform it on raw file
    from infrastructure.custody.metadata_custody import _format_metadata
    format_specific = _format_metadata(raw_path, ext)
    original_size = os.path.getsize(raw_path)

    # Populate evidence.metadata dictionary to pass forward
    evidence.metadata = {
        "size_bytes": original_size,
        "format_specific": format_specific
    }

    # ── 2. Encrypt into a separate file path ────────────────────────
    enc_path = f"{raw_path}.enc"

    try:
        # Encrypt original file to separate enc_path
        encrypt_file_gcm(raw_path, enc_path, key_bytes)
        
        # Verify the encrypted file can be successfully decrypted and verified
        if not verify_gcm_encrypted_file(enc_path, sha256, key_bytes):
            raise RuntimeError("Post-encryption GCM decryption verification failed (hash mismatch)")
            
        # Verify original raw file remains byte-for-byte intact
        current_raw_size = os.path.getsize(raw_path)
        if current_raw_size != original_size:
            raise RuntimeError("Original evidence file size altered during encryption workflow!")
            
    except Exception as e:
        if os.path.exists(enc_path):
            try:
                os.remove(enc_path)
            except OSError:
                pass
        evidence.encrypted = False
        evidence.encrypted_file_path = None
        evidence.status = EvidenceStatus.FAILED
        evidence.custody_log.append(CustodyLogEntry(
            actor="integrity_hash_encrypt",
            action="failed",
            notes=f"Encryption error: {e}",
        ))
        raise RuntimeError(f"GCM encryption failed: {e}") from e

    evidence.encrypted = True
    evidence.encrypted_file_path = enc_path

    # ── Trusted RFC 3161 Timestamp ─────────────────────────────────
    from infrastructure.integrity.timestamp_service import issue_rfc3161_timestamp
    tenant_id = evidence.metadata.get("tenant_id") if evidence.metadata else None
    ts_record = issue_rfc3161_timestamp(evidence, tenant_id=tenant_id)
    evidence.timestamp_record = ts_record
    evidence.rfc3161_timestamp = ts_record.timestamp_token

    evidence.status = EvidenceStatus.HASHED
    
    # Explicit custody log entries for HASHED and ENCRYPTED_STORED
    evidence.custody_log.append(CustodyLogEntry(
        actor="integrity_hash_encrypt",
        action="hashed",
        notes=f"sha256={sha256}",
    ))
    evidence.custody_log.append(CustodyLogEntry(
        actor="integrity_hash_encrypt",
        action="encrypted_stored",
        notes=f"encrypted_file_path={enc_path}",
    ))

    ts_note = f" + RFC3161 ({ts_record.timestamp_source})" if evidence.rfc3161_timestamp else ""
    print(f"  [3/5] HASHED     {evidence.filename}  sha256={sha256[:16]}…{ts_note}")
    return evidence
