"""
OWNER: Person 3
STAGE: SHA-256 Hash + Encrypt

INPUT:  an Evidence object with status=SANDBOXED (never call this on
        something that failed sandboxing)
OUTPUT: the same Evidence, with sha256_hash, encrypted=True, and (stretch
        goal) rfc3161_timestamp filled in, status updated to HASHED

Goal for a first working version:
  - Compute SHA-256 of the file at evidence.file_path -- Python's hashlib
    covers this, no external library needed
  - "Encrypt" can start as something simple (e.g. Fernet from the
    `cryptography` package) -- the point for day one is that the field gets
    set and the pipeline flows, not that it's production-grade crypto yet
  - RFC 3161 timestamping (proves WHEN the hash was created) is a real
    stretch goal -- skip it for the first working version and leave
    rfc3161_timestamp as None, note it as a follow-up
"""

import hashlib
from infrastructure.schemas import Evidence, EvidenceStatus


def hash_and_encrypt(evidence: Evidence) -> Evidence:
    # TODO (Person 3):
    #   1. Read the file at evidence.file_path, compute SHA-256
    #   2. Encrypt the file (simple symmetric encryption is fine to start)
    #   3. Fill in evidence.sha256_hash, evidence.encrypted
    #   4. Set evidence.status = EvidenceStatus.HASHED

    raise NotImplementedError("hash_and_encrypt: Person 3 to implement")

    # Example of what you're building toward:
    # with open(evidence.file_path, "rb") as f:
    #     evidence.sha256_hash = hashlib.sha256(f.read()).hexdigest()
    # evidence.encrypted = True   # once you've actually encrypted the file
    # evidence.status = EvidenceStatus.HASHED
    # return evidence
