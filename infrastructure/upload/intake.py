"""
STAGE 1 — Evidence Upload
Accepts raw file bytes, saves to temp intake directory in chunks, returns Evidence object.
Protects against path traversal.
"""

import os
import uuid
from pathlib import Path
from infrastructure.schemas import Evidence, EvidenceStatus, CustodyLogEntry

INTAKE_DIR = os.getenv("ARGUS_INTAKE_DIR", "data/intake")


def sanitize_segment(val: str, name: str) -> str:
    """Validates segment to prevent path traversal. Raises ValueError on violation."""
    if not val:
        raise ValueError(f"{name} cannot be empty.")
    if ".." in val or "/" in val or "\\" in val:
        raise ValueError(f"Path traversal or invalid characters detected in {name}: {val}")
    cleaned = val.strip().strip(".")
    if not cleaned:
        raise ValueError(f"{name} resolved to empty after sanitization.")
    return cleaned


def upload_evidence(file_bytes: bytes, filename: str, case_id: str, uploaded_by: str) -> Evidence:
    """
    Write the raw bytes to a temp intake location using streaming chunks and return an Evidence object.
    Protects against path traversal and generates a safe uuid-based storage filename.
    """
    # ── Path Traversal Validation (Task 3) ──────────────────────
    sanitized_case_id = sanitize_segment(case_id, "case_id")
    sanitized_filename = sanitize_segment(filename, "filename")

    evidence_id = str(uuid.uuid4())
    ext = os.path.splitext(sanitized_filename)[1].lower()
    safe_filename = f"{evidence_id}{ext}"

    intake_path = Path(INTAKE_DIR) / sanitized_case_id
    intake_path.mkdir(parents=True, exist_ok=True)
    file_path = str(intake_path / safe_filename)

    # ── Streaming chunked write to disk (Task 6) ──────────────────
    CHUNK_SIZE = 64 * 1024  # 64 KB
    with open(file_path, "wb") as f:
        if hasattr(file_bytes, "read"):
            while True:
                chunk = file_bytes.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
        else:
            for i in range(0, len(file_bytes), CHUNK_SIZE):
                f.write(file_bytes[i:i+CHUNK_SIZE])

    evidence = Evidence(
        evidence_id=evidence_id,
        case_id=case_id,
        filename=filename,
        file_path=file_path,
        original_file_path=file_path,
        uploaded_by=uploaded_by,
        status=EvidenceStatus.UPLOADED,
    )

    evidence.custody_log.append(CustodyLogEntry(
        actor="upload_intake",
        action="uploaded",
        notes=f"Saved raw bytes to {file_path}",
    ))

    print(f"  [1/5] UPLOADED   {filename} -> {file_path}")
    return evidence
