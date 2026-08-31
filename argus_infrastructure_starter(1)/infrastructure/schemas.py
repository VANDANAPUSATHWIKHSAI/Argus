"""
Shared contract for the Infrastructure Layer.

Every sub-component (upload, sandbox, integrity, custody, storage) reads and
writes THIS SAME Evidence object, filling in more fields as it moves along.
Nobody invents their own shape for evidence data -- if a field is missing,
add it here first and tell the team, don't quietly rename something.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class EvidenceStatus(str, Enum):
    """Where a piece of evidence currently is in the Infrastructure Layer."""
    UPLOADED = "uploaded"                     # after Person 1's stage
    SANDBOXED = "sandboxed"                    # after Person 2's stage (passed)
    VALIDATION_FAILED = "validation_failed"    # after Person 2's stage (failed -- pipeline stops)
    HASHED = "hashed"                          # after Person 3's stage
    METADATA_EXTRACTED = "metadata_extracted"  # after Person 4's stage
    STORED = "stored"                          # after Person 5's stage -- Infrastructure Layer is DONE
    FAILED = "failed"                          # any unrecoverable error, any stage


class CustodyLogEntry(BaseModel):
    """One line in the evidentiary chain of custody. Append-only -- never edit past entries."""
    actor: str                      # which component/person/analyst performed the action
    action: str                     # e.g. "uploaded", "sandbox_validated", "hashed", "stored"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None


class AuditLogEntry(BaseModel):
    """Operational log entry -- distinct from the evidentiary custody log above."""
    event: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: Optional[str] = None
    detail: Optional[dict] = None


class SandboxResult(BaseModel):
    """Output of Person 2's isolated microVM validation."""
    passed: bool
    flags: list[str] = []           # e.g. ["zip_bomb_suspected"] -- empty list if clean
    execution_time_ms: Optional[int] = None


class CaseSession(BaseModel):
    """One investigation. Created once, referenced by every piece of evidence in it."""
    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str
    status: str = "open"            # open / closed / archived


class Evidence(BaseModel):
    """
    The one object that flows through every sub-component of the Infrastructure Layer.
    Fields are grouped by which person's stage fills them in -- see the comments.
    """
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    filename: str
    file_path: str                  # location of the raw bytes on disk
    uploaded_by: str
    upload_timestamp: datetime = Field(default_factory=datetime.utcnow)
    status: EvidenceStatus = EvidenceStatus.UPLOADED

    # --- Person 2: Sandboxed Intake Validation ---
    sandbox_result: Optional[SandboxResult] = None

    # --- Person 3: SHA-256 Hash + Encrypt ---
    sha256_hash: Optional[str] = None
    encrypted: bool = False
    rfc3161_timestamp: Optional[str] = None

    # --- Person 4: Metadata Extraction + Chain of Custody ---
    metadata: dict = {}
    custody_log: list[CustodyLogEntry] = []

    # --- Person 5: Case ID/Session, Original Evidence Repository, Audit Logging ---
    repository_path: Optional[str] = None
    audit_log: list[AuditLogEntry] = []
