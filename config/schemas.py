# Shared Pydantic data contracts (Evidence, CaseSession, EvidenceStatus)
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum

class EvidenceStatus(str, Enum):
    UPLOADED = 'UPLOADED'
    SANDBOXED = 'SANDBOXED'
    VALIDATION_FAILED = 'VALIDATION_FAILED'
    HASHED = 'HASHED'
    METADATA_EXTRACTED = 'METADATA_EXTRACTED'
    STORED = 'STORED'

class CustodyEntry(BaseModel):
    action: str
    actor: str
    timestamp: datetime
    notes: Optional[str] = None

class Evidence(BaseModel):
    evidence_id: str
    case_id: str
    filename: str
    file_path: str
    uploaded_by: str
    upload_timestamp: datetime
    status: EvidenceStatus = EvidenceStatus.UPLOADED
    sandbox_result: Optional[str] = None
    sha256_hash: Optional[str] = None
    encrypted: bool = False
    rfc3161_timestamp: Optional[str] = None
    metadata: dict = {}
    custody_log: List[CustodyEntry] = []
    repository_path: Optional[str] = None
    audit_log: List[str] = []

class CaseSession(BaseModel):
    case_id: str
    tenant_id: str
    created_at: datetime
    created_by: str
    status: str = 'pending'
