"""
Finding Revision & Correction Schemas
======================================
Defines strongly typed data structures for append-only forensic finding corrections.
Preserves historical raw findings while establishing cryptographic and analytical traceability.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CorrectionStatus(str, Enum):
    PROPOSED = "proposed"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    REJECTED = "rejected"


class FindingCorrectionRecord(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    revision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_finding_id: str
    case_id: str
    tenant_id: str
    original_wording: str
    corrected_interpretation: str
    correction_reason: str
    parser_analyzer_name: str
    parser_version: str
    evidence_references: List[str] = Field(default_factory=list)
    correction_status: CorrectionStatus = CorrectionStatus.PROPOSED
    reviewer_identity: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    previous_revision_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
