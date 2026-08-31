"""
Evidence Consolidation Schemas
==============================
Defines the canonical Pydantic v2 schemas for:
- UnifiedArtifact: Consolidated artifact representation with explicit separation of
  EVENT_IDENTITY vs. IOC_ENTITY_IDENTITY and deterministic identity metadata.
- ConflictRecord: Explicit conflict tracking record (UNRESOLVED status).
- CompletenessMetadata: Coverage tracking record across expected forensic sources.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Sequence, Any
from pydantic import BaseModel, Field, field_validator

from fir.schemas import FIRFinding, ReviewStatus


class UnifiedArtifact(BaseModel):
    """
    Consolidated Unified Artifact (UAI).

    Represents a deterministically grouped or deduplicated forensic artifact.
    Replaces undefined analytical confidence with explicit identity metadata:
    `identity_strength="DETERMINISTIC"`, `identity_method`, `identity_key`, and `source_count`.
    """
    unified_artifact_id:     str
    case_id:                 str
    tenant_id:               str
    canonical_artifact_type: str
    canonical_value:         str
    identity_category:       str                                      # "EVENT_IDENTITY" or "IOC_ENTITY_IDENTITY"
    identity_method:         str                                      # e.g. "SHA256_EXACT_MATCH", "CANONICAL_URL", "PROCESS_HOST_PID_TIME_CONTEXT"
    identity_strength:       str = "DETERMINISTIC"                    # Fixed certainty marker
    identity_key:            str                                      # SHA256 digest of (tenant_id, case_id, canonical_artifact_type, canonical_value)
    source_artifact_ids:     list[str]                                # Source artifact IDs (>= 1)
    source_fcr_ids:          list[str] = Field(default_factory=list)  # Supporting FCR IDs
    source_tools:            list[str] = Field(default_factory=list)  # Originating tools
    source_count:            int                                      # Number of unique source tools
    first_seen:              Optional[datetime] = None
    last_seen:              Optional[datetime] = None
    timestamp_semantics:     Optional[str]      = None
    provenance_reference:    str
    consolidation_algorithm: str = "argus_deterministic_v1"
    consolidation_version:   str = "1.0.0"
    created_at:              datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("unified_artifact_id")
    @classmethod
    def _validate_uai_id(cls, v: str) -> str:
        if not re.match(r"^UAI-[0-9]{5,}$", v):
            raise ValueError(f"Invalid unified_artifact_id '{v}'. Must match pattern ^UAI-[0-9]{{5,}}$")
        return v

    @field_validator("case_id", "tenant_id")
    @classmethod
    def _validate_non_empty_str(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("ID field cannot be empty.")
        return v.strip()

    @field_validator("identity_category")
    @classmethod
    def _validate_identity_category(cls, v: str) -> str:
        cleaned = v.strip().upper()
        if cleaned not in ("EVENT_IDENTITY", "IOC_ENTITY_IDENTITY"):
            raise ValueError(f"Invalid identity_category '{v}'. Must be EVENT_IDENTITY or IOC_ENTITY_IDENTITY")
        return cleaned

    @field_validator("source_artifact_ids")
    @classmethod
    def _validate_source_artifact_ids(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list) or len(v) < 1:
            raise ValueError("source_artifact_ids must contain at least 1 artifact ID.")
        cleaned = [str(x).strip() for x in v if str(x).strip()]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("source_artifact_ids contains duplicate artifact IDs.")
        return cleaned

    def to_fir_handoff(self, severity: str = "medium") -> FIRFinding:
        """
        Build FIRFinding object for handoff into existing FIRRepository.
        Does NOT create a second FIR database.
        """
        finding_num = self.unified_artifact_id.replace("UAI-", "")
        finding_id = f"FIR-UAI-{finding_num}"
        fact_summary = f"Consolidated {self.canonical_artifact_type} ({self.canonical_value}) from {self.source_count} tool(s)"

        return FIRFinding(
            finding_id=finding_id,
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            fact=fact_summary,
            confidence=1.0 if self.identity_strength == "DETERMINISTIC" else 0.8,
            severity=severity.strip().lower(),
            timestamp=self.created_at,
            evidence_reference=f"uai:{self.unified_artifact_id}",
            layer="evidence_consolidation",
            review_status=ReviewStatus.PENDING_REVIEW
        )


class ConflictRecord(BaseModel):
    """
    Explicit Conflict Preservation Record.

    Retains contradictory evidence (timestamps, hosts, PIDs, users) without silent resolution.
    """
    conflict_id:   str
    case_id:       str
    tenant_id:     str
    conflict_type: str                                           # "TIMESTAMP_CONFLICT", "HOST_CONFLICT", "PROCESS_CONFLICT", "USER_CONFLICT", "CLASSIFICATION_CONFLICT", "SOURCE_TOOL_CONFLICT"
    sources:       list[str]                                     # Source artifact or FCR IDs involved
    details:       dict[str, Any] = Field(default_factory=dict) # Conflicting values retained
    status:        str            = "UNRESOLVED"                 # Strictly UNRESOLVED
    created_at:    datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("conflict_id")
    @classmethod
    def _validate_conflict_id(cls, v: str) -> str:
        if not re.match(r"^CNF-[0-9]{5,}$", v):
            raise ValueError(f"Invalid conflict_id '{v}'. Must match pattern ^CNF-[0-9]{{5,}}$")
        return v

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str) -> str:
        if v.upper() != "UNRESOLVED":
            raise ValueError("Conflict status must be strictly UNRESOLVED.")
        return "UNRESOLVED"


class CompletenessMetadata(BaseModel):
    """
    Evidence Completeness & Coverage Tracking Metadata.
    """
    case_id:             str
    tenant_id:           str
    expected_categories: list[str]      = Field(default_factory=list)
    received_categories: list[str]      = Field(default_factory=list)
    parsed_categories:   list[str]      = Field(default_factory=list)
    failed_categories:   list[str]      = Field(default_factory=list)
    missing_categories:  list[str]      = Field(default_factory=list)
    category_statuses:   dict[str, str] = Field(default_factory=dict)
