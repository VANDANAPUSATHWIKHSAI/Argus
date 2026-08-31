"""
Forensic Analysis Layer — Shared Finding Schema & FIR Adapter
================================================================
Defines the canonical Finding model for deterministic forensic analysis engines,
and provides the conversion adapter to FIRFinding for FIR repository persistence.
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Any, List
from pydantic import BaseModel, Field, field_validator, model_validator

from fir.schemas import FIRFinding, ReviewStatus

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


class Finding(BaseModel):
    """
    Atomic Forensic Finding produced by a deterministic analysis engine.

    Traceable back to an FCR or raw Artifact via evidence_reference and source_artifact_id.
    """
    finding_id:                   str                = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id:                      str
    tenant_id:                    str                = "default"
    fact:                         str
    confidence:                   float              = Field(ge=0.0, le=1.0)
    severity:                     str
    mitre_mapping:                Optional[str]      = None
    timestamp:                    datetime           = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_reference:           str                # Primary FCR correlation_id or artifact_id
    source_artifact_id:           str                # Structurally required: underlying artifact ID
    layer:                        str
    contributing_correlation_ids: List[str]          = Field(default_factory=list)
    metadata:                     dict[str, Any]     = Field(default_factory=dict)

    @field_validator("case_id")
    @classmethod
    def _validate_case_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("case_id cannot be empty.")
        return v.strip()

    @field_validator("fact")
    @classmethod
    def _validate_fact(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("fact cannot be empty.")
        return v.strip()

    @field_validator("evidence_reference")
    @classmethod
    def _validate_evidence_reference(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("evidence_reference cannot be empty.")
        return v.strip()

    @field_validator("source_artifact_id")
    @classmethod
    def _validate_source_artifact_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("source_artifact_id cannot be empty.")
        return v.strip()

    @field_validator("layer")
    @classmethod
    def _validate_layer(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("layer cannot be empty.")
        return v.strip()

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if v_clean not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of {VALID_SEVERITIES}")
        return v_clean

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def _ensure_contributing_correlation_ids(self) -> Finding:
        """Ensure contributing_correlation_ids contains at least evidence_reference."""
        if not self.contributing_correlation_ids and self.evidence_reference:
            self.contributing_correlation_ids = [self.evidence_reference]
        elif self.evidence_reference and self.evidence_reference not in self.contributing_correlation_ids:
            self.contributing_correlation_ids.insert(0, self.evidence_reference)
        return self


def finding_to_fir(finding: Finding, tenant_id: Optional[str] = None) -> FIRFinding:
    """
    Adapter function converting a deterministic Finding into a FIRFinding.

    Passes finding.contributing_correlation_ids directly as a list[str].
    """
    eff_tenant = tenant_id or finding.tenant_id or "default"
    ev_refs = list(finding.contributing_correlation_ids) if finding.contributing_correlation_ids else [finding.evidence_reference]

    return FIRFinding(
        finding_id=finding.finding_id,
        case_id=finding.case_id,
        tenant_id=eff_tenant,
        fact=finding.fact,
        confidence=finding.confidence,
        severity=finding.severity,
        mitre_mapping=finding.mitre_mapping,
        timestamp=finding.timestamp,
        evidence_reference=ev_refs,
        layer=finding.layer,
        review_status=ReviewStatus.PENDING_REVIEW,
    )
