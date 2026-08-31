"""
Forensic Correlation Record (FCR) Schema
=========================================
Defines the canonical CorrelationRecord model for Stage 3 FCR Engine.
Satisfies the Forensic Correlation Record Format contract.
"""

from __future__ import annotations

import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator, model_validator


SUPPORTED_RELATIONSHIP_TYPES = {
    "temporal_proximity",
    "shared_ioc",
    "process_tree",
    "network_process",
}


def compute_confidence(distinct_artifact_types: int, source_count: int) -> float:
    """
    Compute deterministic correlation confidence score based on the canonical reference formula:
    min(1.0, 0.30 + 0.15 * (distinct_artifact_types - 1) + 0.20 * (source_count - 1))
    """
    dt_count = max(1, distinct_artifact_types)
    sc_count = max(1, source_count)
    score = 0.30 + 0.15 * (dt_count - 1) + 0.20 * (sc_count - 1)
    return round(min(1.0, max(0.0, score)), 4)


class CorrelationRecord(BaseModel):
    """
    Atomic Forensic Correlation Record (FCR).

    Links 2 or more Stage-2 normalized artifacts together under a specific rule-based relationship.
    """
    correlation_id:          str
    case_id:                 str
    artifact_ids:            list[str]
    relationship_type:       list[str]
    source_count:            int                                      # Number of distinct source_tools (>= 1)
    distinct_artifact_types: int                                      # Number of distinct artifact_types (>= 1)
    confidence:              float                                    # Score: 0.0 <= confidence <= 1.0
    host:                    Optional[str]      = None                # Required if temporal_proximity in relationship_type
    shared_value:            Optional[str]      = None                # Required if shared_ioc in relationship_type
    strategy_params:         dict               = Field(default_factory=dict)
    created_at:              datetime           = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("correlation_id")
    @classmethod
    def _validate_correlation_id(cls, v: str) -> str:
        if not re.match(r"^CORR-[0-9]{5,}$", v):
            raise ValueError(f"Invalid correlation_id '{v}'. Must match pattern ^CORR-[0-9]{{5,}}$")
        return v

    @field_validator("case_id")
    @classmethod
    def _validate_case_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("case_id cannot be empty.")
        return v.strip()

    @field_validator("artifact_ids")
    @classmethod
    def _validate_artifact_ids(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list) or len(v) < 2:
            raise ValueError("artifact_ids must contain at least 2 artifact IDs.")
        cleaned = [str(x).strip() for x in v if str(x).strip()]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("artifact_ids must contain unique artifact IDs (duplicates detected).")
        if len(cleaned) < 2:
            raise ValueError("artifact_ids must contain at least 2 non-empty unique artifact IDs.")
        return cleaned

    @field_validator("relationship_type")
    @classmethod
    def _validate_relationship_type(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list) or not v:
            raise ValueError("relationship_type must be a non-empty list of relationship strings.")
        cleaned = list(dict.fromkeys([str(x).strip() for x in v if str(x).strip()]))
        invalid = [x for x in cleaned if x not in SUPPORTED_RELATIONSHIP_TYPES]
        if invalid:
            raise ValueError(f"Invalid relationship_type(s): {invalid}. Must be subset of {SUPPORTED_RELATIONSHIP_TYPES}")
        return cleaned

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {v}")
        return round(float(v), 4)

    @field_validator("source_count")
    @classmethod
    def _validate_source_count(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"source_count must be >= 1, got {v}")
        return int(v)

    @field_validator("distinct_artifact_types")
    @classmethod
    def _validate_distinct_artifact_types(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"distinct_artifact_types must be >= 1, got {v}")
        return int(v)

    @model_validator(mode="after")
    def _validate_relationship_requirements(self) -> CorrelationRecord:
        rel_types = set(self.relationship_type)
        if "temporal_proximity" in rel_types and not self.host:
            raise ValueError("temporal_proximity relationship requires 'host' field to be set.")
        if "shared_ioc" in rel_types and not self.shared_value:
            raise ValueError("shared_ioc relationship requires 'shared_value' field to be set.")
        return self
