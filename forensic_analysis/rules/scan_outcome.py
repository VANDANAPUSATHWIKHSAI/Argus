"""
Deterministic Forensic Rules — Scan Outcome Semantics
======================================================
Defines typed scan statuses and execution telemetry records for Sigma and YARA engines.
Guarantees distinct representation between clean zero-matches, missing rules, syntax errors,
unsupported input types, safety resource limits, engine unavailability, and execution failures.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """
    Distinct semantic scan execution statuses.
    Ensures missing rules or syntax errors never silently appear as zero-match scans.
    """
    MATCHES_FOUND            = "MATCHES_FOUND"
    ZERO_MATCHES             = "ZERO_MATCHES"
    MISSING_RULE_CONFIG      = "MISSING_RULE_CONFIG"
    INVALID_RULE_SYNTAX      = "INVALID_RULE_SYNTAX"
    UNSUPPORTED_EVIDENCE_TYPE= "UNSUPPORTED_EVIDENCE_TYPE"
    RESOURCE_LIMIT_EXCEEDED  = "RESOURCE_LIMIT_EXCEEDED"
    ENGINE_UNAVAILABLE       = "ENGINE_UNAVAILABLE"
    EXECUTION_FAILURE        = "EXECUTION_FAILURE"


class ScanExecutionRecord(BaseModel):
    """
    Provenance and telemetry record for a Sigma or YARA scan execution.
    """
    engine_name: str
    status: ScanStatus
    rule_count: int = 0
    rule_identifiers: List[str] = Field(default_factory=list)
    rules_hash: Optional[str] = None
    engine_version: Optional[str] = None
    source_evidence_ids: List[str] = Field(default_factory=list)
    artifact_id: Optional[str] = None
    matches_count: int = 0
    error_message: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_success(self) -> bool:
        """Returns True if the scan completed properly (with or without matches)."""
        return self.status in (ScanStatus.MATCHES_FOUND, ScanStatus.ZERO_MATCHES)
