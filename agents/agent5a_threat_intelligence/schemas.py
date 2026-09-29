from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"


class FeedState(str, Enum):
    HEALTHY = "healthy"
    NO_MATCH = "no_match"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    STALE = "stale"
    MALFORMED = "malformed"
    ERROR = "error"


class SanitizationSummary(BaseModel):
    fields_sanitized: int = 0
    injection_flags: int = 0
    blocked_fields: int = 0


class Indicator(BaseModel):
    value: str
    normalized_value: str
    indicator_type: IndicatorType
    finding_ids: List[str] = Field(default_factory=list)


class Provenance(BaseModel):
    source: str
    source_record_id: Optional[str] = None
    finding_ids: List[str] = Field(default_factory=list)
    indicator: str
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidationResult(BaseModel):
    citation_valid: bool
    provenance_valid: bool
    external_is_enrichment_only: bool = True
    notes: List[str] = Field(default_factory=list)


class ThreatMatch(BaseModel):
    indicator: Indicator
    source: str
    match_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[float] = None
    tags: List[str] = Field(default_factory=list)
    provenance: Provenance
    validation: ValidationResult
    enrichment_only: bool = True


class FeedStatus(BaseModel):
    feed: str
    state: FeedState
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: Optional[datetime] = None
    age_seconds: Optional[float] = None
    max_age_seconds: Optional[float] = None
    match_count: int = 0
    error: Optional[str] = None


class Agent5aInput(BaseModel):
    case_id: str
    tenant_id: str
    fir_findings: List[Dict[str, Any]] = Field(default_factory=list)
    agent2_output: Dict[str, Any] = Field(default_factory=dict)


class Agent5aOutput(BaseModel):
    case_id: str
    tenant_id: str
    agent_id: str = "agent5a_threat_intelligence"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    indicators: List[Indicator] = Field(default_factory=list)
    ioc_matches: List[ThreatMatch] = Field(default_factory=list)
    mitre_mappings: List[ThreatMatch] = Field(default_factory=list)
    vulnerability_matches: List[ThreatMatch] = Field(default_factory=list)
    cisa_kev_results: List[ThreatMatch] = Field(default_factory=list)
    feed_status: List[FeedStatus] = Field(default_factory=list)
    provenance: List[Provenance] = Field(default_factory=list)
    sanitization_summary: SanitizationSummary = Field(default_factory=SanitizationSummary)
    validation_flags: List[str] = Field(default_factory=list)
    execution_status: ExecutionStatus
    error_details: List[str] = Field(default_factory=list)
    agent2_context: Dict[str, Any] = Field(default_factory=dict)
    model_used: Optional[str] = None
    reasoning_summary: Optional[str] = None
    claim: str = ""
    evidence_ids: List[str] = Field(default_factory=list)

    def to_agent_output_record(self) -> Dict[str, Any]:
        """Return the legacy persistence shape without losing structured data."""
        payload = self.model_dump(mode="json")
        payload["claim"] = self.claim
        payload["evidence_ids"] = self.evidence_ids
        payload["flags"] = {
            "agent5a": payload,
            "execution_status": self.execution_status.value,
        }
        payload["confidence"] = 1.0 if self.execution_status == ExecutionStatus.SUCCESS else 0.5
        payload["verified"] = all(self.validation_flags) is not False
        return {
            "case_id": self.case_id,
            "agent_id": self.agent_id,
            "claim": self.claim,
            "evidence_ids": self.evidence_ids,
            "confidence": payload["confidence"],
            "verified": payload["verified"],
            "flags": payload["flags"],
        }
