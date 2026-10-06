from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SimilarityExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


class CaseSignature(BaseModel):
    behavior: List[str] = Field(default_factory=list)
    attack_pattern: List[str] = Field(default_factory=list)
    intelligence: List[str] = Field(default_factory=list)
    yara: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)

    def to_text(self) -> str:
        return "\n".join(
            [
                f"behavior: {', '.join(self.behavior)}",
                f"attack_pattern: {', '.join(self.attack_pattern)}",
                f"intelligence: {', '.join(self.intelligence)}",
                f"yara: {', '.join(self.yara)}",
            ]
        )


class HistoricalCaseReference(BaseModel):
    case_id: str
    score: float
    behavior_similarity: float = 0.0
    attack_similarity: float = 0.0
    intelligence_similarity: float = 0.0
    validation_status: Optional[str] = None
    malware_family: Optional[str] = None
    campaign: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    common: List[str] = Field(default_factory=list)
    new: List[str] = Field(default_factory=list)
    different: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class HistoricalSimilarity(BaseModel):
    retrieved_cases: List[HistoricalCaseReference] = Field(default_factory=list)
    behavior_similarity: float = 0.0
    attack_similarity: float = 0.0
    intelligence_similarity: float = 0.0
    composite_similarity: float = 0.0
    common_behaviors: List[str] = Field(default_factory=list)
    new_behaviors: List[str] = Field(default_factory=list)
    different_behaviors: List[str] = Field(default_factory=list)
    historical_only_behaviors: List[str] = Field(default_factory=list)
    similar_malware_families: List[str] = Field(default_factory=list)
    similar_campaigns: List[str] = Field(default_factory=list)
    possible_actor_context: List[str] = Field(default_factory=list)
    novelty_detected: bool = False
    novelty_observations: List[str] = Field(default_factory=list)
    explanations: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = Field(default_factory=list)
    historical_case_references: List[str] = Field(default_factory=list)


class Agent5bOutput(BaseModel):
    case_id: str
    tenant_id: str
    agent_id: str = "agent5b_campaign_similarity"
    execution_status: SimilarityExecutionStatus
    current_signature: CaseSignature = Field(default_factory=CaseSignature)
    historical_similarity: HistoricalSimilarity = Field(default_factory=HistoricalSimilarity)
    error_details: List[str] = Field(default_factory=list)
    claim: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    model_used: Optional[str] = None

    def to_agent_output_record(self) -> Dict[str, Any]:
        payload = self.model_dump(mode="json")
        return {
            "case_id": self.case_id,
            "agent_id": self.agent_id,
            "claim": self.claim,
            "evidence_ids": self.evidence_ids,
            "confidence": self.historical_similarity.confidence,
            "verified": False,
            "flags": {"agent5b": payload, "execution_status": self.execution_status.value},
        }
