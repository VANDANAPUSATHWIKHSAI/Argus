"""
Agent 3 — Attack Reconstruction Schemas
========================================
Defines strict Pydantic data contracts for Agent 3 input and output.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

class InfectionPath(BaseModel):
    entry_point: str = Field(description="The determined earliest supported attack/infection event")
    evidence_ids: List[str] = Field(default_factory=list, description="Citations to evidence")
    confidence: float = Field(description="Confidence score [0.0, 1.0]")
    citation_verified: bool = Field(default=False)
    invalid_citations: List[str] = Field(default_factory=list)

class AttackTimelineEvent(BaseModel):
    timestamp: str = Field(description="Chronological timestamp")
    event: str = Field(description="Description of the event")
    stage: str = Field(description="Attack stage (e.g. Execution, Lateral Movement)")
    mitre_technique: str = Field(description="MITRE technique ID or name")
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(description="Confidence score [0.0, 1.0]")
    citation_verified: bool = Field(default=False)
    invalid_citations: List[str] = Field(default_factory=list)

class AttackChainStage(BaseModel):
    stage: str = Field(description="Kill-chain stage")
    events: List[str] = Field(description="List of events belonging to this stage")
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(description="Confidence score [0.0, 1.0]")
    citation_verified: bool = Field(default=False)
    invalid_citations: List[str] = Field(default_factory=list)

class LateralMovement(BaseModel):
    source_host: str = Field(description="Source host or IP")
    destination_host: str = Field(description="Destination host or IP")
    method: str = Field(description="Method used for lateral movement (e.g. RDP, SMB)")
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(description="Confidence score [0.0, 1.0]")
    citation_verified: bool = Field(default=False)
    invalid_citations: List[str] = Field(default_factory=list)

class MissingExpectedEvent(BaseModel):
    event: str = Field(description="Expected event that is missing from evidence")
    reason: str = Field(description="Why this event was expected")
    status: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"

class Agent3Input(BaseModel):
    case_id: str
    tenant_id: str = "default"

class Agent3Output(BaseModel):
    agent_id: str = "agent_3"
    case_id: str
    tenant_id: str = "default"
    model_used: str = "Qwen3-8B"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    infection_path: InfectionPath
    attack_timeline: List[AttackTimelineEvent] = Field(default_factory=list)
    attack_chain: List[AttackChainStage] = Field(default_factory=list)
    lateral_movement: List[LateralMovement] = Field(default_factory=list)
    missing_expected_events: List[MissingExpectedEvent] = Field(default_factory=list)
    reconstruction_summary: str = ""
    overall_confidence: float = 0.0
    
    total_findings_processed: int = 0
    sanitization_summary: Dict[str, Any] = Field(default_factory=dict)
    execution_status: Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILED"] = "SUCCESS"
    error_message: Optional[str] = None
