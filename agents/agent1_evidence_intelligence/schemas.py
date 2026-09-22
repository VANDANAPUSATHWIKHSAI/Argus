"""
Agent 1 — Evidence Intelligence Schemas
========================================
Defines strict Pydantic data contracts for Agent 1 input, claim structure,
citation verification metrics, and final output payload.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


class Agent1Claim(BaseModel):
    """
    Individual forensic interpretation/claim produced by Agent 1 over sanitized evidence.
    """
    claim_id: str = Field(description="Unique claim identifier, e.g., CLM-AG1-001")
    summary: str = Field(description="Concise summary of the forensic interpretation")
    findings_summary: str = Field(description="Detailed breakdown of what the evidence demonstrates")
    cited_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Exact FIR finding IDs or source evidence IDs supporting this claim"
    )
    assessed_importance: Literal["critical", "high", "medium", "low", "informational"] = Field(
        default="medium",
        description="Assessed importance of evidence according to forensic rules"
    )
    confidence_score: float = Field(
        description="Confidence score in range [0.0, 1.0]"
    )
    missing_evidence_noted: List[str] = Field(
        default_factory=list,
        description="Gaps or missing evidence artifacts identified by reasoning"
    )
    uncertainties_or_conflicts: List[str] = Field(
        default_factory=list,
        description="Contradictions or ambiguities among deterministic findings"
    )
    reasoning_notes: str = Field(
        default="",
        description="Step-by-step reasoning logic connecting evidence to conclusions"
    )
    
    # ── Deterministic Validation Results (Enforced by code, not LLM) ──
    citation_verified: bool = Field(
        default=False,
        description="True if every cited ID strictly exists in FIR findings or lineage"
    )
    invalid_citations: List[str] = Field(
        default_factory=list,
        description="List of cited IDs that do not exist in FIR findings or evidence lineage"
    )
    is_valid_confidence: bool = Field(
        default=True,
        description="True if original LLM confidence score was within [0.0, 1.0]"
    )
    raw_model_confidence: Optional[float] = Field(
        default=None,
        description="Preserves raw un-clamped model confidence score if out of bounds"
    )
    validation_notes: Optional[str] = Field(
        default=None,
        description="Deterministic audit log notes regarding verification outcome"
    )


class Agent1Input(BaseModel):
    """
    Input request contract for Agent 1.
    """
    case_id: str
    tenant_id: str = "default"
    min_confidence_threshold: float = 0.0
    allow_unreviewed_findings: bool = True


class Agent1Output(BaseModel):
    """
    Structured Agent 1 output contract.
    """
    case_id: str
    tenant_id: str = "default"
    agent_id: str = "agent1_evidence_intelligence"
    model_used: str = "Qwen3-8B"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    claims: List[Agent1Claim] = Field(default_factory=list)
    total_findings_processed: int = 0
    sanitization_summary: Dict[str, Any] = Field(default_factory=dict)
    execution_status: Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILED"] = "SUCCESS"
    error_message: Optional[str] = None
