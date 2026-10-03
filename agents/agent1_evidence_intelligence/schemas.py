"""
Agent 1 — Evidence Intelligence & Triage Schemas
================================================
Defines strict Pydantic data contracts for Agent 1 input, evidence triage,
priority assessments, clusters, investigation questions, focus areas, evidence gaps,
and final Agent1Output payload.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


# ── 1. Readiness & Summary Models ──────────────────────────────────────────

class Agent1InvestigationReadiness(BaseModel):
    """Assessed readiness of the evidence base for downstream investigation."""
    status: Literal["READY", "READY_WITH_LIMITATIONS", "LIMITED", "NOT_READY", "UNREADY"] = "READY"
    reason: str = Field(default="Sufficient evidence available for analysis.")


class Agent1EvidenceSummary(BaseModel):
    """Categorized summary of evidence findings count by investigative value."""
    total_findings: int = 0
    high_value_findings: int = 0
    medium_value_findings: int = 0
    low_value_findings: int = 0


# ── 2. Evidence Triage & Priority Models ───────────────────────────────────

class Agent1EvidenceAssessment(BaseModel):
    """
    Investigative triage assessment of a single FIR finding.
    Distinguishes Investigative Value (importance to CURRENT case) from Threat Severity.
    """
    evidence_id: str = Field(description="FIR finding_id or source evidence reference")
    investigative_value: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] = "MEDIUM"
    priority_score: float = Field(default=0.5, ge=0.0, le=1.0, description="Explainable score in [0.0, 1.0]")
    classification: Literal["PRIMARY", "SUPPORTING", "CONTEXTUAL", "LOW_CURRENT_VALUE"] = "CONTEXTUAL"
    reason: List[str] = Field(default_factory=list, description="Evidence-backed reasoning for classification")


class Agent1SupportingLink(BaseModel):
    """Link showing supporting evidence relationship."""
    evidence_id: str
    classification: Literal["SUPPORTING"] = "SUPPORTING"
    supports: List[str] = Field(default_factory=list, description="Primary evidence IDs supported by this finding")


class Agent1EvidenceCluster(BaseModel):
    """Group of related evidence findings (e.g. Possible Persistence). Does NOT prove behavior confirmed."""
    cluster_id: str = Field(description="e.g. CLUSTER-001")
    topic: str = Field(description="e.g. Possible Persistence, Possible Credential Access")
    evidence_ids: List[str] = Field(default_factory=list)


# ── 3. Investigation Plan & Guidance Models ────────────────────────────────

class Agent1InvestigationQuestion(BaseModel):
    """Evidence-driven question generated for downstream investigation."""
    question: str = Field(description="Targeted investigation question")
    priority: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    evidence_ids: List[str] = Field(default_factory=list, description="Supporting evidence IDs")
    relevant_agents: List[str] = Field(default_factory=list, description="Target downstream agents (e.g., agent_2, agent_4)")


class Agent1FocusArea(BaseModel):
    """Compact high-value focus area guiding downstream investigation."""
    topic: str
    priority: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    reason: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    agents: List[str] = Field(default_factory=list)
    related_investigation_questions: List[str] = Field(default_factory=list)


class Agent1EvidenceGap(BaseModel):
    """Identified evidence gap or missing forensic source."""
    gap: str = Field(description="Missing evidence artifact or analysis gap")
    impact: str = Field(description="Investigative impact of missing evidence")
    priority: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"


# ── 4. Legacy Claim Model (Preserved for Backward Compatibility) ──────────

class Agent1Claim(BaseModel):
    """
    Individual forensic interpretation/claim produced by Agent 1 over sanitized evidence.
    Preserved for backward compatibility.
    """
    claim_id: str = Field(description="Unique claim identifier, e.g., CLM-AG1-001")
    summary: str = Field(description="Concise summary of the forensic interpretation")
    findings_summary: str = Field(description="Detailed breakdown of what the evidence demonstrates")
    cited_evidence_ids: List[str] = Field(default_factory=list)
    assessed_importance: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    importance_reason: Optional[str] = None
    confidence_score: float = 0.8
    missing_evidence_noted: List[str] = Field(default_factory=list)
    uncertainties_or_conflicts: List[str] = Field(default_factory=list)
    reasoning_notes: str = ""
    
    # Validation flags
    citation_valid: bool = False
    citation_verified: bool = False
    invalid_citations: List[str] = Field(default_factory=list)
    is_valid_confidence: bool = True
    raw_model_confidence: Optional[float] = None
    validation_notes: Optional[str] = None
    semantic_support_verified: bool = False
    semantic_support_notes: Optional[str] = None


# ── 5. Input & Output Root Contracts ───────────────────────────────────────

class Agent1Input(BaseModel):
    """Input request contract for Agent 1."""
    case_id: str
    tenant_id: str = "default"
    min_confidence_threshold: float = 0.0
    allow_unreviewed_findings: bool = True


class Agent1Output(BaseModel):
    """
    Structured Agent 1 Triage & Evidence Intelligence Output contract.
    Combines Refined Implementation Specification fields with backward-compatible legacy fields.
    """
    case_id: str
    tenant_id: str = "default"
    agent_id: str = "agent1_evidence_intelligence"
    model_used: str = "Qwen3-8B"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # ── Refined Specification Fields ──
    investigation_readiness: Agent1InvestigationReadiness = Field(
        default_factory=Agent1InvestigationReadiness
    )
    evidence_summary: Agent1EvidenceSummary = Field(
        default_factory=Agent1EvidenceSummary
    )
    priority_evidence: List[Agent1EvidenceAssessment] = Field(default_factory=list)
    supporting_evidence: List[Agent1SupportingLink] = Field(default_factory=list)
    evidence_clusters: List[Agent1EvidenceCluster] = Field(default_factory=list)
    investigation_questions: List[Agent1InvestigationQuestion] = Field(default_factory=list)
    focus_areas: List[Agent1FocusArea] = Field(default_factory=list)
    evidence_gaps: List[Agent1EvidenceGap] = Field(default_factory=list)
    coverage: Dict[str, str] = Field(
        default_factory=lambda: {
            "execution": "UNKNOWN",
            "persistence": "UNKNOWN",
            "credential_access": "UNKNOWN",
            "discovery": "UNKNOWN",
            "network_c2": "UNKNOWN",
            "exfiltration": "UNKNOWN",
            "impact": "UNKNOWN",
            "initial_access": "UNKNOWN"
        }
    )
    downstream_relevance: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "agent_2": [],
            "agent_3": [],
            "agent_4": [],
            "agent_5a": []
        }
    )
    limitations: List[str] = Field(default_factory=list)

    # ── Backward Compatibility Fields ──
    claims: List[Agent1Claim] = Field(default_factory=list)
    total_findings_processed: int = 0
    sanitization_summary: Dict[str, Any] = Field(default_factory=dict)
    evidence_trust_score: Optional[float] = None
    evidence_quality_summary: Dict[str, Any] = Field(default_factory=dict)
    readiness_blockers: List[str] = Field(default_factory=list)
    possible_analyses: List[str] = Field(default_factory=list)
    performed_analyses: List[str] = Field(default_factory=list)
    
    execution_status: Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILED"] = "SUCCESS"
    failure_type: Optional[str] = None
    error_message: Optional[str] = None
