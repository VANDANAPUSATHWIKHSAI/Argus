"""
Agent 2 — Evidence Correlation Schemas
=======================================
Defines Pydantic contracts for Agent 2 input, correlation signals,
timeline clusters, graph communities, conflicts, claims, and final output payload.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


class TemporalCluster(BaseModel):
    """
    Chronological cluster of FIR findings occurring within a temporal window.
    """
    cluster_id: str = Field(description="Unique ID of temporal cluster, e.g. TC-001")
    start_time: Optional[datetime] = Field(default=None, description="Earliest timestamp in cluster")
    end_time: Optional[datetime] = Field(default=None, description="Latest timestamp in cluster")
    finding_ids: List[str] = Field(default_factory=list, description="IDs of FIR findings in cluster")
    time_span_seconds: float = Field(default=0.0, description="Time span between first and last event in seconds")
    gap_from_previous_seconds: Optional[float] = Field(default=None, description="Gap in seconds from previous cluster")
    overlap_noted: bool = Field(default=False, description="True if simultaneous execution or timestamp overlap detected")


class GraphCommunity(BaseModel):
    """
    Deterministic community of connected entities and findings from Neo4j WCC or graph builder.
    """
    community_id: str = Field(description="Unique ID of graph community, e.g. GC-001")
    finding_ids: List[str] = Field(default_factory=list, description="FIR finding IDs participating in community")
    entity_names: List[str] = Field(default_factory=list, description="Entities (IPs, users, files, hashes) in community")
    entity_types: List[str] = Field(default_factory=list, description="Types of entities present in community")
    relationship_types: List[str] = Field(default_factory=list, description="Types of relationships linking entities")
    wcc_component_id: Optional[int] = Field(default=None, description="Weakly Connected Component numeric ID from Neo4j GDS or fallback")


class CorrelationConflict(BaseModel):
    """
    Deterministic contradiction or temporal anomaly detected across evidence findings.
    """
    conflict_id: str = Field(description="Unique ID of conflict, e.g. CONF-001")
    conflict_type: Literal["temporal_anomaly", "attitudinal_contradiction", "identity_mismatch", "hash_collision", "causality_violation"] = Field(
        description="Category of deterministic conflict detected"
    )
    description: str = Field(description="Detailed explanation of the contradiction")
    involved_finding_ids: List[str] = Field(default_factory=list, description="FIR finding IDs involved in conflict")
    severity: Literal["high", "medium", "low"] = Field(default="medium", description="Severity level of conflict")


class Agent2CorrelationSignal(BaseModel):
    """
    Aggregated deterministic correlation payload passed to LLM for narration.
    """
    temporal_clusters: List[TemporalCluster] = Field(default_factory=list)
    graph_communities: List[GraphCommunity] = Field(default_factory=list)
    conflicts: List[CorrelationConflict] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    total_communities: int = 0


class Agent2Claim(BaseModel):
    """
    Individual forensic claim produced by Agent 2 regarding evidence correlation.
    """
    claim_id: str = Field(description="Unique claim identifier, e.g., CLM-AG2-001")
    summary: str = Field(description="Concise summary of the correlation finding")
    correlation_type: Literal["temporal", "entity", "shared_artifact", "conflict", "multi_signal"] = Field(
        default="multi_signal",
        description="Type of evidence correlation demonstrated"
    )
    findings_summary: str = Field(description="Detailed breakdown of how findings are connected")
    cited_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Exact FIR finding IDs supporting this correlation claim"
    )
    community_id: Optional[str] = Field(default=None, description="Associated graph community ID if applicable")
    assessed_importance: Literal["critical", "high", "medium", "low", "informational"] = Field(
        default="medium",
        description="Importance of the correlated pattern"
    )
    confidence_score: float = Field(
        description="Confidence score in range [0.0, 1.0]"
    )
    timeline_sequence: List[str] = Field(
        default_factory=list,
        description="Chronological ordered sequence of finding IDs in this claim"
    )
    conflicts_noted: List[str] = Field(
        default_factory=list,
        description="Contradictions or timeline anomalies noted in this claim"
    )
    reasoning_notes: str = Field(
        default="",
        description="Step-by-step reasoning logic connecting evidence graph signals to conclusions"
    )

    # ── Deterministic Validation Results (Enforced by code) ──
    citation_verified: bool = Field(
        default=False,
        description="True if every cited ID strictly exists in FIR findings or lineage"
    )
    invalid_citations: List[str] = Field(
        default_factory=list,
        description="List of cited IDs that do not exist in FIR findings or lineage"
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


class Agent2Input(BaseModel):
    """
    Input request contract for Agent 2.
    """
    case_id: str
    tenant_id: str = "default"
    time_window_seconds: float = 3600.0
    min_confidence_threshold: float = 0.0
    allow_unreviewed_findings: bool = True


class Agent2Output(BaseModel):
    """
    Structured Agent 2 output contract.
    """
    case_id: str
    tenant_id: str = "default"
    agent_id: str = "agent2_evidence_correlation"
    model_used: str = "Qwen3-8B"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    claims: List[Agent2Claim] = Field(default_factory=list)
    total_findings_processed: int = 0
    graph_metrics: Dict[str, Any] = Field(default_factory=dict)
    sanitization_summary: Dict[str, Any] = Field(default_factory=dict)
    execution_status: Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILED"] = "SUCCESS"
    error_message: Optional[str] = None
