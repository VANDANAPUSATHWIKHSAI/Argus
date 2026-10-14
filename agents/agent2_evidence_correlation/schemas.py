"""
Agent 2 — Evidence Correlation Schemas
=======================================
Defines Pydantic contracts for Agent 2 input, correlation signals,
timeline events, graph status & communities, deterministic relationships,
conflicts, claims, Qwen interpretation, provenance, and final output payload.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


class DeterministicRelationship(BaseModel):
    """
    Objective forensic relationship established between entities/findings.
    Distinguishes deterministic rule match confidence (1.0 = rule satisfied) from Qwen model interpretation confidence.
    """
    relationship_id: str = Field(description="Unique ID of relationship, e.g. REL-001")
    relationship_type: str = Field(
        description="Type of relationship (e.g. CONNECTED_TO, CHILD_OF, RESOLVED, ACCESSED, MODIFIED, AUTHENTICATED_TO, SHARED_IP, SHARED_HASH, SHARED_USER, SHARED_ARTIFACT)"
    )
    source_entity: str = Field(description="Source node/entity ID or name")
    target_entity: str = Field(description="Target node/entity ID or name")
    evidence_ids: List[str] = Field(default_factory=list, description="FIR finding IDs supporting this relationship")
    artifact_ids: List[str] = Field(default_factory=list, description="Artifact IDs supporting this relationship")
    deterministic_basis: str = Field(description="Objective rule/source supporting this relationship")
    deterministic_match: bool = Field(default=True, description="True if relationship is established by deterministic rule match")
    rule_match_confidence: float = Field(default=1.0, description="Deterministic rule-match confidence (1.0 = rule satisfied)")
    case_id: str = Field(default="default")
    tenant_id: str = Field(default="default")


class TimelineEvent(BaseModel):
    """
    Individual event entry in the Master Investigation Timeline.
    """
    event_id: str = Field(description="Unique timeline event ID or finding ID")
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp")
    timestamp_type: str = Field(default="event_time", description="Type of timestamp (e.g. event_time, created_at, modified_at)")
    evidence_ids: List[str] = Field(default_factory=list, description="Source evidence/finding IDs")
    source: str = Field(default="unknown", description="Source parser/layer generating event")
    host: Optional[str] = Field(default=None, description="Host machine associated with event")
    user: Optional[str] = Field(default=None, description="User account associated with event")
    process: Optional[str] = Field(default=None, description="Process name or PID associated with event")
    event_description: str = Field(description="Sanitized description of forensic event")
    timestamp_conflict: bool = Field(default=False, description="True if conflicting timestamps were reported for event")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Metadata lineage")


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
    wcc_component_id: Optional[int] = Field(default=None, description="Weakly Connected Component numeric ID from Neo4j GDS")


class GraphStatus(BaseModel):
    """
    Status and component summary of Neo4j graph representation.
    """
    status: Literal["AVAILABLE", "UNAVAILABLE"] = Field(default="AVAILABLE")
    node_count: int = 0
    relationship_count: int = 0
    components: List[GraphCommunity] = Field(default_factory=list)


class CorrelationConflict(BaseModel):
    """
    Deterministic contradiction or temporal anomaly detected across evidence findings.
    """
    conflict_id: str = Field(description="Unique ID of conflict, e.g. CONF-001")
    conflict_type: str = Field(
        description="Category of deterministic conflict detected (e.g. timestamp_conflict, host_attribution_conflict, user_attribution_conflict, process_parent_conflict, artifact_identity_conflict, hash_collision, persistence_disagreement, malware_status_disagreement, severity_disagreement)"
    )
    description: str = Field(description="Detailed explanation of the contradiction")
    involved_finding_ids: List[str] = Field(default_factory=list, description="FIR finding IDs involved in conflict")
    severity: Literal["high", "medium", "low"] = Field(default="medium", description="Severity level of conflict")
    status: Literal["UNRESOLVED", "RESOLVED"] = Field(default="UNRESOLVED", description="Conflict status")
    conflicting_values: Dict[str, Any] = Field(default_factory=dict, description="Conflicting entity values")


class Agent2CorrelationSignal(BaseModel):
    """
    Aggregated deterministic correlation payload passed to LLM for narration.
    """
    temporal_clusters: List[TemporalCluster] = Field(default_factory=list)
    graph_communities: List[GraphCommunity] = Field(default_factory=list)
    conflicts: List[CorrelationConflict] = Field(default_factory=list)
    relationships: List[DeterministicRelationship] = Field(default_factory=list)
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

    # ── Deterministic Validation Results ──
    citation_valid: bool = Field(
        default=False,
        description="True if every cited ID strictly exists in FIR findings or lineage"
    )
    citation_verified: bool = Field(
        default=False,
        description="Alias for citation_valid for backward compatibility"
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


class QwenInterpretation(BaseModel):
    """
    Qwen interpretation of deterministic correlation signals.
    """
    correlated_observations: List[str] = Field(default_factory=list)
    timeline_interpretation: List[str] = Field(default_factory=list)
    conflict_interpretation: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)


class Agent2Provenance(BaseModel):
    """
    Lineage metadata tracking inputs and model version.
    """
    input_finding_ids: List[str] = Field(default_factory=list)
    input_evidence_ids: List[str] = Field(default_factory=list)
    graph_version: str = "1.0.0"
    model: str = "Qwen3-8B"
    prompt_version: str = "1.0.0"


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
    Structured Agent 2 output contract matching ARGUS evidence correlation specifications.
    """
    agent: str = "agent_2"
    agent_version: str = "1.0.0"
    case_id: str
    tenant_id: str = "default"
    agent_id: str = "agent2_evidence_correlation"
    model_used: str = "Qwen3-8B"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    execution_status: Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILED"] = "SUCCESS"
    failure_type: Optional[str] = Field(
        default=None,
        description="Failure classification: NEO4J_UNAVAILABLE, GDS_UNAVAILABLE, MODEL_UNAVAILABLE, MALFORMED_OUTPUT, NO_EVIDENCE"
    )
    error_message: Optional[str] = None

    graph: GraphStatus = Field(default_factory=GraphStatus)
    correlation_signals: Agent2CorrelationSignal = Field(default_factory=Agent2CorrelationSignal)
    relationships: List[DeterministicRelationship] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    conflicts: List[CorrelationConflict] = Field(default_factory=list)
    claims: List[Agent2Claim] = Field(default_factory=list)

    qwen_interpretation: QwenInterpretation = Field(default_factory=QwenInterpretation)
    limitations: List[str] = Field(default_factory=list)
    provenance: Agent2Provenance = Field(default_factory=Agent2Provenance)

    total_findings_processed: int = 0
    graph_metrics: Dict[str, Any] = Field(default_factory=dict)
    sanitization_summary: Dict[str, Any] = Field(default_factory=dict)


