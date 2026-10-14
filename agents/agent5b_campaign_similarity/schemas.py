"""
Agent 5b — Campaign & Behavior Similarity Schemas
=================================================
Pydantic v2 data models for:
- Case Behavioral Signature (Malware Behavior, Attack Pattern, Threat Intel, YARA)
- Multi-Vector Semantic Representations
- Validated Case Repository Records (Maker-Checker approved)
- Deterministic Similarity Scoring & Component Breakdown
- Common / New / Different / Historical-Only Analysis
- Historical Novelty, MITRE Unmapped, Candidate Novelty, Confirmed Novelty
- Explanations, Limitations, and Attribution Safeguards
- Audit Logging & Agent 6 Handoff Contract
"""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


# ---------------------------------------------------------
# Case Behavioral Signature Models
# ---------------------------------------------------------

class MalwareBehaviorSignature(BaseModel):
    execution: List[str] = Field(default_factory=list)
    persistence: List[str] = Field(default_factory=list)
    credential_access: List[str] = Field(default_factory=list)
    privilege_escalation: List[str] = Field(default_factory=list)
    defense_evasion: List[str] = Field(default_factory=list)
    discovery: List[str] = Field(default_factory=list)
    collection: List[str] = Field(default_factory=list)
    command_and_control: List[str] = Field(default_factory=list)
    exfiltration: List[str] = Field(default_factory=list)
    impact: List[str] = Field(default_factory=list)
    # Mapping of behavior string -> supporting evidence IDs
    behavior_evidence_map: Dict[str, List[str]] = Field(default_factory=dict)


class AttackPatternSignature(BaseModel):
    initial_access: List[str] = Field(default_factory=list)
    execution: List[str] = Field(default_factory=list)
    persistence: List[str] = Field(default_factory=list)
    credential_access: List[str] = Field(default_factory=list)
    lateral_movement: List[str] = Field(default_factory=list)
    command_and_control: List[str] = Field(default_factory=list)
    exfiltration: List[str] = Field(default_factory=list)
    infection_source: Optional[str] = None
    attack_path: List[str] = Field(default_factory=list)
    attack_stages: List[str] = Field(default_factory=list)
    kill_chain_steps: List[str] = Field(default_factory=list)
    stage_evidence_map: Dict[str, List[str]] = Field(default_factory=dict)


class ThreatIntelligenceSignature(BaseModel):
    candidate_malware_families: List[str] = Field(default_factory=list)
    ioc_matches: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    cve_references: List[str] = Field(default_factory=list)
    threat_reports: List[Dict[str, Any]] = Field(default_factory=list)
    source_quality: List[Dict[str, Any]] = Field(default_factory=list)
    freshness: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(default=0.8)
    intelligence_conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class YaraSignature(BaseModel):
    matched_rules: List[str] = Field(default_factory=list)
    rule_categories: List[str] = Field(default_factory=list)
    supporting_evidence_references: List[str] = Field(default_factory=list)


class CaseBehavioralSignature(BaseModel):
    case_id: str
    tenant_id: str = "default"
    malware_behavior: MalwareBehaviorSignature = Field(default_factory=MalwareBehaviorSignature)
    attack_pattern: AttackPatternSignature = Field(default_factory=AttackPatternSignature)
    threat_intelligence: ThreatIntelligenceSignature = Field(default_factory=ThreatIntelligenceSignature)
    yara: YaraSignature = Field(default_factory=YaraSignature)
    evidence_ids: List[str] = Field(default_factory=list)
    validation_warnings: List[str] = Field(default_factory=list)
    mismatched_records: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------
# Multi-Vector Representation
# ---------------------------------------------------------

class MultiVector(BaseModel):
    behavior_vector: List[float] = Field(default_factory=list)
    attack_pattern_vector: List[float] = Field(default_factory=list)
    threat_intel_vector: List[float] = Field(default_factory=list)
    composite_vector: List[float] = Field(default_factory=list)


# ---------------------------------------------------------
# Validated Case Data Model (Maker-Checker Approved)
# ---------------------------------------------------------

class CaseValidationRecord(BaseModel):
    status: Literal["approved", "validated", "rejected", "pending", "unvalidated"] = "approved"
    approved_by: Optional[str] = "senior_analyst"
    approval_timestamp: Optional[str] = "2026-01-01T00:00:00Z"
    validation_version: str = "1.0"


class MalwareIdentity(BaseModel):
    family: str
    variant: Optional[str] = None
    identity_confidence: float = Field(default=0.9, ge=0.0, le=1.0)


class ValidatedCase(BaseModel):
    case_id: str
    tenant_id: str = "default"
    validation: CaseValidationRecord = Field(default_factory=CaseValidationRecord)
    malware_identity: MalwareIdentity
    malware_behavior_fingerprint: Dict[str, List[str]] = Field(default_factory=dict)
    behavior_mechanisms: List[Dict[str, Any]] = Field(default_factory=list)
    attack_pattern: Dict[str, Any] = Field(default_factory=dict)
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)
    yara: Dict[str, Any] = Field(default_factory=dict)
    investigation_summary: str = ""
    analyst_notes: str = ""
    associated_campaigns: List[str] = Field(default_factory=list)
    threat_actor: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------
# Retrieval & Similarity Models
# ---------------------------------------------------------

class RetrievedHistoricalCase(BaseModel):
    case_id: str
    tenant_id: str
    similarity_score: float = Field(
        ge=0.0, le=1.0,
        description="Raw vector space cosine similarity from dense vector embedding retrieval (used by Qdrant/repository to rank top-k). Distinct from composite_similarity."
    )
    vector_retrieval_similarity: Optional[float] = Field(
        default=None,
        description="Explicit copy of vector retrieval score to prevent accidental confusion with post-retrieval composite_similarity."
    )
    behavior_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    intelligence_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    case_data: ValidatedCase


class DifferentBehaviorDetail(BaseModel):
    category: str
    current_behavior: str
    historical_behavior: str
    difference_reason: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)


class NoveltyReport(BaseModel):
    detected: bool = False
    observations: List[str] = Field(default_factory=list)
    novelty_score: float = Field(default=0.0, ge=0.0, le=1.0)
    novel_mechanisms: List[str] = Field(default_factory=list)
    historical_novelty: List[str] = Field(default_factory=list)
    mitre_unmapped: List[str] = Field(default_factory=list)
    novel_threat_candidate: bool = False
    novel_threat_candidate_reason: str = ""
    confirmed_novel_threat: bool = False
    confirmation_rationale: str = ""
    historical_cases_compared: List[str] = Field(default_factory=list)
    supporting_evidence_references: List[str] = Field(default_factory=list)


class SimilarMalwareFamily(BaseModel):
    family_name: str
    historical_case_id: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    supporting_behaviors: List[str] = Field(default_factory=list)
    caveat: str = "Similarity is contextual reference only, not proof of malware identity."


class SimilarCampaign(BaseModel):
    campaign_name: str
    historical_case_id: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    overlapping_techniques: List[str] = Field(default_factory=list)
    overlapping_infrastructure: List[str] = Field(default_factory=list)


class ThreatActorContext(BaseModel):
    actor_name: str
    historical_case_id: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    matching_characteristics: List[str] = Field(default_factory=list)
    attribution_caveat: str = "Contextual profiling only. Does not assert that current attack was executed by this actor."


class SimilarityBreakdown(BaseModel):
    behavior_similarity: float = Field(ge=0.0, le=1.0)
    attack_similarity: float = Field(ge=0.0, le=1.0)
    intelligence_similarity: float = Field(ge=0.0, le=1.0)
    composite_similarity: float = Field(ge=0.0, le=1.0)
    weights_used: Dict[str, float] = Field(default_factory=dict)
    formula: str = ""


class HistoricalSimilarityOutput(BaseModel):
    retrieved_cases: List[RetrievedHistoricalCase] = Field(default_factory=list)
    behavior_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    intelligence_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    composite_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    similarity_breakdown: Optional[SimilarityBreakdown] = None

    common_behaviors: List[str] = Field(default_factory=list)
    new_behaviors: List[str] = Field(default_factory=list)
    different_behaviors: List[DifferentBehaviorDetail] = Field(default_factory=list)
    historical_only_behaviors: List[str] = Field(default_factory=list)

    similar_malware_families: List[SimilarMalwareFamily] = Field(default_factory=list)
    similar_campaigns: List[SimilarCampaign] = Field(default_factory=list)
    possible_actor_context: List[ThreatActorContext] = Field(default_factory=list)

    novelty: NoveltyReport = Field(default_factory=NoveltyReport)

    explanations: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_methodology: str = ""
    limitations: List[str] = Field(default_factory=list)
    historical_case_references: List[str] = Field(default_factory=list)


# ---------------------------------------------------------
# Agent 6 Handoff Package & Audit Logging
# ---------------------------------------------------------

class Agent6HandoffPackage(BaseModel):
    case_id: str
    tenant_id: str
    validated_historical_references: List[str] = Field(default_factory=list)
    similarity_metrics: Dict[str, float] = Field(default_factory=dict)
    behavior_comparisons: Dict[str, Any] = Field(default_factory=dict)
    novelty_findings: NoveltyReport = Field(default_factory=NoveltyReport)
    supporting_evidence_references: List[str] = Field(default_factory=list)
    investigative_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_methodology: str = ""
    limitations: List[str] = Field(default_factory=list)
    attribution_safeguards: List[str] = Field(default_factory=list)


class AuditLogRecord(BaseModel):
    timestamp: str
    case_id: str
    tenant_id: str
    scoring_version: str = "1.0.0"
    retrieval_filter: Dict[str, Any] = Field(default_factory=dict)
    model_metadata: Dict[str, str] = Field(default_factory=dict)
    validation_decisions: List[str] = Field(default_factory=list)
    errors_encountered: List[str] = Field(default_factory=list)


class Agent5bOutput(BaseModel):
    case_id: str
    tenant_id: str = "default"
    execution_status: Literal["success", "partial", "degraded", "error"] = "success"
    historical_similarity: HistoricalSimilarityOutput = Field(default_factory=HistoricalSimilarityOutput)
    claim: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    agent6_handoff: Optional[Agent6HandoffPackage] = None
    audit_record: Optional[AuditLogRecord] = None
    validation_warnings: List[str] = Field(default_factory=list)
    mismatched_records: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None
