"""
Agent 6 — Impact Assessment: Schema Contracts
==============================================
Defines all Pydantic models used by Agent 6:
  - CVSS v3.1 base metrics, evidence mapping, and calculation schemas
  - Investigation Severity Score (ISS) multi-factor assessment schemas
  - Affected assets, systems, and device risk profiling schemas
  - Incident recovery recommendations and prioritized checklist schemas
  - Complete Agent 6 output contract with evidence traceability
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


# ── CVSS v3.1 Enums ────────────────────────────────────────────────────────────

class AttackVector(str, Enum):
    NETWORK          = "NETWORK"           # N (0.85)
    ADJACENT_NETWORK = "ADJACENT_NETWORK"  # A (0.62)
    LOCAL            = "LOCAL"             # L (0.55)
    PHYSICAL         = "PHYSICAL"          # P (0.20)


class AttackComplexity(str, Enum):
    LOW  = "LOW"   # L (0.77)
    HIGH = "HIGH"  # H (0.44)


class PrivilegesRequired(str, Enum):
    NONE = "NONE"  # N (0.85 / 0.85)
    LOW  = "LOW"   # L (0.62 / 0.68)
    HIGH = "HIGH"  # H (0.27 / 0.50)


class UserInteraction(str, Enum):
    NONE     = "NONE"      # N (0.85)
    REQUIRED = "REQUIRED"  # R (0.62)


class Scope(str, Enum):
    UNCHANGED = "UNCHANGED"  # U
    CHANGED   = "CHANGED"    # C


class ImpactMetric(str, Enum):
    NONE = "NONE"  # N (0.00)
    LOW  = "LOW"   # L (0.22)
    HIGH = "HIGH"  # H (0.56)


class CVSSSeverity(str, Enum):
    NONE         = "NONE"          # 0.0
    LOW          = "LOW"           # 0.1 - 3.9
    MEDIUM       = "MEDIUM"        # 4.0 - 6.9
    HIGH         = "HIGH"          # 7.0 - 8.9
    CRITICAL     = "CRITICAL"      # 9.0 - 10.0
    UNDETERMINED = "UNDETERMINED"  # When insufficient data to establish score


class AssessmentStatus(str, Enum):
    COMPLETED         = "COMPLETED"          # All required metrics confirmed, score computed
    PARTIAL           = "PARTIAL"            # Score bounded or estimated with explicit missing metrics
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"  # Critical metrics missing; score cannot be justified


# ── CVSS Mapping & Calculation Models ──────────────────────────────────────────

class CVSSMetricEvidence(BaseModel):
    """
    Evidence-grounded justification for an individual CVSS v3.1 metric.
    Prevents hallucinated metrics by requiring traceable evidence IDs.
    """
    metric_name:     str                     # e.g., "Attack Vector"
    metric_code:     str                     # e.g., "AV"
    assigned_value:  Optional[str] = None    # e.g., "NETWORK", "LOW", or None if unknown
    value_code:      Optional[str] = None    # e.g., "N", "L", or None
    is_confirmed:    bool = False            # True if grounded in direct evidence
    evidence_ids:    List[str] = Field(default_factory=list)
    justification:   str = ""
    confidence:      float = Field(default=0.0, ge=0.0, le=1.0)


class CVSSAssessment(BaseModel):
    """
    Deterministic CVSS v3.1 technical vulnerability assessment.
    Distinct from the broader incident Impact Severity Score (ISS).
    """
    assessment_status:        AssessmentStatus = AssessmentStatus.INSUFFICIENT_DATA
    cvss_version:             str = "3.1"
    vector_string:            Optional[str] = None
    base_score:               Optional[float] = Field(default=None, ge=0.0, le=10.0)
    severity:                 CVSSSeverity = CVSSSeverity.UNDETERMINED
    score_range_min:          Optional[float] = Field(default=None, ge=0.0, le=10.0)
    score_range_max:          Optional[float] = Field(default=None, ge=0.0, le=10.0)
    metrics:                  Dict[str, CVSSMetricEvidence] = Field(default_factory=dict)
    missing_metrics:          List[str] = Field(default_factory=list)
    exploitability_subscore:  Optional[float] = None
    impact_subscore:          Optional[float] = None
    calculation_notes:        str = ""
    evidence_ids:             List[str] = Field(default_factory=list)


# ── Investigation Severity Score (ISS) Models ──────────────────────────────────

class ISSSeverity(str, Enum):
    NONE     = "NONE"      # 0.0
    LOW      = "LOW"       # 0.1 - 3.9
    MEDIUM   = "MEDIUM"    # 4.0 - 6.9
    HIGH     = "HIGH"      # 7.0 - 8.9
    CRITICAL = "CRITICAL"  # 9.0 - 10.0


class ISSFactorScore(BaseModel):
    """
    One deterministic component of the ARGUS Investigation Severity Score (ISS).
    """
    factor_name:     str
    weight:          float = Field(..., ge=0.0, le=1.0)
    raw_score:       float = Field(..., ge=0.0, le=10.0)
    weighted_score:  float = Field(..., ge=0.0, le=10.0)
    description:     str
    evidence_ids:    List[str] = Field(default_factory=list)


class ISSAssessment(BaseModel):
    """
    ARGUS Investigation Severity Score (ISS).
    Measures overall investigation-level impact and business risk across compromised assets,
    data exposure, system integrity damage, availability loss, and lateral movement.
    """
    iss_score:                  float = Field(..., ge=0.0, le=10.0)
    severity:                   ISSSeverity = ISSSeverity.MEDIUM
    factor_breakdown:           Dict[str, ISSFactorScore] = Field(default_factory=dict)
    contributing_evidence_ids:  List[str] = Field(default_factory=list)
    executive_summary:          str = ""


# ── Affected Assets & Resources Models ─────────────────────────────────────────

class AssetType(str, Enum):
    ENDPOINT          = "ENDPOINT"
    SERVER            = "SERVER"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DATABASE          = "DATABASE"
    USER_ACCOUNT      = "USER_ACCOUNT"
    SERVICE_ACCOUNT   = "SERVICE_ACCOUNT"
    NETWORK_DEVICE    = "NETWORK_DEVICE"
    CLOUD_RESOURCE    = "CLOUD_RESOURCE"
    FILE_SYSTEM       = "FILE_SYSTEM"
    UNKNOWN           = "UNKNOWN"


class CompromiseState(str, Enum):
    CONFIRMED_COMPROMISED = "CONFIRMED_COMPROMISED"
    SUSPECTED_COMPROMISED = "SUSPECTED_COMPROMISED"
    TARGETED              = "TARGETED"
    AT_RISK               = "AT_RISK"
    EXPOSED               = "EXPOSED"


class AssetCriticality(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class AffectedAsset(BaseModel):
    """
    An asset, system, resource, or user account impacted during the investigation.
    """
    asset_id:          str                      # Hostname, IP, username, DB name
    asset_type:        AssetType = AssetType.UNKNOWN
    criticality:       AssetCriticality = AssetCriticality.MEDIUM
    compromise_state:  CompromiseState = CompromiseState.SUSPECTED_COMPROMISED
    risk_score:        float = Field(default=5.0, ge=0.0, le=10.0)
    impact_details:    str = ""
    evidence_ids:      List[str] = Field(default_factory=list)
    first_observed:    Optional[str] = None
    last_observed:     Optional[str] = None


# ── Recovery Recommendations & Checklist Models ────────────────────────────────

class RecoveryPhase(str, Enum):
    CONTAINMENT  = "CONTAINMENT"
    ERADICATION  = "ERADICATION"
    RECOVERY     = "RECOVERY"
    HARDENING    = "HARDENING"


class RecoveryPriority(str, Enum):
    P1_IMMEDIATE = "P1_IMMEDIATE"  # Execute within 1-2 hours
    P2_HIGH      = "P2_HIGH"       # Execute within 6-12 hours
    P3_MEDIUM    = "P3_MEDIUM"     # Execute within 24-48 hours
    P4_LOW       = "P4_LOW"        # Post-incident review/hardening


class ResponsibleRole(str, Enum):
    SOC_L2              = "SOC_L2"
    INCIDENT_COMMANDER  = "INCIDENT_COMMANDER"
    SYSADMIN            = "SYSADMIN"
    NETWORK_ADMIN       = "NETWORK_ADMIN"
    IAM_ADMIN           = "IAM_ADMIN"
    DATABASE_ADMIN      = "DATABASE_ADMIN"
    FORENSIC_ANALYST    = "FORENSIC_ANALYST"


class RecoveryAction(BaseModel):
    """
    An operational recovery or containment task supported by investigation evidence.
    """
    action_id:         str                      # e.g., "REC-001"
    phase:             RecoveryPhase
    priority:          RecoveryPriority
    title:             str
    description:       str
    target_assets:     List[str] = Field(default_factory=list)
    responsible_role:  ResponsibleRole = ResponsibleRole.SOC_L2
    verification_step: str = ""
    evidence_ids:      List[str] = Field(default_factory=list)
    completed:         bool = False


class RecoveryChecklist(BaseModel):
    """
    Structured checklist organized by lifecycle phases for operations teams.
    """
    containment_steps:  List[RecoveryAction] = Field(default_factory=list)
    eradication_steps:  List[RecoveryAction] = Field(default_factory=list)
    recovery_steps:     List[RecoveryAction] = Field(default_factory=list)
    hardening_steps:    List[RecoveryAction] = Field(default_factory=list)
    total_actions:      int = 0


# ── Agent 6 Complete Output Contract ──────────────────────────────────────────

class Agent6Output(BaseModel):
    """
    Agent 6 — Impact Assessment: Full Output Contract.
    Contains both CVSS technical scoring and ARGUS Investigation Severity (ISS),
    affected assets inventory, recovery checklist, and evidence-grounded LLM explanation.
    """
    agent_id:                str = "agent_6"
    case_id:                 str
    tenant_id:               str = "default"
    timestamp:               str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    model_used:              str = "Qwen3-8B"
    execution_status:        str = "SUCCESS"
    error_message:           Optional[str] = None

    # Technical Vulnerability Severity (CVSS v3.1)
    cvss_assessment:         CVSSAssessment

    # Investigation-Level Impact (ISS)
    iss_assessment:          ISSAssessment

    # Asset Impact Inventory
    affected_assets:         List[AffectedAsset] = Field(default_factory=list)
    total_assets_affected:   int = 0
    critical_assets_count:   int = 0

    # Operational Recovery & Checklist
    recovery_actions:        List[RecoveryAction] = Field(default_factory=list)
    recovery_checklist:      RecoveryChecklist = Field(default_factory=RecoveryChecklist)

    # Narrative explanation (Qwen3-8B)
    explanation:             str = ""

    # Traceability & Verification Metadata
    all_cited_evidence_ids:  List[str] = Field(default_factory=list)
    citation_validation:     Dict[str, Any] = Field(default_factory=dict)
    sanitization_summary:    Dict[str, Any] = Field(default_factory=dict)
