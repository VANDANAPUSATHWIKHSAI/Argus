"""
Agent 6 — Impact Assessment Schemas
====================================
Defines structured data contracts for asset-level impact evaluation,
evidence grounding, and risk-calibrated recommendations.
"""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


class AssetImpactDetail(BaseModel):
    asset_name: str
    status: Literal["confirmed_compromise", "suspected_impact", "unsupported_in_evidence"]
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    observed_facts: List[str] = Field(default_factory=list)
    severity: str = "medium"
    rationale: str = ""


class ImmediateRecommendation(BaseModel):
    action: str
    urgency: Literal["low", "medium", "high", "critical"] = "medium"
    supporting_indicators: List[str] = Field(default_factory=list)
    status: Literal["provisional_recommended", "contingent_on_investigation"] = "provisional_recommended"
    rationale: str


class ImpactAssessmentOutput(BaseModel):
    case_id: str
    tenant_id: str = "default"
    claim: str
    evidence_ids: List[str] = Field(default_factory=list)
    validation_status: Literal["supported", "partially_supported", "insufficient_evidence"]
    asset_impacts: List[AssetImpactDetail] = Field(default_factory=list)
    confirmed_findings: List[str] = Field(default_factory=list)
    immediate_recommendations: List[ImmediateRecommendation] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
