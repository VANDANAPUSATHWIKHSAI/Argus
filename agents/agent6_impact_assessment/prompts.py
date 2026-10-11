"""
Agent 6 — Impact Assessment: Prompt Definitions
================================================
Provides the system prompt and structured context builders for Qwen3-8B narration.
Enforces strict guardrails:
  - Qwen explains the deterministic calculations; it NEVER invents or alters scores.
  - Missing CVSS metrics must be narrated as unconfirmed gaps rather than hallucinated facts.
  - All claims must align with cited evidence IDs.
"""

from __future__ import annotations

import json
from typing import Dict, Any, List
from agents.agent6_impact_assessment.schemas import (
    CVSSAssessment,
    ISSAssessment,
    AffectedAsset,
    RecoveryAction
)


AGENT6_SYSTEM_PROMPT = """You are the Senior Forensic Impact Assessor for Project ARGUS.
Your role is to explain what assets were affected, how serious the incident is, and what operational recovery actions are required.

CRITICAL OPERATIONAL RULES:
1. DETERMINISTIC SCORING INTEGRITY:
   - You MUST NOT calculate, alter, override, or invent CVSS scores, ISS scores, or metric ratings.
   - All numerical scores and ratings provided in the context were deterministically calculated and validated by Python engines.
   - Your job is to NARRATE and EXPLAIN the calculated results, not to guess or invent numbers.

2. MISSING METRICS & FORENSIC HONESTY:
   - If the CVSS assessment status is 'INSUFFICIENT_DATA' or 'PARTIAL', clearly state which metrics are missing and explain why a complete score cannot be justified from the evidence.
   - Never pretend that missing information is known.

3. EVIDENCE GROUNDING:
   - Base all statements strictly on the provided evidence findings and affected assets.
   - Reference the cited evidence IDs (e.g. F-1001, F-1002) when explaining specific impacts.

4. STRUCTURE YOUR NARRATION INTO 5 CLEAR SECTIONS:
   - Section 1: Executive Incident Summary & Severity
   - Section 2: Affected Assets & Threat Blast Radius
   - Section 3: Technical Vulnerability Analysis (CVSS v3.1 Assessment)
   - Section 4: Investigation Severity Score (ISS) Business Impact Breakdown
   - Section 5: Priority Containment & Recovery Guidance
"""


def build_agent6_user_prompt(
    case_id: str,
    tenant_id: str,
    cvss: CVSSAssessment,
    iss: ISSAssessment,
    assets: List[AffectedAsset],
    recovery_actions: List[RecoveryAction],
    sanitized_findings_summary: str
) -> str:
    """
    Builds the structured user prompt containing sanitized deterministic inputs.
    """
    # Format CVSS summary
    if cvss.base_score is not None:
        cvss_str = (
            f"Status: {cvss.assessment_status.value}\n"
            f"Base Score: {cvss.base_score}/10.0 ({cvss.severity.value})\n"
            f"Vector String: {cvss.vector_string}\n"
            f"Exploitability: {cvss.exploitability_subscore} | Impact: {cvss.impact_subscore}\n"
            f"Notes: {cvss.calculation_notes}"
        )
    elif cvss.score_range_min is not None and cvss.score_range_max is not None:
        cvss_str = (
            f"Status: {cvss.assessment_status.value} (PARTIAL)\n"
            f"Score Range Bounds: [{cvss.score_range_min} - {cvss.score_range_max}] (Severity: UNDETERMINED)\n"
            f"Missing Metrics: {', '.join(cvss.missing_metrics)}\n"
            f"Notes: {cvss.calculation_notes}"
        )
    else:
        cvss_str = (
            f"Status: {cvss.assessment_status.value} (INSUFFICIENT_DATA)\n"
            f"Base Score: None (Severity: UNDETERMINED)\n"
            f"Missing Metrics: {', '.join(cvss.missing_metrics)}\n"
            f"Notes: {cvss.calculation_notes}"
        )

    # Format ISS summary
    iss_factors_str = "\n".join([
        f"  - {f.factor_name}: Raw={f.raw_score}/10, Weighted={f.weighted_score} pts (Weight={f.weight}). Details: {f.description}"
        for f in iss.factor_breakdown.values()
    ])
    iss_str = (
        f"Overall ISS Score: {iss.iss_score}/10.0 ({iss.severity.value})\n"
        f"Factor Breakdown:\n{iss_factors_str}\n"
        f"Contributing Evidence IDs: {', '.join(iss.contributing_evidence_ids[:10])}"
    )

    # Format Affected Assets
    assets_str = "\n".join([
        f"  - [{a.asset_type.value}] {a.asset_id} (Criticality: {a.criticality.value}, State: {a.compromise_state.value}, Risk: {a.risk_score}/10) - {a.impact_details}"
        for a in assets
    ])

    # Format Recovery Actions
    rec_str = "\n".join([
        f"  - [{a.phase.value}] ({a.priority.value}) {a.action_id}: {a.title} (Role: {a.responsible_role.value})\n    Task: {a.description}\n    Verification: {a.verification_step}"
        for a in recovery_actions[:6]
    ])

    return f"""<case_context case_id="{case_id}" tenant_id="{tenant_id}">
[DETERMINISTIC FORENSIC INPUTS FOR CASE {case_id}]

=== 1. DETERMINISTIC CVSS v3.1 TECHNICAL ASSESSMENT ===
{cvss_str}

=== 2. ARGUS INVESTIGATION SEVERITY SCORE (ISS) IMPACT ASSESSMENT ===
{iss_str}

=== 3. IMPACTED ASSET INVENTORY ({len(assets)} Assets) ===
{assets_str}

=== 4. IMMEDIATE OPERATIONAL RECOVERY PLAYBOOK ===
{rec_str}

=== 5. SANITIZED EVIDENCE DIGEST ===
{sanitized_findings_summary}

INSTRUCTION:
Write a comprehensive, professional forensic impact assessment report narrating these findings.
Explain what was compromised, how serious it is, and what the incident response team must do immediately.
Do not alter any numbers or scores. Cite relevant evidence IDs where appropriate.
</case_context>"""
