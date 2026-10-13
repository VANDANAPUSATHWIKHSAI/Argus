"""
Unit & Integration Test Suite for Agent 6 — Impact Assessment
==============================================================
Validates:
  1. Exact FIRST.org CVSS v3.1 deterministic calculations across known test vectors.
  2. Evidence-to-CVSS mapping engine with evidence traceability.
  3. Strict anti-hallucination guard: missing metrics explicitly reported, INSUFFICIENT_DATA
     status applied without guessing 9.8 Critical scores.
  4. Separation of technical vulnerability severity (CVSS) from investigation incident impact (ISS).
  5. Deterministic ISS multi-factor scoring with transparent factor attribution.
  6. Affected asset inventory discovery, risk scoring, and compromise classification.
  7. Prioritized operational recovery playbooks and lifecycle checklist generation.
  8. End-to-end ImpactAssessmentAgent execution with LLM narration and deterministic fallback.
  9. Citation validation gate and PostgreSQL persistence.
"""

import pytest
import json
from typing import Dict, Any

from agents.agent6_impact_assessment import (
    ImpactAssessmentAgent,
    Agent6Output,
    CVSSAssessment,
    ISSAssessment,
    AssessmentStatus,
    CVSSSeverity,
    ISSSeverity,
    CVSSCalculator,
    cvss_roundup,
    derive_cvss_severity,
    CVSSMapper,
    ISSCalculator,
    AssetExtractor,
    RecoveryEngine,
    Agent6Validator,
    RecoveryPhase,
    RecoveryPriority,
    AssetCriticality,
    CompromiseState
)
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fir_repo():
    repo = FIRRepository()
    repo.clear()
    yield repo
    repo.clear()


@pytest.fixture
def sanitization_gateway():
    return SanitizationGateway()


@pytest.fixture
def mock_qwen3_8b_model():
    class MockQwen3Model:
        def generate(self, prompt: str, system_prompt: str = None) -> str:
            assert "cvss" in prompt.lower() or "case" in prompt.lower() or "iss" in prompt.lower()
            return (
                "### Section 1: Executive Incident Summary & Severity\n"
                "The investigation indicates a severe intrusion requiring immediate containment.\n\n"
                "### Section 2: Affected Assets\n"
                "Endpoint WIN-WORKSTATION-01 and user admin were compromised.\n\n"
                "### Section 3: Technical Vulnerability Analysis\n"
                "CVSS technical score substantiates remote network exploitation.\n\n"
                "### Section 4: ISS Breakdown\n"
                "Investigation severity score indicates elevated business risk.\n\n"
                "### Section 5: Recovery Guidance\n"
                "Isolate host WIN-WORKSTATION-01 and revoke compromised account credentials."
            )
    return MockQwen3Model()


@pytest.fixture
def sample_upstream_context():
    """Simulates realistic upstream findings from Agents 2, 3, 4, 5 and FIR."""
    return {
        "case_id": "CASE-INCIDENT-2026-001",
        "tenant_id": "default",
        "agent3_output": {
            "infection_path": {
                "entry_point": "Remote network socket connection from external C2",
                "evidence_ids": ["F-1001", "F-1002"],
                "confidence": 0.92
            },
            "attack_path": [
                {
                    "step_number": 1,
                    "action": "Initial network access via cmd.exe spawning powershell.exe",
                    "evidence_ids": ["F-1001"]
                },
                {
                    "step_number": 2,
                    "action": "Persistence installed via scheduled task update.exe",
                    "evidence_ids": ["F-1003"]
                }
            ],
            "lateral_movement": []
        },
        "agent4_output": {
            "claims": [
                {
                    "claim_id": "CLM-AG4-001",
                    "summary": "PowerShell execution correlated with network socket C2 connection to 192.168.1.50",
                    "findings_summary": "Finding F-1001 records process cmd.exe spawning powershell.exe targeting IP 192.168.1.50. Finding F-1002 verifies socket connection to 192.168.1.50 transferring 450KB.",
                    "cited_evidence_ids": ["F-1001", "F-1002"],
                    "infection_stage": "Execution",
                    "ioc_collection": {
                        "ip_addresses": ["192.168.1.50"],
                        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
                    }
                },
                {
                    "claim_id": "CLM-AG4-002",
                    "summary": "Persistence mechanism update.exe installed by user admin",
                    "findings_summary": "Finding F-1003 details user 'admin' on host WIN-WORKSTATION-01 creating a scheduled task persistence update.exe with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
                    "cited_evidence_ids": ["F-1001", "F-1003"],
                    "infection_stage": "Persistence",
                    "ioc_collection": {
                        "ip_addresses": [],
                        "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
                    }
                }
            ]
        },
        "fir_findings": [
            {
                "finding_id": "F-1001",
                "fact": "Process cmd.exe spawned powershell.exe -enc AAAA on host WIN-WORKSTATION-01 targeting IP 192.168.1.50 at 14:00:00 UTC.",
                "evidence_reference": ["EVID-001"]
            },
            {
                "finding_id": "F-1002",
                "fact": "Established network socket connection from WIN-WORKSTATION-01 to external IP 192.168.1.50 transferring 450KB at 14:12:00 UTC.",
                "evidence_reference": ["EVID-002"]
            },
            {
                "finding_id": "F-1003",
                "fact": "User 'admin' created scheduled task persistence update.exe on WIN-WORKSTATION-01 at 14:30:00 UTC.",
                "evidence_reference": ["EVID-003"]
            }
        ]
    }


# ── 1. CVSS v3.1 Calculator Tests ─────────────────────────────────────────────

def test_cvss_roundup_specification():
    """Verifies official FIRST.org Appendix A roundup math."""
    assert cvss_roundup(4.0) == 4.0
    assert cvss_roundup(4.02) == 4.1
    assert cvss_roundup(9.800000000000002) == 9.8
    assert cvss_roundup(9.81) == 9.9
    assert cvss_roundup(0.0) == 0.0


def test_cvss_known_vectors():
    """Validates CVSS base score calculation against official FIRST.org reference vectors."""
    # Critical 9.8: Network, Low Complexity, No Privs, No UI, Scope Unchanged, High C, High I, High A
    v1 = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "H"
    }
    r1 = CVSSCalculator.calculate_base_score(v1)
    assert r1["base_score"] == 9.8
    assert r1["severity"] == CVSSSeverity.CRITICAL
    assert r1["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    # Critical 10.0: Network, Low Complexity, No Privs, No UI, Scope Changed, High C, High I, High A
    v2 = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
        "C": "H", "I": "H", "A": "H"
    }
    r2 = CVSSCalculator.calculate_base_score(v2)
    assert r2["base_score"] == 10.0
    assert r2["severity"] == CVSSSeverity.CRITICAL

    # High 7.8: Local, Low Complexity, Low Privs, No UI, Scope Unchanged, High C, High I, High A
    v3 = {
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U",
        "C": "H", "I": "H", "A": "H"
    }
    r3 = CVSSCalculator.calculate_base_score(v3)
    assert r3["base_score"] == 7.8
    assert r3["severity"] == CVSSSeverity.HIGH

    # Medium 6.1: Network, Low Complexity, No Privs, User Interaction Required, Scope Changed, Low C, Low I, None A
    v4 = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
        "C": "L", "I": "L", "A": "N"
    }
    r4 = CVSSCalculator.calculate_base_score(v4)
    assert r4["base_score"] == 6.1
    assert r4["severity"] == CVSSSeverity.MEDIUM

    # None 0.0: No impact metrics
    v5 = {
        "AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U",
        "C": "N", "I": "N", "A": "N"
    }
    r5 = CVSSCalculator.calculate_base_score(v5)
    assert r5["base_score"] == 0.0
    assert r5["severity"] == CVSSSeverity.NONE


def test_cvss_score_bounds_estimation():
    """Verifies mathematical boundary estimation for partial metrics."""
    known = {"AV": "N", "AC": "L", "PR": "N", "S": "U"}
    missing = ["UI", "C", "I", "A"]
    min_score, max_score = CVSSCalculator.estimate_score_bounds(known, missing)
    # With no impact, minimum is 0.0; with all high impacts, maximum is 9.8
    assert min_score == 0.0
    assert max_score == 9.8
    assert min_score <= max_score


# ── 2. Anti-Hallucination & Missing Metric Safety Tests ────────────────────────

def test_missing_metrics_insufficient_data_safety():
    """
    CRITICAL TEST (User Requirement 4):
    When evidence is vague or missing key metrics (e.g. only suspicious activity noted),
    Agent 6 MUST NOT hallucinate a 9.8 Critical score.
    Must return INSUFFICIENT_DATA and explicit missing_metrics list.
    """
    sparse_agent3 = {
        "infection_path": {"entry_point": "Suspicious activity observed", "evidence_ids": ["F-001"]},
        "attack_path": [],
        "lateral_movement": []
    }
    sparse_agent4 = {
        "claims": [
            {
                "claim_id": "CLM-SPARSE",
                "summary": "Malware-like characteristics detected without definitive execution or C2",
                "findings_summary": "Finding F-001 shows an unconfirmed anomaly.",
                "cited_evidence_ids": ["F-001"]
            }
        ]
    }
    sparse_fir = [
        {"finding_id": "F-001", "fact": "Suspicious activity observed in system telemetry."}
    ]

    cvss_res: CVSSAssessment = CVSSMapper.map_evidence_to_cvss(
        agent3_output=sparse_agent3,
        agent4_output=sparse_agent4,
        fir_findings=sparse_fir
    )

    # Must NOT guess a score!
    assert cvss_res.assessment_status == AssessmentStatus.INSUFFICIENT_DATA
    assert cvss_res.base_score is None
    assert cvss_res.severity == CVSSSeverity.UNDETERMINED
    assert len(cvss_res.missing_metrics) > 0
    assert "attack_vector" in cvss_res.missing_metrics
    assert "privileges_required" in cvss_res.missing_metrics
    assert "Insufficient forensic evidence" in cvss_res.calculation_notes


# ── 3. Evidence-to-CVSS Mapping Engine Tests ──────────────────────────────────

def test_evidence_to_cvss_mapping_with_full_evidence(sample_upstream_context):
    """Verifies grounded mapping from concrete upstream evidence."""
    cvss_res = CVSSMapper.map_evidence_to_cvss(
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"],
        fir_findings=sample_upstream_context["fir_findings"]
    )

    # Check metric grounding
    av = cvss_res.metrics["attack_vector"]
    assert av.is_confirmed is True
    assert av.value_code == "N"
    assert "F-1001" in av.evidence_ids or "F-1002" in av.evidence_ids
    assert "network" in av.justification.lower()

    integ = cvss_res.metrics["integrity"]
    assert integ.is_confirmed is True
    assert integ.value_code == "H"
    assert "F-1003" in integ.evidence_ids

    # Confirmed metrics traceability
    assert len(cvss_res.evidence_ids) >= 2


# ── 4. Separation of CVSS Severity vs Investigation ISS Tests ─────────────────

def test_separation_of_cvss_and_iss(sample_upstream_context):
    """
    Verifies that CVSS (technical vulnerability severity) and ISS (investigation impact)
    are strictly distinct and independently calculated.
    """
    assets = AssetExtractor.extract_assets(
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"],
        fir_findings=sample_upstream_context["fir_findings"]
    )

    # Simulate low technical CVSS (e.g. 4.0)
    low_cvss = CVSSAssessment(
        assessment_status=AssessmentStatus.COMPLETED,
        base_score=4.0,
        severity=CVSSSeverity.MEDIUM,
        vector_string="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        evidence_ids=["F-1001"]
    )

    iss_res = ISSCalculator.calculate_iss(
        affected_assets=assets,
        cvss_assessment=low_cvss,
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"],
        fir_findings=sample_upstream_context["fir_findings"]
    )

    # ISS is not forced to 4.0; it evaluates business risk across assets and integrity!
    assert iss_res.iss_score != low_cvss.base_score
    assert len(iss_res.factor_breakdown) == 6
    assert "asset_criticality" in iss_res.factor_breakdown
    assert "system_integrity" in iss_res.factor_breakdown
    assert iss_res.factor_breakdown["system_integrity"].raw_score >= 7.0  # persistence detected


def test_iss_factor_weights_sum_to_one():
    """Verifies that all 6 ISS factor weights sum to 1.00."""
    total_weights = sum(ISSCalculator.WEIGHTS.values())
    assert round(total_weights, 4) == 1.0000


# ── 5. Affected Asset Extraction Tests ────────────────────────────────────────

def test_affected_asset_extraction(sample_upstream_context):
    """Verifies discovery of affected hosts, accounts, and risk scoring."""
    assets = AssetExtractor.extract_assets(
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"],
        fir_findings=sample_upstream_context["fir_findings"]
    )

    assert len(assets) >= 2
    asset_ids = {a.asset_id for a in assets}
    assert "WIN-WORKSTATION-01" in asset_ids
    assert "admin" in asset_ids

    win_host = next(a for a in assets if a.asset_id == "WIN-WORKSTATION-01")
    assert win_host.compromise_state == CompromiseState.CONFIRMED_COMPROMISED
    assert "F-1001" in win_host.evidence_ids or "F-1003" in win_host.evidence_ids


# ── 6. Recovery Recommendations & Checklist Tests ─────────────────────────────

def test_recovery_plan_generation(sample_upstream_context):
    """Verifies prioritized DFIR recovery playbook across the 4 phases."""
    assets = AssetExtractor.extract_assets(
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"],
        fir_findings=sample_upstream_context["fir_findings"]
    )
    iss_res = ISSCalculator.calculate_iss(
        affected_assets=assets,
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"],
        fir_findings=sample_upstream_context["fir_findings"]
    )

    actions, checklist = RecoveryEngine.generate_recovery_plan(
        affected_assets=assets,
        iss_assessment=iss_res,
        agent3_output=sample_upstream_context["agent3_output"],
        agent4_output=sample_upstream_context["agent4_output"]
    )

    assert len(actions) >= 5
    assert checklist.total_actions == len(actions)

    # Check phase coverage
    assert len(checklist.containment_steps) > 0
    assert len(checklist.eradication_steps) > 0
    assert len(checklist.recovery_steps) > 0
    assert len(checklist.hardening_steps) > 0

    # Containment must be immediate priority
    assert checklist.containment_steps[0].priority == RecoveryPriority.P1_IMMEDIATE
    assert "isolate" in checklist.containment_steps[0].title.lower()


# ── 7. End-to-End Agent 6 Execution Tests ─────────────────────────────────────

def test_agent6_end_to_end_execution(sample_upstream_context, fir_repo, sanitization_gateway, mock_qwen3_8b_model):
    """Verifies complete Agent 6 execution with mock LLM narration and schema validation."""
    agent = ImpactAssessmentAgent(
        model=mock_qwen3_8b_model,
        fir_repo=fir_repo,
        sanitization_gateway=sanitization_gateway,
        tenant_id="default"
    )

    out: Agent6Output = agent.execute_assessment(
        case_id="CASE-INCIDENT-2026-001",
        upstream_context=sample_upstream_context
    )

    assert out.agent_id == "agent_6"
    assert out.execution_status == "SUCCESS"
    assert out.total_assets_affected >= 2
    assert out.iss_assessment.iss_score > 0.0
    assert len(out.recovery_actions) >= 5
    assert len(out.all_cited_evidence_ids) >= 2

    # Verify narration is present
    assert len(out.explanation) > 50
    assert "Section 1" in out.explanation

    # Verify citation validation report
    assert out.citation_validation["citation_valid"] is True
    assert out.citation_validation["total_citations"] >= 2


def test_agent6_deterministic_fallback_narration(sample_upstream_context, fir_repo, sanitization_gateway):
    """Verifies that if LLM fails or is offline, Agent 6 generates deterministic fallback narration."""
    class FailingModel:
        def generate(self, prompt: str, system_prompt: str = None) -> str:
            raise ConnectionError("Ollama endpoint offline")

    agent = ImpactAssessmentAgent(
        model=FailingModel(),
        fir_repo=fir_repo,
        sanitization_gateway=sanitization_gateway,
        tenant_id="default"
    )

    out: Agent6Output = agent.execute_assessment(
        case_id="CASE-INCIDENT-2026-001",
        upstream_context=sample_upstream_context
    )

    assert out.execution_status == "SUCCESS"
    assert len(out.explanation) > 100
    assert "Executive Incident Summary" in out.explanation
    assert "Affected Assets" in out.explanation
    assert "Recovery Guidance" in out.explanation


def test_agent6_citation_validation_flags_hallucinations(sample_upstream_context):
    """Verifies that Agent6Validator catches and flags any cited IDs outside the valid universe."""
    cvss = CVSSAssessment(
        assessment_status=AssessmentStatus.COMPLETED,
        base_score=9.8,
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence_ids=["F-1001", "F-HALLUCINATED-999"]
    )
    iss = ISSAssessment(
        iss_score=8.5,
        contributing_evidence_ids=["F-1001"]
    )
    valid_universe = {"F-1001", "F-1002", "F-1003"}

    res = Agent6Validator.validate_output(
        cvss=cvss,
        iss=iss,
        assets=[],
        recovery_actions=[],
        valid_evidence_universe=valid_universe
    )

    assert res["citation_valid"] is False
    assert "F-HALLUCINATED-999" in res["invalid_citations"]
