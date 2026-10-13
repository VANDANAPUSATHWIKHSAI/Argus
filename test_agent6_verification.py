"""
ARGUS Agent 6 — Impact Assessment Verification Suite
=====================================================
Executes comprehensive end-to-end verification of Agent 6:
  1. Exact FIRST.org CVSS v3.1 deterministic base scores and roundup mathematics.
  2. Anti-hallucination guard: missing metrics explicitly caught as INSUFFICIENT_DATA.
  3. Evidence-to-CVSS metric mapping with traceable evidence citations.
  4. Separation of vulnerability severity (CVSS) and incident impact (ISS).
  5. Multi-factor Investigation Severity Score (ISS) calculations.
  6. Affected asset inventory discovery and risk classification.
  7. Prioritized operational recovery playbook and lifecycle checklist generation.
  8. End-to-end execution of ImpactAssessmentAgent with mock and fallback narrations.
  9. Citation universe validation.
"""

import os
import sys
import json
from datetime import datetime, timezone

# Ensure project root in python path
sys.path.insert(0, os.path.abspath("."))

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


def test_cvss_calculator():
    print("[TEST 1] Testing CVSS v3.1 Official Vectors & Mathematics...")
    # Roundup tests
    assert cvss_roundup(4.0) == 4.0
    assert cvss_roundup(4.02) == 4.1
    assert cvss_roundup(9.800000000000002) == 9.8
    assert cvss_roundup(9.81) == 9.9
    assert cvss_roundup(0.0) == 0.0

    # Official vectors
    # 1. Critical 9.8
    v1 = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    r1 = CVSSCalculator.calculate_base_score(v1)
    assert r1["base_score"] == 9.8, f"Expected 9.8, got {r1['base_score']}"
    assert r1["severity"] == CVSSSeverity.CRITICAL

    # 2. Critical 10.0 (Scope Changed)
    v2 = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"}
    r2 = CVSSCalculator.calculate_base_score(v2)
    assert r2["base_score"] == 10.0, f"Expected 10.0, got {r2['base_score']}"
    assert r2["severity"] == CVSSSeverity.CRITICAL

    # 3. High 7.8
    v3 = {"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    r3 = CVSSCalculator.calculate_base_score(v3)
    assert r3["base_score"] == 7.8, f"Expected 7.8, got {r3['base_score']}"
    assert r3["severity"] == CVSSSeverity.HIGH

    # 4. Medium 6.1
    v4 = {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"}
    r4 = CVSSCalculator.calculate_base_score(v4)
    assert r4["base_score"] == 6.1, f"Expected 6.1, got {r4['base_score']}"
    assert r4["severity"] == CVSSSeverity.MEDIUM

    # 5. None 0.0
    v5 = {"AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U", "C": "N", "I": "N", "A": "N"}
    r5 = CVSSCalculator.calculate_base_score(v5)
    assert r5["base_score"] == 0.0, f"Expected 0.0, got {r5['base_score']}"
    assert r5["severity"] == CVSSSeverity.NONE

    # Score bounds test
    min_s, max_s = CVSSCalculator.estimate_score_bounds({"AV": "N", "AC": "L", "PR": "N", "S": "U"}, ["UI", "C", "I", "A"])
    assert min_s == 0.0 and max_s == 9.8
    print("  [+] CVSS Calculator passed all official vectors and boundary equations.")


def test_missing_metrics_safety():
    print("[TEST 2] Testing Anti-Hallucination & Missing Metrics Safety...")
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

    assert cvss_res.assessment_status == AssessmentStatus.INSUFFICIENT_DATA, f"Expected INSUFFICIENT_DATA, got {cvss_res.assessment_status}"
    assert cvss_res.base_score is None, f"Expected None base_score, got {cvss_res.base_score}"
    assert cvss_res.severity == CVSSSeverity.UNDETERMINED
    assert len(cvss_res.missing_metrics) > 0
    assert "attack_vector" in cvss_res.missing_metrics
    assert "privileges_required" in cvss_res.missing_metrics
    print("  [+] Sparse evidence safely handled: NO guessed 9.8 score, status set to INSUFFICIENT_DATA.")


def test_evidence_to_cvss_mapping(sample_ctx):
    print("[TEST 3] Testing Evidence-to-CVSS Metric Mapping with Full Upstream Findings...")
    cvss_res = CVSSMapper.map_evidence_to_cvss(
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"],
        fir_findings=sample_ctx["fir_findings"]
    )

    av = cvss_res.metrics["attack_vector"]
    assert av.is_confirmed is True
    assert av.value_code == "N"
    assert "F-1001" in av.evidence_ids or "F-1002" in av.evidence_ids

    integ = cvss_res.metrics["integrity"]
    assert integ.is_confirmed is True
    assert integ.value_code == "H"
    assert "F-1003" in integ.evidence_ids
    print("  [+] Evidence mapping successfully substantiated metrics with traceable evidence IDs.")


def test_cvss_and_iss_separation(sample_ctx):
    print("[TEST 4] Testing Separation of Technical CVSS vs Investigation ISS...")
    assets = AssetExtractor.extract_assets(
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"],
        fir_findings=sample_ctx["fir_findings"]
    )

    # Low CVSS baseline (4.0)
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
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"],
        fir_findings=sample_ctx["fir_findings"]
    )

    # Verify independence
    assert iss_res.iss_score != low_cvss.base_score
    assert len(iss_res.factor_breakdown) == 6
    assert sum(ISSCalculator.WEIGHTS.values()) == 1.0
    assert iss_res.factor_breakdown["system_integrity"].raw_score >= 7.0
    print(f"  [+] CVSS ({low_cvss.base_score}) and ISS ({iss_res.iss_score}) are strictly decoupled.")


def test_affected_asset_discovery(sample_ctx):
    print("[TEST 5] Testing Affected Asset Extraction & Device Risk Profiling...")
    assets = AssetExtractor.extract_assets(
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"],
        fir_findings=sample_ctx["fir_findings"]
    )

    assert len(assets) >= 2
    asset_ids = {a.asset_id for a in assets}
    assert "WIN-WORKSTATION-01" in asset_ids
    assert "admin" in asset_ids
    print(f"  [+] Discovered {len(assets)} affected assets: {list(asset_ids)}.")


def test_recovery_playbook(sample_ctx):
    print("[TEST 6] Testing Prioritized Recovery Playbook & Checklist...")
    assets = AssetExtractor.extract_assets(
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"],
        fir_findings=sample_ctx["fir_findings"]
    )
    iss_res = ISSCalculator.calculate_iss(
        affected_assets=assets,
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"],
        fir_findings=sample_ctx["fir_findings"]
    )

    actions, checklist = RecoveryEngine.generate_recovery_plan(
        affected_assets=assets,
        iss_assessment=iss_res,
        agent3_output=sample_ctx["agent3_output"],
        agent4_output=sample_ctx["agent4_output"]
    )

    assert len(actions) >= 5
    assert checklist.total_actions == len(actions)
    assert len(checklist.containment_steps) > 0
    assert checklist.containment_steps[0].priority == RecoveryPriority.P1_IMMEDIATE
    print(f"  [+] Generated {len(actions)} operational actions across Containment, Eradication, Recovery, Hardening.")


def test_agent6_end_to_end(sample_ctx):
    print("[TEST 7] Testing End-to-End ImpactAssessmentAgent Execution...")
    class MockModel:
        def generate(self, prompt: str, system_prompt: str = None) -> str:
            return (
                "### Section 1: Executive Incident Summary & Severity\n"
                "Investigation indicates critical intrusion.\n\n"
                "### Section 2: Affected Assets\n"
                "Endpoint WIN-WORKSTATION-01 compromised.\n\n"
                "### Section 3: Technical Vulnerability Analysis\n"
                "CVSS analysis confirms network vector.\n\n"
                "### Section 4: ISS Breakdown\n"
                "Elevated business impact observed.\n\n"
                "### Section 5: Recovery Guidance\n"
                "Immediate network isolation required."
            )

    agent = ImpactAssessmentAgent(
        model=MockModel(),
        fir_repo=FIRRepository(),
        sanitization_gateway=SanitizationGateway(),
        tenant_id="default"
    )

    output: Agent6Output = agent.execute_assessment(
        case_id="CASE-VERIFY-2026-001",
        upstream_context=sample_ctx
    )

    assert output.agent_id == "agent_6"
    assert output.execution_status == "SUCCESS"
    assert output.total_assets_affected >= 2
    assert output.iss_assessment.iss_score > 0.0
    assert len(output.recovery_actions) >= 5
    assert len(output.all_cited_evidence_ids) >= 2
    assert output.citation_validation["citation_valid"] is True
    print(f"  [+] End-to-End Agent 6 assessment SUCCESS (ISS: {output.iss_assessment.iss_score}/10, Assets: {output.total_assets_affected}).")


def test_deterministic_fallback(sample_ctx):
    print("[TEST 8] Testing Deterministic Fallback Narration when LLM Offline...")
    class OfflineModel:
        def generate(self, prompt: str, system_prompt: str = None) -> str:
            raise ConnectionError("Ollama endpoint offline")

    agent = ImpactAssessmentAgent(
        model=OfflineModel(),
        fir_repo=FIRRepository(),
        sanitization_gateway=SanitizationGateway(),
        tenant_id="default"
    )

    output: Agent6Output = agent.execute_assessment(
        case_id="CASE-VERIFY-2026-001",
        upstream_context=sample_ctx
    )

    assert output.execution_status == "SUCCESS"
    assert len(output.explanation) > 100
    assert "Executive Incident Summary" in output.explanation
    assert "Affected Assets" in output.explanation
    assert "Recovery Guidance" in output.explanation
    print("  [+] Deterministic fallback narration verified.")


def test_citation_integrity():
    print("[TEST 9] Testing Citation Universe Validation Gate...")
    cvss = CVSSAssessment(
        assessment_status=AssessmentStatus.COMPLETED,
        base_score=9.8,
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence_ids=["F-1001", "F-HALLUCINATED-999"]
    )
    iss = ISSAssessment(iss_score=8.5, contributing_evidence_ids=["F-1001"])
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
    print("  [+] Citation gate successfully flagged hallucinated evidence ID.")


def main():
    print("=" * 80)
    print("         ARGUS AGENT 6 — IMPACT ASSESSMENT VERIFICATION SUITE")
    print("=" * 80)

    sample_ctx = {
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

    test_cvss_calculator()
    test_missing_metrics_safety()
    test_evidence_to_cvss_mapping(sample_ctx)
    test_cvss_and_iss_separation(sample_ctx)
    test_affected_asset_discovery(sample_ctx)
    test_recovery_playbook(sample_ctx)
    test_agent6_end_to_end(sample_ctx)
    test_deterministic_fallback(sample_ctx)
    test_citation_integrity()

    print("=" * 80)
    print("  [SUCCESS] ALL 9 VERIFICATION TESTS PASSED PERFECTLY FOR AGENT 6!")
    print("=" * 80)


if __name__ == "__main__":
    main()
