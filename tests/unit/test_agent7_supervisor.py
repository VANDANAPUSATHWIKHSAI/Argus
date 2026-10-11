"""
Unit Test Suite — Agent 7 (Supervisor + Verification + Report Generation)
========================================================================
Comprehensive verification and quality validation test suite for Agent 7:
  1. Call 1 Synthesis (Structured claims, evidence attachments, conflict resolution)
  2. Call 2 Independent Verification (Existence, DeBERTa-MNLI support, Severity inflation, Divergence)
  3. Critical Rule: Inconclusive DeBERTa entailment (< 0.70) remains unverified (LLM fallback cannot self-approve)
  4. Cross-Tenant Evidence Reference Security Validation
  5. Confidence Gate Maker-Checker Routing & Boundary Tests (0.849 vs 0.850 vs 0.851)
  6. Deterministic Multi-Audience Report Generation & Metadata Stamping (No Fabricated Hashes)
  7. Interactive Investigation Assistant (Grounded Q&A, Tenant Scoping, Unavailable Data Handling)
  8. LangGraph StateGraph Execution:
     - Happy Path (Routine Review)
     - Senior/Dual Review Branch
     - Failure Terminal Node on Invalid/Missing case_id
  9. Real DeBERTa-v3-large-MNLI Entailment Integration Test
  10. ISM Integration Boundary Contract Validation
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository
from confidence_gate.gate import ConfidenceGate, ReviewRoute
from agents.agent7_supervisor.schemas import StructuredClaim, ClaimVerificationResult
from agents.agent7_supervisor.call1_synthesis import SupervisorSynthesis
from agents.agent7_supervisor.call2_verification import SupervisorVerification
from agents.agent7_supervisor.report_builder import SupervisorReportBuilder
from agents.agent7_supervisor.assistant import InteractiveInvestigationAssistant
from agents.agent7_supervisor.agent import SupervisorAgent
from agents.agent7_supervisor.ism_contract import (
    ISMAgent7ExecutionRecord, ISMExecutionStatus, ISMErrorCategory, build_ism_idempotency_key
)


def make_test_finding(
    finding_id: str = "FIR-7001",
    case_id: str = "CASE-701",
    tenant_id: str = "default",
    fact: str = "Suspicious process powershell.exe executed with encoded command line -enc SQBFAFgA",
    confidence: float = 0.95,
    severity: str = "high",
    review_status: ReviewStatus = ReviewStatus.PENDING_REVIEW,
) -> FIRFinding:
    return FIRFinding(
        finding_id=finding_id,
        case_id=case_id,
        tenant_id=tenant_id,
        fact=fact,
        sanitized_fact=fact,
        confidence=confidence,
        severity=severity,
        mitre_mapping="T1059.001",
        timestamp=datetime.now(timezone.utc),
        evidence_reference=["LOG-7001"],
        layer="powershell_analyzer",
        review_status=review_status,
    )


# ── 1. Call 1 Synthesis Tests ──────────────────────────────────────────────────

def test_call1_synthesis_structured_claim_generation():
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    synthesis_llm_json = json.dumps({
        "executive_summary": "Initial compromise observed via PowerShell execution.",
        "incident_narrative": "Adversary ran encoded command to download secondary payload.",
        "claims": [
            {
                "claim_id": "CLM-101",
                "claim": "PowerShell executed encoded download cradle on endpoint.",
                "evidence_ids": ["FIR-7001"],
                "severity": "high",
                "is_attribution": False,
                "confidence": 0.95,
                "mitre_tactics": ["Execution"],
                "mitre_techniques": ["T1059.001"]
            }
        ],
        "attack_timeline": [
            {
                "timestamp": "2026-10-11T12:00:00Z",
                "stage": "Execution",
                "summary": "Encoded powershell execution",
                "evidence_id": "FIR-7001"
            }
        ],
        "conflicts_resolved": [],
        "confidence_score": 0.92
    })
    mock_model.generate.return_value = synthesis_llm_json

    agent = SupervisorSynthesis(mock_model, mock_fir, mock_gateway, tenant_id="default")
    result = agent.run("CASE-701", {
        "agent_outputs": {"agent3": {"kill_chain": "Execution"}},
        "evidence_ids": ["FIR-7001"]
    })

    assert result["case_id"] == "CASE-701"
    assert result["confidence_score"] == 0.92
    assert len(result["claims"]) == 1
    claim = result["claims"][0]
    assert claim["claim_id"] == "CLM-101"
    assert claim["evidence_ids"] == ["FIR-7001"]
    assert claim["severity"] == "high"
    assert len(result["attack_timeline"]) == 1


# ── 2. Call 2 Independent Verification Tests ──────────────────────────────────

def test_call2_verification_all_checks_pass():
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    finding = make_test_finding(finding_id="FIR-7001", severity="high", confidence=0.95)
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="default")

    # Mock MNLI classifier entailment to return supports
    with patch("models.classifiers.ClassifierLoader.load_mnli") as mock_mnli_loader:
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.88, 0.08, 0.04]
        }
        mock_mnli_loader.return_value = mock_pipeline

        claim = {
            "claim_id": "CLM-001",
            "claim": "Process powershell.exe executed malicious script block.",
            "evidence_ids": ["FIR-7001"],
            "severity": "high",
            "confidence": 0.90,
        }

        ver_result = verifier.verify(claim, tenant_id="default")

        assert ver_result["verified"] is True
        assert ver_result["status"] == "verified"
        assert ver_result["checks"]["existence"] is True
        assert ver_result["checks"]["support"] is True
        assert ver_result["checks"]["severity"] is True
        assert ver_result["checks"]["divergence"] is True
        assert ver_result["support_score"] == 0.88
        assert len(ver_result["flags"]) == 0


def test_call2_verification_existence_check_fails_on_missing_evidence():
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="default")

    claim = {
        "claim_id": "CLM-002",
        "claim": "Non-existent finding assertion.",
        "evidence_ids": ["FIR-GHOST-9999"],
        "severity": "low",
        "confidence": 0.80,
    }

    ver_result = verifier.verify(claim, tenant_id="default")
    assert ver_result["verified"] is False
    assert ver_result["status"] == "unverified — requires manual confirmation"
    assert ver_result["checks"]["existence"] is False
    assert any("not found in FIR" in f for f in ver_result["flags"])


def test_call2_verification_severity_inflation_check():
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    # Evidence is only informational with 0.50 confidence
    finding = make_test_finding(
        finding_id="FIR-7002",
        severity="informational",
        confidence=0.50,
        fact="Service status query executed."
    )
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="default")

    with patch("models.classifiers.ClassifierLoader.load_mnli") as mock_mnli_loader:
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.90, 0.05, 0.05]
        }
        mock_mnli_loader.return_value = mock_pipeline

        # Claim attempts to claim CRITICAL severity and 0.95 confidence
        claim = {
            "claim_id": "CLM-003",
            "claim": "Critical infrastructure compromise.",
            "evidence_ids": ["FIR-7002"],
            "severity": "critical",
            "confidence": 0.95,
        }

        ver_result = verifier.verify(claim, tenant_id="default")
        assert ver_result["verified"] is False
        assert ver_result["checks"]["severity"] is False
        assert any("inflated" in f for f in ver_result["flags"])


def test_call2_verification_divergence_check_on_rejected_finding():
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    # Finding was rejected by human analyst in Layer 4
    finding = make_test_finding(
        finding_id="FIR-7003",
        severity="high",
        confidence=0.90,
        review_status=ReviewStatus.ANALYST_REJECTED
    )
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="default")

    with patch("models.classifiers.ClassifierLoader.load_mnli") as mock_mnli_loader:
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.85, 0.10, 0.05]
        }
        mock_mnli_loader.return_value = mock_pipeline

        claim = {
            "claim_id": "CLM-004",
            "claim": "Adversary confirmed malicious persistence.",
            "evidence_ids": ["FIR-7003"],
            "severity": "high",
            "confidence": 0.90,
        }

        ver_result = verifier.verify(claim, tenant_id="default")
        assert ver_result["verified"] is False
        assert ver_result["checks"]["divergence"] is False
        assert any("ANALYST_REJECTED" in f for f in ver_result["flags"])


# ── 3. Critical Rule: LLM Fallback Policy Audit ───────────────────────────────

def test_call2_inconclusive_deberta_score_remains_unverified():
    """
    CRITICAL POLICY: If DeBERTa score is < 0.70, the claim MUST remain unverified
    even if an LLM fallback generates 'YES'. Agent 7 cannot self-approve claims.
    """
    mock_model = MagicMock()
    mock_model.generate.return_value = "YES"  # LLM tries to self-approve

    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    finding = make_test_finding(finding_id="FIR-7010", severity="medium", confidence=0.80)
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="default")

    with patch("models.classifiers.ClassifierLoader.load_mnli") as mock_mnli_loader:
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = {
            "labels": ["neutral", "supports", "contradicts"],
            "scores": [0.55, 0.40, 0.05]  # Support score 0.40 < 0.70
        }
        mock_mnli_loader.return_value = mock_pipeline

        claim = {
            "claim_id": "CLM-FALLBACK-1",
            "claim": "Uncertain assertion about malware staging.",
            "evidence_ids": ["FIR-7010"],
            "severity": "medium",
            "confidence": 0.80,
        }

        ver_result = verifier.verify(claim, tenant_id="default")

        # Crucial assertions:
        assert ver_result["verified"] is False
        assert ver_result["status"] == "unverified — requires manual confirmation"
        assert ver_result["checks"]["support"] is False
        assert ver_result["fallback_used"] is True
        assert ver_result["secondary_assessment"] == "SECONDARY_AFFIRMED"
        assert any("Inconclusive semantic entailment" in f for f in ver_result["flags"])


# ── 4. Cross-Tenant Evidence Reference Security Tests ─────────────────────────

def test_call2_verification_cross_tenant_reference_rejected():
    """
    Cross-tenant reference violation must be blocked and fail verification.
    """
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    # Finding inserted for TENANT-A
    finding = make_test_finding(finding_id="FIR-TENANT-A-01", tenant_id="TENANT-A")
    mock_fir.insert(finding)

    # Verifier invoked on behalf of TENANT-B
    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="TENANT-B")

    claim = {
        "claim_id": "CLM-X-TENANT",
        "claim": "Claim referencing evidence from another tenant.",
        "evidence_ids": ["FIR-TENANT-A-01"],
        "severity": "medium",
        "confidence": 0.80,
    }

    ver_result = verifier.verify(claim, tenant_id="TENANT-B")
    assert ver_result["verified"] is False
    assert ver_result["checks"]["existence"] is False
    assert any("not found in FIR for tenant 'TENANT-B'" in f for f in ver_result["flags"])


# ── 5. Confidence Gate Routing & Boundary Tests ───────────────────────────────

def test_confidence_gate_routine_routing():
    gate = ConfidenceGate(confidence_threshold=0.85)

    verification_output = {
        "confidence_score": 0.92,
        "verification_results": [
            {
                "claim_id": "CLM-001",
                "verified": True,
                "is_attribution": False,
                "severity": "high",
                "checks": {"existence": True, "support": True, "severity": True, "divergence": True},
                "flags": []
            }
        ],
        "claims": [{"claim_id": "CLM-001", "is_attribution": False, "severity": "high"}],
        "divergence_flags": []
    }

    decision = gate.evaluate(verification_output)
    assert decision["route"] == ReviewRoute.ROUTINE
    assert decision["requires_senior_review"] is False
    assert decision["unverified_claim_count"] == 0


def test_confidence_gate_boundary_evaluation():
    """
    Tests exact boundary values: 0.849 (senior/dual), 0.850 (routine), 0.851 (routine).
    """
    gate = ConfidenceGate(confidence_threshold=0.85)
    base_results = [
        {
            "claim_id": "CLM-B-1",
            "verified": True,
            "is_attribution": False,
            "severity": "medium",
            "checks": {"existence": True, "support": True, "severity": True, "divergence": True},
            "flags": []
        }
    ]

    # Test 1: Exactly 0.849 -> below threshold -> SENIOR_DUAL
    dec_below = gate.evaluate({"confidence_score": 0.849, "verification_results": base_results})
    assert dec_below["route"] == ReviewRoute.SENIOR_DUAL
    assert dec_below["requires_senior_review"] is True

    # Test 2: Exactly 0.850 -> at threshold -> ROUTINE
    dec_at = gate.evaluate({"confidence_score": 0.850, "verification_results": base_results})
    assert dec_at["route"] == ReviewRoute.ROUTINE
    assert dec_at["requires_senior_review"] is False

    # Test 3: Exactly 0.851 -> above threshold -> ROUTINE
    dec_above = gate.evaluate({"confidence_score": 0.851, "verification_results": base_results})
    assert dec_above["route"] == ReviewRoute.ROUTINE
    assert dec_above["requires_senior_review"] is False


def test_confidence_gate_senior_dual_routing_on_unverified_claim():
    gate = ConfidenceGate(confidence_threshold=0.85)

    verification_output = {
        "confidence_score": 0.90,
        "verification_results": [
            {
                "claim_id": "CLM-001",
                "verified": False,
                "checks": {"existence": True, "support": False, "severity": True, "divergence": True},
                "flags": ["Support score 0.45 < 0.70"]
            }
        ],
        "claims": [{"claim_id": "CLM-001", "severity": "medium"}],
    }

    decision = gate.evaluate(verification_output)
    assert decision["route"] == ReviewRoute.SENIOR_DUAL
    assert decision["requires_senior_review"] is True
    assert decision["unverified_claim_count"] == 1
    assert any("Unverified claim [CLM-001]" in r for r in decision["reasons"])


def test_confidence_gate_senior_dual_routing_on_high_severity_attribution():
    gate = ConfidenceGate(confidence_threshold=0.85)

    verification_output = {
        "confidence_score": 0.95,
        "verification_results": [
            {
                "claim_id": "CLM-ATTR-1",
                "verified": True,
                "is_attribution": True,
                "severity": "critical",
                "checks": {"existence": True, "support": True, "severity": True, "divergence": True},
                "flags": []
            }
        ],
        "claims": [{"claim_id": "CLM-ATTR-1", "is_attribution": True, "severity": "critical"}],
    }

    decision = gate.evaluate(verification_output)
    assert decision["route"] == ReviewRoute.SENIOR_DUAL
    assert decision["requires_senior_review"] is True
    assert any("attribution" in r.lower() for r in decision["reasons"])


# ── 6. Report Builder & Legal Metadata Tests ──────────────────────────────────

def test_report_builder_no_fabricated_hashes():
    builder = SupervisorReportBuilder()

    synthesis = {
        "executive_summary": "Ransomware staging activity stopped before encryption.",
        "incident_narrative": "Initial access through credential stuffing on VPN.",
        "confidence_score": 0.92,
        "attack_timeline": [
            {"timestamp": "2026-10-11T10:00:00Z", "stage": "Initial Access", "summary": "VPN login", "evidence_id": "FIR-001"}
        ],
        "conflicts_resolved": [],
    }

    ver_results = [
        {
            "claim_id": "CLM-001",
            "claim": "VPN login originated from unauthorized foreign ASN.",
            "verified": True,
            "status": "verified",
            "evidence_ids": ["FIR-001"],
            "severity": "high",
            "checks": {"existence": True, "support": True, "severity": True, "divergence": True},
            "flags": [],
        }
    ]

    conf_gate = {
        "route": "routine",
        "reasons": ["All claims verified"],
        "attention_items": [],
    }

    # Pass without providing external snapshot/hash
    package = builder.build_report_package(
        case_id="CASE-REP-900",
        tenant_id="default",
        synthesis=synthesis,
        verification_results=ver_results,
        confidence_gate=conf_gate
    )

    metadata = package["metadata"]
    assert metadata["prompt_template_version"] == "v2.4-supervisor"
    assert metadata["model_name"] == "Qwen3-8B / DeBERTa-v3-large-MNLI"
    assert metadata["model_version_hash"] == "unavailable"
    assert metadata["retrieval_corpus_snapshot_id"] == "unavailable"

    rendered = package["rendered"]
    assert "analyst" in rendered and "customer" in rendered and "executive" in rendered
    assert rendered["analyst"]["html"].startswith("<!DOCTYPE html>")
    assert "VPN login originated from unauthorized foreign ASN." in rendered["analyst"]["html"]


# ── 7. Interactive Investigation Assistant Tests ──────────────────────────────

def test_interactive_investigation_assistant():
    sample_output = {
        "case_id": "CASE-ASSIST-1",
        "tenant_id": "default",
        "synthesis": {
            "executive_summary": "Adversary established persistence via scheduled task.",
            "confidence_score": 0.94,
            "claims": [
                {"claim_id": "CLM-001", "claim": "Task schtasks.exe created daily trigger.", "evidence_ids": ["FIR-8888"]}
            ],
            "attack_timeline": [
                {"timestamp": "2026-10-11T12:00:00Z", "summary": "schtasks created", "evidence_id": "FIR-8888"}
            ]
        },
        "verification_results": [
            {
                "claim_id": "CLM-001",
                "claim": "Task schtasks.exe created daily trigger.",
                "verified": True,
                "status": "verified",
                "evidence_ids": ["FIR-8888"],
                "checks": {"existence": True, "support": True, "severity": True, "divergence": True},
            }
        ],
        "confidence_gate": {
            "route": "routine",
            "confidence_threshold": 0.85,
            "reasons": ["Fully verified"],
            "attention_items": []
        }
    }

    assistant = InteractiveInvestigationAssistant(sample_output)

    # Question A: Timeline
    res_timeline = assistant.ask("Show attack timeline")
    assert res_timeline["query_type"] == "attack_timeline"
    assert len(res_timeline["timeline_events"]) == 1

    # Question B: Supporting evidence
    res_evidence = assistant.ask("Show supporting evidence for findings")
    assert res_evidence["query_type"] == "supporting_evidence"
    assert "FIR-8888" in res_evidence["supporting_evidence"]

    # Question C: Specific evidence lookup
    res_lookup = assistant.ask("Show details for FIR-8888")
    assert res_lookup["query_type"] == "evidence_lookup"
    assert "FIR-8888" in res_lookup["supporting_evidence"]

    # Question D: Nonexistent evidence lookup
    res_none = assistant.ask("Show details for FIR-999999")
    assert res_none["query_type"] == "evidence_lookup"
    assert "unavailable" in res_none["reasoning_explanation"].lower()

    # Question E: Cross-tenant / mismatching tenant security check
    res_unauth = assistant.ask("Why?", context={"tenant_id": "UNAUTHORIZED_TENANT"})
    assert res_unauth["query_type"] == "access_denied"


# ── 8. LangGraph StateGraph Execution Tests ────────────────────────────────────

def test_supervisor_agent_langgraph_workflow_happy_path():
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    finding = make_test_finding(finding_id="FIR-9001", severity="high", confidence=0.95)
    mock_fir.insert(finding)

    # Synthesis LLM output
    synthesis_json = json.dumps({
        "executive_summary": "Host intrusion detected and verified.",
        "incident_narrative": "Encoded execution followed by lateral probe.",
        "claims": [
            {
                "claim_id": "CLM-901",
                "claim": "PowerShell command execution detected.",
                "evidence_ids": ["FIR-9001"],
                "severity": "high",
                "confidence": 0.90,
            }
        ],
        "attack_timeline": [
            {"timestamp": "2026-10-11T12:00:00Z", "stage": "Execution", "summary": "PowerShell execution", "evidence_id": "FIR-9001"}
        ],
        "confidence_score": 0.91
    })
    mock_model.generate.return_value = synthesis_json

    agent = SupervisorAgent(
        model=mock_model,
        fir_repo=mock_fir,
        sanitization_gateway=mock_gateway,
        tenant_id="default"
    )

    with patch("models.classifiers.ClassifierLoader.load_mnli") as mock_mnli_loader:
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = {
            "labels": ["supports", "neutral", "contradicts"],
            "scores": [0.89, 0.08, 0.03]
        }
        mock_mnli_loader.return_value = mock_pipeline

        output = agent.run("CASE-LANGGRAPH-101", {
            "evidence_ids": ["FIR-9001"]
        })

        assert output["case_id"] == "CASE-LANGGRAPH-101"
        assert output["status"] == "COMPLETED"
        assert output["review_level"] == "ROUTINE_ANALYST_REVIEW"
        assert output["all_claims_verified"] is True
        assert output["unverified_claim_count"] == 0
        assert output["confidence_gate"]["route"] == "routine"
        assert "analyst" in output["reports"]


def test_supervisor_agent_langgraph_failure_terminal_on_missing_case_id():
    """
    Verifies that missing/invalid case_id halts the graph at the failure terminal
    without silently generating an approved report package.
    """
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    agent = SupervisorAgent(
        model=mock_model,
        fir_repo=mock_fir,
        sanitization_gateway=mock_gateway,
        tenant_id="default"
    )

    # Empty case_id triggers failure branch
    output = agent.run("", {"evidence_ids": ["FIR-001"]})

    assert output["status"] == "FAILED"
    assert "INVALID_INPUTS" in output["error"]
    assert output["reports"] == {}
    assert output["confidence_gate"]["route"] == "senior_dual"


# ── 9. Real DeBERTa-v3-large-MNLI Live Integration Test ───────────────────────

@pytest.mark.integration
def test_real_deberta_v3_large_mnli_live_entailment():
    """
    Tests live inference against the downloaded MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli model.
    """
    from models.classifiers import ClassifierLoader
    loader = ClassifierLoader()
    classifier = loader.load_mnli()

    claim = "Adversary executed powershell.exe with an encoded command line."
    evidence = "Evidence log shows powershell.exe spawned with parameters -EncodedCommand SQBFAFgA"

    res = classifier(
        sequences=claim,
        candidate_labels=["supports", "neutral", "contradicts"],
        hypothesis_template="This evidence: {}"
    )

    assert "supports" in res["labels"]
    supp_idx = res["labels"].index("supports")
    assert res["scores"][supp_idx] > 0.50


# ── 10. ISM Integration Boundary Contract Tests ───────────────────────────────

def test_ism_contract_record_schema():
    record = ISMAgent7ExecutionRecord(
        case_id="CASE-ISM-101",
        tenant_id="default",
        execution_id="EXEC-A7-9999",
        idempotency_key=build_ism_idempotency_key("CASE-ISM-101", "default", ["FIR-01", "FIR-02"]),
        status=ISMExecutionStatus.COMPLETED,
        audit_correlation_id="AUDIT-A7-8888",
        review_level_required="ROUTINE"
    )

    assert record.agent_id == "agent7_supervisor"
    assert record.status == ISMExecutionStatus.COMPLETED
    assert len(record.idempotency_key) == 64
    assert record.error_category == ISMErrorCategory.NONE
