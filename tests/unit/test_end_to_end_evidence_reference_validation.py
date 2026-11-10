"""
Unit Tests — Task 1: End-to-End Evidence Reference Validation
=============================================================
Tests that every evidence reference supplied to or produced by an agent
is strictly connected to a real, immutable evidence record.

Covers:
  - Valid direct evidence citations
  - Valid FIR finding citations with unbroken provenance
  - Missing records (MISSING_RECORD)
  - Deleted references (DELETED_REFERENCE)
  - Cross-case references (CROSS_CASE_VIOLATION)
  - Cross-tenant references (CROSS_TENANT_VIOLATION)
  - Invalid artifact IDs (INVALID_ARTIFACT_ID)
  - Mismatched provenance (MISMATCHED_PROVENANCE)
  - Empty or whitespace references (EMPTY_REFERENCE)
  - Non-empty evidence ID is NEVER automatically considered valid
  - Invalid references are rejected or flagged, NEVER silently replaced
  - Original evidence and historical findings remain untouched (immutable)
  - Downstream Agent 1, 2, 3, 4, 7 validation enforcement
"""

import pytest
from datetime import datetime, timezone
from fir.repository import FIRRepository
from fir.schemas import FIRFinding, ReviewStatus
from infrastructure.schemas import Evidence, EvidenceStatus
from infrastructure.repository.evidence_store import DELETED_EVIDENCE_IDS, delete_evidence
from forensic_analysis.evidence_reference_validator import (
    EvidenceReferenceValidator,
    ReferenceDefectType,
    ReferenceValidationResult,
)
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent2_evidence_correlation.validator import Agent2Validator
from agents.agent2_evidence_correlation.schemas import Agent2Claim
from agents.agent3_attack_reconstruction.validator import Agent3Validator
from agents.agent4_malware_behaviour.evidence_validator import EvidenceValidator as Agent4EvidenceValidator
from agents.agent4_malware_behaviour.schemas import BehaviorObservation
from agents.agent7_supervisor.call2_verification import SupervisorVerification


@pytest.fixture(autouse=True)
def clean_stores():
    """Ensure in-memory repositories and registries are clean before each test."""
    EvidenceReferenceValidator.clear_cache()
    FIRRepository._shared_findings.clear()
    DELETED_EVIDENCE_IDS.clear()
    yield
    EvidenceReferenceValidator.clear_cache()
    FIRRepository._shared_findings.clear()
    DELETED_EVIDENCE_IDS.clear()


@pytest.fixture
def sample_evidence_repo():
    """Sets up standard immutable evidence in Case A and Case B."""
    ev_case_a = Evidence(
        evidence_id="EVID-CASE-A-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
        filename="sysmon_alpha.evtx",
        file_path="/tmp/sysmon_alpha.evtx",
        uploaded_by="analyst1",
        status=EvidenceStatus.STORED,
    )
    ev_case_b = Evidence(
        evidence_id="EVID-CASE-B-001",
        case_id="CASE-BETA",
        tenant_id="tenant-alpha",
        filename="firewall_beta.log",
        file_path="/tmp/firewall_beta.log",
        uploaded_by="analyst2",
        status=EvidenceStatus.STORED,
    )
    ev_tenant_b = Evidence(
        evidence_id="EVID-TENANT-B-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-bravo",
        filename="memory_bravo.raw",
        file_path="/tmp/memory_bravo.raw",
        uploaded_by="analyst3",
        status=EvidenceStatus.STORED,
    )
    EvidenceReferenceValidator.register_evidence(ev_case_a)
    EvidenceReferenceValidator.register_evidence(ev_case_b)
    EvidenceReferenceValidator.register_evidence(ev_tenant_b)

    return {
        "ev_case_a": ev_case_a,
        "ev_case_b": ev_case_b,
        "ev_tenant_b": ev_tenant_b,
    }


@pytest.fixture
def sample_fir_findings(sample_evidence_repo):
    """Sets up FIR findings linking to real evidence."""
    fir_repo = FIRRepository()

    # 1. Valid finding with proven lineage to ev_case_a
    finding_valid = FIRFinding(
        finding_id="F-VALID-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
        fact="Suspicious rundll32.exe process spawned from powershell.exe",
        confidence=0.95,
        severity="high",
        evidence_reference=["EVID-CASE-A-001"],
        source_artifact_id="EVID-CASE-A-001",
        layer="host_telemetry",
    )
    fir_repo.insert(finding_valid)

    # 2. Finding belonging to Case BETA
    finding_beta = FIRFinding(
        finding_id="F-BETA-001",
        case_id="CASE-BETA",
        tenant_id="tenant-alpha",
        fact="Outbound connection to known C2 IP 198.51.100.24",
        confidence=0.90,
        severity="high",
        evidence_reference=["EVID-CASE-B-001"],
        source_artifact_id="EVID-CASE-B-001",
        layer="network_telemetry",
    )
    fir_repo.insert(finding_beta)

    # 3. Finding belonging to Tenant BRAVO
    finding_bravo = FIRFinding(
        finding_id="F-BRAVO-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-bravo",
        fact="Registry Run key persistence established under CurrentVersion",
        confidence=0.85,
        severity="medium",
        evidence_reference=["EVID-TENANT-B-001"],
        source_artifact_id="EVID-TENANT-B-001",
        layer="host_telemetry",
    )
    fir_repo.insert(finding_bravo)

    return {
        "finding_valid": finding_valid,
        "finding_beta": finding_beta,
        "finding_bravo": finding_bravo,
    }


def test_valid_direct_evidence_reference(sample_evidence_repo):
    """Direct evidence citation pointing to active evidence in same case and tenant is valid."""
    validator = EvidenceReferenceValidator()
    result = validator.verify_reference(
        ref_id="EVID-CASE-A-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is True
    assert result.defect_type is None
    assert result.record_type == "evidence"
    assert result.provenance_chain == ["EVID-CASE-A-001"]


def test_valid_fir_finding_reference_with_provenance(sample_evidence_repo, sample_fir_findings):
    """FIR finding citation pointing to finding with verified lineage to real evidence is valid."""
    validator = EvidenceReferenceValidator()
    result = validator.verify_reference(
        ref_id="F-VALID-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is True
    assert result.defect_type is None
    assert result.record_type == "fir_finding"
    assert result.provenance_chain == ["EVID-CASE-A-001", "F-VALID-001"]


def test_missing_record_rejected():
    """Fabricated or non-existent record IDs are rejected as MISSING_RECORD."""
    validator = EvidenceReferenceValidator()
    result = validator.verify_reference(
        ref_id="FABRICATED-CLAIM-999",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is False
    assert result.defect_type == ReferenceDefectType.MISSING_RECORD
    assert "Missing record" in result.defect_message


def test_deleted_reference_rejected(sample_evidence_repo):
    """References to deleted or tombstoned evidence are rejected as DELETED_REFERENCE."""
    validator = EvidenceReferenceValidator()

    # Mark evidence deleted
    validator.mark_evidence_deleted("EVID-CASE-A-001")

    result = validator.verify_reference(
        ref_id="EVID-CASE-A-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is False
    assert result.defect_type == ReferenceDefectType.DELETED_REFERENCE
    assert "deleted from evidence custody" in result.defect_message


def test_cross_case_reference_violation(sample_evidence_repo, sample_fir_findings):
    """References to evidence or findings from a different case are rejected as CROSS_CASE_VIOLATION."""
    validator = EvidenceReferenceValidator()

    # Case BETA evidence cited in Case ALPHA
    res_ev = validator.verify_reference(
        ref_id="EVID-CASE-B-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert res_ev.is_valid is False
    assert res_ev.defect_type == ReferenceDefectType.CROSS_CASE_VIOLATION
    assert "Cross-case reference violation" in res_ev.defect_message

    # Case BETA finding cited in Case ALPHA
    res_find = validator.verify_reference(
        ref_id="F-BETA-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert res_find.is_valid is False
    assert res_find.defect_type == ReferenceDefectType.CROSS_CASE_VIOLATION


def test_cross_tenant_reference_violation(sample_evidence_repo, sample_fir_findings):
    """References to evidence or findings from a different tenant are rejected as CROSS_TENANT_VIOLATION."""
    validator = EvidenceReferenceValidator()

    # Tenant BRAVO evidence cited in Tenant ALPHA
    res_ev = validator.verify_reference(
        ref_id="EVID-TENANT-B-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert res_ev.is_valid is False
    assert res_ev.defect_type == ReferenceDefectType.CROSS_TENANT_VIOLATION
    assert "Cross-tenant reference violation" in res_ev.defect_message

    # Tenant BRAVO finding cited in Tenant ALPHA
    res_find = validator.verify_reference(
        ref_id="F-BRAVO-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert res_find.is_valid is False
    assert res_find.defect_type == ReferenceDefectType.CROSS_TENANT_VIOLATION


def test_invalid_artifact_id_rejected():
    """Unrecognized artifact identifier formats or missing telemetry files return INVALID_ARTIFACT_ID."""
    validator = EvidenceReferenceValidator()
    result = validator.verify_reference(
        ref_id="ART-NONEXISTENT-999.evtx",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is False
    assert result.defect_type == ReferenceDefectType.INVALID_ARTIFACT_ID
    assert "Invalid artifact ID" in result.defect_message


def test_mismatched_provenance_empty_lineage():
    """Finding with no source artifact or evidence reference fails provenance verification."""
    validator = EvidenceReferenceValidator()
    fir_repo = FIRRepository()

    unanchored = FIRFinding(
        finding_id="F-UNANCHORED-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
        fact="Speculative finding without evidence backing",
        confidence=0.80,
        severity="low",
        evidence_reference=["NONE"],
        source_artifact_id=None,
        layer="analysis",
    )
    fir_repo.insert(unanchored)

    result = validator.verify_reference(
        ref_id="F-UNANCHORED-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is False
    assert result.defect_type == ReferenceDefectType.MISMATCHED_PROVENANCE


def test_mismatched_provenance_cross_case_lineage(sample_evidence_repo):
    """Finding in Case ALPHA citing evidence in Case BETA has mismatched provenance."""
    validator = EvidenceReferenceValidator()
    fir_repo = FIRRepository()

    tainted_finding = FIRFinding(
        finding_id="F-TAINTED-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
        fact="Finding in Case ALPHA citing Case BETA evidence",
        confidence=0.85,
        severity="medium",
        evidence_reference=["EVID-CASE-B-001"],  # Belongs to CASE-BETA
        source_artifact_id="EVID-CASE-B-001",
        layer="host_telemetry",
    )
    fir_repo.insert(tainted_finding)

    result = validator.verify_reference(
        ref_id="F-TAINTED-001",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert result.is_valid is False
    assert result.defect_type == ReferenceDefectType.MISMATCHED_PROVENANCE
    assert "Mismatched provenance" in result.defect_message


def test_empty_or_whitespace_reference():
    """Empty, None, or whitespace strings are rejected as EMPTY_REFERENCE."""
    validator = EvidenceReferenceValidator()
    for empty_val in [None, "", "   ", "\t\n"]:
        res = validator.verify_reference(empty_val, case_id="CASE-ALPHA", tenant_id="tenant-alpha")
        assert res.is_valid is False
        assert res.defect_type == ReferenceDefectType.EMPTY_REFERENCE


def test_non_empty_evidence_id_never_automatically_valid():
    """A non-empty, well-formatted string is NEVER automatically considered valid."""
    validator = EvidenceReferenceValidator()
    plausible_ids = [
        "EVID-00000000-0000-0000-0000-000000000001",
        "EVID-POWERSHELL-EXEC-4104",
        "FIR-FINDING-CRITICAL-001",
        "EVIDENCE-SYS-32",
    ]
    for cid in plausible_ids:
        res = validator.verify_reference(cid, case_id="CASE-ALPHA", tenant_id="tenant-alpha")
        assert res.is_valid is False
        assert res.defect_type in (
            ReferenceDefectType.MISSING_RECORD,
            ReferenceDefectType.INVALID_ARTIFACT_ID,
        )


def test_invalid_references_never_silently_replaced(sample_evidence_repo):
    """Batch citation validation flags invalid citations and NEVER replaces them with other IDs."""
    validator = EvidenceReferenceValidator()
    batch_citations = ["EVID-CASE-A-001", "FABRICATED-001", "EVID-CASE-B-001"]

    summary = validator.validate_citations(
        cited_ids=batch_citations,
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert summary["all_valid"] is False
    assert summary["valid_citations"] == ["EVID-CASE-A-001"]
    assert "FABRICATED-001" in summary["invalid_citations"]
    assert "EVID-CASE-B-001" in summary["invalid_citations"]

    # Strict invariant: invalid citations list contains the exact invalid IDs, untouched
    assert summary["defects"]["FABRICATED-001"] == ReferenceDefectType.MISSING_RECORD.value
    assert summary["defects"]["EVID-CASE-B-001"] == ReferenceDefectType.CROSS_CASE_VIOLATION.value


def test_original_evidence_and_historical_findings_remain_untouched(sample_evidence_repo, sample_fir_findings):
    """Validating references is strictly read-only and leaves original evidence and FIR findings intact."""
    validator = EvidenceReferenceValidator()

    # Pre-validation snapshot
    ev_a_before = sample_evidence_repo["ev_case_a"].model_dump()
    f_valid_before = sample_fir_findings["finding_valid"].model_dump()

    # Perform extensive validation sweeps including invalid checks
    _ = validator.verify_reference("EVID-CASE-A-001", "CASE-ALPHA", "tenant-alpha")
    _ = validator.verify_reference("F-VALID-001", "CASE-ALPHA", "tenant-alpha")
    _ = validator.verify_reference("FABRICATED-999", "CASE-ALPHA", "tenant-alpha")

    # Post-validation snapshot
    ev_a_after = sample_evidence_repo["ev_case_a"].model_dump()
    f_valid_after = sample_fir_findings["finding_valid"].model_dump()

    assert ev_a_before == ev_a_after
    assert f_valid_before == f_valid_after


def test_agent1_validator_rejects_empty_and_invalid_citations(sample_evidence_repo, sample_fir_findings):
    """Agent 1 validator rejects empty and invalid citations without silent replacement."""
    val = Agent1Validator()
    valid_finding_ids, valid_lineage_ids = val.extract_valid_id_universe(
        findings=[sample_fir_findings["finding_valid"]],
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert "F-VALID-001" in valid_finding_ids
    assert "EVID-CASE-A-001" in valid_lineage_ids

    # Output with one valid, one invalid, one empty
    output_dict = {
        "priority_evidence": [
            {"evidence_id": "F-VALID-001", "investigative_value": "HIGH"},
            {"evidence_id": "FABRICATED-999", "investigative_value": "HIGH"},
            {"evidence_id": "", "investigative_value": "LOW"},
        ]
    }
    cleaned_out, invalid_citations = val.validate_triage_output(
        output_dict=output_dict,
        valid_finding_ids=valid_finding_ids,
        valid_lineage_ids=valid_lineage_ids,
    )
    assert len(cleaned_out["priority_evidence"]) == 1
    assert cleaned_out["priority_evidence"][0]["evidence_id"] == "F-VALID-001"
    assert "FABRICATED-999" in invalid_citations
    assert "<empty_evidence_id>" in invalid_citations


def test_agent2_validator_flags_invalid_claim_citations(sample_evidence_repo, sample_fir_findings):
    """Agent 2 validator flags invalid citations without fabricating replacements."""
    val = Agent2Validator()
    valid_fids, valid_lids = val.extract_valid_id_universe(
        findings=[sample_fir_findings["finding_valid"]],
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )

    claims = [
        Agent2Claim(
            claim_id="CLM-01",
            summary="Legitimate observable",
            findings_summary="Findings demonstrate correlation",
            cited_evidence_ids=["F-VALID-001"],
            confidence_score=0.9,
        ),
        Agent2Claim(
            claim_id="CLM-02",
            summary="Hallucinated correlation",
            findings_summary="Speculative connection",
            cited_evidence_ids=["FABRICATED-999"],
            confidence_score=0.9,
        ),
    ]
    validated_claims = val.validate_claims(claims, valid_finding_ids=valid_fids, valid_lineage_ids=valid_lids)
    assert validated_claims[0].citation_valid is True
    assert validated_claims[1].citation_valid is False
    assert validated_claims[1].invalid_citations == ["FABRICATED-999"]


def test_agent3_validator_never_replaces_invalid_ids(sample_evidence_repo, sample_fir_findings):
    """Agent 3 validator separates invalid citations into invalid_citations without replacing."""
    val = Agent3Validator()
    valid_fids, valid_lids = val.extract_valid_id_universe(
        findings=[sample_fir_findings["finding_valid"]],
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    universe = valid_fids.union(valid_lids)

    raw_data = {
        "infection_path": {
            "entry_point": "Phishing attachment",
            "evidence_ids": ["F-VALID-001", "FABRICATED-ID"],
            "confidence": 0.85,
        },
        "attack_path": [
            {
                "step_number": 1,
                "stage": "Execution",
                "description": "Script execution",
                "evidence_ids": ["FABRICATED-STEP-ID"],
                "confidence": 0.80,
            }
        ],
    }
    normalized = val.normalize_raw_dict(raw_data, valid_universe=universe)
    assert normalized["infection_path"]["evidence_ids"] == ["F-VALID-001"]
    assert normalized["infection_path"]["invalid_citations"] == ["FABRICATED-ID"]
    assert normalized["attack_path"][0]["evidence_ids"] == []
    assert normalized["attack_path"][0]["invalid_citations"] == ["FABRICATED-STEP-ID"]


def test_agent4_evidence_validator_enforces_case_fir(sample_fir_findings):
    """Agent 4 validator rejects fabricated evidence citations."""
    valid_ids = Agent4EvidenceValidator.extract_valid_evidence_ids(
        [sample_fir_findings["finding_valid"]],
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert "F-VALID-001" in valid_ids

    obs = [
        BehaviorObservation(
            behavior_id="BEH-01",
            category="execution",
            behavior="Process execution via cmd",
            action="creates",
            evidence_ids=["F-VALID-001"],
            confidence=0.9,
        ),
        BehaviorObservation(
            behavior_id="BEH-02",
            category="execution",
            behavior="Fabricated execution",
            action="creates",
            evidence_ids=["FABRICATED-EVID-99"],
            confidence=0.9,
        ),
    ]
    val_obs = Agent4EvidenceValidator.validate_observations(obs, valid_ids)
    assert val_obs[0].unverified is False
    assert val_obs[1].unverified is True
    assert val_obs[1].confidence <= 0.2


def test_supervisor_agent7_call2_catches_all_defects(sample_evidence_repo, sample_fir_findings):
    """Agent 7 Call 2 flags specific defect types on claims with cross-case, deleted, or missing citations."""
    supervisor = SupervisorVerification(
        model=None,
        fir_repo=FIRRepository(),
        sanitization_gateway=None,
        tenant_id="tenant-alpha",
    )

    # 1. Valid Claim
    res_valid = supervisor.verify(
        claim={"claim_id": "C-1", "claim": "Valid activity", "evidence_ids": ["F-VALID-001"]},
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert not any("Cross-case" in f or "Tenant boundary" in f or "not found" in f for f in res_valid.get("flags", []))

    # 2. Cross-case citation
    res_cross = supervisor.verify(
        claim={"claim_id": "C-2", "claim": "Cross case claim", "evidence_ids": ["EVID-CASE-B-001"]},
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert any("Cross-case access violation" in f for f in res_cross.get("flags", []))

    # 3. Deleted citation
    EvidenceReferenceValidator.mark_evidence_deleted("EVID-CASE-A-001")
    res_deleted = supervisor.verify(
        claim={"claim_id": "C-3", "claim": "Deleted citation claim", "evidence_ids": ["EVID-CASE-A-001"]},
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha",
    )
    assert any("Deleted reference violation" in f for f in res_deleted.get("flags", []))
