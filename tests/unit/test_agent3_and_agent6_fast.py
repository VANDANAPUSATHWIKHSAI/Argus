import pytest
from datetime import datetime, timezone
from fir.schemas import FIRFinding
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from agents.agent3_attack_reconstruction.validator import Agent3Validator
from agents.agent3_attack_reconstruction.schemas import Agent3Output, InfectionPath
from agents.agent6_impact_assessment.agent import ImpactAssessmentAgent
from agents.agent6_impact_assessment.schemas import ISSAssessment, ISSSeverity, Agent6Output, CVSSAssessment, AssessmentStatus

def test_agent3_failure_confidence_zero():
    """Agent 3 must report overall_confidence == 0.0 and execution_status == FAILED when LLM fails."""
    finding = FIRFinding(
        finding_id="F-TEST-01",
        case_id="CASE-UNIT-01",
        tenant_id="tenant-unit",
        fact="Malicious process injected into explorer.exe",
        confidence=0.9,
        severity="high",
        evidence_reference=["ART-001"],
        layer="process"
    )
    
    agent = AttackReconstructionAgent(model=None, fir_repo=None, tenant_id="tenant-unit")
    # Simulate LLM failure by passing a non-callable model
    result = agent.run(case_id="CASE-UNIT-01", context={"fir_findings": [finding], "tenant_id": "tenant-unit"})
    
    assert result["execution_status"] == "FAILED"
    assert "MODEL_UNAVAILABLE" in result["error_message"]
    assert result["overall_confidence"] == 0.0
    # Ensure zero fabricated entity names
    assert "Host-A" not in str(result)
    assert "f-001" not in str(result)

def test_agent3_validator_preserves_zero_confidence_on_failure():
    """AttackPathValidator must not elevate confidence to 0.1 when execution_status is FAILED."""
    validator = Agent3Validator()
    out = Agent3Output(
        agent_id="agent_3",
        execution_status="FAILED",
        error_message="MODEL_UNAVAILABLE",
        total_findings_processed=1,
        case_id="CASE-01",
        tenant_id="default",
        model_used="test",
        infection_path=InfectionPath(entry_point="none", evidence_ids=[], confidence=0.0, citation_verified=False),
        attack_path=[],
        attack_timeline=[],
        attack_chain=[],
        lateral_movement=[],
        missing_expected_events=[],
        reconstruction_summary="failed",
        overall_confidence=0.0
    )
    validated = validator.validate_output(out, set(), set())
    assert validated.overall_confidence == 0.0
    assert validated.execution_status == "FAILED"

def test_agent6_iss_and_cvss_score_serialization():
    """Agent 6 output schema must serialize iss_assessment.iss_score and cvss_assessment accurately."""
    finding = FIRFinding(
        finding_id="F-TEST-02",
        case_id="CASE-UNIT-02",
        tenant_id="tenant-unit",
        fact="Unauthorized privilege escalation detected on domain controller DC-01",
        confidence=0.95,
        severity="critical",
        evidence_reference=["ART-002"],
        layer="identity"
    )
    
    agent = ImpactAssessmentAgent(model=None, fir_repo=None, tenant_id="tenant-unit")
    output = agent.run(
        case_id="CASE-UNIT-02",
        context={"case_id": "CASE-UNIT-02", "tenant_id": "tenant-unit", "fir_findings": [finding]}
    )
    
    # Verify structure and types
    assert "iss_assessment" in output
    iss_obj = output["iss_assessment"]
    assert "iss_score" in iss_obj
    assert isinstance(iss_obj["iss_score"], float)
    assert 0.0 <= iss_obj["iss_score"] <= 10.0
    
    # Check CVSS structure
    assert "cvss_assessment" in output
    cvss_obj = output["cvss_assessment"]
    assert "assessment_status" in cvss_obj
    assert cvss_obj["assessment_status"] in (
        AssessmentStatus.COMPLETED, AssessmentStatus.PARTIAL, AssessmentStatus.INSUFFICIENT_DATA,
        AssessmentStatus.COMPLETED.value, AssessmentStatus.PARTIAL.value, AssessmentStatus.INSUFFICIENT_DATA.value
    )

def test_agent6_schema_missing_metrics_handled_without_invention():
    """When evidence is sparse, CVSS should report INSUFFICIENT_DATA or PARTIAL without inventing scores."""
    agent = ImpactAssessmentAgent(model=None, fir_repo=None, tenant_id="tenant-unit")
    output = agent.run(
        case_id="CASE-EMPTY",
        context={"case_id": "CASE-EMPTY", "tenant_id": "tenant-unit", "fir_findings": []}
    )
    assert "iss_assessment" in output
    assert "cvss_assessment" in output
    cvss_status = output["cvss_assessment"]["assessment_status"]
    assert cvss_status in (AssessmentStatus.INSUFFICIENT_DATA, AssessmentStatus.INSUFFICIENT_DATA.value)
    assert output["cvss_assessment"]["base_score"] is None
    assert 0.0 <= output["iss_assessment"]["iss_score"] <= 10.0
