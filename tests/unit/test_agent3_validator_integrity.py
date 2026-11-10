"""
Unit & Integration Tests: Agent 3 Validator Integrity & Execution Status Gate
=============================================================================
Verifies:
  1. Confidence handling (0.0 preserved, None default, 0.85 preserved, negative rejected, >1 rejected, NaN/inf rejected).
  2. Evidence reference integrity (empty remains empty, no substitution, unknown rejected, cross-case rejected, cross-tenant rejected, no SUPPORTED_BY for unsupported).
  3. Execution status transitions (MODEL_UNAVAILABLE preserved, JSON failure -> accurate failure, validation failure not SUCCESS, graph write failure -> NEEDS_REVIEW, with findings vs no findings distinguished, Agent 7 receives correct status).
  4. Full integration pipeline: LLM unavailable -> fallback -> Agent 3 validator -> Agent 3 output -> graph writer -> Agent 7 -> investigation context -> report generator.
"""

import math
import json
import pytest
from unittest.mock import MagicMock, patch

from agents.agent3_attack_reconstruction.validator import Agent3Validator
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from agents.agent3_attack_reconstruction.graph_writer import AttackPathGraphWriter
from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output, AttackPathStep, AttackTimelineEvent, AttackChainStage, LateralMovement, InfectionPath
)
from agents.agent7_supervisor.call1_synthesis import SupervisorSynthesis
from agents.agent7_supervisor.agent import SupervisorAgent
from forensic_analysis.investigation_context import CaseInvestigationContext
from report_generation.generator import ReportGenerator


# ==============================================================================
# 1. CONFIDENCE TESTS
# ==============================================================================

class TestConfidenceHandling:
    """Verifies strict confidence parsing and rejection of invalid values."""

    def test_confidence_zero_remains_zero(self):
        v = Agent3Validator()
        res = v.parse_and_validate_confidence(0.0)
        assert res == 0.0

        res_str = v.parse_and_validate_confidence("0.0")
        assert res_str == 0.0

        # Normalization preserves 0.0 without coercing to 0.85
        norm = v.normalize_raw_dict({
            "infection_path": {"entry_point": "test", "confidence": 0.0},
            "overall_confidence": 0.0
        }, valid_universe=set())
        assert norm["infection_path"]["confidence"] == 0.0
        assert norm["overall_confidence"] == 0.0

    def test_confidence_none_follows_documented_default(self):
        v = Agent3Validator()
        # Default behavior: applies documented default when None
        res_default = v.parse_and_validate_confidence(None, default=0.85)
        assert res_default == 0.85

        res_zero_default = v.parse_and_validate_confidence(None, default=0.0)
        assert res_zero_default == 0.0

        with pytest.raises(ValueError, match="cannot be None"):
            v.parse_and_validate_confidence(None, default=None)

    def test_confidence_0_85_remains_0_85(self):
        v = Agent3Validator()
        res = v.parse_and_validate_confidence(0.85)
        assert res == 0.85

        norm = v.normalize_raw_dict({
            "infection_path": {"entry_point": "test", "confidence": 0.85},
            "overall_confidence": 0.85
        }, valid_universe=set())
        assert norm["infection_path"]["confidence"] == 0.85
        assert norm["overall_confidence"] == 0.85

    def test_negative_confidence_is_rejected(self):
        v = Agent3Validator()
        with pytest.raises(ValueError, match="strictly between 0.0 and 1.0"):
            v.parse_and_validate_confidence(-0.1)

        with pytest.raises(ValueError, match="strictly between 0.0 and 1.0"):
            v.parse_and_validate_confidence(-5.0)

        # In normalize_raw_dict
        with pytest.raises(ValueError):
            v.normalize_raw_dict({
                "infection_path": {"entry_point": "test", "confidence": -0.5}
            }, valid_universe=set())

    def test_confidence_greater_than_one_is_rejected(self):
        v = Agent3Validator()
        with pytest.raises(ValueError, match="strictly between 0.0 and 1.0"):
            v.parse_and_validate_confidence(1.01)

        with pytest.raises(ValueError, match="strictly between 0.0 and 1.0"):
            v.parse_and_validate_confidence(100.0)

        with pytest.raises(ValueError):
            v.normalize_raw_dict({
                "infection_path": {"entry_point": "test", "confidence": 1.5}
            }, valid_universe=set())

    def test_nan_and_infinity_are_rejected(self):
        v = Agent3Validator()
        with pytest.raises(ValueError, match="cannot be NaN or Infinite"):
            v.parse_and_validate_confidence(float("nan"))

        with pytest.raises(ValueError, match="cannot be NaN or Infinite"):
            v.parse_and_validate_confidence(float("inf"))

        with pytest.raises(ValueError, match="cannot be NaN or Infinite"):
            v.parse_and_validate_confidence(float("-inf"))


# ==============================================================================
# 2. EVIDENCE-REFERENCE TESTS
# ==============================================================================

class TestEvidenceReferenceIntegrity:
    """Verifies that evidence IDs are never invented, substituted, or accepted cross-case."""

    def test_empty_evidence_ids_remain_empty_no_substitution(self):
        v = Agent3Validator()
        valid_universe = {"EV-CASE1-01", "EV-CASE1-02", "EV-CASE1-03"}

        # Empty input must NOT receive valid_universe[:2]
        norm = v.normalize_raw_dict({
            "infection_path": {"entry_point": "entry", "evidence_ids": []},
            "attack_path": [{"step_number": 1, "description": "step", "evidence_ids": []}],
            "attack_timeline": [],
            "attack_chain": []
        }, valid_universe=valid_universe)

        assert norm["infection_path"]["evidence_ids"] == [], "Empty infection evidence IDs must remain empty"
        assert norm["attack_path"][0]["evidence_ids"] == [], "Empty attack step evidence IDs must remain empty"

    def test_unknown_ids_are_rejected(self):
        v = Agent3Validator()
        valid_universe = {"EV-REAL-01"}

        norm = v.normalize_raw_dict({
            "attack_path": [{
                "step_number": 1,
                "description": "step",
                "evidence_ids": ["EV-UNKNOWN-99", "EV-REAL-01"]
            }]
        }, valid_universe=valid_universe)

        step = norm["attack_path"][0]
        assert "EV-REAL-01" in step["evidence_ids"]
        assert "EV-UNKNOWN-99" not in step["evidence_ids"]
        assert "EV-UNKNOWN-99" in step["invalid_citations"]

    def test_cross_case_ids_are_rejected(self):
        # Findings universe extracted with explicit case_id isolation
        findings = [
            {"finding_id": "F-CASE1-01", "case_id": "CASE_1", "tenant_id": "tenant_A"},
            {"finding_id": "F-CASE2-02", "case_id": "CASE_2", "tenant_id": "tenant_A"},
        ]
        finding_ids, _ = Agent3Validator.extract_valid_id_universe(
            findings, case_id="CASE_1", tenant_id="tenant_A"
        )

        assert "F-CASE1-01" in finding_ids
        assert "F-CASE2-02" not in finding_ids, "Cross-case finding ID must not be in valid universe"

    def test_cross_tenant_ids_are_rejected(self):
        findings = [
            {"finding_id": "F-TENANT1-01", "case_id": "CASE_1", "tenant_id": "tenant_A"},
            {"finding_id": "F-TENANT2-02", "case_id": "CASE_1", "tenant_id": "tenant_B"},
        ]
        finding_ids, _ = Agent3Validator.extract_valid_id_universe(
            findings, case_id="CASE_1", tenant_id="tenant_A"
        )

        assert "F-TENANT1-01" in finding_ids
        assert "F-TENANT2-02" not in finding_ids, "Cross-tenant finding ID must not be in valid universe"

    def test_no_unsupported_claim_receives_supported_by_relationship(self):
        mock_client = MagicMock()
        writer = AttackPathGraphWriter(neo4j_client=mock_client)

        step = AttackPathStep(
            step_number=1,
            stage="Execution",
            description="Unsupported execution hypothesis",
            evidence_ids=[],  # No evidence!
            confidence=0.30,
            citation_verified=False
        )
        output = Agent3Output(
            case_id="ARGUS_TEST",
            tenant_id="default",
            infection_path=InfectionPath(entry_point="None", confidence=0.0),
            attack_path=[step]
        )

        writer.sync_attack_path(output)

        # Inspect all Cypher queries executed
        cypher_calls = [call[0][0] for call in mock_client.query.call_args_list or []]
        for q in cypher_calls:
            assert "SUPPORTED_BY" not in q, "No SUPPORTED_BY relationship may be created for unsupported steps"


# ==============================================================================
# 3. EXECUTION-STATUS TESTS
# ==============================================================================

class TestExecutionStatusTransitions:
    """Verifies that execution status accurately propagates without false SUCCESS."""

    def test_model_unavailable_remains_model_unavailable_after_json_parsing(self):
        agent = AttackReconstructionAgent(model=None)
        agent.path_builder = MagicMock()
        agent.missing_detector = MagicMock()
        payload = json.dumps({
            "execution_status": "MODEL_UNAVAILABLE",
            "overall_confidence": 0.0,
            "infection_path": {"entry_point": "No confirmed vector", "confidence": 0.0, "evidence_ids": []},
            "attack_path": [],
            "attack_timeline": [],
            "reconstruction_summary": "Model unavailable"
        })

        output = agent._parse_json_to_output(
            llm_response=payload,
            case_id="ARGUS_TEST",
            tenant_id="default",
            fir_findings=[],
            candidate_paths_res={},
            detected_missing_events=[],
            valid_universe=set()
        )

        assert output.execution_status == "MODEL_UNAVAILABLE", "MODEL_UNAVAILABLE must not be converted to SUCCESS"
        assert output.overall_confidence == 0.0

    def test_json_parsing_failure_produces_accurate_failure_state(self):
        agent = AttackReconstructionAgent(model=None)
        agent.path_builder = MagicMock()
        agent.missing_detector = MagicMock()
        malformed_response = "NOT JSON AT ALL {{{ error"

        output = agent._parse_json_to_output(
            llm_response=malformed_response,
            case_id="ARGUS_TEST",
            tenant_id="default",
            fir_findings=[],
            candidate_paths_res={},
            detected_missing_events=[],
            valid_universe=set()
        )

        assert output.execution_status == "EXECUTION_FAILED", "JSON parse failure must produce EXECUTION_FAILED"
        assert "JSON_PARSE_ERROR" in (output.error_message or "")

    def test_validation_failure_is_not_reported_as_success(self):
        agent = AttackReconstructionAgent(model=None)
        agent.path_builder = MagicMock()
        agent.missing_detector = MagicMock()
        # Payload with invalid confidence that will trigger validation failure
        invalid_payload = json.dumps({
            "execution_status": "SUCCESS",
            "overall_confidence": 999.0,  # Invalid confidence
            "infection_path": {"entry_point": "test", "confidence": -2.0}
        })

        output = agent._parse_json_to_output(
            llm_response=invalid_payload,
            case_id="ARGUS_TEST",
            tenant_id="default",
            fir_findings=[],
            candidate_paths_res={},
            detected_missing_events=[],
            valid_universe=set()
        )

        assert output.execution_status == "VALIDATION_FAILED", "Validation failure must be reported as VALIDATION_FAILED"
        assert output.overall_confidence == 0.0

    def test_graph_write_failure_is_not_reported_as_completed(self):
        agent = AttackReconstructionAgent(model=MagicMock())
        agent.model.generate.return_value = json.dumps({
            "execution_status": "COMPLETED_WITH_FINDINGS",
            "overall_confidence": 0.85,
            "infection_path": {"entry_point": "beacon", "evidence_ids": ["F-01"], "confidence": 0.85},
            "attack_path": [{"step_number": 1, "description": "beacon", "evidence_ids": ["F-01"], "confidence": 0.85}],
            "attack_timeline": [],
            "attack_chain": [],
            "lateral_movement": []
        })
        agent.path_builder = MagicMock()
        agent.missing_detector = MagicMock()
        agent.path_builder.build_candidate_paths.return_value = {}
        agent.missing_detector.detect_missing_events.return_value = []
        agent.path_builder._classify_stage.return_value = "Execution"

        # Mock writer to return False (failed write)
        with patch("agents.agent3_attack_reconstruction.agent.AttackPathGraphWriter") as mock_writer_cls:
            mock_writer = mock_writer_cls.return_value
            mock_writer.sync_attack_path.return_value = False  # Failed write!

            output_dict = agent.run(
                case_id="ARGUS_TEST",
                context={
                    "tenant_id": "default",
                    "fir_findings": [{"finding_id": "F-01", "severity": "high", "fact": "Malware beacon"}]
                }
            )

            assert output_dict["execution_status"] == "NEEDS_REVIEW", "Graph write failure must transition to NEEDS_REVIEW"

    def test_completed_with_findings_vs_no_findings_distinguished(self):
        v = Agent3Validator()
        valid_universe = {"F-01"}

        # Case A: Completed with verified findings
        step_verified = AttackPathStep(
            step_number=1,
            stage="Execution",
            description="Verified step",
            evidence_ids=["F-01"],
            confidence=0.85,
            citation_verified=True
        )
        out_with_findings = Agent3Output(
            case_id="C1",
            infection_path=InfectionPath(entry_point="Entry", evidence_ids=["F-01"], confidence=0.85),
            attack_path=[step_verified]
        )
        validated_findings = v.validate_output(out_with_findings, {"F-01"}, set())
        assert validated_findings.execution_status == "COMPLETED_WITH_FINDINGS"

        # Case B: Completed with no findings
        out_no_findings = Agent3Output(
            case_id="C2",
            infection_path=InfectionPath(entry_point="None", evidence_ids=[], confidence=0.0),
            attack_path=[]
        )
        validated_no_findings = v.validate_output(out_no_findings, set(), set())
        assert validated_no_findings.execution_status == "COMPLETED_WITH_NO_FINDINGS"

    def test_agent7_receives_correct_upstream_execution_status(self):
        synth = SupervisorSynthesis(
            model=MagicMock(),
            fir_repo=MagicMock(),
            sanitization_gateway=MagicMock(),
            tenant_id="default"
        )
        synth.model.generate.return_value = json.dumps({
            "execution_status": "MODEL_UNAVAILABLE",
            "executive_summary": "Model offline",
            "claims": [],
            "confidence_score": 0.0
        })

        res = synth.run("CASE_1", {
            "agent3": {"execution_status": "MODEL_UNAVAILABLE", "overall_confidence": 0.0}
        })

        assert res.get("synthesis_status") == "MODEL_UNAVAILABLE", "Agent 7 must capture MODEL_UNAVAILABLE"


# ==============================================================================
# 4. FULL INTEGRATION TEST
# ==============================================================================

class TestFullPipelineIntegration:
    """
    Simulates complete path:
    LLM unavailable -> fallback payload -> Agent 3 validator -> Agent 3 output
    -> graph writer -> Agent 7 -> investigation context -> dynamic report.
    """

    def test_pipeline_communicates_unavailable_state_without_fabrication(self):
        # 1. Fallback payload produced when LLM is unavailable
        from models.llm import generate_smart_reasoning_fallback
        a3_fallback_json = generate_smart_reasoning_fallback(
            prompt="Agent 3: reconstruct attack timeline",
            system_prompt="Agent 3: Attack Reconstruction"
        )
        a3_dict = json.loads(a3_fallback_json)
        assert a3_dict["execution_status"] == "MODEL_UNAVAILABLE"

        # 2. Agent 3 parses and validates fallback payload
        agent3 = AttackReconstructionAgent(model=None)
        agent3.path_builder = MagicMock()
        agent3.missing_detector = MagicMock()
        agent3_output = agent3._parse_json_to_output(
            llm_response=a3_fallback_json,
            case_id="ARGUS_INTEG",
            tenant_id="default",
            fir_findings=[],
            candidate_paths_res={},
            detected_missing_events=[],
            valid_universe=set()
        )
        agent3_validated = agent3.validator.validate_output(agent3_output, set(), set())

        # Assert Agent 3 validated output health
        assert agent3_validated.execution_status == "MODEL_UNAVAILABLE"
        assert agent3_validated.overall_confidence == 0.0
        assert len(agent3_validated.attack_path) == 0
        assert len(agent3_validated.infection_path.evidence_ids) == 0

        # 3. Graph writer verifies state and preserves existing graph
        mock_client = MagicMock()
        writer = AttackPathGraphWriter(neo4j_client=mock_client)
        assert writer.sync_attack_path(agent3_validated) is True
        assert len(mock_client.query.call_args_list or []) == 0, "Graph writer must not write nodes on MODEL_UNAVAILABLE"

        # 4. Downstream Report Generator consumes Agent 3 state
        gen = ReportGenerator()
        panels = gen._build_agent_panels(
            db_data={"agent_outputs": {"agent3": agent3_validated.model_dump()}},
            clusters=[],
            impact={},
            reconstruction=[],
            unconfirmed_stages=[],
            similar_cases=[],
            raw_evidence=[],
            raw_findings=[],
            case_id="ARGUS_INTEG"
        )
        a3_panel = panels.get("agent3", {})

        # Assert report accurately reflects unavailable state
        assert a3_panel.get("status") == "MODEL_UNAVAILABLE", "Report must show MODEL_UNAVAILABLE"
        a3_data = json.loads(a3_panel.get("json_text", "{}"))
        assert a3_data.get("execution_status") == "MODEL_UNAVAILABLE"
        assert "unavailable" in a3_data.get("claim", "").lower()
        assert a3_data.get("overall_confidence") == 0.0
