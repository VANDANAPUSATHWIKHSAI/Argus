"""
Unit Tests — Task 2: Historical Neo4j Graph-Node Classification & Downstream Enforcement
========================================================================================
Verifies that historical synthetic attack-stage nodes (Initial Access, Execution, etc.)
are preserved and classified strictly as HYPOTHESIS (confidence <= 0.35).

Enforces:
  1. Neo4j queries & investigation context preserve historical hypothesis nodes without deletion.
  2. Fallbacks, graph sync, and report generation NEVER accidentally promote a hypothesis to confirmed fact.
  3. Attack steps are only promoted when valid evidence IDs and verified provenance support them.
  4. Distinct relationships: OBSERVED, EVIDENCE_CORRELATED, HYPOTHESIS.
  5. Downstream consumers (Agent 2, Agent 3, Agent 7, Chatbot, Report Generator) respect classification.
"""

import pytest
from unittest.mock import MagicMock
from forensic_analysis.investigation_context import (
    CaseInvestigationContext,
    AttackStageProvenance,
)
from agents.agent3_attack_reconstruction.graph_writer import AttackPathGraphWriter
from agents.agent3_attack_reconstruction.schemas import (
    Agent3Output,
    AttackPathStep,
    InfectionPath,
)
from report_generation.generator import ReportGenerator


def test_historical_hypothesis_node_preserved_and_capped():
    """Historical synthetic attack steps (confidence 0.95) must be preserved as HYPOTHESIS capped at 0.35."""
    mock_neo4j = MagicMock()
    mock_session = MagicMock()
    mock_neo4j.session.return_value.__enter__.return_value = mock_session

    # Neo4j returns legacy synthetic attack step (seeded with 0.95 confidence, no evidence)
    mock_session.run.return_value.data.side_effect = [
        [
            {
                "id": "STEP-CASE-01-01",
                "step_number": 1,
                "stage": "Initial Access",
                "description": "Adversary activity detected: Spearphishing attachment ingress",
                "confidence": 0.95,
                "provenance_type": AttackStageProvenance.SYNTHETIC_SEED,
                "status": "UNCONFIRMED",
                "reasoning_basis": "Synthetic seed stage without telemetry",
                "supported_evidence_ids": [],
            }
        ],
        []  # entity query
    ]

    ctx = CaseInvestigationContext(case_id="CASE-TEST-01", tenant_id="default", neo4j_driver=mock_neo4j)
    ctx._load_graph_data()

    assert len(ctx.attack_steps) == 1
    step = ctx.attack_steps[0]
    assert step["id"] == "STEP-CASE-01-01"
    assert step["stage"] == "Initial Access"
    # Preserved as HYPOTHESIS
    assert step["provenance_type"] == AttackStageProvenance.HYPOTHESIS
    assert step["status"] == "UNCONFIRMED_HYPOTHESIS"
    # Confidence strictly capped at 0.35
    assert step["confidence"] <= 0.35


def test_no_accidental_promotion_from_case_findings():
    """Critical or High case findings elsewhere in the case must NOT promote an unevidenced hypothesis stage."""
    mock_neo4j = MagicMock()
    mock_session = MagicMock()
    mock_neo4j.session.return_value.__enter__.return_value = mock_session

    mock_session.run.return_value.data.side_effect = [
        [
            {
                "id": "STEP-CASE-01-02",
                "step_number": 2,
                "stage": "Execution",
                "description": "Adversary activity detected: In-memory shellcode execution",
                "confidence": 0.90,
                "provenance_type": AttackStageProvenance.HYPOTHESIS,
                "status": "UNCONFIRMED_HYPOTHESIS",
                "reasoning_basis": "Kill-chain hypothesis",
                "supported_evidence_ids": [],
            }
        ],
        []
    ]

    ctx = CaseInvestigationContext(case_id="CASE-TEST-01", tenant_id="default", neo4j_driver=mock_neo4j)
    # Simulate presence of unrelated Critical finding in case
    ctx.findings = [
        {
            "finding_id": "F-CRIT-99",
            "severity": "critical",
            "fact": "Outbound DNS beaconing to anomalous TLD",
            "evidence_reference": ["EVID-NET-01"],
        }
    ]
    ctx._load_graph_data()

    step = ctx.attack_steps[0]
    # Invariant: Must remain HYPOTHESIS and cannot be promoted to EVIDENCE_CORRELATED
    assert step["provenance_type"] == AttackStageProvenance.HYPOTHESIS
    assert step["status"] == "UNCONFIRMED_HYPOTHESIS"
    assert step["confidence"] <= 0.35


def test_promotion_only_with_valid_evidence_citations():
    """An attack step is only promoted to CONFIRMED / EVIDENCE_CORRELATED when direct supporting evidence exists."""
    mock_neo4j = MagicMock()
    mock_session = MagicMock()
    mock_neo4j.session.return_value.__enter__.return_value = mock_session

    mock_session.run.return_value.data.side_effect = [
        [
            {
                "id": "STEP-CASE-01-03",
                "step_number": 3,
                "stage": "Command and Control",
                "description": "Periodic HTTP POST beaconing to 198.51.100.5",
                "confidence": 0.88,
                "provenance_type": AttackStageProvenance.EVIDENCE_CORRELATED,
                "status": "CONFIRMED",
                "reasoning_basis": "Correlated across firewall logs and pcap flow records",
                "supported_evidence_ids": ["EVID-NET-01", "EVID-PCAP-02"],
            }
        ],
        []
    ]

    ctx = CaseInvestigationContext(case_id="CASE-TEST-01", tenant_id="default", neo4j_driver=mock_neo4j)
    ctx._load_graph_data()

    step = ctx.attack_steps[0]
    assert step["provenance_type"] == AttackStageProvenance.EVIDENCE_CORRELATED
    assert step["status"] == "CONFIRMED"
    assert step["confidence"] >= 0.70


def test_graph_writer_demotes_unsupported_stages():
    """AttackPathGraphWriter demotes any step claiming confirmed status without validated citations."""
    mock_neo4j = MagicMock()
    writer = AttackPathGraphWriter(neo4j_client=mock_neo4j)

    # Output where step claims OBSERVED with 0.95 confidence but has empty citations
    output = Agent3Output(
        case_id="CASE-TEST-01",
        tenant_id="default",
        infection_path=InfectionPath(entry_point="Initial Access", evidence_ids=[], confidence=0.85),
        attack_path=[
            AttackPathStep(
                step_number=1,
                stage="Initial Access",
                description="Exploit public facing application",
                evidence_ids=[],
                citation_verified=False,
                confidence=0.95,
            )
        ],
    )

    executed_queries = []
    executed_params = []

    def mock_cypher(query, params):
        executed_queries.append(query)
        executed_params.append(params)

    writer._exec_cypher = mock_cypher
    success = writer.sync_attack_path(output)

    assert success is True
    # Verify that the step merged in Neo4j was demoted to HYPOTHESIS with confidence <= 0.35
    node_params = [p for p in executed_params if "provenance_type" in p]
    assert len(node_params) == 1
    step_param = node_params[0]
    assert step_param["provenance_type"] == "HYPOTHESIS"
    assert step_param["status"] == "UNCONFIRMED_HYPOTHESIS"
    assert step_param["confidence"] <= 0.35

    # Verify no SUPPORTED_BY relationships were written
    supported_by_calls = [q for q in executed_queries if "SUPPORTED_BY" in q]
    assert len(supported_by_calls) == 0


def test_report_generator_segregates_hypotheses():
    """Report generator strictly places HYPOTHESIS attack steps into unconfirmed hypotheses."""
    gen = ReportGenerator()
    mock_ctx = MagicMock()
    mock_ctx.evidence_records = [{"filename": "sysmon.evtx"}]
    mock_ctx.get_evidence_provenance_summary.return_value = {"uncollected_evidence": []}

    # Mix of confirmed step and unconfirmed hypothesis step
    mock_ctx.attack_steps = [
        {
            "step_number": 1,
            "stage": "Network Beaconing",
            "description": "Outbound DNS beaconing confirmed by pcap",
            "provenance_type": "OBSERVED",
            "status": "CONFIRMED",
            "confidence": 0.90,
            "supported_evidence_ids": ["EVID-01"],
        },
        {
            "step_number": 2,
            "stage": "Initial Access",
            "description": "Theoretical spearphishing attachment",
            "provenance_type": "HYPOTHESIS",
            "status": "UNCONFIRMED_HYPOTHESIS",
            "confidence": 0.35,
            "supported_evidence_ids": [],
        },
    ]

    confirmed, unconfirmed = gen._build_reconstruction(
        clusters=[],
        dedup={},
        db_data={},
        ctx=mock_ctx,
    )

    # Initial Access hypothesis must land in unconfirmed, NEVER in confirmed
    assert any("Initial Access" in u["stage"] for u in unconfirmed)
    assert not any("Initial Access" in c["stage"] for c in confirmed)

    # Pipeline steps must mark hypothesis as confirmed: False
    story = gen._build_attack_story(clusters=[], raw_findings=[], ctx=mock_ctx)
    pipeline_steps = story["pipeline_steps"]
    hyp_pipe = [p for p in pipeline_steps if "Initial Access" in p["title"]][0]
    assert hyp_pipe["confirmed"] is False


def test_chatbot_context_enforces_hypothesis_safeguard():
    """CaseInvestigationContext formats hypothesis steps with explicit unconfirmed safeguard warning."""
    ctx = CaseInvestigationContext(case_id="CASE-TEST-01", tenant_id="default")
    ctx.attack_steps = [
        {
            "step_number": 1,
            "stage": "Execution",
            "description": "Theoretical payload execution",
            "provenance_type": AttackStageProvenance.HYPOTHESIS,
            "status": "UNCONFIRMED_HYPOTHESIS",
            "confidence": 0.35,
            "reasoning_basis": "Hypothesis based on user profile",
        }
    ]

    prompt_context = ctx.get_llm_grounding_block()
    assert "UNCONFIRMED HYPOTHESIS" in prompt_context
    assert "CRITICAL SAFEGUARD: This is an analytical kill-chain hypothesis" in prompt_context
    assert "ZERO evidence of exploit or adversary payload execution" in prompt_context
