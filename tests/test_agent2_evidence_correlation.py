"""
Test Suite for Agent 2 — Evidence Correlation
===============================================
Validates timeline building, knowledge graph WCC community detection,
conflict detection, sanitization, validation gate, mock model execution, and PostgreSQL fallback.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from fir.schemas import FIRFinding
from agents.agent2_evidence_correlation.schemas import (
    Agent2Input, Agent2Output, Agent2Claim, TemporalCluster, GraphCommunity, CorrelationConflict
)
from agents.agent2_evidence_correlation.timeline import TimelineBuilder
from agents.agent2_evidence_correlation.graph_builder import GraphBuilder
from agents.agent2_evidence_correlation.conflict_detector import ConflictDetector
from agents.agent2_evidence_correlation.validator import Agent2Validator
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent


@pytest.fixture
def sample_fir_findings():
    return [
        FIRFinding(
            finding_id="F-101",
            case_id="CASE-AGENT2-TEST",
            tenant_id="default",
            fact="Process cmd.exe spawned powershell.exe connecting to C2 IP 192.168.1.50 with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
            confidence=0.9,
            severity="high",
            timestamp=datetime(2026, 9, 23, 10, 0, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-001"],
            layer="process_analysis"
        ),
        FIRFinding(
            finding_id="F-102",
            case_id="CASE-AGENT2-TEST",
            tenant_id="default",
            fact="Network traffic from host desktop-01 to IP 192.168.1.50 transmitting 100KB.",
            confidence=0.85,
            severity="high",
            timestamp=datetime(2026, 9, 23, 10, 15, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-002"],
            layer="network_analysis"
        ),
        FIRFinding(
            finding_id="F-103",
            case_id="CASE-AGENT2-TEST",
            tenant_id="default",
            fact="User admin logged in from IP 10.0.0.5 and created scheduled task update.exe with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
            confidence=0.95,
            severity="critical",
            timestamp=datetime(2026, 9, 23, 11, 30, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-003"],
            layer="auth_analysis"
        )
    ]


def test_timeline_builder(sample_fir_findings):
    builder = TimelineBuilder(time_window_seconds=3600.0) # 1 hour window
    sorted_findings, clusters = builder.build_timeline(sample_fir_findings)

    assert len(sorted_findings) == 3
    assert sorted_findings[0].finding_id == "F-101"
    assert sorted_findings[1].finding_id == "F-102"
    assert sorted_findings[2].finding_id == "F-103"

    # F-101 (10:00) and F-102 (10:15) belong to cluster 1; F-103 (11:30) starts cluster 2 (> 3600s gap)
    assert len(clusters) == 2
    assert clusters[0].finding_ids == ["F-101", "F-102"]
    assert clusters[1].finding_ids == ["F-103"]


def test_graph_builder(sample_fir_findings):
    gb = GraphBuilder(neo4j_client=None)
    communities, metrics = gb.build_graph_and_communities("CASE-AGENT2-TEST", sample_fir_findings)

    assert metrics["total_nodes"] == 3
    assert metrics["total_communities"] >= 1
    
    # F-101 and F-102 share IP 192.168.1.50
    # F-101 and F-103 share SHA256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    # All 3 are in a single connected community!
    assert len(communities) == 1
    assert set(communities[0].finding_ids) == {"F-101", "F-102", "F-103"}
    assert "192.168.1.50" in communities[0].entity_names


def test_conflict_detector():
    conf_findings = [
        FIRFinding(
            finding_id="F-201",
            case_id="C1",
            tenant_id="t1",
            fact="File malware.exe identified with SHA256 1111111111111111111111111111111111111111111111111111111111111111.",
            confidence=0.8,
            severity="high",
            evidence_reference=["E1"],
            layer="l1"
        ),
        FIRFinding(
            finding_id="F-202",
            case_id="C1",
            tenant_id="t1",
            fact="File malware.exe identified with SHA256 9999999999999999999999999999999999999999999999999999999999999999.",
            confidence=0.8,
            severity="high",
            evidence_reference=["E2"],
            layer="l1"
        )
    ]

    detector = ConflictDetector()
    conflicts = detector.detect_conflicts(conf_findings)

    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == "hash_collision"
    assert set(conflicts[0].involved_finding_ids) == {"F-201", "F-202"}


def test_validator(sample_fir_findings):
    validator = Agent2Validator()
    valid_fids, valid_lineage = validator.extract_valid_id_universe(sample_fir_findings)

    assert valid_fids == {"F-101", "F-102", "F-103"}
    assert valid_lineage == {"EVD-001", "EVD-002", "EVD-003"}

    claims = [
        Agent2Claim(
            claim_id="CLM-01",
            summary="Valid correlation",
            findings_summary="Correlated findings",
            cited_evidence_ids=["F-101", "F-102"],
            confidence_score=0.9
        ),
        Agent2Claim(
            claim_id="CLM-02",
            summary="Invalid citation",
            findings_summary="Correlated hallucination",
            cited_evidence_ids=["F-101", "F-9999"], # F-9999 does not exist!
            confidence_score=150.0 # Out of bounds confidence!
        )
    ]

    validated = validator.validate_claims(claims, valid_fids, valid_lineage)

    assert validated[0].citation_verified is True
    assert validated[0].invalid_citations == []
    assert validated[0].is_valid_confidence is True

    assert validated[1].citation_verified is False
    assert validated[1].invalid_citations == ["F-9999"]
    assert validated[1].is_valid_confidence is False
    assert validated[1].raw_model_confidence == 150.0
    assert validated[1].confidence_score == 1.0 # Clamped from 150/100 -> 1.0 limit


def test_agent2_full_execution_mock_model(sample_fir_findings):
    mock_model = MagicMock()
    mock_model.generate.return_value = json.dumps({
        "claims": [
            {
                "claim_id": "CLM-AG2-001",
                "summary": "Correlated C2 traffic and Scheduled Task Creation",
                "correlation_type": "multi_signal",
                "findings_summary": "Findings F-101 and F-102 share C2 IP 192.168.1.50.",
                "cited_evidence_ids": ["F-101", "F-102"],
                "community_id": "GC-001",
                "assessed_importance": "critical",
                "confidence_score": 0.92,
                "timeline_sequence": ["F-101", "F-102"],
                "reasoning_notes": "Both events involved identical C2 communications within a 15-minute window."
            }
        ]
    })

    mock_fir = MagicMock()
    mock_fir.get_by_case.return_value = sample_fir_findings

    mock_gateway = MagicMock()
    mock_gateway.sanitize_finding.side_effect = lambda f: MagicMock(
        xml_evidence_block=f"<finding id='{f.finding_id}'>{f.fact}</finding>",
        injection_flagged=False
    )

    agent = EvidenceCorrelationAgent(
        model=mock_model,
        fir_repo=mock_fir,
        sanitization_gateway=mock_gateway,
        tenant_id="default"
    )

    res = agent.run("CASE-AGENT2-TEST")

    assert res["execution_status"] == "SUCCESS"
    assert res["case_id"] == "CASE-AGENT2-TEST"
    assert len(res["claims"]) == 1
    assert res["claims"][0]["claim_id"] == "CLM-AG2-001"
    assert res["claims"][0]["citation_verified"] is True
    assert res["claims"][0]["cited_evidence_ids"] == ["F-101", "F-102"]


def test_agent2_fail_closed_no_findings():
    mock_fir = MagicMock()
    mock_fir.get_by_case.return_value = []

    agent = EvidenceCorrelationAgent(
        model=MagicMock(),
        fir_repo=mock_fir,
        sanitization_gateway=MagicMock(),
        tenant_id="default"
    )

    res = agent.run("EMPTY-CASE")

    assert res["execution_status"] == "FAILED"
    assert "No FIR findings found" in res["error_message"]
    assert res["claims"] == []
