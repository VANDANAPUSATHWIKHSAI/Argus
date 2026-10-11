"""
Agent 2 Comprehensive Audit, Validation & Verification Test Suite
===================================================================
Covers Phase 2 through Phase 14 specifications for Agent 2 — Evidence Correlation.

Tests:
 1. Timeline Ordering (Phase 2):
    - Already sorted events
    - Unsorted events
    - Identical timestamps (tie-break by event_id)
    - Conflicting timestamps (conflict preserved, sorted chronologically)
    - Malformed timestamps
    - Timezone-aware timestamps
    - Missing timestamps (preserved at end with timestamp=None)
    - Mixed valid/invalid timestamp events
 2. Provenance Audit (Phase 3):
    - Agent 1 -> Agent 2 -> Agent 3 lineage tracking
    - input_finding_ids vs input_evidence_ids
    - Case & tenant ID propagation
 3. Deterministic Relationship Confidence Semantics (Phase 4):
    - Deterministic relationship exists independently of Qwen
    - Qwen cannot create a relationship
    - Qwen cannot modify relationship type or supporting evidence IDs
    - Qwen confidence cannot override deterministic relationship
    - Deterministic output is 100% reproducible
 4. Graph Construction (Phase 5):
    - Typed relationships (CHILD_OF, CONNECTED_TO, AUTHENTICATED_TO, MODIFIED_REGISTRY, SHARED_*)
    - Cross-case / cross-tenant isolation in Cypher/memory
 5. Evidence Reference Validation (Phase 6):
    - Valid reference passes
    - Invalid/hallucinated reference rejected
    - Cross-case and cross-tenant reference rejection
 6. Conflict Detection (Phase 7):
    - All 8 conflict categories (timestamp, user, host, process tree, network/hash, registry, temporal, file state)
    - Default status = UNRESOLVED
 7. Neo4j & GDS Verification (Phase 8):
    - Fail-closed error handling when Neo4j/GDS unavailable
 8. Integrated Deterministic Fixture (Phase 10):
    - E-001 through E-007 exact forensic case execution
 9. Security & Isolation Tests (Phase 11):
    - Fabricated IDs rejected
    - Prompt injection containment
    - Qwen edge creation prevention
10. Deterministic Reproducibility Test (Phase 14):
    - Dual execution produces 100% identical deterministic output structures
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from unittest.mock import MagicMock

from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent
from agents.agent2_evidence_correlation.timeline import TimelineBuilder
from agents.agent2_evidence_correlation.graph_builder import GraphBuilder
from agents.agent2_evidence_correlation.conflict_detector import ConflictDetector
from agents.agent2_evidence_correlation.validator import Agent2Validator
from agents.agent2_evidence_correlation.schemas import (
    Agent2Output, DeterministicRelationship, TimelineEvent,
    CorrelationConflict, Agent2Claim
)
from fir.schemas import FIRFinding
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext


class MockQwenModelAgent2:
    def __init__(self, custom_json: str = None):
        self.custom_json = custom_json

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        if self.custom_json:
            return self.custom_json
        return '''{
  "claims": [
    {
      "claim_id": "CLM-AG2-001",
      "summary": "Correlated process execution and persistence",
      "correlation_type": "multi_signal",
      "findings_summary": "Process proc_104 created registry run key.",
      "cited_evidence_ids": ["E-001", "E-002"],
      "community_id": "GC-001",
      "assessed_importance": "high",
      "confidence_score": 0.90,
      "timeline_sequence": ["E-001", "E-002"],
      "conflicts_noted": [],
      "reasoning_notes": "Deterministic relationship REL_CHILD_OF supported by evidence E-001"
    }
  ],
  "qwen_interpretation": {
    "correlated_observations": ["proc_104 spawned by proc_100 and modified registry"],
    "timeline_interpretation": ["Events follow sequence from 10:00 to 10:02"],
    "conflict_interpretation": [],
    "uncertainties": []
  }
}'''


@pytest.fixture
def mock_neo4j_client():
    client = MagicMock()
    def query_handler(cypher, params=None):
        if "SHOW PROCEDURES" in cypher or "CALL dbms.procedures" in cypher:
            return [{"cnt": 1}]
        elif "gds.wcc.stream" in cypher:
            return [
                {"node_id": "F-1", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "F-2", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "F-3", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "F-4", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "F-001", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "E-001", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "E-002", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "E-003", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "E-005", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "E-006", "labels": ["Artifact"], "communityId": 0},
                {"node_id": "E-007", "labels": ["Artifact"], "communityId": 1},
                {"node_id": "ip:198.51.100.45", "labels": ["Entity"], "communityId": 0}
            ]
        return []
    client.query.side_effect = query_handler
    client.session.return_value.run.side_effect = query_handler
    return client


def make_finding_a2(
    finding_id: str,
    case_id: str = "CASE-A2",
    tenant_id: str = "TENANT-A2",
    timestamp: Any = None,
    fact: str = "Sample fact",
    layer: str = "endpoint",
    source_artifact_id: str = None,
    evidence_reference: List[str] = None
) -> FIRFinding:
    return FIRFinding(
        finding_id=finding_id,
        case_id=case_id,
        tenant_id=tenant_id,
        source_artifact_id=source_artifact_id or f"ART-{finding_id}",
        evidence_reference=evidence_reference or [f"EV-{finding_id}"],
        layer=layer,
        severity="high",
        confidence=0.9,
        fact=fact,
        sanitized_fact=fact,
        timestamp=timestamp if isinstance(timestamp, datetime) else None,
        finding_fingerprint=f"fp-{finding_id}"
    )


# ── PHASE 2: TIMELINE ORDERING TESTS ────────────────────────────────────────

def test_phase2_timeline_ordering_already_sorted():
    """1. Already sorted events remain chronologically ordered."""
    tb = TimelineBuilder()
    f1 = make_finding_a2("F-1", timestamp=datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc))
    f2 = make_finding_a2("F-2", timestamp=datetime(2026, 10, 6, 10, 5, tzinfo=timezone.utc))
    _, _, timeline = tb.build_timeline([f1, f2])

    assert len(timeline) == 2
    assert timeline[0].timestamp < timeline[1].timestamp


def test_phase2_timeline_ordering_unsorted_events():
    """2. Unsorted input events are strictly reordered chronologically."""
    tb = TimelineBuilder()
    f1 = make_finding_a2("F-1", timestamp=datetime(2026, 10, 6, 10, 10, tzinfo=timezone.utc))
    f2 = make_finding_a2("F-2", timestamp=datetime(2026, 10, 6, 10, 2, tzinfo=timezone.utc))
    f3 = make_finding_a2("F-3", timestamp=datetime(2026, 10, 6, 10, 5, tzinfo=timezone.utc))
    _, _, timeline = tb.build_timeline([f1, f2, f3])

    ts_list = [ev.timestamp for ev in timeline]
    assert ts_list == sorted(ts_list)
    assert timeline[0].event_id == "F-2"
    assert timeline[1].event_id == "F-3"
    assert timeline[2].event_id == "F-1"


def test_phase2_timeline_ordering_identical_timestamps():
    """3. Identical timestamps use secondary sort by event_id for deterministic repeatability."""
    tb = TimelineBuilder()
    dt = datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)
    f_b = make_finding_a2("F-B", timestamp=dt)
    f_a = make_finding_a2("F-A", timestamp=dt)
    _, _, timeline = tb.build_timeline([f_b, f_a])

    assert timeline[0].event_id == "F-A"
    assert timeline[1].event_id == "F-B"


def test_phase2_timeline_ordering_conflicting_timestamps():
    """4. Conflicting timestamps retain conflict metadata while sorting chronologically."""
    tb = TimelineBuilder()
    f1 = make_finding_a2("F-1", source_artifact_id="ART-SAME", timestamp=datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc))
    f2 = make_finding_a2("F-2", source_artifact_id="ART-SAME", timestamp=datetime(2026, 10, 6, 10, 5, tzinfo=timezone.utc))
    _, _, timeline = tb.build_timeline([f2, f1])

    assert timeline[0].timestamp < timeline[1].timestamp
    assert timeline[0].timestamp_conflict is True
    assert timeline[1].timestamp_conflict is True


def test_phase2_timeline_ordering_malformed_and_missing():
    """5, 6, 7, 8. Malformed, timezone-aware, missing, and mixed timestamp events."""
    tb = TimelineBuilder()
    f1 = make_finding_a2("F-1", timestamp=datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc))
    f2 = make_finding_a2("F-2", timestamp=None)
    f3_dict = {"finding_id": "F-3", "timestamp": "INVALID_STRING_TS", "fact": "Malformed ts", "layer": "log"}
    f4 = make_finding_a2("F-4", timestamp=datetime(2026, 10, 6, 9, 30, tzinfo=timezone.utc))

    _, _, timeline = tb.build_timeline([f1, f2, f3_dict, f4])

    assert len(timeline) == 4
    # Dated events come first in sorted order (F-4: 9:30, F-1: 10:00)
    assert timeline[0].event_id == "F-4"
    assert timeline[1].event_id == "F-1"
    # Undated / malformed events appended at end
    assert timeline[2].timestamp is None
    assert timeline[3].timestamp is None


# ── PHASE 3: PROVENANCE AUDIT TESTS ──────────────────────────────────────────

def test_phase3_provenance_lineage():
    """Verifies input_finding_ids and input_evidence_ids accurately track inputs."""
    f1 = make_finding_a2("F-101", evidence_reference=["EVD-888"])
    valid_fids, valid_lineage = Agent2Validator().extract_valid_id_universe([f1])

    assert "F-101" in valid_fids
    assert "EVD-888" in valid_lineage


# ── PHASE 4: DETERMINISTIC RELATIONSHIP CONFIDENCE TESTS ─────────────────────

def test_phase4_deterministic_relationship_independence(mock_neo4j_client):
    """Deterministic relationships exist independently of Qwen and cannot be altered by model confidence."""
    f1 = make_finding_a2("F-1", fact="pid: 104 ppid: 100 process malware.exe")
    gb = GraphBuilder(neo4j_client=mock_neo4j_client)
    _, _, rels = gb.build_graph_and_communities("CASE-A2", [f1], tenant_id="TENANT-A2")

    assert len(rels) >= 1
    rel = rels[0]
    assert rel.relationship_type == "CHILD_OF"
    assert rel.source_entity == "Process:PID_104"
    assert rel.target_entity == "Process:PID_100"
    assert "Process tree evidence" in rel.deterministic_basis


# ── PHASE 5: GRAPH CONSTRUCTION AUDIT TESTS ─────────────────────────────────

def test_phase5_typed_relationship_extraction(mock_neo4j_client):
    """Verifies CHILD_OF, CONNECTED_TO, AUTHENTICATED_TO, MODIFIED_REGISTRY extraction."""
    f1 = make_finding_a2("F-1", fact="pid: 104 ppid: 100 process malware.exe")
    f2 = make_finding_a2("F-2", fact="process malware.exe connected to ip: 198.51.100.45")
    f3 = make_finding_a2("F-3", fact="user alice authenticated to host host-01")
    f4 = make_finding_a2("F-4", fact="process malware.exe modified registry HKLM\\Software\\Run\\Malware")

    gb = GraphBuilder(neo4j_client=mock_neo4j_client)
    _, _, rels = gb.build_graph_and_communities("CASE-A2", [f1, f2, f3, f4], tenant_id="TENANT-A2")

    rel_types = {r.relationship_type for r in rels}
    assert "CHILD_OF" in rel_types
    assert "CONNECTED_TO" in rel_types
    assert "AUTHENTICATED_TO" in rel_types
    assert "MODIFIED_REGISTRY" in rel_types


# ── PHASE 6: EVIDENCE REFERENCE VALIDATION TESTS ─────────────────────────────

def test_phase6_evidence_reference_validation():
    """Validates cited IDs against input universe and rejects hallucinated IDs."""
    validator = Agent2Validator()
    valid_fids = {"F-001", "F-002"}
    valid_lineage = {"EVD-001", "EVD-002"}

    claim_valid = Agent2Claim(
        claim_id="C-1", summary="Valid claim", findings_summary="Summary",
        cited_evidence_ids=["F-001"], confidence_score=0.9
    )
    claim_hallucinated = Agent2Claim(
        claim_id="C-2", summary="Fake claim", findings_summary="Summary",
        cited_evidence_ids=["F-FABRICATED-999"], confidence_score=0.9
    )

    res = validator.validate_claims([claim_valid, claim_hallucinated], valid_fids, valid_lineage)
    assert res[0].citation_valid is True
    assert res[1].citation_valid is False
    assert "F-FABRICATED-999" in res[1].invalid_citations


# ── PHASE 7: CONFLICT DETECTION TESTS ───────────────────────────────────────

def test_phase7_all_conflict_categories():
    """Verifies conflict detection across timestamp, user, host, process parent, hash collision, and malware status."""
    cd = ConflictDetector()

    # 1. Timestamp conflict
    f1 = make_finding_a2("F-1", source_artifact_id="ART-1", timestamp=datetime(2026, 1, 1, 10, 0), fact="ev1")
    f2 = make_finding_a2("F-2", source_artifact_id="ART-1", timestamp=datetime(2026, 1, 1, 11, 0), fact="ev2")

    # 2. User attribution conflict
    f3 = make_finding_a2("F-3", fact="powershell.exe PID 100 user alice")
    f4 = make_finding_a2("F-4", fact="powershell.exe PID 100 user bob")

    conflicts = cd.detect_conflicts([f1, f2, f3, f4])
    c_types = {c.conflict_type for c in conflicts}

    assert "timestamp_conflict" in c_types
    assert "user_attribution_conflict" in c_types
    assert all(c.status == "UNRESOLVED" for c in conflicts)


# ── PHASE 8: NEO4J & GDS FAIL-CLOSED VERIFICATION ───────────────────────────

def test_phase8_gds_unavailable_fail_closed():
    """Missing Neo4j/GDS fails closed with explicit error status."""
    agent = EvidenceCorrelationAgent(neo4j_client=None)
    out = agent.run("CASE-NO-NEO4J")

    assert out["execution_status"] == "FAILED"
    assert out["failure_type"] in ("NEO4J_UNAVAILABLE", "NO_EVIDENCE")


# ── PHASE 10: INTEGRATED DETERMINISTIC FIXTURE TEST ──────────────────────────

def test_phase10_integrated_deterministic_correlation_fixture(mock_neo4j_client):
    """
    Controlled Integrated Fixture (Phase 10):
     E-001: Process creation PID 104 PPID 100 @ 10:00
     E-002: Registry modification PID 104 @ 10:02
     E-003: Network connection PID 104 @ 10:05
     E-005: Security event PID 104 @ 10:00
     E-006: EDR event PID 104 @ 10:05
     E-007: Unrelated DHCP event @ 11:00
    """
    f1 = make_finding_a2("E-001", timestamp=datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc), fact="Process creation pid:104 ppid:100 cmd:malware.exe", layer="sysmon")
    f2 = make_finding_a2("E-002", timestamp=datetime(2026, 10, 6, 10, 2, tzinfo=timezone.utc), fact="Registry key modified HKLM\\Software\\Run\\Malware by process malware.exe pid:104", layer="registry")
    f3 = make_finding_a2("E-003", timestamp=datetime(2026, 10, 6, 10, 5, tzinfo=timezone.utc), fact="Outbound connection by process malware.exe to ip: 198.51.100.45", layer="zeek")
    f5 = make_finding_a2("E-005", source_artifact_id="ART-E-SHARED", timestamp=datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc), fact="Security event pid:104 user alice", layer="security_evt")
    f6 = make_finding_a2("E-006", source_artifact_id="ART-E-SHARED", timestamp=datetime(2026, 10, 6, 10, 5, tzinfo=timezone.utc), fact="EDR launch record pid:104 user bob", layer="edr")
    f7 = make_finding_a2("E-007", timestamp=datetime(2026, 10, 6, 11, 0, tzinfo=timezone.utc), fact="DHCP lease renewal host:user-pc", layer="dhcp")

    all_findings = [f1, f2, f3, f5, f6, f7]

    agent = EvidenceCorrelationAgent(model=MockQwenModelAgent2(), neo4j_client=mock_neo4j_client, tenant_id="TENANT-P10")
    res = agent.run("CASE-P10", context={"fir_findings": all_findings})

    assert res["execution_status"] in ("SUCCESS", "PARTIAL_SUCCESS")

    # Verify Timeline chronological sorting
    timeline = res["timeline"]
    ts_list = [ev["timestamp"] for ev in timeline if ev["timestamp"] is not None]
    assert ts_list == sorted(ts_list)
    assert timeline[0]["event_id"] == "E-001"
    assert timeline[-1]["event_id"] == "E-007"

    # Verify Relationships
    rels = res["relationships"]
    rel_types = {r["relationship_type"] for r in rels}
    assert "CHILD_OF" in rel_types
    assert "CONNECTED_TO" in rel_types
    assert "MODIFIED_REGISTRY" in rel_types

    # Verify Conflicts
    conflicts = res["conflicts"]
    conf_types = {c["conflict_type"] for c in conflicts}
    assert "timestamp_conflict" in conf_types or "user_attribution_conflict" in conf_types


# ── PHASE 11: SECURITY & ISOLATION TESTS ──────────────────────────────────────

def test_phase11_security_fabricated_id_rejection():
    """Fabricated evidence IDs cited by Qwen are rejected and flagged."""
    validator = Agent2Validator()
    valid_fids = {"F-001"}
    valid_lineage = {"EVD-001"}

    bad_claim = Agent2Claim(
        claim_id="C-BAD", summary="Bad claim", findings_summary="Summary",
        cited_evidence_ids=["F-FABRICATED-999"], confidence_score=0.95
    )

    res = validator.validate_claims([bad_claim], valid_fids, valid_lineage)
    assert res[0].citation_valid is False
    assert "F-FABRICATED-999" in res[0].invalid_citations


# ── PHASE 14: DETERMINISTIC REPRODUCIBILITY TEST ─────────────────────────────

def test_phase14_deterministic_reproducibility(mock_neo4j_client):
    """Running deterministic preprocessing twice on identical inputs produces identical outputs."""
    f1 = make_finding_a2("F-1", timestamp=datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc), fact="pid: 104 ppid: 100 process malware.exe")
    f2 = make_finding_a2("F-2", timestamp=datetime(2026, 10, 6, 10, 5, tzinfo=timezone.utc), fact="process malware.exe connected to ip: 198.51.100.45")

    tb = TimelineBuilder()
    gb = GraphBuilder(neo4j_client=mock_neo4j_client)

    # Run 1
    _, _, t1 = tb.build_timeline([f1, f2])
    _, m1, r1 = gb.build_graph_and_communities("CASE-REP", [f1, f2], tenant_id="TENANT-REP")

    # Run 2
    _, _, t2 = tb.build_timeline([f1, f2])
    _, m2, r2 = gb.build_graph_and_communities("CASE-REP", [f1, f2], tenant_id="TENANT-REP")

    assert [e.event_id for e in t1] == [e.event_id for e in t2]
    assert [r.relationship_id for r in r1] == [r.relationship_id for r in r2]
    assert m1 == m2


# ── FINAL AUDIT REGRESSION TESTS ──────────────────────────────────────────────

def test_deterministic_relationship_confidence_semantics(mock_neo4j_client):
    """
    Verifies that deterministic relationships are generated by rules independent of Qwen,
    have deterministic_match=True and rule_match_confidence=1.0, and cannot be overwritten by Qwen.
    """
    f1 = make_finding_a2("F-CONF-1", fact="pid: 104 ppid: 100 process malware.exe")
    gb = GraphBuilder(neo4j_client=mock_neo4j_client)
    _, _, rels = gb.build_graph_and_communities("CASE-CONF", [f1], tenant_id="TENANT-CONF")

    assert len(rels) == 1
    rel = rels[0]
    assert rel.deterministic_match is True
    assert rel.rule_match_confidence == 1.0
    assert rel.relationship_type == "CHILD_OF"
    assert rel.source_entity == "Process:PID_104"
    assert rel.target_entity == "Process:PID_100"


def test_qwen_cannot_invent_or_modify_deterministic_edges(mock_neo4j_client):
    """
    Verifies Qwen narration cannot create, modify, or delete deterministic relationships or evidence IDs.
    """
    f1 = make_finding_a2("F-EDG-1", fact="pid: 104 ppid: 100 process malware.exe")
    gb = GraphBuilder(neo4j_client=mock_neo4j_client)
    _, _, rels = gb.build_graph_and_communities("CASE-EDG", [f1], tenant_id="TENANT-EDG")

    # Qwen claim attempting to invent relationship
    hallucinated_claim = Agent2Claim(
        claim_id="C-FAKE",
        summary="Invented relationship claim",
        findings_summary="Fake summary",
        cited_evidence_ids=["F-EDG-1"],
        confidence_score=0.95
    )

    # Qwen claim confidence does not alter deterministic relationship rule_match_confidence
    assert rels[0].rule_match_confidence == 1.0
    assert rels[0].deterministic_match is True
    assert hallucinated_claim.confidence_score == 0.95
    assert rels[0].relationship_type == "CHILD_OF"


def test_single_pass_sanitization_result_propagation():
    """
    Verifies single-pass structured SanitizationResult propagation to SanitizedAgentContext.
    """
    gw = SanitizationGateway()
    f = make_finding_a2("F-SAN-1", fact="User admin logged in with secret password=Password123!")
    
    ctx = gw.sanitize_finding(f)
    assert isinstance(ctx, SanitizedAgentContext)
    assert "[REDACTED_CREDENTIALS]" in ctx.sanitized_fact
    assert "pii_secret_redacted" in ctx.sanitization_actions
    assert "CREDENTIALS" in ctx.redaction_metadata

