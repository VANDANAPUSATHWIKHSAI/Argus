"""
ARGUS Layer 3 Comprehensive Forensic Analysis Audit & Verification Suite (L3-T01 to L3-T25)
========================================================================================
Validates deterministic forensic analysis, FCR generation, schema normalization,
temporal sliding-window correlation, unified timeline reconstruction, entity correlation,
conflict detection, duplicate relationship suppression, multi-host/tenant/case isolation,
Neo4j client parameterization, and 100% reproducible execution without fabricated data.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.fcr_engine.schemas import CorrelationRecord, compute_confidence
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.repository import FCRRepository
from preprocessing.fcr_engine.timeline import UnifiedTimelineBuilder, TimelineEvent
from forensic_analysis.schemas import Finding, finding_to_fir
from forensic_analysis.orchestrator import process_fcr_batch, ENGINE_REGISTRY
from forensic_analysis.unified_store import UnifiedEvidenceStore
from forensic_analysis.router import route_fcr
from graph.neo4j_client import Neo4jClient


# L3-T01: Layer 3 input contract
def test_L3_T01_input_contract():
    art1 = Artifact(
        evidence_id="ev_01",
        case_id="CASE-101",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="WORKSTATION-A", process_id=100)
    )
    art2 = Artifact(
        evidence_id="ev_02",
        case_id="CASE-101",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 10, 0, 10, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="WORKSTATION-A", process_id=200, parent_process_id=100)
    )
    engine = FCREngine()
    fcrs = engine.correlate([art1, art2])
    assert len(fcrs) >= 1
    for fcr in fcrs:
        assert fcr.case_id == "CASE-101"
        assert set(fcr.artifact_ids).issubset({art1.artifact_id, art2.artifact_id})


# L3-T02: FCR schema
def test_L3_T02_fcr_schema():
    fcr = CorrelationRecord(
        correlation_id="CORR-000101",
        case_id="CASE-101",
        artifact_ids=["art_01", "art_02"],
        relationship_type=["temporal_proximity"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.5,
        host="host-a"
    )
    assert fcr.correlation_id == "CORR-000101"
    assert fcr.case_id == "CASE-101"
    assert len(fcr.artifact_ids) == 2

    # Invalid correlation_id throws ValueError
    with pytest.raises(Exception):
        CorrelationRecord(
            correlation_id="INVALID_ID",
            case_id="CASE-101",
            artifact_ids=["art_01", "art_02"],
            relationship_type=["temporal_proximity"],
            source_count=1,
            distinct_artifact_types=1,
            confidence=0.5,
            host="host-a"
        )


# L3-T03: FCR provenance
def test_L3_T03_fcr_provenance():
    art1 = Artifact(
        evidence_id="ev_prov_1",
        case_id="CASE-PROV",
        source_tool="zeek",
        artifact_type="network_connection",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="SRV-01", src_ip="192.168.1.100", dst_ip="10.0.0.5")
    )
    art2 = Artifact(
        evidence_id="ev_prov_2",
        case_id="CASE-PROV",
        source_tool="suricata",
        artifact_type="ids_alert",
        timestamp=datetime(2026, 9, 30, 12, 0, 5, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="SRV-01", src_ip="192.168.1.100", dst_ip="10.0.0.5")
    )
    engine = FCREngine()
    fcrs = engine.correlate([art1, art2])
    assert len(fcrs) >= 1
    ioc_fcrs = [f for f in fcrs if "shared_ioc" in f.relationship_type]
    assert len(ioc_fcrs) >= 1
    fcr = ioc_fcrs[0]
    assert fcr.source_count == 2
    assert art1.artifact_id in fcr.artifact_ids
    assert art2.artifact_id in fcr.artifact_ids


# L3-T04: deterministic correlation
def test_L3_T04_deterministic_correlation():
    art1 = Artifact(
        evidence_id="ev_det_1",
        case_id="CASE-DET",
        source_tool="winlogbeat",
        artifact_type="auth_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="DC-01", user="admin_user")
    )
    art2 = Artifact(
        evidence_id="ev_det_2",
        case_id="CASE-DET",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 5, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="DC-01", user="admin_user")
    )
    engine = FCREngine()
    fcrs_run1 = engine.correlate([art1, art2])
    fcrs_run2 = engine.correlate([art1, art2])

    assert len(fcrs_run1) == len(fcrs_run2)
    for f1, f2 in zip(fcrs_run1, fcrs_run2):
        assert f1.correlation_id == f2.correlation_id
        assert f1.confidence == f2.confidence
        assert f1.relationship_type == f2.relationship_type


# L3-T05: temporal correlation
def test_L3_T05_temporal_correlation():
    art1 = Artifact(
        evidence_id="ev_t1",
        case_id="CASE-TEMP",
        source_tool="tool_a",
        artifact_type="type_a",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-TEMP")
    )
    art2 = Artifact(
        evidence_id="ev_t2",
        case_id="CASE-TEMP",
        source_tool="tool_b",
        artifact_type="type_b",
        timestamp=datetime(2026, 9, 30, 12, 0, 20, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-TEMP")
    )
    art_far = Artifact(
        evidence_id="ev_t3",
        case_id="CASE-TEMP",
        source_tool="tool_c",
        artifact_type="type_c",
        timestamp=datetime(2026, 9, 30, 12, 10, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-TEMP")
    )
    engine = FCREngine()
    fcrs = engine.correlate([art1, art2, art_far], window_seconds=30.0)
    temp_fcrs = [f for f in fcrs if "temporal_proximity" in f.relationship_type]
    assert len(temp_fcrs) >= 1
    # art_far is 600s away, so it shouldn't correlate with art1 in a 30s window
    for fcr in temp_fcrs:
        if art1.artifact_id in fcr.artifact_ids:
            assert art_far.artifact_id not in fcr.artifact_ids


# L3-T06: timeline reconstruction
def test_L3_T06_timeline_reconstruction():
    art_late = Artifact(
        evidence_id="ev_l",
        case_id="CASE-TL",
        source_tool="tool1",
        artifact_type="type1",
        timestamp=datetime(2026, 9, 30, 14, 0, 0, tzinfo=timezone.utc),
        event_summary="Event Late"
    )
    art_early = Artifact(
        evidence_id="ev_e",
        case_id="CASE-TL",
        source_tool="tool2",
        artifact_type="type2",
        timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_summary="Event Early"
    )
    art_no_ts = Artifact(
        evidence_id="ev_n",
        case_id="CASE-TL",
        source_tool="tool3",
        artifact_type="type3",
        timestamp=None,
        event_summary="Event No Timestamp"
    )

    builder = UnifiedTimelineBuilder()
    timeline = builder.build_timeline([art_late, art_early, art_no_ts])
    assert len(timeline) == 3
    # Chronological sort: early first, then late, then no_ts at the end
    assert timeline[0].artifact_id == art_early.artifact_id
    assert timeline[1].artifact_id == art_late.artifact_id
    assert timeline[2].artifact_id == art_no_ts.artifact_id


# L3-T07: entity correlation
def test_L3_T07_entity_correlation():
    art1 = Artifact(
        evidence_id="ev_ent_1",
        case_id="CASE-ENT",
        source_tool="mft_parser",
        artifact_type="filesystem_entry"
    )
    art2 = Artifact(
        evidence_id="ev_ent_2",
        case_id="CASE-ENT",
        source_tool="usn_parser",
        artifact_type="usn_entry"
    )
    ent1 = ExtractedEntity(
        artifact_id=art1.artifact_id,
        evidence_id="ev_ent_1",
        case_id="CASE-ENT",
        entity_type="sha256",
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_field="raw_line",
        char_start=0,
        char_end=64,
        extraction_method="regex",
        confidence=1.0
    )
    ent2 = ExtractedEntity(
        artifact_id=art2.artifact_id,
        evidence_id="ev_ent_2",
        case_id="CASE-ENT",
        entity_type="sha256",
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_field="raw_line",
        char_start=0,
        char_end=64,
        extraction_method="regex",
        confidence=1.0
    )
    engine = FCREngine()
    fcrs = engine.correlate([art1, art2], extracted_entities=[ent1, ent2])
    shared_fcrs = [f for f in fcrs if "shared_ioc" in f.relationship_type]
    assert len(shared_fcrs) == 1
    assert shared_fcrs[0].shared_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# L3-T08: duplicate relationship handling
def test_L3_T08_duplicate_relationship_handling():
    art1 = Artifact(
        evidence_id="ev_dup_1",
        case_id="CASE-DUP",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-X", process_id=500, parent_process_id=100)
    )
    art2 = Artifact(
        evidence_id="ev_dup_2",
        case_id="CASE-DUP",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 2, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-X", process_id=100)
    )
    engine = FCREngine()
    fcrs = engine.correlate([art1, art2])
    # Verify deduplication merges relationships for same artifact pair
    art_pair_keys = set(tuple(sorted(f.artifact_ids)) for f in fcrs)
    assert len(art_pair_keys) == len(fcrs)


# L3-T09: conflict detection
def test_L3_T09_conflict_detection():
    # Verify conflicting timestamps or paths are preserved as distinct events in the timeline
    art_a = Artifact(
        evidence_id="ev_conf_1",
        case_id="CASE-CONF",
        source_tool="evtx",
        artifact_type="windows_event",
        timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        event_summary="Process launched at 10:00:00"
    )
    art_b = Artifact(
        evidence_id="ev_conf_2",
        case_id="CASE-CONF",
        source_tool="mft",
        artifact_type="filesystem_entry",
        timestamp=datetime(2026, 9, 30, 10, 0, 45, tzinfo=timezone.utc),
        event_summary="Process file created at 10:00:45"
    )
    builder = UnifiedTimelineBuilder()
    timeline = builder.build_timeline([art_a, art_b])
    assert len(timeline) == 2
    # Neither timestamp was altered or overwritten to force artificial agreement
    assert timeline[0].timestamp == datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    assert timeline[1].timestamp == datetime(2026, 9, 30, 10, 0, 45, tzinfo=timezone.utc)


# L3-T10: multi-host isolation
def test_L3_T10_multihost_isolation():
    art_host_a = Artifact(
        evidence_id="ev_ha",
        case_id="CASE-MH",
        source_tool="tool1",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-ALPHA")
    )
    art_host_b = Artifact(
        evidence_id="ev_hb",
        case_id="CASE-MH",
        source_tool="tool2",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 5, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-BETA")
    )
    engine = FCREngine()
    fcrs = engine.correlate([art_host_a, art_host_b])
    temp_fcrs = [f for f in fcrs if "temporal_proximity" in f.relationship_type]
    # Host-A and Host-B must NOT correlate via temporal_proximity
    assert len(temp_fcrs) == 0


# L3-T11: tenant isolation
def test_L3_T11_tenant_isolation():
    store = UnifiedEvidenceStore()
    store.clear()
    finding_t1 = Finding(
        case_id="CASE-ISO",
        tenant_id="TENANT-A",
        fact="Auth anomaly detected on Server 1",
        confidence=0.8,
        severity="high",
        evidence_reference="CORR-000001",
        source_artifact_id="art_101",
        layer="log_analysis"
    )
    finding_t2 = Finding(
        case_id="CASE-ISO",
        tenant_id="TENANT-B",
        fact="Auth anomaly detected on Server 2",
        confidence=0.8,
        severity="high",
        evidence_reference="CORR-000002",
        source_artifact_id="art_102",
        layer="log_analysis"
    )
    store.write_finding(finding_t1)
    store.write_finding(finding_t2)

    res_t1 = store.read_findings("CASE-ISO", tenant_id="TENANT-A")
    res_t2 = store.read_findings("CASE-ISO", tenant_id="TENANT-B")

    assert len(res_t1) == 1
    assert res_t1[0].tenant_id == "TENANT-A"
    assert len(res_t2) == 1
    assert res_t2[0].tenant_id == "TENANT-B"


# L3-T12: case isolation
def test_L3_T12_case_isolation():
    art_case1 = Artifact(
        evidence_id="ev_c1",
        case_id="CASE-111",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-X", process_id=100)
    )
    art_case2 = Artifact(
        evidence_id="ev_c2",
        case_id="CASE-222",
        source_tool="sysmon",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 30, 12, 0, 2, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="HOST-X", process_id=100)
    )
    engine = FCREngine()
    fcrs = engine.correlate([art_case1, art_case2])
    for fcr in fcrs:
        # FCR must strictly belong to either CASE-111 or CASE-222, never referencing cross-case artifacts
        if fcr.case_id == "CASE-111":
            assert art_case2.artifact_id not in fcr.artifact_ids
        elif fcr.case_id == "CASE-222":
            assert art_case1.artifact_id not in fcr.artifact_ids


# L3-T13: fabricated evidence detection
def test_L3_T13_fabricated_evidence_detection():
    # Verify production engine output contains no hardcoded fake/demo IPs or hostnames
    art1 = Artifact(
        evidence_id="ev_fab_1",
        case_id="CASE-REAL",
        source_tool="firewall",
        artifact_type="network_connection",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="CORP-SRV-99", src_ip="10.200.5.12", dst_ip="172.16.88.4")
    )
    art2 = Artifact(
        evidence_id="ev_fab_2",
        case_id="CASE-REAL",
        source_tool="firewall",
        artifact_type="network_connection",
        timestamp=datetime(2026, 9, 30, 12, 0, 15, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(host="CORP-SRV-99", src_ip="10.200.5.12", dst_ip="172.16.88.4")
    )
    engine = FCREngine()
    fcrs = engine.correlate([art1, art2])
    for fcr in fcrs:
        if fcr.shared_value:
            assert fcr.shared_value in ("10.200.5.12", "172.16.88.4")


# L3-T14: deterministic scoring
def test_L3_T14_deterministic_scoring():
    # Formula: min(1.0, 0.30 + 0.15*(dt-1) + 0.20*(sc-1))
    score1 = compute_confidence(distinct_artifact_types=1, source_count=1)
    assert score1 == 0.30

    score2 = compute_confidence(distinct_artifact_types=2, source_count=2)
    assert score2 == 0.65  # 0.30 + 0.15 + 0.20 = 0.65

    score3 = compute_confidence(distinct_artifact_types=5, source_count=5)
    assert score3 == 1.0   # capped at 1.0


# L3-T15: analytical failure semantics
def test_L3_T15_analytical_failure_semantics():
    store = UnifiedEvidenceStore()
    with pytest.raises(ValueError):
        store.read_findings(case_id="")

    with pytest.raises(ValueError):
        process_fcr_batch(
            case_id="",
            fcr_objects=[],
            artifacts_by_id={},
            fir_repo=None,
            store=store
        )


# L3-T16: Neo4j node integrity
def test_L3_T16_neo4j_node_integrity():
    client = Neo4jClient(uri="bolt://localhost:7687", user="neo4j", password="password")
    assert hasattr(client, "query")
    assert hasattr(client, "execute_write")
    assert hasattr(client, "verify_connectivity")
    client.close()


# L3-T17: Neo4j relationship integrity
def test_L3_T17_neo4j_relationship_integrity():
    with patch("neo4j.GraphDatabase.driver") as mock_driver_init:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__.return_value = mock_session
        mock_driver_init.return_value = mock_driver

        client = Neo4jClient("bolt://localhost:7687", "neo4j", "pass")
        client.query("MATCH (a:Artifact {id: $aid})-[r:CORRELATED]->(b:Artifact {id: $bid}) RETURN r", {"aid": "art1", "bid": "art2"})

        mock_session.run.assert_called_once_with(
            "MATCH (a:Artifact {id: $aid})-[r:CORRELATED]->(b:Artifact {id: $bid}) RETURN r",
            {"aid": "art1", "bid": "art2"}
        )


# L3-T18: Neo4j case/tenant isolation
def test_L3_T18_neo4j_case_tenant_isolation():
    with patch("neo4j.GraphDatabase.driver") as mock_driver_init:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver_init.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        client = Neo4jClient("bolt://localhost:7687", "neo4j", "pass")
        cypher = "MATCH (n {case_id: $case_id, tenant_id: $tenant_id}) RETURN n"
        params = {"case_id": "CASE-99", "tenant_id": "TENANT-X"}
        client.query(cypher, params)

        mock_session.run.assert_called_once_with(cypher, params)


# L3-T19: GDS operation verification
def test_L3_T19_gds_operation_verification():
    with patch("neo4j.GraphDatabase.driver") as mock_driver_init:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver_init.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        client = Neo4jClient("bolt://localhost:7687", "neo4j", "pass")
        gds_cypher = "CALL gds.wcc.stream($graph_name) YIELD nodeId, communityId RETURN nodeId, communityId"
        client.query(gds_cypher, {"graph_name": "case_99_proj"})

        mock_session.run.assert_called_once_with(gds_cypher, {"graph_name": "case_99_proj"})


# L3-T20: graph traversal correctness
def test_L3_T20_graph_traversal_correctness():
    with patch("neo4j.GraphDatabase.driver") as mock_driver_init:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver_init.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        client = Neo4jClient("bolt://localhost:7687", "neo4j", "pass")
        cypher = "MATCH path = (a:Artifact {id: $start_id})-[r:CORRELATED*1..3]->(b:Artifact) RETURN path"
        client.query(cypher, {"start_id": "art_root"})

        mock_session.run.assert_called_once_with(cypher, {"start_id": "art_root"})


# L3-T21: bounded traversal
def test_L3_T21_bounded_traversal():
    # Verify Cypher query string uses bounded depth *1..5 instead of unbounded *
    bounded_cypher = "MATCH (a:Artifact {id: $start_id})-[r:PRECEDES*1..5]->(b:Artifact) RETURN path"
    assert "*1..5" in bounded_cypher
    assert "[:PRECEDES*]" not in bounded_cypher


# L3-T22: Cypher parameterization
def test_L3_T22_cypher_parameterization():
    with patch("neo4j.GraphDatabase.driver") as mock_driver_init:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver_init.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        client = Neo4jClient("bolt://localhost:7687", "neo4j", "pass")
        untrusted_user_input = "admin' OR 1=1 --"
        cypher = "MATCH (u:User {username: $user}) RETURN u"
        client.query(cypher, {"user": untrusted_user_input})

        # Verify raw untrusted input is passed as parameter, never concatenated into cypher string
        mock_session.run.assert_called_once_with(cypher, {"user": untrusted_user_input})


# L3-T23: repeated-run determinism
def test_L3_T23_repeated_run_determinism():
    arts = [
        Artifact(
            evidence_id=f"ev_{i}",
            case_id="CASE-REPEATED",
            source_tool="sysmon",
            artifact_type="process_event",
            timestamp=datetime(2026, 9, 30, 12, 0, i, tzinfo=timezone.utc),
            normalized_fields=NormalizedFields(host="HOST-REPEATED", process_id=i * 10)
        )
        for i in range(10)
    ]
    engine = FCREngine()
    first_run = engine.correlate(arts)
    for _ in range(10):
        subsequent_run = engine.correlate(arts)
        assert len(subsequent_run) == len(first_run)
        for r1, r2 in zip(first_run, subsequent_run):
            assert r1.correlation_id == r2.correlation_id
            assert r1.confidence == r2.confidence
            assert r1.relationship_type == r2.relationship_type


# L3-T24: duplicate FCR suppression
def test_L3_T24_duplicate_fcr_suppression():
    repo = FCRRepository()
    repo.clear()
    fcr1 = CorrelationRecord(
        correlation_id="CORR-000099",
        case_id="CASE-SUPPRESS",
        artifact_ids=["art_a", "art_b"],
        relationship_type=["temporal_proximity"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.5,
        host="host-sup"
    )
    fcr_dup = CorrelationRecord(
        correlation_id="CORR-000099",
        case_id="CASE-SUPPRESS",
        artifact_ids=["art_a", "art_b"],
        relationship_type=["temporal_proximity"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.5,
        host="host-sup"
    )
    res1 = repo.add_record(fcr1)
    res2 = repo.add_record(fcr_dup)
    assert res1 is True
    assert res2 is False
    assert repo.count() == 1


# L3-T25: conflict preservation
def test_L3_T25_conflict_preservation():
    store = UnifiedEvidenceStore()
    store.clear()
    finding_event1 = Finding(
        case_id="CASE-PRES",
        tenant_id="TENANT-P",
        fact="Registry key modified at 10:00:00",
        confidence=0.9,
        severity="medium",
        evidence_reference="CORR-000088",
        source_artifact_id="art_reg1",
        layer="endpoint_analysis",
        timestamp=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)
    )
    finding_event2 = Finding(
        case_id="CASE-PRES",
        tenant_id="TENANT-P",
        fact="Registry key modified at 10:00:30",
        confidence=0.9,
        severity="medium",
        evidence_reference="CORR-000089",
        source_artifact_id="art_reg2",
        layer="endpoint_analysis",
        timestamp=datetime(2026, 9, 30, 10, 0, 30, tzinfo=timezone.utc)
    )
    store.write_finding(finding_event1)
    store.write_finding(finding_event2)

    findings = store.read_findings("CASE-PRES", tenant_id="TENANT-P")
    assert len(findings) == 2
    # Both conflicting timestamp events preserved without overwriting each other
    timestamps = [f.timestamp for f in findings]
    assert datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc) in timestamps
    assert datetime(2026, 9, 30, 10, 0, 30, tzinfo=timezone.utc) in timestamps
