"""
Unit Tests for PCAP Semantic Deduplication & Provenance Preservation
=====================================================================
Validates that NetworkAnalysisEngine properly deduplicates identical network findings
without over-deduplicating distinct forensic facts, preserving 100% of contributing provenance.
"""

import pytest
from datetime import datetime, timezone
from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.network_analysis.network_engine import NetworkAnalysisEngine
from forensic_analysis.schemas import finding_to_fir


def create_mock_ids_alert(
    art_id: str,
    src_ip: str = "10.9.11.135",
    dst_ip: str = "10.9.11.2",
    src_port: int = 52525,
    dst_port: int = 53,
    signature: str = "ET INFO Observed DNS Query to .cfd TLD",
    timestamp: str = "2026-09-11T20:05:56.328762+0000"
) -> Artifact:
    return Artifact(
        artifact_id=art_id,
        evidence_id="EV-TEST-001",
        case_id="CASE-PCAP-TEST",
        source_tool="suricata",
        artifact_type="ids_alert",
        timestamp=datetime.now(timezone.utc),
        raw_fields={
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "proto": "UDP",
            "alert": {
                "signature": signature,
                "severity": 3,
                "category": "Misc activity"
            }
        },
        normalized_fields=NormalizedFields(
            src_ip=src_ip,
            dst_ip=dst_ip,
            severity="low"
        )
    )


def make_fcr(corr_id: str, art_ids: list[str], case_id: str = "CASE-PCAP-TEST") -> CorrelationRecord:
    rel_type = ["single_artifact"] if len(art_ids) == 1 else ["network_process"]
    return CorrelationRecord(
        correlation_id=corr_id,
        case_id=case_id,
        artifact_ids=art_ids,
        relationship_type=rel_type,
        source_count=len(art_ids),
        distinct_artifact_types=len(art_ids),
        confidence=0.8
    )


def test_scenario_1_same_dns_logical_fact_duplicate_resolution():
    """
    TEST 1: Same DNS logical fact represented multiple times
    -> exactly ONE canonical finding
    -> provenance from all contributing records retained.
    """
    engine = NetworkAnalysisEngine()
    art1 = create_mock_ids_alert("art-ids-001", signature="ET INFO Observed DNS Query to .cfd TLD")
    art2 = create_mock_ids_alert("art-ids-002", signature="ET INFO Observed DNS Query to .cfd TLD")

    artifacts_by_id = {art1.artifact_id: art1, art2.artifact_id: art2}
    fcrs = [
        make_fcr("CORR-00001", ["art-ids-001"]),
        make_fcr("CORR-00002", ["art-ids-002"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)

    assert len(findings) == 1, f"Expected exactly 1 canonical finding, got {len(findings)}"
    canonical = findings[0]
    assert canonical.layer == "network.alert"
    assert "ET INFO Observed DNS Query to .cfd TLD" in canonical.fact

    # Verify provenance retention
    assert "art-ids-001" in canonical.contributing_correlation_ids
    assert "art-ids-002" in canonical.contributing_correlation_ids


def test_scenario_2_same_domain_different_endpoints():
    """
    TEST 2: Same domain/rule but different source/destination/session
    -> separate findings.
    """
    engine = NetworkAnalysisEngine()
    art1 = create_mock_ids_alert("art-stream-001", dst_ip="172.67.180.55", signature="SURICATA STREAM excessive retransmissions")
    art2 = create_mock_ids_alert("art-stream-002", dst_ip="104.16.212.131", signature="SURICATA STREAM excessive retransmissions")

    artifacts_by_id = {art1.artifact_id: art1, art2.artifact_id: art2}
    fcrs = [
        make_fcr("CORR-00001", ["art-stream-001"]),
        make_fcr("CORR-00002", ["art-stream-002"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)

    assert len(findings) == 2, f"Expected 2 separate findings for different destination endpoints, got {len(findings)}"
    dest_ips = {f.fact for f in findings}
    assert any("172.67.180.55" in fact for fact in dest_ips)
    assert any("104.16.212.131" in fact for fact in dest_ips)


def test_scenario_3_zeek_suricata_equivalent_consolidation():
    """
    TEST 3: Zeek + Suricata records representing the same logical fact
    -> consolidate only when forensic identity is actually equivalent.
    """
    engine = NetworkAnalysisEngine()
    suricata_art = create_mock_ids_alert("art-suri-001", signature="ET INFO Observed DNS Query to .cfd TLD")
    zeek_art = create_mock_ids_alert("art-zeek-001", signature="ET INFO Observed DNS Query to .cfd TLD")
    zeek_art.source_tool = "zeek"

    artifacts_by_id = {suricata_art.artifact_id: suricata_art, zeek_art.artifact_id: zeek_art}
    fcrs = [
        make_fcr("CORR-00001", ["art-suri-001", "art-zeek-001"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)

    assert len(findings) == 1
    canonical = findings[0]
    assert "art-suri-001" in canonical.contributing_correlation_ids
    assert "art-zeek-001" in canonical.contributing_correlation_ids


def test_scenario_4_different_dns_queries():
    """
    TEST 4: Different DNS queries
    -> separate findings.
    """
    engine = NetworkAnalysisEngine()
    art1 = create_mock_ids_alert("art-dns-001", signature="ET INFO Observed DNS Query to .cfd TLD")
    art2 = create_mock_ids_alert("art-dns-002", signature="ET INFO Observed DNS Query to .xyz TLD")

    artifacts_by_id = {art1.artifact_id: art1, art2.artifact_id: art2}
    fcrs = [
        make_fcr("CORR-00001", ["art-dns-001"]),
        make_fcr("CORR-00002", ["art-dns-002"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)

    assert len(findings) == 2


def test_scenario_5_different_network_behaviors_same_domain():
    """
    TEST 5: Different network behaviors involving the same domain
    -> separate findings.
    """
    engine = NetworkAnalysisEngine()

    art_dga = Artifact(
        artifact_id="art-dga-001",
        evidence_id="EV-TEST-001",
        case_id="CASE-PCAP-TEST",
        source_tool="zeek",
        artifact_type="dns_query",
        timestamp=datetime.now(timezone.utc),
        raw_fields={"query": "ab789xyz12345longlabel.eval-domain.com", "qtype": "A"},
        normalized_fields=NormalizedFields(domain="ab789xyz12345longlabel.eval-domain.com")
    )

    art_alert = create_mock_ids_alert("art-alert-001", signature="ET INFO Observed Suspicious DNS query to eval-domain.com")

    artifacts_by_id = {art_dga.artifact_id: art_dga, art_alert.artifact_id: art_alert}
    fcrs = [
        make_fcr("CORR-00001", ["art-dga-001"]),
        make_fcr("CORR-00002", ["art-alert-001"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)

    assert len(findings) == 2
    layers = {f.layer for f in findings}
    assert "network.dns_analyzer" in layers
    assert "network.alert" in layers


def test_scenario_6_merged_finding_retains_full_provenance():
    """
    TEST 6: Merged finding retains all contributing artifact/FCR/UAI provenance.
    """
    engine = NetworkAnalysisEngine()
    art1 = create_mock_ids_alert("art-prov-1", signature="ET INFO Observed DNS Query to .cfd TLD")
    art2 = create_mock_ids_alert("art-prov-2", signature="ET INFO Observed DNS Query to .cfd TLD")
    art3 = create_mock_ids_alert("art-prov-3", signature="ET INFO Observed DNS Query to .cfd TLD")

    artifacts_by_id = {art1.artifact_id: art1, art2.artifact_id: art2, art3.artifact_id: art3}
    fcrs = [
        make_fcr("CORR-00001", ["art-prov-1"]),
        make_fcr("CORR-00002", ["art-prov-2"]),
        make_fcr("CORR-00003", ["art-prov-3"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)
    assert len(findings) == 1

    fir = finding_to_fir(findings[0])
    assert isinstance(fir.evidence_reference, list)
    assert len(fir.evidence_reference) >= 3
    assert "art-prov-1" in fir.evidence_reference
    assert "art-prov-2" in fir.evidence_reference
    assert "art-prov-3" in fir.evidence_reference


def test_scenario_7_existing_detection_rules_continue_to_fire():
    """
    TEST 7: Existing network detection rules continue to fire.
    """
    engine = NetworkAnalysisEngine()
    art_dga = Artifact(
        artifact_id="art-rule-dga",
        evidence_id="EV-TEST-001",
        case_id="CASE-PCAP-TEST",
        source_tool="zeek",
        artifact_type="dns_query",
        timestamp=datetime.now(timezone.utc),
        raw_fields={"query": "x8f93m2a7q1p9w4z7c.testdga.org", "qtype": "A"},
        normalized_fields=NormalizedFields(domain="x8f93m2a7q1p9w4z7c.testdga.org")
    )
    art_txt = Artifact(
        artifact_id="art-rule-txt",
        evidence_id="EV-TEST-001",
        case_id="CASE-PCAP-TEST",
        source_tool="zeek",
        artifact_type="dns_query",
        timestamp=datetime.now(timezone.utc),
        raw_fields={"query": "tunnel.testdga.org", "qtype": "TXT", "answers": "A" * 150},
        normalized_fields=NormalizedFields(domain="tunnel.testdga.org")
    )

    artifacts_by_id = {art_dga.artifact_id: art_dga, art_txt.artifact_id: art_txt}
    fcrs = [
        make_fcr("CORR-00001", ["art-rule-dga"]),
        make_fcr("CORR-00002", ["art-rule-txt"]),
    ]

    findings = engine.analyze(fcrs, artifacts_by_id)

    assert len(findings) >= 2
    mitre_codes = {f.mitre_mapping for f in findings}
    assert "T1568.002" in mitre_codes
    assert "T1071.004" in mitre_codes
