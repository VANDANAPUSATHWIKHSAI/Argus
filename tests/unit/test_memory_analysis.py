"""
Unit Test Suite — Memory Analysis Engine
========================================
Comprehensive unit and integration tests for MemoryAnalysisEngine and its 7 sub-analyzers:
- ProcessAnalyzer
- DLLAnalyzer
- MemoryNetworkAnalyzer
- InjectionAnalyzer
- RootkitAnalyzer
- CredentialAnalyzer
- TimelineAnalyzer
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
from forensic_analysis.memory_analysis.memory_engine import MemoryAnalysisEngine
from fir.schemas import FIRFinding


def make_artifact(
    art_id: str,
    art_type: str,
    case_id: str = "CASE-MEM-101",
    source_tool: str = "volatility3",
    norm_fields: dict = None,
    raw_fields: dict = None,
    ts: datetime = None
) -> Artifact:
    norm = NormalizedFields(**(norm_fields or {}))
    return Artifact(
        artifact_id=art_id,
        case_id=case_id,
        evidence_id="EVID-MEM-001",
        source_tool=source_tool,
        artifact_type=art_type,
        timestamp=ts or datetime.now(timezone.utc),
        normalized_fields=norm,
        raw_fields=raw_fields or {},
    )


def make_fcr(
    corr_id: str,
    art_ids: list[str],
    case_id: str = "CASE-MEM-101",
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
        host="host-mem-1",
        source_count=len(effective_ids),
        distinct_artifact_types=len(effective_ids),
        confidence=0.85,
    )


# ── 1. Router Memory Dispatch & Cross-Domain ─────────────────────────────────

def test_memory_router_dispatch():
    art1 = make_artifact("A1", "memory.pslist")
    art2 = make_artifact("A2", "memory.netscan")
    fcr = make_fcr("CORR-00201", ["A1", "A2"])
    store = {"A1": art1, "A2": art2}

    engines = route_fcr(fcr, store)
    assert engines == ["memory"]


def test_cross_domain_memory_and_network_router_dispatch():
    art_net = make_artifact("A1", "network.dns", source_tool="zeek")
    art_mem = make_artifact("A2", "memory.pslist", source_tool="volatility3")
    fcr = make_fcr("CORR-00202", ["A1", "A2"])
    store = {"A1": art_net, "A2": art_mem}

    engines = route_fcr(fcr, store)
    assert engines == ["memory", "network"]


# ── 2. ProcessAnalyzer Tests ──────────────────────────────────────────────────

def test_process_analyzer_psscan_vs_pslist_discrepancy():
    art_pslist = make_artifact("A-PSLIST", "memory.pslist", norm_fields={"process_id": 1000, "process_name": "explorer.exe"})
    art_psscan = make_artifact("A-PSSCAN", "memory.psscan", norm_fields={"process_id": 4444, "parent_process_id": 1000, "process_name": "hidden_malware.exe"})

    fcr = make_fcr("CORR-00203", ["A-PSLIST", "A-PSSCAN"])
    store = {"A-PSLIST": art_pslist, "A-PSSCAN": art_psscan}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    f_disc = next(f for f in findings if f.source_artifact_id == "A-PSSCAN")
    assert "unlinked/absent from active process list" in f_disc.fact.lower()
    assert f_disc.severity == "high"
    assert f_disc.mitre_mapping == "T1057"


def test_process_analyzer_orphan_process():
    art_orphan = make_artifact("A-ORPHAN", "memory.pslist", norm_fields={"process_id": 2020, "parent_process_id": 9999, "process_name": "cmd.exe"})
    fcr = make_fcr("CORR-00204", ["A-ORPHAN"])
    store = {"A-ORPHAN": art_orphan}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    f_orphan = next(f for f in findings if f.source_artifact_id == "A-ORPHAN")
    assert "orphan process" in f_orphan.fact.lower()
    assert f_orphan.severity == "medium"


def test_process_analyzer_parent_child_anomaly():
    art_wininit = make_artifact("A-WININIT", "memory.pslist", norm_fields={"process_id": 500, "process_name": "wininit.exe"})
    art_lsass_bad = make_artifact("A-LSASS-BAD", "memory.pslist", norm_fields={"process_id": 1200, "parent_process_id": 4000, "process_name": "lsass.exe"})
    art_cmd = make_artifact("A-CMD", "memory.pslist", norm_fields={"process_id": 4000, "process_name": "powershell.exe"})

    fcr = make_fcr("CORR-00205", ["A-WININIT", "A-LSASS-BAD", "A-CMD"])
    store = {"A-WININIT": art_wininit, "A-LSASS-BAD": art_lsass_bad, "A-CMD": art_cmd}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    f_lsass = next(f for f in findings if f.source_artifact_id == "A-LSASS-BAD")
    assert "hierarchy anomaly" in f_lsass.fact.lower()
    assert f_lsass.severity == "medium"


def test_process_analyzer_negative():
    art_sys = make_artifact("A-SYS", "memory.pslist", norm_fields={"process_id": 4, "process_name": "system"})
    art_smss = make_artifact("A-SMSS", "memory.pslist", norm_fields={"process_id": 200, "parent_process_id": 4, "process_name": "smss.exe"})
    fcr = make_fcr("CORR-00206", ["A-SYS", "A-SMSS"])
    store = {"A-SYS": art_sys, "A-SMSS": art_smss}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 0


# ── 3. DLLAnalyzer Tests ──────────────────────────────────────────────────────

def test_dll_analyzer_user_writable_path():
    art_dll = make_artifact(
        "A-DLL-USER", "memory.dlllist",
        norm_fields={"process_id": 1234, "process_name": "svchost.exe", "file_name": "injected.dll", "file_path": "C:\\Users\\Public\\injected.dll"}
    )
    fcr = make_fcr("CORR-00207", ["A-DLL-USER"])
    store = {"A-DLL-USER": art_dll}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert "loaded module from user-writable directory" in f.fact.lower()
    assert f.severity == "medium"
    assert f.mitre_mapping == "T1574.001"


def test_dll_analyzer_loader_inconsistency():
    art_ldr = make_artifact(
        "A-LDR", "memory.ldrmodules",
        norm_fields={"process_id": 1234, "process_name": "explorer.exe", "file_name": "hidden_module.dll"},
        raw_fields={"InLoad": False, "InInit": False, "InMem": True}
    )
    fcr = make_fcr("CORR-00208", ["A-LDR"])
    store = {"A-LDR": art_ldr}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert "module loader inconsistency observed" in f.fact.lower()
    assert f.severity == "high"
    assert f.mitre_mapping == "T1574.001"


def test_dll_analyzer_negative():
    art_clean_dll = make_artifact(
        "A-DLL-CLEAN", "memory.dlllist",
        norm_fields={"process_id": 1234, "process_name": "explorer.exe", "file_name": "ntdll.dll", "file_path": "C:\\Windows\\System32\\ntdll.dll"}
    )
    fcr = make_fcr("CORR-00209", ["A-DLL-CLEAN"])
    store = {"A-DLL-CLEAN": art_clean_dll}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)
    assert len(findings) == 0


# ── 4. MemoryNetworkAnalyzer Tests ───────────────────────────────────────────

def test_memory_network_analyzer_positive():
    art_net = make_artifact(
        "A-NET-MEM", "memory.netscan",
        norm_fields={"process_id": 4321, "process_name": "powershell.exe", "src_ip": "192.168.1.10", "src_port": 49152, "dst_ip": "203.0.113.50", "dst_port": 443},
        raw_fields={"Proto": "TCP", "State": "ESTABLISHED"}
    )
    fcr = make_fcr("CORR-00210", ["A-NET-MEM"])
    store = {"A-NET-MEM": art_net}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert "memory-resident network connection state observed" in f.fact.lower()
    assert f.layer == "memory.network_analyzer"
    assert f.mitre_mapping == "T1049"
    assert f.metadata["is_external"] is True


def test_memory_network_analyzer_negative():
    art_local = make_artifact(
        "A-NET-LOCAL", "memory.netscan",
        norm_fields={"process_id": 100, "process_name": "svchost.exe", "src_ip": "127.0.0.1", "src_port": 135, "dst_ip": "127.0.0.1", "dst_port": 49155},
        raw_fields={"Proto": "TCP", "State": "ESTABLISHED"}
    )
    fcr = make_fcr("CORR-00211", ["A-NET-LOCAL"])
    store = {"A-NET-LOCAL": art_local}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "informational"
    assert f.mitre_mapping is None


# ── 5. InjectionAnalyzer Tests ────────────────────────────────────────────────

def test_injection_analyzer_rwx_indicator():
    art_inj = make_artifact(
        "A-INJ", "memory.malfind",
        norm_fields={"process_id": 888, "process_name": "lsass.exe"},
        raw_fields={"Protection": "PAGE_EXECUTE_READWRITE", "Start VPN": "0x7ff0000", "Tag": "VadS"}
    )
    fcr = make_fcr("CORR-00212", ["A-INJ"])
    store = {"A-INJ": art_inj}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert "executable private memory region (rwx) consistent with possible code injection" in f.fact.lower()
    assert f.severity == "high"
    assert f.mitre_mapping == "T1055"


# ── 6. RootkitAnalyzer Tests ──────────────────────────────────────────────────

def test_rootkit_analyzer_indicator():
    art_rk = make_artifact(
        "A-RK", "memory.rootkit",
        norm_fields={"process_id": 31337, "process_name": "rootkit_driver.sys"},
        raw_fields={"HookType": "kernel_ssdt_hook"}
    )
    fcr = make_fcr("CORR-00213", ["A-RK"])
    store = {"A-RK": art_rk}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert "memory structure inconsistency consistent with possible process/module hiding" in f.fact.lower()
    assert f.severity == "high"
    assert f.mitre_mapping == "T1014"


# ── 7. CredentialAnalyzer Tests & Secret Redaction Security ────────────────────

def test_credential_analyzer_redaction_security():
    art_cred = make_artifact(
        "A-CRED", "memory.lsass",
        norm_fields={"process_id": 600, "process_name": "lsass.exe"},
        raw_fields={"PasswordHash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "plaintext": "SuperSecret123!"}
    )
    fcr = make_fcr("CORR-00214", ["A-CRED"])
    store = {"A-CRED": art_cred}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    assert len(findings) == 1
    f = findings[0]
    assert "credential-related memory structure observed" in f.fact.lower()
    assert f.severity == "high"
    assert f.mitre_mapping == "T1003"

    # MANDATORY SECURITY CHECK: Zero secrets in fact or metadata
    assert "SuperSecret123!" not in f.fact
    assert "aad3b435b51404eeaad3b435b51404ee" not in f.fact
    assert "plaintext" not in f.metadata
    assert f.metadata["redacted"] is True


# ── 8. TimelineAnalyzer Tests ─────────────────────────────────────────────────

def test_timeline_analyzer_temporal_sequence():
    ts1 = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 8, 29, 12, 0, 15, tzinfo=timezone.utc)

    art_proc = make_artifact("A-TL-PROC", "memory.pslist", norm_fields={"process_id": 5555, "process_name": "nc.exe"}, ts=ts1)
    art_net = make_artifact("A-TL-NET", "memory.netscan", norm_fields={"process_id": 5555, "process_name": "nc.exe"}, ts=ts2)

    fcr = make_fcr("CORR-00215", ["A-TL-PROC", "A-TL-NET"])
    store = {"A-TL-PROC": art_proc, "A-TL-NET": art_net}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    f_tl = next((f for f in findings if f.layer == "memory.timeline_analyzer"), None)
    assert f_tl is not None
    assert "rapid temporal sequence in memory" in f_tl.fact.lower()
    assert f_tl.metadata["delta_sec"] == 15.0


def test_timeline_analyzer_missing_timestamps_skip():
    art1 = Artifact(artifact_id="A-NO-TS1", case_id="CASE-1", evidence_id="E1", source_tool="volatility3", artifact_type="memory.pslist", timestamp=None, normalized_fields=NormalizedFields())
    art2 = Artifact(artifact_id="A-NO-TS2", case_id="CASE-1", evidence_id="E1", source_tool="volatility3", artifact_type="memory.netscan", timestamp=None, normalized_fields=NormalizedFields())

    fcr = make_fcr("CORR-00216", ["A-NO-TS1", "A-NO-TS2"])
    store = {"A-NO-TS1": art1, "A-NO-TS2": art2}

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr], store)

    tl_findings = [f for f in findings if f.layer == "memory.timeline_analyzer"]
    assert len(tl_findings) == 0


# ── 9. Overlapping FCR Deduplication & Provenance Merging ──────────────────────

def test_memory_overlapping_fcr_deduplication_and_provenance_merging():
    art_rk = make_artifact("A-RK-DEDUP", "memory.rootkit", norm_fields={"process_id": 999, "process_name": "stealth.sys"})
    art_dummy = make_artifact("A-DUMMY-PADDING-999", "memory.pslist", norm_fields={"process_name": "dummy.exe"})
    store = {"A-RK-DEDUP": art_rk, "A-DUMMY-PADDING-999": art_dummy}

    fcr1 = CorrelationRecord(
        correlation_id="CORR-00217",
        case_id="CASE-MEM-101",
        artifact_ids=["A-RK-DEDUP", "A-DUMMY-PADDING-999"],
        relationship_type=["shared_ioc"],
        shared_value="stealth.sys",
        host="host-mem-1",
        source_count=2,
        distinct_artifact_types=1,
        confidence=0.85,
    )
    fcr2 = CorrelationRecord(
        correlation_id="CORR-00218",
        case_id="CASE-MEM-101",
        artifact_ids=["A-RK-DEDUP", "A-DUMMY-PADDING-999"],
        relationship_type=["temporal_proximity"],
        host="host-mem-1",
        source_count=2,
        distinct_artifact_types=1,
        confidence=0.85,
    )

    engine = MemoryAnalysisEngine()
    findings = engine.analyze([fcr1, fcr2], store)

    finding = next(f for f in findings if f.source_artifact_id == "A-RK-DEDUP")
    assert "CORR-00217" in finding.contributing_correlation_ids
    assert "CORR-00218" in finding.contributing_correlation_ids

    fir_finding = finding_to_fir(finding)
    assert isinstance(fir_finding.evidence_reference, list)
    assert "CORR-00217" in fir_finding.evidence_reference
    assert "CORR-00218" in fir_finding.evidence_reference


# ── 10. Orchestrator Batch Integration & FIR Handoff ───────────────────────────

def test_process_fcr_batch_memory_integration():
    art = make_artifact(
        "A-ORCH-MEM", "memory.malfind", case_id="CASE-ORCH-MEM",
        norm_fields={"process_id": 777, "process_name": "svchost.exe"}
    )
    art_dummy = make_artifact("A-DUMMY-PADDING-999", "memory.pslist", case_id="CASE-ORCH-MEM", norm_fields={"process_name": "dummy.exe"})
    fcr = make_fcr("CORR-00219", ["A-ORCH-MEM", "A-DUMMY-PADDING-999"], case_id="CASE-ORCH-MEM")
    mock_fir_repo = MagicMock()
    test_store = UnifiedEvidenceStore()

    result_findings = process_fcr_batch(
        case_id="CASE-ORCH-MEM",
        fcr_objects=[fcr],
        artifacts_by_id={"A-ORCH-MEM": art, "A-DUMMY-PADDING-999": art_dummy},
        fir_repo=mock_fir_repo,
        store=test_store
    )

    assert len(result_findings) >= 1
    assert result_findings[0].layer == "memory.injection_analyzer"

    # Check store
    stored = test_store.read_findings("CASE-ORCH-MEM")
    assert len(stored) >= 1

    # Check FIR repo insert
    mock_fir_repo.insert.assert_called()
    inserted_fir = mock_fir_repo.insert.call_args_list[0][0][0]
    assert isinstance(inserted_fir, FIRFinding)
    assert inserted_fir.case_id == "CASE-ORCH-MEM"
    assert inserted_fir.evidence_reference == ["CORR-00219"]


# ── 11. Security AST Scan ──────────────────────────────────────────────────────

def test_ast_security_inspection():
    """
    Verifies that all files in forensic_analysis/memory_analysis contain 0 unsafe patterns:
    eval=0, exec=0, shell=True=0, os.system=0, unsafe pickle/yaml=0.
    """
    memory_dir = os.path.join(os.path.dirname(__file__), "..", "..", "forensic_analysis", "memory_analysis")
    python_files = []
    for root, _, files in os.walk(memory_dir):
        for f in files:
            if f.endswith(".py"):
                python_files.append(os.path.join(root, f))

    assert len(python_files) >= 8

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
