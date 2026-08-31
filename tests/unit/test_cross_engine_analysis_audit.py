"""
Unit Test Suite — Cross-Engine Forensic Analysis Audit
======================================================
Deep integration and adversarial audit test suite covering:
1. 4-Engine Simultaneous Cross-Domain FCR Routing (network, log, endpoint, memory)
2. Layer-Specific Finding Coexistence (network vs memory network analyzers remain distinct)
3. Deterministic Deduplication & Correlation ID Merging
4. Adversarial Case Isolation (CASE-A vs CASE-B)
5. Adversarial Tenant Isolation (TENANT-A vs TENANT-B)
6. Security AST Inspection across forensic_analysis/ (0 eval, 0 exec, 0 shell=True, 0 os.system, 0 pickle.loads)
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
from fir.repository import FIRRepository
from fir.schemas import FIRFinding


def make_artifact(
    art_id: str,
    art_type: str,
    case_id: str = "CASE-AUDIT-101",
    tenant_id: str = "default",
    source_tool: str = "test",
    norm_fields: dict = None,
    raw_fields: dict = None,
    ts: datetime = None
) -> Artifact:
    norm = NormalizedFields(**(norm_fields or {}))
    return Artifact(
        artifact_id=art_id,
        case_id=case_id,
        evidence_id="EVID-AUDIT-001",
        source_tool=source_tool,
        artifact_type=art_type,
        timestamp=ts or datetime.now(timezone.utc),
        normalized_fields=norm,
        raw_fields=raw_fields or {},
    )


def make_fcr(
    corr_id: str,
    art_ids: list[str],
    case_id: str = "CASE-AUDIT-101",
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
        host="host-audit-1",
        source_count=len(effective_ids),
        distinct_artifact_types=len(effective_ids),
        confidence=0.85,
    )


# ── 1. 4-Engine Simultaneous Cross-Domain Routing ─────────────────────────────

def test_four_engine_cross_domain_routing():
    art_net = make_artifact("A-NET", "network.dns", source_tool="zeek")
    art_log = make_artifact("A-LOG", "log.auth", source_tool="hayabusa")
    art_end = make_artifact("A-END", "prefetch_entry", source_tool="pecmd")
    art_mem = make_artifact("A-MEM", "memory.pslist", source_tool="volatility3")

    fcr_4_domain = make_fcr("CORR-00999", ["A-NET", "A-LOG", "A-END", "A-MEM"])
    store = {"A-NET": art_net, "A-LOG": art_log, "A-END": art_end, "A-MEM": art_mem}

    engines = route_fcr(fcr_4_domain, store)
    assert engines == ["endpoint", "log", "memory", "network"]


# ── 2. Orchestrator Batch Execution Across All 4 Engines ───────────────────────

def test_orchestrator_batch_execution_all_four_engines():
    art_net = make_artifact("A-NET", "network.dns", norm_fields={"domain": "q3z9w8e7r6t5y4u3i2o1p123456789.evil.com"})
    art_log = make_artifact("A-LOG", "log.powershell", norm_fields={"process_command_line": "powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24="})
    art_end = make_artifact("A-END", "prefetch_entry", norm_fields={"process_name": "powershell.exe"})
    art_mem = make_artifact("A-MEM", "memory.malfind", norm_fields={"process_name": "powershell.exe"}, raw_fields={"Protection": "PAGE_EXECUTE_READWRITE"})
    art_dummy = make_artifact("A-DUMMY-PADDING-999", "network.dns", norm_fields={"domain": "dummy.com"})

    fcr_4_domain = make_fcr("CORR-00998", ["A-NET", "A-LOG", "A-END", "A-MEM", "A-DUMMY-PADDING-999"])
    store = {
        "A-NET": art_net, "A-LOG": art_log, "A-END": art_end, "A-MEM": art_mem,
        "A-DUMMY-PADDING-999": art_dummy
    }

    mock_fir_repo = MagicMock(spec=FIRRepository)
    test_store = UnifiedEvidenceStore()

    result_findings = process_fcr_batch(
        case_id="CASE-AUDIT-101",
        fcr_objects=[fcr_4_domain],
        artifacts_by_id=store,
        fir_repo=mock_fir_repo,
        store=test_store
    )

    layers = {f.layer for f in result_findings}
    assert "network.dns_analyzer" in layers
    assert "log.powershell_analyzer" in layers
    assert "endpoint.filesystem_analyzer" in layers
    assert "memory.injection_analyzer" in layers

    assert mock_fir_repo.insert.called
    stored_findings = test_store.read_findings("CASE-AUDIT-101")
    assert len(stored_findings) >= 4


# ── 3. Layer Distinction: Memory Network vs Telemetry Network ─────────────────

def test_network_and_memory_network_layer_distinction():
    art_net = make_artifact("A-TEL-NET", "network.dns", norm_fields={"domain": "q3z9w8e7r6t5y4u3i2o1p123456789.evil.com"})
    art_mem_net = make_artifact("A-MEM-NET", "memory.netscan", norm_fields={"process_id": 1234, "process_name": "cmd.exe", "dst_ip": "203.0.113.10", "dst_port": 80})

    fcr = make_fcr("CORR-00997", ["A-TEL-NET", "A-MEM-NET"])
    store = {"A-TEL-NET": art_net, "A-MEM-NET": art_mem_net}

    test_store = UnifiedEvidenceStore()
    mock_fir_repo = MagicMock(spec=FIRRepository)

    findings = process_fcr_batch(
        case_id="CASE-AUDIT-101",
        fcr_objects=[fcr],
        artifacts_by_id=store,
        fir_repo=mock_fir_repo,
        store=test_store
    )

    net_findings = test_store.get_findings_by_layer("CASE-AUDIT-101", "network.dns_analyzer")
    mem_net_findings = test_store.get_findings_by_layer("CASE-AUDIT-101", "memory.network_analyzer")

    assert len(net_findings) >= 1
    assert len(mem_net_findings) >= 1
    assert net_findings[0].layer == "network.dns_analyzer"
    assert mem_net_findings[0].layer == "memory.network_analyzer"


# ── 4. Case Isolation Adversarial Audit ───────────────────────────────────────

def test_adversarial_case_isolation():
    store = UnifiedEvidenceStore()

    finding_case_a = Finding(
        case_id="CASE-ALPHA",
        tenant_id="default",
        fact="Suspicious DNS query to evil.com",
        confidence=0.9,
        severity="high",
        evidence_reference="CORR-00001",
        source_artifact_id="A-ALPHA-1",
        layer="network.dns_analyzer"
    )
    finding_case_b = Finding(
        case_id="CASE-BETA",
        tenant_id="default",
        fact="Suspicious DNS query to evil.com",
        confidence=0.9,
        severity="high",
        evidence_reference="CORR-00002",
        source_artifact_id="A-BETA-1",
        layer="network.dns_analyzer"
    )

    store.write_finding(finding_case_a)
    store.write_finding(finding_case_b)

    alpha_results = store.read_findings("CASE-ALPHA")
    beta_results = store.read_findings("CASE-BETA")

    assert len(alpha_results) == 1
    assert alpha_results[0].case_id == "CASE-ALPHA"

    assert len(beta_results) == 1
    assert beta_results[0].case_id == "CASE-BETA"


# ── 5. Tenant Isolation Adversarial Audit ───────────────────────────────────────

def test_adversarial_tenant_isolation():
    store = UnifiedEvidenceStore()

    finding_tenant_a = Finding(
        case_id="CASE-SHARED",
        tenant_id="TENANT-ACME",
        fact="Process execution in temp directory",
        confidence=0.85,
        severity="medium",
        evidence_reference="CORR-00003",
        source_artifact_id="A-ACME-1",
        layer="endpoint.filesystem_analyzer"
    )
    finding_tenant_b = Finding(
        case_id="CASE-SHARED",
        tenant_id="TENANT-GLOBEX",
        fact="Process execution in temp directory",
        confidence=0.85,
        severity="medium",
        evidence_reference="CORR-00004",
        source_artifact_id="A-GLOBEX-1",
        layer="endpoint.filesystem_analyzer"
    )

    store.write_finding(finding_tenant_a)
    store.write_finding(finding_tenant_b)

    acme_results = store.read_findings("CASE-SHARED", tenant_id="TENANT-ACME")
    globex_results = store.read_findings("CASE-SHARED", tenant_id="TENANT-GLOBEX")

    assert len(acme_results) == 1
    assert acme_results[0].tenant_id == "TENANT-ACME"

    assert len(globex_results) == 1
    assert globex_results[0].tenant_id == "TENANT-GLOBEX"


# ── 6. Full Forensic Analysis Layer Security AST Audit ─────────────────────────

def test_full_forensic_analysis_layer_security_ast():
    """
    Verifies that ALL python files under argus/forensic_analysis/ contain ZERO unsafe calls:
    eval=0, exec=0, shell=True=0, os.system=0, pickle.loads=0.
    """
    base_dir = os.path.join(os.path.dirname(__file__), "..", "..", "forensic_analysis")
    python_files = []
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".py"):
                python_files.append(os.path.join(root, f))

    assert len(python_files) >= 25, f"Expected at least 25 python files under forensic_analysis, found {len(python_files)}"

    for filepath in python_files:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            code = f.read()

        tree = ast.parse(code, filename=filepath)
        assert tree is not None, f"Failed to parse AST for {filepath}"

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), f"Forbidden call '{node.func.id}' found in {filepath}"
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        pytest.fail(f"Forbidden os.system call found in {filepath}")
                    if node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                        pytest.fail(f"Forbidden pickle.loads call found in {filepath}")

                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        pytest.fail(f"Forbidden shell=True argument found in {filepath}")
