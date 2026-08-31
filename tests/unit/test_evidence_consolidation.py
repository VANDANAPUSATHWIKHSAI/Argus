"""
Unit & Adversarial Test Suite for Evidence Consolidation Layer
================================================================
Covers schema validation, deterministic identity resolution, deduplication,
IOC vs Event identity separation, conflict preservation, completeness metadata,
provenance graph lineage, case/tenant isolation, immutability, and security audit.
"""

from __future__ import annotations

import ast
import inspect
import pytest
from datetime import datetime, timezone

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.evidence_consolidation.schemas import UnifiedArtifact, ConflictRecord, CompletenessMetadata
from preprocessing.evidence_consolidation.identity import resolve_identity
from preprocessing.evidence_consolidation.deduplication import deduplicate_artifacts
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from preprocessing.evidence_consolidation.repository import EvidenceConsolidationRepository
from preprocessing.evidence_consolidation.provenance import ProvenanceGraph
from fir.schemas import FIRFinding, ReviewStatus


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_file_artifacts():
    a1 = Artifact(
        artifact_id="ART-FILE-001",
        evidence_id="EVID-001",
        case_id="CASE-CONS-100",
        source_tool="mftecmd",
        artifact_type="file",
        normalized_fields=NormalizedFields(host="HOST-A", file_path="C:\\Windows\\System32\\cmd.exe", hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    )
    a2 = Artifact(
        artifact_id="ART-FILE-002",
        evidence_id="EVID-002",
        case_id="CASE-CONS-100",
        source_tool="pecmd",
        artifact_type="file",
        normalized_fields=NormalizedFields(host="HOST-A", file_path="C:\\Windows\\System32\\cmd.exe", hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    )
    return [a1, a2]


# ── 1. Schema & Certainty Validation ──────────────────────────────────────────

def test_valid_unified_artifact():
    uai = UnifiedArtifact(
        unified_artifact_id="UAI-000001",
        case_id="CASE-CONS-100",
        tenant_id="tenant_a",
        canonical_artifact_type="file",
        canonical_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        identity_category="IOC_ENTITY_IDENTITY",
        identity_method="SHA256_EXACT_MATCH",
        identity_strength="DETERMINISTIC",
        identity_key="key123",
        source_artifact_ids=["ART-FILE-001", "ART-FILE-002"],
        source_tools=["mftecmd", "pecmd"],
        source_count=2,
        provenance_reference="provenance:UAI-000001"
    )
    assert uai.unified_artifact_id == "UAI-000001"
    assert uai.identity_strength == "DETERMINISTIC"
    assert uai.source_count == 2


def test_invalid_uai_pattern():
    with pytest.raises(ValueError, match="Invalid unified_artifact_id"):
        UnifiedArtifact(
            unified_artifact_id="INVALID-UAI",
            case_id="CASE-CONS-100",
            tenant_id="tenant_a",
            canonical_artifact_type="file",
            canonical_value="val",
            identity_category="IOC_ENTITY_IDENTITY",
            identity_method="SHA256_EXACT_MATCH",
            identity_key="key123",
            source_artifact_ids=["ART-001"],
            source_count=1,
            provenance_reference="prov"
        )


# ── 2. Identity Safety Tests (FALSE MERGE > FALSE SPLIT) ──────────────────────

def test_identity_safety_different_hash_same_filename():
    a1 = Artifact(
        artifact_id="ART-101",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="tool1",
        artifact_type="file",
        normalized_fields=NormalizedFields(host="HOST-A", file_path="C:\\malware.exe", hash="hash_aaa")
    )
    a2 = Artifact(
        artifact_id="ART-102",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="tool2",
        artifact_type="file",
        normalized_fields=NormalizedFields(host="HOST-A", file_path="C:\\malware.exe", hash="hash_bbb")
    )
    res1 = resolve_identity(a1)
    res2 = resolve_identity(a2)
    # Different hashes MUST produce different identity keys
    assert res1[4] != res2[4]


def test_identity_safety_same_pid_different_host():
    a1 = Artifact(
        artifact_id="ART-201",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="evtx",
        artifact_type="process",
        normalized_fields=NormalizedFields(host="HOST-A", process_id=1000, process_name="cmd.exe")
    )
    a2 = Artifact(
        artifact_id="ART-202",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="evtx",
        artifact_type="process",
        normalized_fields=NormalizedFields(host="HOST-B", process_id=1000, process_name="cmd.exe")
    )
    res1 = resolve_identity(a1)
    res2 = resolve_identity(a2)
    # Same PID on different hosts MUST NOT merge
    assert res1[4] != res2[4]


def test_identity_safety_same_domain_different_url_events():
    a1 = Artifact(
        artifact_id="ART-301",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="hindsight",
        artifact_type="browser",
        normalized_fields=NormalizedFields(host="HOST-A", url="http://example.com/login", domain="example.com")
    )
    a2 = Artifact(
        artifact_id="ART-302",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="hindsight",
        artifact_type="browser",
        normalized_fields=NormalizedFields(host="HOST-A", url="http://example.com/admin", domain="example.com")
    )
    res1 = resolve_identity(a1)
    res2 = resolve_identity(a2)
    # Different URLs MUST produce different URL identity keys
    assert res1[4] != res2[4]


def test_ioc_entity_vs_event_identity():
    # IP artifact resolved as standalone vs network connection event
    art_ip = Artifact(
        artifact_id="ART-401",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="suricata",
        artifact_type="ip",
        normalized_fields=NormalizedFields(dst_ip="192.168.1.10")
    )
    res = resolve_identity(art_ip)
    assert res[2] == "IOC_ENTITY_IDENTITY"
    assert res[3] == "CANONICAL_IP"


# ── 3. Case & Tenant Isolation Tests ──────────────────────────────────────────

def test_case_isolation():
    a1 = Artifact(
        artifact_id="ART-501",
        evidence_id="EVID-1",
        case_id="CASE-A",
        source_tool="mftecmd",
        artifact_type="file",
        normalized_fields=NormalizedFields(hash="hash_same")
    )
    a2 = Artifact(
        artifact_id="ART-502",
        evidence_id="EVID-1",
        case_id="CASE-B",
        source_tool="mftecmd",
        artifact_type="file",
        normalized_fields=NormalizedFields(hash="hash_same")
    )
    res1 = resolve_identity(a1, tenant_id="tenant_1")
    res2 = resolve_identity(a2, tenant_id="tenant_1")
    # Same hash in different cases MUST produce different identity keys and UAIs
    assert res1[4] != res2[4]


def test_tenant_isolation():
    a1 = Artifact(
        artifact_id="ART-601",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="mftecmd",
        artifact_type="file",
        normalized_fields=NormalizedFields(hash="hash_same")
    )
    a2 = Artifact(
        artifact_id="ART-602",
        evidence_id="EVID-1",
        case_id="CASE-1",
        source_tool="mftecmd",
        artifact_type="file",
        normalized_fields=NormalizedFields(hash="hash_same")
    )
    res1 = resolve_identity(a1, tenant_id="TENANT-A")
    res2 = resolve_identity(a2, tenant_id="TENANT-B")
    # Same evidence in different tenants MUST produce different identity keys
    assert res1[4] != res2[4]


# ── 4. Deduplication & Determinism Tests ──────────────────────────────────────

def test_deduplication(sample_file_artifacts):
    uais = deduplicate_artifacts(sample_file_artifacts, tenant_id="tenant_a")
    assert len(uais) == 1
    uai = uais[0]
    assert len(uai.source_artifact_ids) == 2
    assert "mftecmd" in uai.source_tools
    assert "pecmd" in uai.source_tools


def test_order_invariance(sample_file_artifacts):
    uais1 = deduplicate_artifacts(sample_file_artifacts, tenant_id="tenant_a")
    uais2 = deduplicate_artifacts(list(reversed(sample_file_artifacts)), tenant_id="tenant_a")
    assert [u.unified_artifact_id for u in uais1] == [u.unified_artifact_id for u in uais2]


def test_repeated_execution_reproducibility(sample_file_artifacts):
    engine = EvidenceConsolidationEngine()
    u1, c1, m1 = engine.consolidate(sample_file_artifacts, tenant_id="tenant_a")
    u2, c2, m2 = engine.consolidate(sample_file_artifacts, tenant_id="tenant_a")
    assert [u.model_dump(exclude={"created_at"}) for u in u1] == [u.model_dump(exclude={"created_at"}) for u in u2]


# ── 5. Conflict Preservation Tests ───────────────────────────────────────────

def test_conflict_preservation_host():
    a1 = Artifact(
        artifact_id="ART-701",
        evidence_id="EVID-1",
        case_id="CASE-CONF-1",
        source_tool="tool1",
        artifact_type="process",
        normalized_fields=NormalizedFields(host="HOST-ALPHA")
    )
    a2 = Artifact(
        artifact_id="ART-702",
        evidence_id="EVID-1",
        case_id="CASE-CONF-1",
        source_tool="tool2",
        artifact_type="process",
        normalized_fields=NormalizedFields(host="HOST-BETA")
    )
    engine = EvidenceConsolidationEngine()
    uais, conflicts, meta = engine.consolidate([a1, a2], tenant_id="tenant_a")
    assert len(conflicts) >= 1
    cnf = conflicts[0]
    assert cnf.conflict_type == "HOST_CONFLICT"
    assert cnf.status == "UNRESOLVED"


# ── 6. Completeness & Provenance Tests ────────────────────────────────────────

def test_completeness_metadata_tracking(sample_file_artifacts):
    engine = EvidenceConsolidationEngine()
    expected = ["file", "memory_dump", "evtx"]
    uais, conflicts, meta = engine.consolidate(sample_file_artifacts, expected_categories=expected, tenant_id="tenant_a")
    assert "file" in meta.received_categories
    assert "memory_dump" in meta.missing_categories
    assert meta.category_statuses["memory_dump"] == "MISSING"


def test_provenance_graph():
    graph = ProvenanceGraph()
    graph.add_node("ART-001", "Artifact")
    graph.add_node("UAI-00001", "UnifiedArtifact")
    graph.add_edge("ART-001", "UAI-00001", "CONSOLIDATED_FROM", case_id="CASE-1", tenant_id="T1", reason="SHA256 Match")
    lineage = graph.get_lineage("UAI-00001")
    assert len(lineage["upstream"]) == 1
    assert lineage["upstream"][0]["source_id"] == "ART-001"
    assert lineage["upstream"][0]["relationship_type"] == "CONSOLIDATED_FROM"


# ── 7. Repository & FIR Handoff Tests ─────────────────────────────────────────

def test_repository_and_fir_handoff(sample_file_artifacts):
    repo = EvidenceConsolidationRepository()
    engine = EvidenceConsolidationEngine()
    uais, conflicts, meta = engine.consolidate(sample_file_artifacts, tenant_id="tenant_a")
    repo.add_unified_artifacts(uais)

    fetched = repo.get_by_uai(uais[0].unified_artifact_id)
    assert fetched == uais[0]

    fir_findings = repo.to_fir_handoff("CASE-CONS-100")
    assert len(fir_findings) == 1
    f = fir_findings[0]
    assert isinstance(f, FIRFinding)
    assert f.evidence_reference[0].startswith("uai:UAI-")
    assert f.review_status == ReviewStatus.PENDING_REVIEW


# ── 8. Immutability Tests ─────────────────────────────────────────────────────

def test_immutability(sample_file_artifacts):
    art_copy = sample_file_artifacts[0].model_copy(deep=True)
    engine = EvidenceConsolidationEngine()
    engine.consolidate(sample_file_artifacts, tenant_id="tenant_a")
    assert sample_file_artifacts[0] == art_copy


# ── 9. Security Audit Test ────────────────────────────────────────────────────

def test_security_audit():
    """Verify 0 eval, 0 exec, 0 shell=True in Evidence Consolidation implementation."""
    import preprocessing.evidence_consolidation.schemas as con_schemas
    import preprocessing.evidence_consolidation.identity as con_identity
    import preprocessing.evidence_consolidation.deduplication as con_dedup
    import preprocessing.evidence_consolidation.consolidation as con_engine
    import preprocessing.evidence_consolidation.repository as con_repo
    import preprocessing.evidence_consolidation.provenance as con_prov

    for mod in [con_schemas, con_identity, con_dedup, con_engine, con_repo, con_prov]:
        source = inspect.getsource(mod)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), f"Forbidden function call {node.func.id} found!"
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in ("eval", "exec"), f"Forbidden method call {node.func.attr} found!"
            elif isinstance(node, ast.keyword):
                if node.arg == "shell" and isinstance(node.value, ast.Constant):
                    assert node.value.value is not True, "Forbidden shell=True keyword argument found!"
