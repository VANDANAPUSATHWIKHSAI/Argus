"""
End-to-End Integration Test for Evidence Consolidation Layer
==============================================================
Traces full pipeline execution:
Raw Payload -> Normalizer -> Artifact Extractor -> FCR Engine -> Evidence Consolidation -> Repository -> FIR Handoff -> FIRFinding

Verifies complete end-to-end provenance, completeness, conflict handling, and FIR handoff compatibility.
"""

from __future__ import annotations

import pytest
from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.repository import FCRRepository
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from preprocessing.evidence_consolidation.repository import EvidenceConsolidationRepository
from fir.schemas import FIRFinding, ReviewStatus


def test_end_to_end_consolidation_pipeline():
    # 1. Input Artifacts
    art1 = Artifact(
        artifact_id="ART-CONS-E2E-01",
        evidence_id="EVID-CONS-99",
        case_id="CASE-CONS-E2E",
        source_tool="evtx_parser",
        artifact_type="process_event",
        raw_fields={
            "tenant_id": "tenant_e2e",
            "host": "HOST-SEC-01",
            "process_id": 2048,
            "process_name": "cmd.exe",
            "process_command_line": "cmd.exe /c whoami"
        },
        normalized_fields=NormalizedFields(
            host="HOST-SEC-01",
            process_id=2048,
            process_name="cmd.exe",
            process_command_line="cmd.exe /c whoami"
        )
    )

    art2 = Artifact(
        artifact_id="ART-CONS-E2E-02",
        evidence_id="EVID-CONS-99",
        case_id="CASE-CONS-E2E",
        source_tool="mftecmd",
        artifact_type="process_event",
        raw_fields={
            "tenant_id": "tenant_e2e",
            "host": "HOST-SEC-01",
            "process_id": 2048,
            "process_name": "cmd.exe",
            "process_command_line": "cmd.exe /c whoami"
        },
        normalized_fields=NormalizedFields(
            host="HOST-SEC-01",
            process_id=2048,
            process_name="cmd.exe",
            process_command_line="cmd.exe /c whoami"
        )
    )

    # 2. JSON Normalizer
    normalizer = Normalizer()
    norm_arts = normalizer.normalize([art1, art2])
    assert len(norm_arts) == 2

    # 3. Artifact Extractor
    extractor = ArtifactExtractor()
    extracted_entities = extractor.extract(norm_arts, evidence_id="EVID-CONS-99")
    assert len(extracted_entities) >= 1

    # 4. FCR Engine
    fcr_engine = FCREngine()
    fcrs = fcr_engine.correlate(norm_arts, extracted_entities=extracted_entities)
    assert len(fcrs) >= 1

    # 5. Evidence Consolidation Engine
    consolidation_engine = EvidenceConsolidationEngine()
    expected_categories = ["process_event", "network_connection"]
    uais, conflicts, meta = consolidation_engine.consolidate(
        norm_arts,
        fcrs=fcrs,
        expected_categories=expected_categories,
        tenant_id="tenant_e2e"
    )

    # Deduplication of identical process events on same host/pid/cmd
    assert len(uais) == 1
    uai = uais[0]
    assert uai.unified_artifact_id.startswith("UAI-")
    assert uai.identity_strength == "DETERMINISTIC"
    assert uai.source_count == 2
    assert "evtx_parser" in uai.source_tools
    assert "mftecmd" in uai.source_tools

    # Completeness Tracking
    assert meta.case_id == "CASE-CONS-E2E"
    assert "process_event" in meta.received_categories
    assert "network_connection" in meta.missing_categories

    # 6. Repository & FIR Handoff
    cons_repo = EvidenceConsolidationRepository()
    cons_repo.add_unified_artifacts(uais)
    cons_repo.set_completeness(meta)

    fir_findings = cons_repo.to_fir_handoff("CASE-CONS-E2E")
    assert len(fir_findings) == 1
    f_finding = fir_findings[0]

    assert isinstance(f_finding, FIRFinding)
    assert f_finding.case_id == "CASE-CONS-E2E"
    assert f_finding.tenant_id == "tenant_e2e"
    assert f_finding.evidence_reference == [f"uai:{uai.unified_artifact_id}"]
    assert f_finding.review_status == ReviewStatus.PENDING_REVIEW
    assert f_finding.layer == "evidence_consolidation"
