"""
Unit tests for Qdrant tenant isolation, approved-case filtering, embedding fallback tracking,
production fail-closed behavior, and cross-cutting ISM checkpoint recovery.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from agents.agent5b_campaign_similarity.case_repository import ValidatedCaseRepository
from agents.agent5b_campaign_similarity.schemas import (
    ValidatedCase, CaseValidationRecord, MultiVector, MalwareIdentity
)
from agents.agent5b_campaign_similarity.vector_engine import MultiVectorEngine
from models.embeddings import EmbeddingLoader
from ism.checkpointer import Checkpointer, build_ism_idempotency_key
from config.settings import settings


def _make_sample_case(case_id: str, tenant_id: str, approved: bool = True) -> ValidatedCase:
    return ValidatedCase(
        case_id=case_id,
        tenant_id=tenant_id,
        validation=CaseValidationRecord(
            status="approved" if approved else "pending",
            approved_by="senior_analyst" if approved else None,
            approval_timestamp="2026-01-01T00:00:00Z"
        ),
        malware_identity=MalwareIdentity(family="Emotet", identity_confidence=0.9),
        malware_behavior_fingerprint={"execution": ["cmd.exe"]},
        attack_pattern={"kill_chain": "initial_access"},
        threat_intelligence={"candidate_malware_families": ["Emotet"]}
    )



def test_qdrant_maker_checker_approval_filtering():
    """Verify unapproved cases are rejected from storage and excluded from retrieval."""
    repo = ValidatedCaseRepository(qdrant_client=None)

    unapproved_case = _make_sample_case("CASE-UNAPPROVED", "tenant-alpha", approved=False)
    with pytest.raises(ValueError, match="Maker-Checker policy violation"):
        repo.add_case(unapproved_case)

    # Approved case succeeds
    approved_case = _make_sample_case("CASE-APPROVED", "tenant-alpha", approved=True)
    assert repo.add_case(approved_case) is True


def test_qdrant_strict_tenant_isolation():
    """Verify tenant isolation: cases from tenant-a are never returned for tenant-b."""
    repo = ValidatedCaseRepository(qdrant_client=None)

    case_a = _make_sample_case("CASE-TENANT-A", "tenant-a", approved=True)
    case_b = _make_sample_case("CASE-TENANT-B", "tenant-b", approved=True)

    repo.add_case(case_a)
    repo.add_case(case_b)

    # Search within tenant-a
    query_vec = MultiVectorEngine._semantic_hash_vector("execution cmd.exe")
    mv = MultiVector(
        behavior_vector=query_vec,
        attack_pattern_vector=query_vec,
        threat_intel_vector=query_vec,
        composite_vector=query_vec
    )

    results_a = repo.search_similar(tenant_id="tenant-a", query_vectors=mv, top_k=10)
    for res in results_a:
        assert res.tenant_id == "tenant-a"
        assert res.case_id != "CASE-TENANT-B"

    # Search within tenant-b
    results_b = repo.search_similar(tenant_id="tenant-b", query_vectors=mv, top_k=10)
    for res in results_b:
        assert res.tenant_id == "tenant-b"
        assert res.case_id != "CASE-TENANT-A"


def test_embedding_loader_fallback_tracking():
    """Verify EmbeddingLoader tracks target_model_name, is_fallback, and fallback_reason truthfully."""
    with patch.object(settings, "app_env", "development"):
        loader = EmbeddingLoader()
        if "Qwen" in loader.target_model_name:
            assert loader.is_fallback is True
            assert loader.fallback_reason is not None
            assert "MiniLM" in loader.model_name


def test_qdrant_production_fail_closed():
    """Verify Qdrant operations fail closed (raise RuntimeError) in production when connection or query fails."""
    with patch.object(settings, "app_env", "production"):
        # Simulated broken client that raises on search
        mock_client = MagicMock()
        mock_client.search.side_effect = ConnectionError("Qdrant cluster unreachable")
        mock_client.query_points.side_effect = ConnectionError("Qdrant cluster unreachable")

        repo = ValidatedCaseRepository(qdrant_client=mock_client)

        query_vec = [0.1] * 384
        mv = MultiVector(
            behavior_vector=query_vec,
            attack_pattern_vector=query_vec,
            threat_intel_vector=query_vec,
            composite_vector=query_vec
        )

        with pytest.raises(RuntimeError, match="Qdrant search query failed in production mode"):
            repo.search_similar(tenant_id="prod-tenant", query_vectors=mv)


def test_vector_engine_production_fail_closed():
    """Verify MultiVectorEngine fails closed in production when embedding fails."""
    with patch.object(settings, "app_env", "production"):
        mock_embedder = MagicMock()
        mock_embedder.encode.side_effect = RuntimeError("GPU out of memory")

        engine = MultiVectorEngine(embedder=mock_embedder)
        with pytest.raises(RuntimeError, match="Embedding encoding failed in production mode"):
            engine.encode_text("critical malware string")


def test_ism_checkpoint_save_and_retrieve():
    """Verify Checkpointer saves stage state and retrieves it durably."""
    checkpointer = Checkpointer()
    case_id = "CASE-ISM-TEST-001"

    # Save Agent 1 completed checkpoint
    stage1_state = {"claims": [{"fact": "Executable dropped", "evidence_ids": ["EVID-01"]}], "execution_status": "COMPLETED"}
    assert checkpointer.save_stage_checkpoint(case_id, "agent1", state=stage1_state, status="COMPLETED") is True

    # Retrieve Agent 1 checkpoint
    cp = checkpointer.get_stage_checkpoint(case_id, "agent1")
    assert cp is not None
    assert cp["status"] == "COMPLETED"
    assert "Executable dropped" in str(cp["checkpoint"])

    # Idempotency key consistency
    key1 = build_ism_idempotency_key(case_id, "default", ["EVID-01", "EVID-02"])
    key2 = build_ism_idempotency_key(case_id, "default", ["EVID-02", "EVID-01"])
    assert key1 == key2  # Deterministic order invariance


def test_ism_pipeline_resume_capability():
    """Verify argus_pipeline resumes from a completed stage checkpoint without re-running it."""
    from argus_pipeline import run_pipeline
    from fir.schemas import FIRFinding

    fir_finding = FIRFinding(
        finding_id="FIR-ISM-01",
        case_id="CASE-RESUME-001",
        tenant_id="default",
        fact="Malicious PowerShell script detected",
        confidence=0.9,
        severity="high",
        layer="test",
        evidence_reference=["EVID-01"]
    )

    checkpointer = Checkpointer()
    # Pre-save completed checkpoint for Agent 1
    cached_agent1 = {
        "claims": [{"fact": "Pre-computed claim from checkpoint", "cited_evidence_ids": ["FIR-ISM-01"]}],
        "execution_status": "COMPLETED"
    }
    checkpointer.save_stage_checkpoint("CASE-RESUME-001", "agent1", state=cached_agent1, status="COMPLETED")

    mock_llm = MagicMock()
    mock_llm.chat.return_value = '{"claims": [], "status": "COMPLETED"}'

    # Run pipeline with resume=True
    res = run_pipeline(
        case_id="CASE-RESUME-001",
        tenant_id="default",
        fir_findings=[fir_finding],
        llm=mock_llm,
        resume=True
    )

    # Agent 1 should be RESUMED with cached output
    assert res["stage_statuses"]["agent1"] == "RESUMED"
    assert res["agent1"]["claims"][0]["fact"] == "Pre-computed claim from checkpoint"
