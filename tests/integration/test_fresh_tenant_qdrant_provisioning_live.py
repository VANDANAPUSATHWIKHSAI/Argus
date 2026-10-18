"""
Integration test for fresh-tenant Qdrant provisioning, retry safety,
partial-initialization detection, approved-case insertion, retrieval, and cross-tenant isolation.
Runs directly against live Qdrant at localhost:6333.
"""

import uuid
import pytest
from qdrant_client import QdrantClient, models
from agents.agent5b_campaign_similarity.case_repository import ValidatedCaseRepository
from agents.agent5b_campaign_similarity.schemas import (
    ValidatedCase, CaseValidationRecord, MultiVector, MalwareIdentity
)
from agents.agent5b_campaign_similarity.vector_engine import MultiVectorEngine
from config.settings import settings


@pytest.fixture(scope="module")
def live_qdrant_client():
    """Returns a live QdrantClient connected to configured Qdrant service."""
    try:
        qc = QdrantClient(url=settings.qdrant_url, api_key=settings.qdrant_api_key or None)
        qc.get_collections()
        return qc
    except Exception as e:
        pytest.skip(f"Live Qdrant service unavailable: {e}")


def _build_test_case(case_id: str, tenant_id: str, approved: bool = True) -> ValidatedCase:
    return ValidatedCase(
        case_id=case_id,
        tenant_id=tenant_id,
        validation=CaseValidationRecord(
            status="approved" if approved else "pending",
            approved_by="senior_lead_analyst" if approved else None,
            approval_timestamp="2026-10-16T12:00:00Z"
        ),
        malware_identity=MalwareIdentity(family="CobaltStrike", identity_confidence=0.96),
        malware_behavior_fingerprint={"persistence": ["run_key"], "network": ["beacon_https"]},
        attack_pattern={"kill_chain": "command_and_control", "tactics": ["TA0011"]},
        threat_intelligence={"candidate_malware_families": ["CobaltStrike"]}
    )


def test_fresh_tenant_provisioning_and_retry_safety(live_qdrant_client):
    """
    Verify:
    1. Fresh tenant creation initializes collection with exact multi-vector contract.
    2. Initialization is safe to retry without corrupting or duplicating state.
    3. is_tenant_ready returns True.
    """
    repo = ValidatedCaseRepository(qdrant_client=live_qdrant_client)
    fresh_tenant = f"tenant_fresh_{uuid.uuid4().hex[:8]}"

    try:
        # Step 1: Before provisioning, tenant is NOT ready
        assert repo.is_tenant_ready(fresh_tenant) is False

        # Step 2: Provision fresh tenant
        prov_result = repo.provision_tenant(fresh_tenant)
        assert prov_result["status"] == "READY"
        assert prov_result["is_ready"] is True
        assert prov_result["recreated"] is True
        assert prov_result["vector_dim"] == 384
        assert set(prov_result["vectors"]) == {"behavior", "attack", "threat_intel", "composite"}

        # Step 3: is_tenant_ready is now True
        assert repo.is_tenant_ready(fresh_tenant) is True

        # Step 4: Retry provisioning: must be safe and idempotent (recreated=False)
        retry_result = repo.provision_tenant(fresh_tenant)
        assert retry_result["status"] == "READY"
        assert retry_result["is_ready"] is True
        assert retry_result["recreated"] is False

    finally:
        col_name = repo._get_collection_name(fresh_tenant)
        try:
            live_qdrant_client.delete_collection(col_name)
        except Exception:
            pass


def test_partially_initialized_tenant_detected_and_repaired(live_qdrant_client):
    """
    Verify that a partially initialized collection (e.g. missing required named vectors):
    1. Returns False from is_tenant_ready().
    2. Does NOT appear ready to consumers.
    3. Is automatically repaired/re-provisioned when provision_tenant or ensure_collection is called.
    """
    repo = ValidatedCaseRepository(qdrant_client=live_qdrant_client)
    partial_tenant = f"tenant_partial_{uuid.uuid4().hex[:8]}"
    col_name = repo._get_collection_name(partial_tenant)

    try:
        # Intentionally create a defective collection with only 1 vector instead of 4
        live_qdrant_client.create_collection(
            collection_name=col_name,
            vectors_config={"composite": models.VectorParams(size=384, distance=models.Distance.COSINE)}
        )

        # 1. Defective collection must NOT be considered ready!
        assert repo.is_tenant_ready(partial_tenant) is False

        # 2. ensure_collection detects partial state and safely repairs/reprovisions it
        repaired = repo.ensure_collection(partial_tenant)
        assert repaired is True
        assert repo.is_tenant_ready(partial_tenant) is True

        # Verify all 4 vectors now exist
        col_info = live_qdrant_client.get_collection(col_name)
        vectors = col_info.config.params.vectors
        assert set(vectors.keys()) == {"behavior", "attack", "threat_intel", "composite"}

    finally:
        try:
            live_qdrant_client.delete_collection(col_name)
        except Exception:
            pass


def test_approved_case_insertion_retrieval_and_cross_tenant_isolation(live_qdrant_client):
    """
    Verify:
    1. Approved case is successfully stored into Qdrant.
    2. Unapproved case is rejected by Maker-Checker policy.
    3. Retrieval finds the case for authorized tenant.
    4. Cross-tenant isolation strictly prevents tenant B from seeing tenant A's cases.
    """
    repo = ValidatedCaseRepository(qdrant_client=live_qdrant_client)
    tenant_a = f"tenant_iso_a_{uuid.uuid4().hex[:8]}"
    tenant_b = f"tenant_iso_b_{uuid.uuid4().hex[:8]}"

    try:
        # Provision both tenants
        repo.provision_tenant(tenant_a)
        repo.provision_tenant(tenant_b)

        # 1. Unapproved case fails closed
        unapproved = _build_test_case("CASE-UNAPPROVED-01", tenant_a, approved=False)
        with pytest.raises(ValueError, match="Maker-Checker policy violation"):
            repo.add_case(unapproved)

        # 2. Approved case succeeds
        approved_case = _build_test_case("CASE-APPROVED-A", tenant_a, approved=True)
        assert repo.add_case(approved_case) is True

        # Generate query vectors
        query_vec = MultiVectorEngine._semantic_hash_vector("CobaltStrike beacon_https persistence")
        mv = MultiVector(
            behavior_vector=query_vec,
            attack_pattern_vector=query_vec,
            threat_intel_vector=query_vec,
            composite_vector=query_vec
        )

        # 3. Tenant A retrieves its case
        results_a = repo.search_similar(tenant_id=tenant_a, query_vectors=mv, top_k=5)
        assert len(results_a) >= 1
        assert results_a[0].case_id == "CASE-APPROVED-A"
        assert results_a[0].tenant_id == tenant_a
        assert results_a[0].similarity_score > 0.0

        # 4. Tenant B searches and CANNOT see Tenant A's case
        results_b = repo.search_similar(tenant_id=tenant_b, query_vectors=mv, top_k=5)
        assert len(results_b) == 0

    finally:
        for tid in (tenant_a, tenant_b):
            c_name = repo._get_collection_name(tid)
            try:
                live_qdrant_client.delete_collection(c_name)
            except Exception:
                pass
