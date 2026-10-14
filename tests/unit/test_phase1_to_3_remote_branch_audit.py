"""
Regression Test Suite — ARGUS Remote Branch Audit (Phases 1, 2, 3)
===================================================================
Validates:
  Phase 1: Tenant Isolation across FIR, FCR, Evidence Store, Agent 7, and API boundaries.
  Phase 2: Agent 1 Citation and Confidence Integrity (No implicit 0.8, empty citation rejection, DB recovery).
  Phase 3: Agent 7 Verification Integrity (Compound claims, no default 0.90, DeBERTa authority, report status).
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
from fastapi import HTTPException

import json
from fir.schemas import FIRFinding, ReviewStatus
from fir.repository import FIRRepository
from infrastructure.repository.evidence_store import get_evidence
from api.routes.evidence import authorize_tenant_access
from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.schemas import CorrelationRecord
from confidence_gate.gate import ConfidenceGate, ReviewRoute
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Claim, Agent1Output
from agents.agent7_supervisor.schemas import StructuredClaim, ClaimVerificationResult
from agents.agent7_supervisor.call2_verification import SupervisorVerification
from agents.agent7_supervisor.report_builder import SupervisorReportBuilder


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: TENANT ISOLATION REGRESSION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_cross_tenant_same_case_id_fir_isolation():
    """
    Two tenants ('tenant-alpha', 'tenant-beta') use the exact same case_id 'CASE-DUAL-001'.
    Confirms no cross-tenant retrieval, scoping bypass, or blanket 'default' access.
    """
    repo = FIRRepository()
    repo.clear()

    finding_alpha = FIRFinding(
        finding_id="FIR-ALPHA-101",
        case_id="CASE-DUAL-001",
        tenant_id="tenant-alpha",
        fact="Alpha attacker persistence via registry Run key",
        confidence=0.92,
        severity="high",
        evidence_reference=["LOG-ALPHA-01"],
        layer="endpoint",
    )
    finding_beta = FIRFinding(
        finding_id="FIR-BETA-202",
        case_id="CASE-DUAL-001",
        tenant_id="tenant-beta",
        fact="Beta credential dumping via lsass memory injection",
        confidence=0.95,
        severity="critical",
        evidence_reference=["LOG-BETA-01"],
        layer="endpoint",
    )

    repo.insert(finding_alpha)
    repo.insert(finding_beta)

    # 1. Scoped case retrieval
    alpha_cases = repo.get_by_case("CASE-DUAL-001", tenant_id="tenant-alpha")
    beta_cases = repo.get_by_case("CASE-DUAL-001", tenant_id="tenant-beta")
    assert len(alpha_cases) == 1
    assert alpha_cases[0].finding_id == "FIR-ALPHA-101"
    assert len(beta_cases) == 1
    assert beta_cases[0].finding_id == "FIR-BETA-202"

    # 2. Cross-tenant get_by_id rejection
    assert repo.get_by_id("tenant-alpha", "FIR-BETA-202") is None
    assert repo.get_by_id("tenant-beta", "FIR-ALPHA-101") is None

    # 3. Blanket bypass removal: 'default', '', and '*' must not read foreign tenant data
    assert repo.get_by_id("default", "FIR-ALPHA-101") is None
    assert repo.get_by_id("", "FIR-ALPHA-101") is None
    assert repo.get_by_id("*", "FIR-ALPHA-101") is None


def test_fcr_engine_partitions_by_tenant_and_case():
    """
    Ensures FCR engine strictly partitions correlation by (tenant_id, case_id).
    Artifacts with same case_id and same hash but different tenants must never correlate together.
    """
    engine = FCREngine()
    t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    art_alpha_1 = Artifact(
        artifact_id="ART-ALPHA-01",
        case_id="CASE-SHARED-01",
        tenant_id="tenant-alpha",
        evidence_id="EV-ALPHA-01",
        source_tool="hayabusa",
        artifact_type="process_execution",
        host_id="WORKSTATION-01",
        timestamp=t0,
        normalized_fields=NormalizedFields(hash=sha256),
    )
    art_alpha_2 = Artifact(
        artifact_id="ART-ALPHA-02",
        case_id="CASE-SHARED-01",
        tenant_id="tenant-alpha",
        evidence_id="EV-ALPHA-02",
        source_tool="zeek",
        artifact_type="network_connection",
        host_id="WORKSTATION-01",
        timestamp=t0,
        normalized_fields=NormalizedFields(hash=sha256),
    )
    art_beta_1 = Artifact(
        artifact_id="ART-BETA-01",
        case_id="CASE-SHARED-01",  # Same case ID!
        tenant_id="tenant-beta",   # Different tenant!
        evidence_id="EV-BETA-01",
        source_tool="hayabusa",
        artifact_type="process_execution",
        host_id="WORKSTATION-01",
        timestamp=t0,
        normalized_fields=NormalizedFields(hash=sha256),
    )

    records = engine.correlate([art_alpha_1, art_alpha_2, art_beta_1])
    # Alpha artifacts correlate with each other
    alpha_recs = [r for r in records if r.tenant_id == "tenant-alpha"]
    assert len(alpha_recs) >= 1
    for r in alpha_recs:
        assert "ART-BETA-01" not in r.artifact_ids

    # Beta cannot correlate across tenant boundaries
    for r in records:
        if "ART-BETA-01" in r.artifact_ids:
            assert r.tenant_id == "tenant-beta"
            assert "ART-ALPHA-01" not in r.artifact_ids
            assert "ART-ALPHA-02" not in r.artifact_ids


def test_negative_authorization_tenant_claims():
    """
    Verifies that wildcard '*', empty tenant, or unassigned tenants fail authorization.
    """
    analyst_user = {
        "user_id": "usr-01",
        "username": "analyst",
        "tenants": ["tenant-alpha", "tenant-gamma"],
        "is_admin": False,
    }

    # 1. Authorized tenant passes
    assert authorize_tenant_access(analyst_user, "tenant-alpha") == "tenant-alpha"

    # 2. Unassigned tenant raises 403
    with pytest.raises(HTTPException) as exc_info:
        authorize_tenant_access(analyst_user, "tenant-beta")
    assert exc_info.value.status_code == 403

    # 3. Wildcard '*' raises 400
    with pytest.raises(HTTPException) as exc_info:
        authorize_tenant_access(analyst_user, "*")
    assert exc_info.value.status_code in (400, 403)

    # 4. Empty tenant raises 400
    with pytest.raises(HTTPException) as exc_info:
        authorize_tenant_access(analyst_user, "")
    assert exc_info.value.status_code in (400, 403)


def test_evidence_store_filesystem_fallback_tenant_isolation(tmp_path, monkeypatch):
    """
    Verifies local filesystem fallback in get_evidence respects tenant boundaries.
    """
    monkeypatch.setattr("infrastructure.repository.evidence_store._should_attempt_postgres", lambda: False)
    monkeypatch.setattr("infrastructure.repository.evidence_store.REPOSITORY_DIR", str(tmp_path))

    # Create Alpha evidence on local disk
    ev_dir = tmp_path / "CASE-SAME-01" / "EVD-ALPHA-99"
    ev_dir.mkdir(parents=True)
    meta = {
        "evidence_id": "EVD-ALPHA-99",
        "case_id": "CASE-SAME-01",
        "tenant_id": "tenant-alpha",
        "filename": "memory.raw",
        "file_path": str(ev_dir / "memory.raw"),
        "uploaded_by": "analyst",
        "upload_timestamp": "2026-01-01T00:00:00Z",
        "status": "stored",
        "sha256_hash": "a" * 64,
    }
    with open(ev_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f)

    # 1. Alpha lookup succeeds
    ev_alpha = get_evidence("tenant-alpha", "EVD-ALPHA-99")
    assert ev_alpha is not None
    assert ev_alpha.evidence_id == "EVD-ALPHA-99"

    # 2. Beta lookup returns None
    assert get_evidence("tenant-beta", "EVD-ALPHA-99") is None

    # 3. Default lookup returns None
    assert get_evidence("default", "EVD-ALPHA-99") is None


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: AGENT 1 CITATION AND CONFIDENCE INTEGRITY REGRESSION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_agent1_claim_zero_evidence_ids_never_verified():
    """
    A claim with no evidence IDs must never receive citation_valid=True or citation_verified=True.
    """
    claim = Agent1Claim(
        claim_id="CLM-EMPTY-01",
        summary="Claim with zero citations",
        findings_summary="No evidence provided",
        cited_evidence_ids=[],
        confidence_score=0.85,
    )
    validator = Agent1Validator()
    valid_universe = {"FIR-001", "SRC-001"}

    validated_claims = validator.validate_claims([claim], valid_finding_ids=valid_universe, valid_lineage_ids=set())
    assert len(validated_claims) == 1
    v_claim = validated_claims[0]
    assert v_claim.citation_valid is False
    assert v_claim.citation_verified is False
    assert "zero evidence IDs" in v_claim.validation_notes


def test_agent1_claim_missing_confidence_is_none():
    """
    Remove implicit 0.8 confidence default. Missing confidence must be None and is_valid_confidence=False.
    """
    claim = Agent1Claim(
        claim_id="CLM-NOCONF-01",
        summary="Claim without confidence",
        findings_summary="Missing confidence score in LLM output",
        cited_evidence_ids=["FIR-001"],
        confidence_score=None,
    )
    validator = Agent1Validator()
    valid_universe = {"FIR-001"}

    validated_claims = validator.validate_claims([claim], valid_finding_ids=valid_universe, valid_lineage_ids=set())
    assert len(validated_claims) == 1
    v_claim = validated_claims[0]
    assert v_claim.confidence_score is None
    assert v_claim.is_valid_confidence is False
    assert "Missing confidence_score" in v_claim.validation_notes


def test_agent1_triage_empty_evidence_id_rejected():
    """
    Triage items (priority_evidence, supporting_evidence, etc.) with empty evidence_id are rejected.
    """
    validator = Agent1Validator()
    output_dict = {
        "priority_evidence": [
            {"evidence_id": "FIR-001", "reason": "Valid priority", "priority_score": 0.9},
            {"evidence_id": "", "reason": "Empty evidence id", "priority_score": 0.8},
            {"reason": "Missing evidence_id key", "priority_score": 0.8},
        ],
        "supporting_evidence": [
            {"evidence_id": "   ", "notes": "Whitespace only"},
            {"evidence_id": "FIR-002", "notes": "Valid supporting"},
        ],
    }

    validated, invalid_citations = validator.validate_triage_output(
        output_dict,
        valid_finding_ids={"FIR-001", "FIR-002"},
        valid_lineage_ids=set()
    )

    # Only valid non-empty items are kept
    assert len(validated["priority_evidence"]) == 1
    assert validated["priority_evidence"][0]["evidence_id"] == "FIR-001"
    assert len(validated["supporting_evidence"]) == 1
    assert validated["supporting_evidence"][0]["evidence_id"] == "FIR-002"


def test_agent1_database_persistence_recovery():
    """
    Test that Agent 1 avoids a permanent process-wide degraded flag and can recover
    persistence when PostgreSQL becomes available again.
    """
    mock_model = MagicMock()
    mock_fir = MagicMock()
    mock_gateway = MagicMock()
    agent = EvidenceIntelligenceAgent(mock_model, mock_fir, mock_gateway)

    # Simulate DB failure
    EvidenceIntelligenceAgent._db_unreachable = True
    output = MagicMock(spec=Agent1Output)
    output.persistence_status = "PENDING"

    agent._persist_agent_output(output)
    assert output.persistence_status == "PERSISTENCE_DEGRADED"

    # Reset DB unreachable state
    EvidenceIntelligenceAgent.reset_db_unreachable()
    assert EvidenceIntelligenceAgent._should_attempt_postgres() is True


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: AGENT 7 VERIFICATION INTEGRITY REGRESSION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_agent7_legacy_missing_tenant_metadata_rejected():
    """
    Every evidence record must be verified against authorized tenant;
    missing/legacy tenant metadata must not automatically authorize the record.
    """
    mock_model = MagicMock()
    mock_gateway = MagicMock()

    # 1. FIRFinding schema itself strictly rejects missing/None tenant_id
    with pytest.raises(Exception):
        FIRFinding(
            finding_id="FIR-LEGACY-01",
            case_id="CASE-LEGACY-01",
            tenant_id=None,
            fact="Malicious service installed",
            confidence=0.90,
            severity="high",
            evidence_reference=["LOG-01"],
            layer="endpoint",
        )

    # 2. Verifier rejects mock finding that somehow lacks tenant_id
    mock_legacy_finding = MagicMock()
    mock_legacy_finding.finding_id = "FIR-LEGACY-01"
    mock_legacy_finding.case_id = "CASE-LEGACY-01"
    mock_legacy_finding.tenant_id = None
    mock_legacy_finding.fact = "Malicious service installed"
    mock_legacy_finding.sanitized_fact = "Malicious service installed"
    mock_legacy_finding.severity = "high"
    mock_legacy_finding.confidence = 0.90
    mock_legacy_finding.review_status = ReviewStatus.PENDING_REVIEW

    mock_fir = MagicMock()
    mock_fir.get_by_id.return_value = mock_legacy_finding

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="tenant-alpha")
    claim = {
        "claim_id": "CLM-LEG-01",
        "claim": "Malicious service installed",
        "evidence_ids": ["FIR-LEGACY-01"],
        "severity": "high",
        "confidence": 0.90,
    }

    res = verifier.verify(claim, tenant_id="tenant-alpha", case_id="CASE-LEGACY-01")
    assert res["verified"] is False
    assert res["checks"]["existence"] is False
    assert any("Tenant boundary violation" in f for f in res["flags"])


def test_agent7_compound_claim_unsupported_assertion_fails():
    """
    Do not verify a compound claim just because one cited finding has maximum entailment score.
    Each material assertion must be supported by evidence.
    """
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    # Evidence only supports the first clause, NOT the second clause
    finding = FIRFinding(
        finding_id="FIR-7010",
        case_id="CASE-710",
        tenant_id="tenant-alpha",
        fact="Host downloaded payload.exe from external server.",
        confidence=0.95,
        severity="high",
        evidence_reference=["LOG-01"],
        layer="endpoint",
    )
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="tenant-alpha")

    # Compound claim with two distinct sentences/assertions
    claim = {
        "claim_id": "CLM-COMP-01",
        "claim": "Host downloaded payload.exe from external server. Entire active directory database was exported.",
        "evidence_ids": ["FIR-7010"],
        "severity": "high",
        "confidence": 0.90,
    }

    # Patch classifier so clause 1 has high entailment and clause 2 has low entailment
    with patch("models.classifiers.ClassifierLoader.classify_nli") as mock_nli:
        def side_effect(premise, hypothesis):
            if "downloaded" in hypothesis:
                return {"label": "entailment", "entailment": 0.92, "neutral": 0.05, "contradiction": 0.03}
            else:
                return {"label": "neutral", "entailment": 0.15, "neutral": 0.80, "contradiction": 0.05}

        mock_nli.side_effect = side_effect

        res = verifier.verify(claim, tenant_id="tenant-alpha", case_id="CASE-710")
        assert res["verified"] is False
        assert res["checks"]["support"] is False
        assert any("unsupported clause" in f for f in res["flags"])


def test_agent7_structured_claim_missing_confidence():
    """
    Remove schema-level default confidence of 0.90 from StructuredClaim.
    Missing confidence must remain unknown/unverified and route to senior review.
    """
    claim = StructuredClaim(
        claim_id="CLM-NOCONF-02",
        claim="Suspicious scheduled task registered",
        evidence_ids=["FIR-7001"],
        severity="medium",
        confidence=None,
    )
    assert claim.confidence is None

    # Verification must flag missing confidence
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()
    finding = FIRFinding(
        finding_id="FIR-7001",
        case_id="CASE-001",
        tenant_id="tenant-alpha",
        fact="Scheduled task registered",
        confidence=0.85,
        severity="medium",
        evidence_reference=["LOG-01"],
        layer="endpoint",
    )
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="tenant-alpha")
    ver_res = verifier.verify(claim.model_dump(), tenant_id="tenant-alpha", case_id="CASE-001")
    assert ver_res["verified"] is False
    assert ver_res["checks"]["severity"] is False
    assert any("Missing model confidence" in f for f in ver_res["flags"])


def test_agent7_contradiction_never_verified():
    """
    Contradictory evidence must set contradiction label, divergence flag, and verified=False.
    """
    mock_model = MagicMock()
    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    finding = FIRFinding(
        finding_id="FIR-7020",
        case_id="CASE-720",
        tenant_id="tenant-alpha",
        fact="Firewall strictly blocked all outbound connections to IP 203.0.113.5",
        confidence=0.98,
        severity="medium",
        evidence_reference=["LOG-01"],
        layer="endpoint",
    )
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="tenant-alpha")
    claim = {
        "claim_id": "CLM-CONTRA-01",
        "claim": "Host successfully established outbound connection to IP 203.0.113.5",
        "evidence_ids": ["FIR-7020"],
        "severity": "medium",
        "confidence": 0.85,
    }

    with patch("models.classifiers.ClassifierLoader.classify_nli") as mock_nli:
        mock_nli.return_value = {
            "label": "contradiction",
            "entailment": 0.05,
            "neutral": 0.10,
            "contradiction": 0.85,
        }
        res = verifier.verify(claim, tenant_id="tenant-alpha", case_id="CASE-720")
        assert res["verified"] is False
        assert res["checks"]["support"] is False
        assert res["checks"]["divergence"] is False
        assert res["entailment_label"] == "contradiction"


def test_agent7_secondary_llm_cannot_override_unverified():
    """
    Secondary LLM assessment is strictly informational and CANNOT override an unverified DeBERTa verdict.
    """
    mock_model = MagicMock()
    # Secondary model attempts to say YES
    mock_model.generate.return_value = "YES"

    mock_fir = FIRRepository()
    mock_gateway = MagicMock()

    finding = FIRFinding(
        finding_id="FIR-7030",
        case_id="CASE-730",
        tenant_id="tenant-alpha",
        fact="User logged in during normal business hours.",
        confidence=0.90,
        severity="medium",
        evidence_reference=["LOG-01"],
        layer="endpoint",
    )
    mock_fir.insert(finding)

    verifier = SupervisorVerification(mock_model, mock_fir, mock_gateway, tenant_id="tenant-alpha")
    claim = {
        "claim_id": "CLM-LLM-01",
        "claim": "Attacker compromised privileged credentials after hours.",
        "evidence_ids": ["FIR-7030"],
        "severity": "medium",
        "confidence": 0.80,
    }

    with patch("models.classifiers.ClassifierLoader.classify_nli") as mock_nli:
        # Inconclusive/neutral score
        mock_nli.return_value = {
            "label": "neutral",
            "entailment": 0.25,
            "neutral": 0.70,
            "contradiction": 0.05,
        }
        res = verifier.verify(claim, tenant_id="tenant-alpha", case_id="CASE-730")
        assert res["verified"] is False
        assert res["secondary_assessment"] == "SECONDARY_AFFIRMED"
        assert res["status"] == "unverified — requires manual confirmation"


def test_agent7_report_builder_distinguishes_verdicts():
    """
    SupervisorReportBuilder explicitly distinguishes verified facts, unverified claims,
    contradictions, missing evidence, and execution failures in report payloads.
    """
    builder = SupervisorReportBuilder()
    synthesis = {
        "confidence_score": 0.88,
        "executive_summary": "Test Executive Summary",
        "incident_narrative": "Test Narrative",
        "synthesis_status": "COMPLETED",
    }
    verification_results = [
        {
            "claim_id": "CLM-V1",
            "claim": "Verified finding",
            "verified": True,
            "status": "supported",
            "support_score": 0.95,
        },
        {
            "claim_id": "CLM-UV1",
            "claim": "Unverified finding",
            "verified": False,
            "status": "unverified",
            "support_score": 0.40,
        },
        {
            "claim_id": "CLM-CT1",
            "claim": "Contradicted finding",
            "verified": False,
            "status": "contradicted",
            "support_score": 0.10,
        },
        {
            "claim_id": "CLM-ME1",
            "claim": "Missing evidence finding",
            "verified": False,
            "status": "invalid_or_missing_evidence",
            "support_score": 0.0,
        },
    ]
    confidence_gate = {"route": "senior_dual", "reasons": ["Unverified findings"]}

    package = builder.build_report_package(
        case_id="CASE-REP-01",
        tenant_id="tenant-alpha",
        synthesis=synthesis,
        verification_results=verification_results,
        confidence_gate=confidence_gate,
    )

    analyst_data = package["rendered"]["analyst"]["data"]
    assert len(analyst_data["verified_facts"]) == 1
    assert analyst_data["verified_facts"][0]["finding_id"] == "CLM-V1"
    assert len(analyst_data["unverified_claims"]) == 1
    assert analyst_data["unverified_claims"][0]["finding_id"] == "CLM-UV1"
    assert len(analyst_data["contradictions"]) == 1
    assert analyst_data["contradictions"][0]["finding_id"] == "CLM-CT1"
    assert len(analyst_data["missing_evidence"]) == 1
    assert analyst_data["missing_evidence"][0]["finding_id"] == "CLM-ME1"
    assert analyst_data["execution_status"] == "SUCCESS"
