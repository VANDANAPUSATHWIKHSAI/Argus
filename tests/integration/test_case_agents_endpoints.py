"""
Automated Endpoint Tests for Multi-Agent Swarm Integration
===========================================================
Covers all requirements from the audit remediation:
1. Authentication: 401 when unauthenticated or token invalid/missing.
2. Case Existence: 404 when case does not exist in store, DB, or sessions.
3. Tenant Isolation: 404 when accessing a case owned by another tenant.
4. Empty Cases: 400 on run-agents when case has no findings or evidence; 200 READY on GET.
5. Duplicate Execution: 200 with status RUNNING when job is already running for the case.
6. Failure Handling: Correct FAILED status and error telemetry returned, never marked as success.
7. Result Retrieval: Accurate population of Agents 1-7, claims, and supervisor synthesis.
"""

import shutil
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch

from api.main import app
from api.routes.auth import create_access_token
from api.routes.cases import _agent_jobs, _agent_jobs_lock
from infrastructure.repository.evidence_store import create_case_session, store_evidence


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers():
    token = create_access_token({"sub": "EMP-002", "role": "forensic_analyst", "name": "Lead Analyst"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def cleanup_test_cases():
    test_case_ids = [
        "CASE-EP-AUTH-01",
        "CASE-EP-NOTFOUND-01",
        "CASE-EP-TENANT-A",
        "CASE-EP-EMPTY-01",
        "CASE-EP-DUP-01",
        "CASE-EP-FAIL-01",
        "CASE-EP-RESULTS-01",
        "CASE-EP-ENCODED%22-01",
    ]
    yield
    # Cleanup memory and disk after test runs
    with _agent_jobs_lock:
        for cid in test_case_ids:
            _agent_jobs.pop(cid, None)

    for cid in test_case_ids:
        p = Path("data/repository") / cid
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)


# ── 1. Authentication Tests ──────────────────────────────────────────────────

def test_run_agents_unauthenticated_fails(client):
    """POST /cases/{case_id}/run-agents without Authorization header returns 401."""
    resp = client.post("/cases/CASE-EP-AUTH-01/run-agents")
    assert resp.status_code == 401
    assert "Not authenticated" in resp.text or "detail" in resp.json()


def test_get_agents_unauthenticated_fails(client):
    """GET /cases/{case_id}/agents without Authorization header returns 401."""
    resp = client.get("/cases/CASE-EP-AUTH-01/agents")
    assert resp.status_code == 401


def test_invalid_token_fails(client):
    """Requests with forged or expired token return 401."""
    resp = client.get(
        "/cases/CASE-EP-AUTH-01/agents",
        headers={"Authorization": "Bearer invalid_or_forged_jwt_token"}
    )
    assert resp.status_code == 401


# ── 2. Case Existence Tests ──────────────────────────────────────────────────

def test_run_agents_nonexistent_case_returns_404(client, auth_headers):
    """POST /cases/{case_id}/run-agents returns 404 for unknown cases."""
    resp = client.post(
        "/cases/CASE-EP-NOTFOUND-01/run-agents",
        headers={**auth_headers, "X-Tenant-ID": "default"}
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_get_agents_nonexistent_case_returns_404(client, auth_headers):
    """GET /cases/{case_id}/agents returns 404 for unknown cases."""
    resp = client.get(
        "/cases/CASE-EP-NOTFOUND-01/agents",
        headers={**auth_headers, "X-Tenant-ID": "default"}
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ── 3. Tenant Isolation Tests ────────────────────────────────────────────────

def test_tenant_isolation_boundary_enforced(client, auth_headers):
    """A case session created by tenant_alpha must return 404 when queried by tenant_beta."""
    case_id = "CASE-EP-TENANT-A"
    tenant_owner = "tenant_alpha"
    tenant_intruder = "tenant_beta"

    # Create session under tenant_alpha
    create_case_session(case_id=case_id, tenant_id=tenant_owner, created_by="analyst_alpha")

    # 1. Owner can see the case
    resp_owner = client.get(
        f"/cases/{case_id}/agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_owner}
    )
    assert resp_owner.status_code == 200
    assert resp_owner.json()["case_id"] == case_id
    assert resp_owner.json()["tenant_id"] == tenant_owner

    # 2. Cross-tenant GET must return 404 Not Found (strict tenant isolation)
    resp_cross_get = client.get(
        f"/cases/{case_id}/agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_intruder}
    )
    assert resp_cross_get.status_code == 404
    assert "not found for tenant" in resp_cross_get.json()["detail"]

    # 3. Cross-tenant POST run-agents must also return 404 Not Found
    resp_cross_post = client.post(
        f"/cases/{case_id}/run-agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_intruder}
    )
    assert resp_cross_post.status_code == 404
    assert "not found for tenant" in resp_cross_post.json()["detail"]


# ── 4. Empty Cases Handling ──────────────────────────────────────────────────

def test_empty_case_run_agents_rejected_with_400(client, auth_headers):
    """Case exists but has zero ingested evidence and zero findings; running agents must be rejected with 400."""
    case_id = "CASE-EP-EMPTY-01"
    tenant_id = "default"

    create_case_session(case_id=case_id, tenant_id=tenant_id, created_by="analyst")

    # POST run-agents must refuse execution
    resp = client.post(
        f"/cases/{case_id}/run-agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_id}
    )
    assert resp.status_code == 400
    assert "no ingested evidence or findings" in resp.json()["detail"].lower()

    # GET must return 200 with status READY and zero counts
    get_resp = client.get(
        f"/cases/{case_id}/agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_id}
    )
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["status"] == "READY"
    assert data["findings_count"] == 0
    assert data["evidence_count"] == 0
    assert data["stage_statuses"]["agent1"] == "PENDING"
    assert data["stage_statuses"]["agent7"] == "PENDING"


# ── 5. Duplicate Execution Prevention ────────────────────────────────────────

def test_duplicate_execution_prevention(client, auth_headers):
    """When a multi-agent job is already RUNNING, subsequent POST returns 200 with status RUNNING without duplicate spawn."""
    case_id = "CASE-EP-DUP-01"
    tenant_id = "default"

    create_case_session(case_id=case_id, tenant_id=tenant_id, created_by="analyst")

    # Simulate an active running job in state tracker
    with _agent_jobs_lock:
        _agent_jobs[case_id] = {
            "status": "RUNNING",
            "case_id": case_id,
            "tenant_id": tenant_id,
            "stage_statuses": {"agent1": "RUNNING", "agent2": "PENDING"}
        }

    # Attempt to trigger analysis while already running
    resp = client.post(
        f"/cases/{case_id}/run-agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_id}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "RUNNING"
    assert "already running" in data["message"].lower()


# ── 6. Failure Handling & Telemetry ──────────────────────────────────────────

def test_failure_handling_and_error_reporting(client, auth_headers):
    """When an agent job fails, status must be FAILED with exact agent_errors, never masquerading as SUCCESS."""
    case_id = "CASE-EP-FAIL-01"
    tenant_id = "default"

    create_case_session(case_id=case_id, tenant_id=tenant_id, created_by="analyst")

    # Set up failed state with explicit error details
    error_msg = "Agent 4 deterministic signature engine failed: syntax error in custom rule."
    with _agent_jobs_lock:
        _agent_jobs[case_id] = {
            "status": "FAILED",
            "case_id": case_id,
            "tenant_id": tenant_id,
            "error": error_msg,
            "stage_statuses": {
                "agent1": "COMPLETED",
                "agent2": "COMPLETED",
                "agent3": "COMPLETED",
                "agent4": "FAILED",
                "agent5a": "PENDING",
                "agent5b": "PENDING",
                "agent6": "PENDING",
                "agent7": "PENDING"
            }
        }

    resp = client.get(
        f"/cases/{case_id}/agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_id}
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "FAILED"
    assert data["agent_errors"] == error_msg
    assert data["stage_statuses"]["agent4"] == "FAILED"
    assert data["stage_statuses"]["agent1"] == "COMPLETED"
    assert data["stage_statuses"]["agent7"] == "PENDING"


# ── 7. Result Retrieval & Field Mapping ──────────────────────────────────────

def test_result_retrieval_and_structured_intelligence(client, auth_headers):
    """GET /cases/{case_id}/agents accurately maps Pydantic outputs from Agents 1 through 7."""
    case_id = "CASE-EP-RESULTS-01"
    tenant_id = "default"

    create_case_session(case_id=case_id, tenant_id=tenant_id, created_by="analyst")

    # Populate job with structured agent outputs conforming to schemas
    mock_pipeline_results = {
        "status": "COMPLETED",
        "case_id": case_id,
        "tenant_id": tenant_id,
        "stage_statuses": {
            "agent1": "COMPLETED", "agent2": "COMPLETED", "agent3": "COMPLETED",
            "agent4": "COMPLETED", "agent5a": "COMPLETED", "agent5b": "COMPLETED",
            "agent6": "COMPLETED", "agent7": "COMPLETED"
        },
        "results": {
            "agent1": {
                "evidence_summary": {"total_findings": 12, "high_value_findings": 5},
                "investigation_readiness": {"status": "READY", "reason": "High-fidelity EVTX logs present."},
                "claims": [{"claim_id": "CLM-01", "claim": "Valid EVTX timeline identified", "confidence": 0.94}]
            },
            "agent2": {
                "graph": {"status": "AVAILABLE", "node_count": 28, "relationship_count": 42, "components": [{"community_id": "GC-001"}]},
                "claims": [{"claim_id": "CLM-02", "claim": "PowerShell spawned from Word doc", "confidence": 0.91}]
            },
            "agent3": {
                "reconstruction_summary": "Initial access via phishing attachment leading to credential dumping.",
                "attack_chain": [{"stage": "Execution"}, {"stage": "Persistence"}],
                "attack_path": [{"step_number": 1, "technique": "T1059.001"}],
                "overall_confidence": 0.93
            },
            "agent4": {
                "threat_classification": {"classification": "MALICIOUS", "confidence": 0.96, "reason": "Known Cobalt Strike beacon activity detected."},
                "behavior_observations": [{"category": "Process Injection", "action": "VirtualAllocEx", "subject": "lsass.exe", "evidence_ids": ["FIR-01"]}],
                "yara_matches": [{"rule_name": "CobaltStrike_Beacon_x64"}],
                "novel_threat_detected": False
            },
            "agent5a": {
                "claim": "Correlated C2 IP to known APT29 infrastructure.",
                "ioc_matches": [{"indicator_value": "198.51.100.42", "threat_actor": "APT29", "severity": "HIGH"}],
                "candidate_malware_families": ["Cobalt Strike", "Sliver"]
            },
            "agent5b": {
                "historical_similarity": {
                    "composite_similarity": 0.87,
                    "behavior_similarity": 0.92,
                    "attack_similarity": 0.85,
                    "similar_campaigns": [{"campaign_name": "SolarWinds UNC2452", "historical_case_id": "CASE-2021-009", "similarity_score": 0.89}]
                }
            },
            "agent6": {
                "cvss_assessment": {"base_score": 8.8, "severity": "HIGH", "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
                "iss_assessment": {"iss_score": 7.9, "severity": "HIGH", "executive_summary": "Domain controller compromise with high risk of lateral exfiltration."},
                "affected_assets": [{"asset_id": "DC01.corp.local", "asset_type": "DOMAIN_CONTROLLER", "criticality": "CRITICAL", "compromise_state": "CONFIRMED_COMPROMISED"}]
            },
            "agent7": {
                "synthesis": {"executive_summary": "Critical intrusion identified and contained. Attack progression corroborated across all data sources."},
                "confidence_gate": {
                    "route": "routine",
                    "requires_senior_review": False,
                    "investigation_confidence_score": 0.94,
                    "verified_claim_count": 6,
                    "unverified_claim_count": 0
                },
                "review_level": "ROUTINE_ANALYST_REVIEW",
                "verification": [
                    {"claim_id": "CLM-01", "claim": "Valid EVTX timeline identified", "verified": True, "verdict": "entailment", "support_score": 0.97}
                ]
            }
        }
    }

    with _agent_jobs_lock:
        _agent_jobs[case_id] = mock_pipeline_results

    resp = client.get(
        f"/cases/{case_id}/agents",
        headers={**auth_headers, "X-Tenant-ID": tenant_id}
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "COMPLETED"
    assert data["agent1"]["evidence_summary"]["high_value_findings"] == 5
    assert data["agent2"]["graph"]["node_count"] == 28
    assert data["agent3"]["attack_chain"][0]["stage"] == "Execution"
    assert data["agent4"]["threat_classification"]["classification"] == "MALICIOUS"
    assert data["agent5a"]["ioc_matches"][0]["threat_actor"] == "APT29"
    assert data["agent5b"]["historical_similarity"]["composite_similarity"] == 0.87
    assert data["agent6"]["cvss_assessment"]["base_score"] == 8.8
    assert data["agent7"]["confidence_gate"]["investigation_confidence_score"] == 0.94
    assert len(data["claims"]) >= 2
    assert data["review_level"] == "ROUTINE_ANALYST_REVIEW"
