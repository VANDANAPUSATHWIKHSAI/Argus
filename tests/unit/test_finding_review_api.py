"""
Unit Tests for Task A — Finding Review API
==========================================
PUT /cases/{case_id}/findings/{finding_id}/review

Validates:
1. Role authorization: senior_analyst and admin succeed; analyst, auditor, viewer rejected (403).
2. Unauthenticated request rejection (401).
3. Reviewer identity derived strictly from authenticated JWT/context (no client spoofing).
4. Strict tenant isolation: cross-tenant review fails closed (404/403) without leaking records.
5. Case containment: finding belonging to a different case rejected (404).
6. State machine & double-review protection: duplicate review rejected (409) unless force=True.
7. Status validation: pending_review rejected (400); invalid enum rejected (422).
8. Missing finding and missing case handling (404).
9. Notes capture and persistence in response and audit trail.
10. Immutable hash-chained audit record generation.
"""

from __future__ import annotations

import os
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from fir.schemas import FIRFinding, ReviewStatus
from api.routes.auth import get_current_user
from infrastructure.audit_logger import verify_chain

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure clean in-memory state and reset dependency overrides."""
    repo = FIRRepository()
    repo.clear()
    FIRRepository.reset_db_unreachable()
    app.dependency_overrides.clear()
    yield
    repo.clear()
    app.dependency_overrides.clear()


def _create_sample_finding(
    finding_id: str = "fnd-test-01",
    case_id: str = "CASE-REV-01",
    tenant_id: str = "tenant-review",
    status: ReviewStatus = ReviewStatus.PENDING_REVIEW
) -> FIRFinding:
    repo = FIRRepository()
    finding = FIRFinding(
        finding_id=finding_id,
        case_id=case_id,
        tenant_id=tenant_id,
        fact="Lateral movement via WMI execution detected on DC-01",
        sanitized_fact="Lateral movement via WMI execution detected on DC-01",
        confidence=0.92,
        severity="high",
        mitre_mapping="T1047",
        layer="endpoint",
        timestamp=datetime.now(timezone.utc),
        evidence_reference=["CORR-WMI-01"],
        review_status=status
    )
    return repo.insert(finding)


# 1. Senior analyst can successfully confirm a finding
def test_senior_analyst_review_confirmed():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "email": "senior@argus.local",
        "role": "senior_analyst",
        "name": "Lead Forensic Reviewer"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed", "notes": "Verified malicious WMI cradle"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )

    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["finding_id"] == finding.finding_id
    assert data["case_id"] == finding.case_id
    assert data["tenant_id"] == finding.tenant_id
    assert data["review_status"] == "analyst_confirmed"
    assert data["reviewed_by"] == "senior_01"
    assert data["notes"] == "Verified malicious WMI cradle"
    assert data["reviewed_at"] is not None


# 2. Admin can successfully reject a finding (false positive)
def test_admin_review_rejected():
    finding = _create_sample_finding(finding_id="fnd-admin-01", case_id="CASE-ADMIN-01", tenant_id="tenant-admin")
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "admin_root",
        "email": "admin@argus.local",
        "role": "admin",
        "name": "System Administrator"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_rejected", "notes": "Legitimate admin maintenance activity"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )

    assert res.status_code == 200, res.text
    data = res.json()
    assert data["review_status"] == "analyst_rejected"
    assert data["reviewed_by"] == "admin_root"
    assert data["notes"] == "Legitimate admin maintenance activity"


# 3. Unauthenticated request rejection (401)
def test_unauthenticated_request_rejected():
    finding = _create_sample_finding()
    # No dependency override and no Authorization header
    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed"}
    )
    assert res.status_code == 401


# 4. Unauthorized role rejection (analyst role rejected with 403)
def test_unauthorized_role_analyst_rejected():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "junior_01",
        "email": "analyst@argus.local",
        "role": "analyst",
        "name": "Junior Analyst"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()


# 5. Unauthorized role rejection (auditor role rejected with 403)
def test_unauthorized_role_auditor_rejected():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "auditor_01",
        "email": "auditor@argus.local",
        "role": "auditor",
        "name": "Compliance Auditor"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()


# 6. Unauthorized role rejection (viewer / guest rejected with 403)
def test_unauthorized_role_guest_rejected():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "guest_01",
        "email": "guest@argus.local",
        "role": "guest",
        "name": "External Observer"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 403


# 7. Cross-tenant finding rejection (fails closed without leaking finding existence)
def test_cross_tenant_finding_rejected():
    finding_alpha = _create_sample_finding(
        finding_id="fnd-alpha-01",
        case_id="CASE-ALPHA",
        tenant_id="tenant-alpha"
    )
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_beta",
        "email": "senior@beta.local",
        "role": "senior_analyst",
        "name": "Beta Senior",
        "tenant_id": "tenant-beta"
    }

    # Request finding from alpha using tenant-beta context
    res = client.put(
        f"/cases/{finding_alpha.case_id}/findings/{finding_alpha.finding_id}/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": "tenant-beta"}
    )
    # Must fail closed with 404 (or 403 for tenant mismatch)
    assert res.status_code in (403, 404)


# 8. Finding belonging to a different case is rejected (404)
def test_cross_case_finding_rejected():
    finding = _create_sample_finding(
        finding_id="fnd-case-a",
        case_id="CASE-A",
        tenant_id="tenant-isolation"
    )
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_iso",
        "role": "senior_analyst",
        "tenant_id": "tenant-isolation"
    }

    # Try to review fnd-case-a under CASE-B
    res = client.put(
        f"/cases/CASE-B/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": "tenant-isolation"}
    )
    assert res.status_code == 404
    assert "not belong" in res.json()["detail"].lower() or "not found" in res.json()["detail"].lower()


# 9. Invalid review status: pending_review cannot be used as a review decision (400)
def test_invalid_review_status_pending_review_rejected():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "pending_review"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 400
    assert "pending_review" in res.json()["detail"].lower()


# 10. Malformed review status string rejected by schema validation (422)
def test_invalid_status_enum_schema_validation():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "not_a_real_status"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 422


# 11. Duplicate review conflict without force=True rejected (409)
def test_duplicate_review_conflict_prevention():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # First review: succeeds
    res1 = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed", "notes": "Initial confirmation"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res1.status_code == 200

    # Second review without force: must raise 409 Conflict
    res2 = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_rejected", "notes": "Mistake corrected"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res2.status_code == 409
    assert "already been reviewed" in res2.json()["detail"].lower()


# 12. Overwrite with force=True succeeds
def test_overwrite_review_with_force():
    finding = _create_sample_finding()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    # Initial confirmation
    res1 = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res1.status_code == 200

    # Overwrite with force=True
    res2 = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_rejected", "force": True, "notes": "Supervisory correction"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res2.status_code == 200
    assert res2.json()["review_status"] == "analyst_rejected"
    assert res2.json()["notes"] == "Supervisory correction"


# 13. Missing finding returns 404
def test_missing_finding_not_found():
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_01",
        "role": "senior_analyst"
    }

    res = client.put(
        "/cases/CASE-01/findings/non_existent_id/review",
        json={"status": "analyst_confirmed"},
        headers={"X-Tenant-ID": "default"}
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# 14. Reviewer identity taken strictly from authentication token
def test_reviewer_identity_from_authenticated_claims():
    finding = _create_sample_finding(finding_id="fnd-spoof-check", tenant_id="tenant-spoof")
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "trusted_senior_emp99",
        "email": "trusted@argus.corp",
        "role": "senior_analyst"
    }

    # Even if an adversary includes "reviewer_id": "spoofed_admin" in payload,
    # the endpoint takes it strictly from current_user["id"]
    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed", "reviewer_id": "spoofed_admin"},
        headers={"X-Tenant-ID": finding.tenant_id}
    )
    assert res.status_code == 200
    assert res.json()["reviewed_by"] == "trusted_senior_emp99"


# 15. Immutable hash-chained audit event generated on review
def test_audit_event_logged_and_chained():
    tenant_id = f"tenant-audit-{uuid.uuid4().hex[:6]}"
    finding = _create_sample_finding(finding_id=f"fnd-audit-{uuid.uuid4().hex[:6]}", tenant_id=tenant_id)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "senior_auditor",
        "role": "senior_analyst"
    }

    res = client.put(
        f"/cases/{finding.case_id}/findings/{finding.finding_id}/review",
        json={"status": "analyst_confirmed", "notes": "Audited finding"},
        headers={"X-Tenant-ID": tenant_id}
    )
    assert res.status_code == 200

    # Cryptographically verify the audit chain for this tenant
    chain_ver = verify_chain(tenant_id)
    assert chain_ver["ok"] is True
    assert chain_ver["entries_verified"] >= 1
