"""
Unit Tests for ARGUS REST API Routes and Report Generation Engine
===================================================================
Tests POST /evidence/upload, GET /cases/{case_id}, GET /reports/{case_id}/report,
ReportGenerator HTML/JSON formatting, HTML escaping safety, tenant isolation,
review gating, and 404/400 error handling.
"""

from __future__ import annotations

import io
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from fir.schemas import FIRFinding, ReviewStatus
from report_generation.generator import ReportGenerator

client = TestClient(app)


class TestApiAndReportGeneration:

    def setup_method(self):
        """Set up clean repository state before each test."""
        self.fir_repo = FIRRepository()
        self.fir_repo.findings.clear()
        self.fir_repo._fingerprints.clear()
        self.service = AnalystFindingService(fir_repo=self.fir_repo)

    def test_post_evidence_upload(self):
        """Test POST /evidence/upload with a text log evidence file."""
        content = b"2026-08-31 12:00:00 [ERROR] User admin failed login from 192.168.1.50\n"
        file_obj = io.BytesIO(content)

        response = client.post(
            "/evidence/upload",
            files={"file": ("narrative.txt", file_obj, "text/plain")},
            data={"case_id": "CASE-API-TEST", "uploaded_by": "unit_test_analyst"},
            headers={"X-Tenant-ID": "tenant-api"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("SUCCESS", "PARTIAL_SUCCESS")
        assert data["case_id"] == "CASE-API-TEST"
        assert data["tenant_id"] == "tenant-api"
        assert data["filename"] == "narrative.txt"
        assert len(data["sha256_hash"]) == 64
        assert "parsed_artifact_count" in data

    def test_get_case_summary(self):
        """Test GET /cases/{case_id} returning severity & review status metrics."""
        case_id = "CASE-SUMMARY-001"
        tenant_id = "tenant-summary"

        finding = FIRFinding(
            finding_id="fnd-001",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Unauthorized login from 198.51.100.1",
            sanitized_fact="Unauthorized login from [IP_REDACTED]",
            confidence=0.95,
            severity="high",
            mitre_mapping="T1078",
            layer="endpoint",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["CORR-001"],
            review_status=ReviewStatus.PENDING_REVIEW
        )
        self.fir_repo.insert(finding)

        response = client.get(f"/cases/{case_id}", headers={"X-Tenant-ID": tenant_id})
        assert response.status_code == 200
        data = response.json()
        assert data["case_id"] == case_id
        assert data["tenant_id"] == tenant_id
        assert data["total_findings"] == 1
        assert data["severity_breakdown"]["high"] == 1
        assert data["review_status_breakdown"]["pending_review"] == 1

    def test_get_case_not_found(self):
        """Test GET /cases/{case_id} returning 404 for non-existent case."""
        response = client.get("/cases/NON-EXISTENT-CASE", headers={"X-Tenant-ID": "default"})
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_tenant_isolation_enforcement(self):
        """Test that a tenant cannot access another tenant's case summary or report."""
        case_id = "CASE-ISOLATED-01"
        self.fir_repo.insert(
            FIRFinding(
                finding_id="fnd-iso-1",
                case_id=case_id,
                tenant_id="tenant-alpha",
                fact="Secret finding",
                confidence=0.9,
                severity="critical",
                layer="endpoint",
                timestamp=datetime.now(timezone.utc),
                evidence_reference=["CORR-ISO-1"]
            )
        )

        # Request as tenant-beta
        res_case = client.get(f"/cases/{case_id}", headers={"X-Tenant-ID": "tenant-beta"})
        assert res_case.status_code == 404

        res_report = client.get(f"/reports/{case_id}/report", headers={"X-Tenant-ID": "tenant-beta"})
        assert res_report.status_code == 404

    def test_get_report_html_and_json(self):
        """Test GET /reports/{case_id}/report in HTML and JSON format."""
        case_id = "CASE-REPORT-001"
        tenant_id = "tenant-report"

        finding = FIRFinding(
            finding_id="fnd-rep-1",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="PowerShell execution detected",
            sanitized_fact="PowerShell execution detected",
            confidence=0.9,
            severity="high",
            mitre_mapping="T1059.001",
            layer="endpoint",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["CORR-REP-1"],
            review_status=ReviewStatus.ANALYST_CONFIRMED
        )
        self.fir_repo.insert(finding)

        # Test JSON format
        res_json = client.get(
            f"/reports/{case_id}/report?format=json&allow_unreviewed=true",
            headers={"X-Tenant-ID": tenant_id}
        )
        assert res_json.status_code == 200
        assert res_json.headers["content-type"].startswith("application/json")
        data = res_json.json()
        assert data["case_id"] == case_id
        assert len(data["findings"]) == 1

        # Test HTML format
        res_html = client.get(
            f"/reports/{case_id}/report?format=html&allow_unreviewed=true",
            headers={"X-Tenant-ID": tenant_id}
        )
        assert res_html.status_code == 200
        assert "text/html" in res_html.headers["content-type"]
        html_text = res_html.text
        assert "<html" in html_text
        assert case_id in html_text
        assert "PowerShell execution detected" in html_text

    def test_get_report_unsupported_format(self):
        """Test requesting an unsupported report format returns 400 Bad Request."""
        case_id = "CASE-REPORT-002"
        self.fir_repo.insert(
            FIRFinding(
                finding_id="fnd-1",
                case_id=case_id,
                tenant_id="default",
                fact="Fact",
                confidence=0.9,
                severity="low",
                layer="endpoint",
                timestamp=datetime.now(timezone.utc),
                evidence_reference=["CORR-1"]
            )
        )
        res = client.get(f"/reports/{case_id}/report?format=xyz_invalid", headers={"X-Tenant-ID": "default"})
        assert res.status_code == 400
        assert "unsupported report format" in res.json()["detail"].lower()

    def test_report_generator_html_escaping_safety(self):
        """Test that ReportGenerator escapes malicious HTML/XSS injection attempts in findings."""
        generator = ReportGenerator()
        malicious_payload = {
            "case_id": "<script>alert('xss_case')</script>",
            "tenant_id": "<b style='color:red;'>tenant</b>",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": [
                {
                    "finding_id": "fnd-xss",
                    "severity": "high",
                    "fact": "<img src=x onerror=alert('xss_fact')>",
                    "sanitized_fact": "<script>alert('xss_sanitized')</script>",
                    "confidence": 0.9,
                    "mitre_mapping": "<svg/onload=alert(1)>",
                    "layer": "endpoint",
                    "review_status": "CONFIRMED"
                }
            ],
            "timeline": []
        }

        rendered_html = generator.generate(malicious_payload, format="html")
        assert "<script>alert('xss_case')</script>" not in rendered_html
        assert "&lt;script&gt;alert(&#39;xss_case&#39;)&lt;/script&gt;" in rendered_html or "&lt;script&gt;alert('xss_case')&lt;/script&gt;" in rendered_html
        assert "<img src=x onerror=alert('xss_fact')>" not in rendered_html

    def test_review_status_export_gating(self):
        """Test that unreviewed findings are omitted from export unless allow_unreviewed=True."""
        case_id = "CASE-GATING-01"
        tenant_id = "tenant-gating"

        f_pending = FIRFinding(
            finding_id="fnd-pending",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Unreviewed finding",
            confidence=0.9,
            severity="medium",
            layer="endpoint",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["CORR-P"],
            review_status=ReviewStatus.PENDING_REVIEW
        )
        f_confirmed = FIRFinding(
            finding_id="fnd-confirmed",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Confirmed finding",
            confidence=0.9,
            severity="high",
            layer="endpoint",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["CORR-C"],
            review_status=ReviewStatus.ANALYST_CONFIRMED
        )
        self.fir_repo.insert(f_pending)
        self.fir_repo.insert(f_confirmed)

        # allow_unreviewed = False -> Should only return f_confirmed
        exported_default = self.service.export_report(case_id, tenant_id=tenant_id, allow_unreviewed=False)
        assert len(exported_default) == 1
        assert exported_default[0]["finding_id"] == "fnd-confirmed"

        # allow_unreviewed = True -> Should return both
        exported_all = self.service.export_report(case_id, tenant_id=tenant_id, allow_unreviewed=True)
        assert len(exported_all) == 2
