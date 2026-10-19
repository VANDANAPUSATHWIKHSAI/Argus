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
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from fir.schemas import FIRFinding, ReviewStatus
from report_generation.generator import ReportGenerator

from api.routes.auth import get_current_user

client = TestClient(app)

app.dependency_overrides[get_current_user] = lambda: {"username": "test_user"}

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

        test_case_id = "11111111-1111-1111-1111-111111111111"
        response = client.post(
            "/evidence/upload",
            files={"file": ("narrative.txt", file_obj, "text/plain")},
            data={"case_id": test_case_id, "uploaded_by": "unit_test_analyst"},
            headers={"X-Tenant-ID": "tenant-api"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("SUCCESS", "PARTIAL_SUCCESS", "PROCESSING")
        assert data["case_id"] == test_case_id
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

    def test_get_report_pdf_graceful_handling(self):
        """Test GET /reports/{case_id}/report?format=pdf handles missing native PDF engines gracefully."""
        case_id = "CASE-PDF-TEST"
        tenant_id = "tenant-pdf"

        finding = FIRFinding(
            finding_id="fnd-pdf-1",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="PDF test finding",
            sanitized_fact="PDF test finding",
            confidence=0.9,
            severity="medium",
            layer="endpoint",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["CORR-PDF"]
        )
        self.fir_repo.insert(finding)

        response = client.get(
            f"/reports/{case_id}/report?format=pdf&allow_unreviewed=true",
            headers={"X-Tenant-ID": tenant_id}
        )
        # Must return either 200 (if PDF library present & works) or 400 (if missing/unconfigured); NEVER 500
        assert response.status_code in (200, 400)
        if response.status_code == 400:
            assert "pdf" in response.json()["detail"].lower()

    def test_async_evidence_upload_and_status_polling(self):
        """Test POST /evidence/upload?async_mode=true returns PROCESSING and can be polled via GET /evidence/status/{evidence_id}."""
        import time
        content = b"2026-09-02 10:00:00 [INFO] Authentication successful for user analyst from 10.0.0.5\n"
        file_obj = io.BytesIO(content)
        test_case_id = "55555555-5555-5555-5555-555555555555"
        tenant_id = "tenant-async-test"

        response = client.post(
            "/evidence/upload?async_mode=true",
            files={"file": ("auth.log", file_obj, "text/plain")},
            data={"case_id": test_case_id, "uploaded_by": "async_analyst"},
            headers={"X-Tenant-ID": tenant_id}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "PROCESSING"
        evidence_id = data["evidence_id"]
        assert evidence_id

        # Poll status endpoint
        completed = False
        final_data = None
        for _ in range(30):
            status_res = client.get(
                f"/evidence/status/{evidence_id}",
                headers={"X-Tenant-ID": tenant_id}
            )
            assert status_res.status_code == 200
            final_data = status_res.json()
            if final_data["status"] in ("SUCCESS", "PARTIAL_SUCCESS", "FAILED"):
                completed = True
                break
            time.sleep(0.5)

        assert completed, f"Async ingestion did not complete in time, last status: {final_data}"
        assert final_data["status"] in ("SUCCESS", "PARTIAL_SUCCESS")
        assert final_data["evidence_id"] == evidence_id
        assert final_data["case_id"] == test_case_id

    def test_evidence_status_tenant_isolation(self):
        """Test GET /evidence/status/{evidence_id} enforces tenant isolation."""
        content = b"2026-09-02 10:00:00 [INFO] System boot\n"
        file_obj = io.BytesIO(content)
        test_case_id = "66666666-6666-6666-6666-666666666666"

        response = client.post(
            "/evidence/upload",
            files={"file": ("sys.log", file_obj, "text/plain")},
            data={"case_id": test_case_id, "uploaded_by": "analyst_a"},
            headers={"X-Tenant-ID": "tenant-owner"}
        )
        assert response.status_code == 200
        ev_id = response.json()["evidence_id"]

        # Attempt to access status with unauthorized tenant
        unauth_res = client.get(
            f"/evidence/status/{ev_id}",
            headers={"X-Tenant-ID": "tenant-unauthorized"}
        )
        assert unauth_res.status_code in (403, 404)

    def test_post_evidence_upload_empty_file_rejected(self):
        """Test POST /evidence/upload with an empty file returns HTTP 400."""
        empty_obj = io.BytesIO(b"")
        response = client.post(
            "/evidence/upload",
            files={"file": ("empty.log", empty_obj, "text/plain")},
            data={"case_id": "77777777-7777-7777-7777-777777777777"},
            headers={"X-Tenant-ID": "tenant-empty"}
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    def test_evidence_repository_fallback_retrieval(self):
        """Test that get_evidence retrieves stored evidence in local fallback mode."""
        from infrastructure.repository.evidence_store import get_evidence
        content = b"2026-09-02 11:00:00 [ALERT] Port scan detected\n"
        file_obj = io.BytesIO(content)
        test_case_id = "88888888-8888-8888-8888-888888888888"
        tenant_id = "tenant-fallback-retrieval"

        response = client.post(
            "/evidence/upload",
            files={"file": ("scan.log", file_obj, "text/plain")},
            data={"case_id": test_case_id, "uploaded_by": "analyst_fallback"},
            headers={"X-Tenant-ID": tenant_id}
        )
        assert response.status_code == 200
        ev_id = response.json()["evidence_id"]

        ev_record = get_evidence(tenant_id=tenant_id, evidence_id=ev_id)
        assert ev_record is not None
        assert ev_record.evidence_id == ev_id
        assert ev_record.filename == "scan.log"

    def test_api_upload_to_agent7_orchestration_flow(self):
        """
        Integration test verifying that the real evidence upload API invokes the
        full multi-agent pipeline through Agent 7 synthesis, independent verification,
        and confidence gate routing.
        """
        case_id = "CASE-INTEG-API-7777"
        tenant_id = "tenant-api-integ"
        content = b"2026-10-15 10:00:00 [ALERT] Lateral movement detected WIN-DC-01\n"
        file_obj = io.BytesIO(content)

        mock_fir_finding = FIRFinding(
            finding_id="F-API-001",
            case_id=case_id,
            tenant_id=tenant_id,
            fact="Compromised credentials used for SMB lateral movement to WIN-DC-01",
            confidence=0.96,
            severity="critical",
            layer="network",
            timestamp=datetime.now(timezone.utc),
            evidence_reference=["EVID-API-001"],
            source_artifact_id="EVID-API-001"
        )

        mock_pipeline_res = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "evidence_id": "EVID-API-001",
            "execution_status": "SUCCESS",
            "stage_statuses": {
                "stage1_intake": "COMPLETED",
                "stage2_extractor": "COMPLETED",
                "stage3_fcr": "COMPLETED",
                "stage4_fir_ingestion": "COMPLETED",
                "agent1": "COMPLETED",
                "agent2": "COMPLETED",
                "agent3": "COMPLETED",
                "agent4": "COMPLETED",
                "agent5a": "COMPLETED",
                "agent5b": "COMPLETED",
                "agent6": "COMPLETED",
                "agent7": "COMPLETED",
            },
            "agent1": {"claims": [{"claim_id": "CLM-001", "summary": "Initial access"}]},
            "agent2": {"claims": [{"claim_id": "CLM-002", "summary": "Correlated timeline"}]},
            "agent3": {"attack_path": [{"stage": "Lateral Movement"}]},
            "agent4": {"execution_status": "SUCCESS", "claims": []},
            "agent5a": {"claim": "STIX intelligence correlated"},
            "agent5b": {"claim": "Historical campaign similarity matched"},
            "agent6": {"cvss_assessment": {"base_score": 9.1}},
            "agent7": {
                "synthesis": {
                    "claims": [{
                        "claim_id": "CLM-AG7-001",
                        "claim": "Attacker compromised domain controller via SMB lateral movement",
                        "evidence_ids": ["F-API-001"]
                    }]
                },
                "verification": [{
                    "claim_id": "CLM-AG7-001",
                    "verified": True,
                    "checks": {"existence": True, "support": True, "divergence": False}
                }],
                "confidence_gate": {
                    "route": "routine",
                    "requires_senior_review": False
                },
                "reports": {
                    "analyst_report": "# Comprehensive Forensic Incident Report",
                    "executive_summary": "# Executive Briefing"
                },
                "status": "COMPLETED",
                "execution_status": "SUCCESS",
                "review_level": "ROUTINE_ANALYST_REVIEW"
            },
            "agent_errors": {}
        }

        mock_parser = MagicMock()
        mock_artifact = MagicMock()
        mock_artifact.artifact_id = "ART-001"
        mock_parser.parse.return_value = [mock_artifact]
        mock_routing = MagicMock()
        mock_routing.status = "ROUTED"
        mock_routing.parser_instance = mock_parser

        with patch("api.routes.evidence._parser_router.determine_routing", return_value=mock_routing), \
             patch("api.routes.evidence._extractor.extract", return_value=[]), \
             patch("api.routes.evidence._fcr_engine.correlate", return_value=[MagicMock()]), \
             patch("api.routes.evidence.process_fcr_batch", return_value=[mock_fir_finding]), \
             patch("argus_pipeline.run_pipeline", return_value=mock_pipeline_res) as mock_pipe:

            response = client.post(
                "/evidence/upload",
                files={"file": ("synthetic_evtx.bin", file_obj, "application/octet-stream")},
                data={"case_id": case_id, "uploaded_by": "lead_forensic_analyst"},
                headers={"X-Tenant-ID": tenant_id}
            )

            assert response.status_code == 200
            data = response.json()

            # 1. Pipeline execution status must accurately reflect full Agent 7 success
            assert data["status"] == "SUCCESS"
            assert data["case_id"] == case_id
            assert data["tenant_id"] == tenant_id
            assert "finding_count" in data

            # 2. Stage statuses must expose all stages including Agent 7
            stages = data.get("stage_statuses", {})
            assert stages.get("intake") == "COMPLETED"
            assert stages.get("agent7") == "COMPLETED"
            assert stages.get("agent7_supervisor") == "COMPLETED"

            # 3. Agent results must contain full Agent 7 synthesis & verification
            agent_res = data.get("agent_results", {})
            assert agent_res is not None
            assert "agent7" in agent_res
            ag7 = agent_res["agent7"]
            assert "synthesis" in ag7
            assert "verification" in ag7
            assert ag7["status"] == "COMPLETED"
            assert ag7["verification"][0]["verified"] is True

            # 4. Status endpoint reflects the actual execution state
            ev_id = data["evidence_id"]
            status_res = client.get(
                f"/evidence/status/{ev_id}",
                headers={"X-Tenant-ID": tenant_id}
            )
            assert status_res.status_code == 200
            status_data = status_res.json()
            assert status_data["status"] == "SUCCESS"
            assert status_data["stage_statuses"]["agent7"] == "COMPLETED"

            # 5. Idempotency: Repeated upload returns existing job record without re-dispatching
            file_obj.seek(0)
            dup_res = client.post(
                "/evidence/upload",
                files={"file": ("synthetic_evtx.bin", file_obj, "application/octet-stream")},
                data={"case_id": case_id, "uploaded_by": "lead_forensic_analyst"},
                headers={"X-Tenant-ID": tenant_id}
            )
            assert dup_res.status_code == 200
            dup_data = dup_res.json()
            assert dup_data["evidence_id"] == ev_id
            assert dup_data["status"] == "SUCCESS"
