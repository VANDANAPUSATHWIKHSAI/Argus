"""
Focused Regression Test Suite for Targeted Integration Fixes
============================================================
1. Fix 1: FIRRepository PostgreSQL SQL syntax termination check.
2. Fix 2: Tenant ID propagation from upload_evidence to process_fcr_batch and FIRRepository.
3. Fix 3: ZIP upload pipeline executing Stage 2.5 Extractor, Stage 3 FCR, and Stage 4 Analysis exactly ONCE per ZIP upload, with Zip Slip path traversal prevention.
"""

import io
import os
import zipfile
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from fir.repository import FIRRepository
from fir.schemas import FIRFinding
from forensic_analysis.orchestrator import process_fcr_batch
from forensic_analysis.schemas import Finding
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact

client = TestClient(app)


def test_fix1_fir_repository_sql_syntax():
    """Verify that FIRRepository DDL SQL has properly terminated CREATE TABLE statement."""
    repo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "fir", "repository.py")
    with open(repo_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify CREATE TABLE ends with ');' before ALTER TABLE statements
    sql_start = content.find("CREATE TABLE IF NOT EXISTS fir_findings")
    assert sql_start != -1, "CREATE TABLE statement not found in fir/repository.py"
    
    sql_block = content[sql_start:sql_start + 1500]
    alter_pos = sql_block.find("ALTER TABLE fir_findings")
    assert alter_pos != -1, "ALTER TABLE statement not found after CREATE TABLE"

    before_alter = sql_block[:alter_pos].strip()
    assert before_alter.endswith(");"), f"CREATE TABLE statement is not closed with ');' before ALTER TABLE. Found: ...{before_alter[-30:]!r}"


def test_fix2_tenant_id_propagation_direct_orchestrator():
    """Verify process_fcr_batch propagates tenant_id to Finding objects and FIRRepository persistence."""
    fir_repo = FIRRepository()
    fir_repo.clear()

    case_id = "CASE-TENANT-PROPAGATE-01"
    custom_tenant = "tenant-enterprise-99"

    fcr = CorrelationRecord(
        correlation_id="CORR-00001",
        case_id=case_id,
        artifact_ids=["art-network-001"],
        relationship_type=["single_artifact"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.9
    )
    
    art = Artifact(
        artifact_id="art-network-001",
        case_id=case_id,
        evidence_id="ev-net-001",
        source_tool="zeek",
        artifact_type="network.dns",
        raw_data={"query": "malicious.c2.org"}
    )

    mock_engine = MagicMock()
    mock_engine.analyze.return_value = [
        Finding(
            case_id=case_id,
            fact="C2 traffic detected to malicious.c2.org",
            confidence=0.95,
            severity="high",
            evidence_reference="CORR-00001",
            source_artifact_id="art-network-001",
            layer="network"
        )
    ]

    with patch("forensic_analysis.orchestrator.ENGINE_REGISTRY", {"network": mock_engine}):
        findings = process_fcr_batch(
            case_id=case_id,
            fcr_objects=[fcr],
            artifacts_by_id={"art-network-001": art},
            fir_repo=fir_repo,
            tenant_id=custom_tenant
        )

    assert len(findings) == 1, "Expected exactly one finding generated from engine"
    assert findings[0].tenant_id == custom_tenant, f"Finding tenant_id expected {custom_tenant}, got {findings[0].tenant_id}"

    # Verify FIRRepository insertion retained custom_tenant
    stored_findings = fir_repo.get_by_case(tenant_id=custom_tenant, case_id=case_id)
    assert len(stored_findings) >= 1
    for stored_f in stored_findings:
        assert stored_f.tenant_id == custom_tenant

    # Verify tenant isolation: another tenant cannot query these findings
    other_tenant_findings = fir_repo.get_by_case(tenant_id="tenant-unauthorized", case_id=case_id)
    assert len(other_tenant_findings) == 0, "Tenant isolation violation: unauthorized tenant retrieved findings"


def test_fix2_tenant_id_propagation_in_evidence_upload():
    """Verify X-Tenant-ID header is propagated from upload_evidence route to process_fcr_batch."""
    fir_repo = FIRRepository()
    fir_repo.clear()

    custom_tenant = "tenant-api-custom-77"
    test_case_id = "22222222-2222-2222-2222-222222222222"

    dummy_art = MagicMock()
    dummy_art.artifact_id = "art-dummy-1"
    dummy_art.case_id = test_case_id

    dummy_fcr = CorrelationRecord(
        correlation_id="CORR-00002",
        case_id=test_case_id,
        artifact_ids=["art-dummy-1"],
        relationship_type=["single_artifact"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.85
    )

    with patch("api.routes.evidence._parser_router.determine_routing") as mock_router, \
         patch("api.routes.evidence._extractor.extract") as mock_extract, \
         patch("api.routes.evidence._fcr_engine.correlate") as mock_correlate, \
         patch("api.routes.evidence.process_fcr_batch", wraps=process_fcr_batch) as mock_stage4:

        mock_router_res = MagicMock()
        mock_router_res.status = "ROUTED"
        mock_parser = MagicMock()
        mock_parser.parse.return_value = [dummy_art]
        mock_router_res.parser_instance = mock_parser
        mock_router.return_value = mock_router_res

        mock_extract.return_value = []
        mock_correlate.return_value = [dummy_fcr]

        content = b"LOG CONTENT"
        response = client.post(
            "/evidence/upload",
            files={"file": ("log.txt", io.BytesIO(content), "text/plain")},
            data={"case_id": test_case_id, "uploaded_by": "tenant_test_user"},
            headers={"X-Tenant-ID": custom_tenant}
        )

        assert response.status_code == 200
        assert mock_stage4.call_count == 1
        # Check that process_fcr_batch was called with tenant_id=custom_tenant
        _, kwargs = mock_stage4.call_args
        assert kwargs.get("tenant_id") == custom_tenant, f"Expected process_fcr_batch tenant_id={custom_tenant}, got {kwargs.get('tenant_id')}"


def test_fix3_zip_single_pass_pipeline():
    """Verify ZIP upload executes extractor, FCR engine, and Stage 4 analysis exactly ONCE per ZIP upload."""
    fir_repo = FIRRepository()
    fir_repo.clear()

    # Create a test zip file containing one evidence log file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence_log.txt", "2026-09-01 12:00:00 [INFO] User login success from 192.168.1.10\n")
    zip_buffer.seek(0)

    test_case_id = "33333333-3333-3333-3333-333333333333"

    dummy_fcr = CorrelationRecord(
        correlation_id="CORR-00003",
        case_id=test_case_id,
        artifact_ids=["art-zip-1"],
        relationship_type=["single_artifact"],
        source_count=1,
        distinct_artifact_types=1,
        confidence=0.8
    )

    with patch("api.routes.evidence._extractor.extract") as mock_extract, \
         patch("api.routes.evidence._fcr_engine.correlate") as mock_correlate, \
         patch("api.routes.evidence.process_fcr_batch") as mock_stage4:

        mock_extract.return_value = []
        mock_correlate.return_value = [dummy_fcr]
        mock_stage4.return_value = []

        response = client.post(
            "/evidence/upload",
            files={"file": ("archive_test.zip", zip_buffer, "application/zip")},
            data={"case_id": test_case_id, "uploaded_by": "zip_test_analyst"},
            headers={"X-Tenant-ID": "tenant-zip-pass"}
        )

        assert response.status_code == 200
        assert mock_extract.call_count == 1, f"Extractor must be called exactly 1 time, called {mock_extract.call_count} times"
        assert mock_correlate.call_count == 1, f"FCR correlate must be called exactly 1 time, called {mock_correlate.call_count} times"
        assert mock_stage4.call_count == 1, f"Stage 4 process_fcr_batch must be called exactly 1 time, called {mock_stage4.call_count} times"


def test_fix3_zip_path_traversal_prevention(tmp_path):
    """Verify that Zip Slip path traversal attempts in ZIP archives are safely prevented."""
    fir_repo = FIRRepository()
    fir_repo.clear()

    # Create a zip containing a path traversal file entry "../../evil.txt"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../evil_traversal.txt", "MALICIOUS CONTENT")
        zf.writestr("valid_log.txt", "2026-09-01 12:00:00 [WARN] Firewall rule modified\n")
    zip_buffer.seek(0)

    test_case_id = "44444444-4444-4444-4444-444444444444"
    response = client.post(
        "/evidence/upload",
        files={"file": ("malicious_slip.zip", zip_buffer, "application/zip")},
        data={"case_id": test_case_id},
        headers={"X-Tenant-ID": "tenant-zip-slip"}
    )

    assert response.status_code == 200
    # Ensure that no file named evil_traversal.txt was created outside temp directory
    outside_file = tmp_path.parent / "evil_traversal.txt"
    assert not outside_file.exists(), "Zip Slip vulnerability! File escaped extraction root."
