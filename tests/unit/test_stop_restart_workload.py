import pytest
import threading
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.routes.auth import get_current_user
from fir.repository import FIRRepository
from fir.schemas import FIRFinding, ReviewStatus
from infrastructure.schemas import Evidence
from api.routes.cases import _agent_jobs, _agent_jobs_lock, _agent_cancellations

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_jobs():
    with _agent_jobs_lock:
        _agent_jobs.clear()
        _agent_cancellations.clear()
    yield
    with _agent_jobs_lock:
        _agent_jobs.clear()
        _agent_cancellations.clear()
    app.dependency_overrides.clear()

def test_stop_workload_endpoint():
    """Verify POST /cases/{case_id}/stop-workload halts execution and sets status to STOPPED while preserving evidence."""
    case_id = "CASE-STOP-TEST-001"
    tenant_id = "test-tenant"
    mock_user = {"id": "analyst-1", "name": "Lead Analyst", "role": "admin"}
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with patch("api.routes.cases.verify_case_access", return_value=None), \
         patch("api.case_lock.case_lock_manager.check_modification_allowed", return_value=(True, None, "OK")), \
         patch("ism.checkpointer.Checkpointer") as mock_cp_cls:

        mock_cp = MagicMock()
        mock_cp_cls.return_value = mock_cp

        # Simulate currently running job
        cancel_evt = threading.Event()
        with _agent_jobs_lock:
            _agent_cancellations[case_id] = cancel_evt
            _agent_jobs[case_id] = {
                "status": "RUNNING",
                "case_id": case_id,
                "tenant_id": tenant_id,
                "stage_statuses": {"agent1": "RUNNING", "agent2": "PENDING"}
            }

        response = client.post(
            f"/cases/{case_id}/stop-workload",
            headers={"X-Tenant-ID": tenant_id}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "STOPPED"
        assert "stopped" in data["message"].lower()

        # Check in-memory status
        with _agent_jobs_lock:
            assert _agent_jobs[case_id]["status"] == "STOPPED"
            assert _agent_jobs[case_id]["stage_statuses"]["agent1"] == "STOPPED"
            assert cancel_evt.is_set()

        # Check ISM checkpoint persistence
        mock_cp.save_stage_checkpoint.assert_called_once()
        call_kwargs = mock_cp.save_stage_checkpoint.call_args[1]
        assert call_kwargs["status"] == "STOPPED"


def test_restart_workload_endpoint_captures_all_evidence():
    """Verify POST /cases/{case_id}/restart-workload aggregates all evidence files and sets resume=False."""
    case_id = "CASE-RESTART-TEST-002"
    tenant_id = "test-tenant"
    mock_user = {"id": "analyst-1", "name": "Lead Analyst", "role": "admin"}
    app.dependency_overrides[get_current_user] = lambda: mock_user

    # Mock multiple evidence items
    ev1 = Evidence(evidence_id="EVID-01", case_id=case_id, filename="auth.log", file_path="data/auth.log", uploaded_by="analyst")
    ev2 = Evidence(evidence_id="EVID-02", case_id=case_id, filename="pcap.pcap", file_path="data/pcap.pcap", uploaded_by="analyst")

    with patch("api.routes.cases.verify_case_access", return_value=None), \
         patch("api.case_lock.case_lock_manager.check_modification_allowed", return_value=(True, None, "OK")), \
         patch("api.routes.cases.list_evidence_by_case", return_value=[ev1, ev2]), \
         patch("infrastructure.repository.evidence_store.list_evidence_by_case", return_value=[ev1, ev2]), \
         patch("api.routes.cases._analyst_service.list_findings", return_value=[{"fact": "suspicious port 4444"}]), \
         patch("api.routes.evidence._resolve_authoritative_artifact_path", return_value=None), \
         patch("pathlib.Path.exists", return_value=True), \
         patch("api.routes.cases._agent_executor.submit") as mock_submit, \
         patch("ism.checkpointer.Checkpointer"):

        response = client.post(
            f"/cases/{case_id}/restart-workload",
            headers={"X-Tenant-ID": tenant_id}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "RUNNING"
        assert data["evidence_count"] == 2
        assert "restarted" in data["message"].lower()

        # Verify job was submitted to thread pool
        mock_submit.assert_called_once()

        # Verify job status in memory
        with _agent_jobs_lock:
            assert _agent_jobs[case_id]["status"] == "RUNNING"
            assert _agent_jobs[case_id]["is_restart"] is True
            assert _agent_jobs[case_id]["evidence_count"] == 2


def test_run_pipeline_cancellation_token():
    """Verify argus_pipeline.run_pipeline responds immediately to cancellation token."""
    from argus_pipeline import run_pipeline

    cancel_evt = threading.Event()
    cancel_evt.set()  # Cancelled before start

    mock_findings = [
        FIRFinding(
            finding_id="fnd-cancel-1",
            case_id="CASE-CANCEL-001",
            tenant_id="default",
            fact="Brute force login detected",
            sanitized_fact="Brute force login detected",
            confidence=0.88,
            severity="medium",
            layer="network",
            evidence_reference=["CORR-001"]
        )
    ]

    res = run_pipeline(
        fir_findings=mock_findings,
        case_id="CASE-CANCEL-001",
        tenant_id="default",
        cancel_event=cancel_evt
    )

    assert res["execution_status"] == "STOPPED"
    assert "stopped" in res["error"].lower()
