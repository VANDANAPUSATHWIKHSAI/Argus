"""
Unit Tests for Celery Task Queue Integration
===========================================
Tests Celery application initialization, broker detection, forensic task
execution, and the GET /evidence/task/{task_id} status endpoint.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.routes.auth import get_current_user
from tasks.celery_app import celery_app, is_celery_broker_available
from tasks.forensic_tasks import process_forensic_pipeline_task, run_pipeline_core


@pytest.fixture
def client():
    app.dependency_overrides[get_current_user] = lambda: {"username": "test_user"}
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_celery_app_configuration():
    """Verify Celery app is configured with standard settings."""
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert celery_app.conf.timezone == "UTC"
    assert celery_app.conf.task_acks_late is True


def test_is_celery_broker_available():
    """Verify broker ping returns boolean without unhandled exceptions."""
    is_up = is_celery_broker_available(timeout_sec=0.2)
    assert isinstance(is_up, bool)


def test_get_task_status_endpoint(client):
    """Test GET /evidence/task/{task_id} with mock AsyncResult."""
    mock_result = MagicMock()
    mock_result.status = "PROGRESS"
    mock_result.ready.return_value = False
    mock_result.info = {"stage": "parsing", "progress": 40}

    with patch("celery.result.AsyncResult", return_value=mock_result):
        # We need an auth token or mock user dependency
        response = client.get(
            "/evidence/task/test-task-uuid-1234",
            headers={"Authorization": "Bearer mock_token", "X-Tenant-ID": "default"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "test-task-uuid-1234"
        assert data["status"] == "PROGRESS"
        assert data["ready"] is False
        assert data["metadata"]["stage"] == "parsing"
