"""
Comprehensive Unit Test Suite for ISM Full Implementation
=========================================================
Tests:
  1. FailureClassifier: Granular categorization, transient vs fatal detection.
  2. RetryHandler: Transient error retries, backoff computation, fatal error fast-fail, exhaustion.
  3. InvestigationStateMachine: DAG dependency validation, topological execution,
     checkpointing integration, stage resume, failure isolation, and stop_on_error behavior.
"""

import pytest
import time
from unittest.mock import MagicMock

from ism.failure_classifier import FailureClassifier, FailureType, FailureClassificationResult
from ism.retry_handler import RetryHandler, RetryExhaustedError
from ism.state_machine import (
    InvestigationStateMachine,
    CaseState,
    StageState,
    STAGE_DEPENDENCIES,
)
from ism.checkpointer import Checkpointer


# ── 1. FailureClassifier Tests ──────────────────────────────────────────────

def test_failure_classifier_security_violation():
    classifier = FailureClassifier()
    err = RuntimeError("Tenant access denied: cross-tenant boundary breach detected.")
    res = classifier.classify_detailed(err)
    assert res.failure_type == FailureType.SECURITY_VIOLATION
    assert res.is_retryable is False
    assert classifier.classify(err) == "security_violation"


def test_failure_classifier_timeout():
    classifier = FailureClassifier()
    err = TimeoutError("The connection timed out while contacting Ollama.")
    res = classifier.classify_detailed(err)
    assert res.failure_type == FailureType.TIMEOUT
    assert res.is_retryable is True
    assert res.recommended_backoff_seconds > 0


def test_failure_classifier_infra_transient_vs_fatal():
    classifier = FailureClassifier()
    
    # Transient connection refused
    transient_err = ConnectionError("Connection refused by PostgreSQL on port 5433")
    res1 = classifier.classify_detailed(transient_err)
    assert res1.failure_type == FailureType.INFRA_CRASH
    assert res1.is_retryable is True

    # Fatal auth failure
    fatal_err = PermissionError("Password authentication failed for user argus_user")
    res2 = classifier.classify_detailed(fatal_err)
    assert res2.is_retryable is False


def test_failure_classifier_parser_error():
    classifier = FailureClassifier()
    err = ValueError("EvtxParser failed: corrupt chunk magic bytes at offset 0x1000")
    res = classifier.classify_detailed(err)
    assert res.failure_type == FailureType.PARSER_ERROR
    assert res.is_retryable is False


def test_failure_classifier_ai_agent_failure():
    classifier = FailureClassifier()
    transient_llm = RuntimeError("Ollama service unavailable: too many requests")
    res = classifier.classify_detailed(transient_llm)
    assert res.failure_type == FailureType.AI_AGENT_FAILURE
    assert res.is_retryable is True


# ── 2. RetryHandler Tests ───────────────────────────────────────────────────

def test_retry_handler_succeeds_without_retries():
    handler = RetryHandler(max_retries=3)
    call_count = 0

    def successful_op():
        nonlocal call_count
        call_count += 1
        return "SUCCESS"

    result = handler.execute(successful_op)
    assert result == "SUCCESS"
    assert call_count == 1


def test_retry_handler_retries_transient_and_recovers():
    sleep_calls = []
    handler = RetryHandler(max_retries=3, sleep_fn=lambda s: sleep_calls.append(s))
    call_count = 0

    def flaky_op():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise TimeoutError("Temporary timeout connecting to service")
        return "RECOVERED"

    result = handler.execute(flaky_op)
    assert result == "RECOVERED"
    assert call_count == 3
    assert len(sleep_calls) == 2  # Slept twice before 3rd attempt succeeded


def test_retry_handler_aborts_non_retryable_immediately():
    sleep_calls = []
    handler = RetryHandler(max_retries=3, sleep_fn=lambda s: sleep_calls.append(s))
    call_count = 0

    def fatal_op():
        nonlocal call_count
        call_count += 1
        raise ValueError("Unsafe path traversal detected in evidence file path")

    with pytest.raises(ValueError):
        handler.execute(fatal_op)

    assert call_count == 1  # Aborted immediately on attempt 1 without retry
    assert len(sleep_calls) == 0


def test_retry_handler_exhaustion():
    sleep_calls = []
    handler = RetryHandler(max_retries=2, sleep_fn=lambda s: sleep_calls.append(s))
    call_count = 0

    def constantly_failing():
        nonlocal call_count
        call_count += 1
        raise ConnectionError("Server connection reset by peer")

    with pytest.raises(RetryExhaustedError) as exc_info:
        handler.execute(constantly_failing)

    assert call_count == 3  # Attempt 1 + 2 retries
    assert exc_info.value.attempts == 2


def test_retry_handler_compute_backoff():
    handler = RetryHandler(backoff_factor=2.0, max_backoff=10.0, jitter=False)
    assert handler.compute_backoff(1, base_seconds=1.0) == 1.0
    assert handler.compute_backoff(2, base_seconds=1.0) == 2.0
    assert handler.compute_backoff(3, base_seconds=1.0) == 4.0
    assert handler.compute_backoff(10, base_seconds=1.0) == 10.0  # Capped at max_backoff


# ── 3. InvestigationStateMachine Tests ──────────────────────────────────────

def test_state_machine_dag_prerequisites():
    sm = InvestigationStateMachine(case_id="CASE-TEST-DAG-01", tenant_id="tenant-test")
    
    # Root stage has no prerequisites
    can_intake, _ = sm.can_run_stage("intake")
    assert can_intake is True

    # agent3 requires agent2, which is still PENDING
    can_a3, reason_a3 = sm.can_run_stage("agent3")
    assert can_a3 is False
    assert "agent2" in reason_a3

    # Mark agent2 as COMPLETE
    sm.stage_states["agent2"] = StageState.COMPLETE
    can_a3_now, _ = sm.can_run_stage("agent3")
    assert can_a3_now is True


def test_state_machine_pipeline_execution_and_checkpointing():
    # In-memory checkpointer for pure unit isolation
    mock_cp = MagicMock(spec=Checkpointer)
    mock_cp.get_stage_checkpoint.return_value = None

    sm = InvestigationStateMachine(
        case_id="CASE-TEST-EXEC-01",
        tenant_id="tenant-alpha",
        checkpointer=mock_cp,
        retry_handler=RetryHandler(max_retries=0)
    )

    # Register handlers for pipeline stages
    sm.register_handler("intake", lambda ctx: {"evidence_count": 2})
    sm.register_handler("preprocessing", lambda ctx: {"artifact_count": 10})
    sm.register_handler("fcr", lambda ctx: {"fcr_count": 5})
    sm.register_handler("fir_ingestion", lambda ctx: {"finding_count": 8})
    sm.register_handler("agent1", lambda ctx: {"triage": "READY"})
    sm.register_handler("agent2", lambda ctx: {"communities": 2})
    sm.register_handler("agent3", lambda ctx: {"attack_steps": 3})
    sm.register_handler("agent4", lambda ctx: {"malware_claims": 1})
    sm.register_handler("agent5a", lambda ctx: {"threat_intel": "MATCHED"})
    sm.register_handler("agent5b", lambda ctx: {"similar_cases": 1})
    sm.register_handler("agent6", lambda ctx: {"cvss": 7.5})
    sm.register_handler("agent7", lambda ctx: {"synthesis": "VERIFIED"})
    sm.register_handler("report_generation", lambda ctx: {"report_pdf": "ready"})

    summary = sm.run_pipeline(initial_context={"initial_evidence": "test.evtx"})

    assert summary["case_state"] == "complete"
    assert summary["completed_stage_count"] == 13
    assert summary["failed_stage_count"] == 0
    assert mock_cp.save_stage_checkpoint.call_count == 13


def test_state_machine_resume_from_checkpoint():
    mock_cp = MagicMock(spec=Checkpointer)
    # Simulate agent1 and agent2 already checkpointed
    def fake_get_cp(case_id, stage, tenant_id, **kwargs):
        if stage in ("intake", "preprocessing", "fcr", "fir_ingestion", "agent1", "agent2"):
            return {"status": "COMPLETED", "checkpoint": {f"{stage}_resumed": True}}
        return None
    mock_cp.get_stage_checkpoint.side_effect = fake_get_cp

    sm = InvestigationStateMachine(
        case_id="CASE-RESUME-01",
        tenant_id="tenant-alpha",
        checkpointer=mock_cp
    )

    agent3_executed = False
    def a3_handler(ctx):
        nonlocal agent3_executed
        agent3_executed = True
        return {"a3": "done"}

    sm.register_handler("intake", lambda ctx: {})
    sm.register_handler("preprocessing", lambda ctx: {})
    sm.register_handler("fcr", lambda ctx: {})
    sm.register_handler("fir_ingestion", lambda ctx: {})
    sm.register_handler("agent1", lambda ctx: {})
    sm.register_handler("agent2", lambda ctx: {})
    sm.register_handler("agent3", a3_handler)

    sm.run_pipeline(initial_context={})

    # Resumed stages should be marked RESUMED
    assert sm.stage_states["agent1"] == StageState.RESUMED
    assert sm.stage_states["agent2"] == StageState.RESUMED
    # agent3 should execute fresh
    assert sm.stage_states["agent3"] == StageState.COMPLETE
    assert agent3_executed is True


def test_state_machine_failure_isolation():
    mock_cp = MagicMock(spec=Checkpointer)
    mock_cp.get_stage_checkpoint.return_value = None

    sm = InvestigationStateMachine(
        case_id="CASE-ISOLATION-01",
        tenant_id="tenant-alpha",
        checkpointer=mock_cp,
        stop_on_error=False,
        retry_handler=RetryHandler(max_retries=0)
    )

    sm.register_handler("intake", lambda ctx: {})
    sm.register_handler("preprocessing", lambda ctx: {})
    sm.register_handler("fcr", lambda ctx: {})
    sm.register_handler("fir_ingestion", lambda ctx: {})
    sm.register_handler("agent1", lambda ctx: {})
    sm.register_handler("agent2", lambda ctx: {})
    # agent4 succeeds, agent5a fails (e.g. TAXII feed timeout)
    sm.register_handler("agent4", lambda ctx: {"behaviors": 4})
    def failing_feed(ctx):
        raise TimeoutError("External TAXII threat intel feed unreachable")
    sm.register_handler("agent5a", failing_feed)
    # agent5b depends on agent4 and should still succeed
    sm.register_handler("agent5b", lambda ctx: {"cluster": "A"})

    summary = sm.run_pipeline(initial_context={})

    assert sm.stage_states["agent5a"] == StageState.FAILED
    assert "timeout" in sm.stage_errors["agent5a"].lower()
    # Independent branch agent4 and agent5b succeeded despite agent5a failure
    assert sm.stage_states["agent4"] == StageState.COMPLETE
    assert sm.stage_states["agent5b"] == StageState.COMPLETE
    assert summary["failed_stage_count"] == 1
    assert summary["completed_stage_count"] >= 7


def test_state_machine_stop_on_error():
    mock_cp = MagicMock(spec=Checkpointer)
    mock_cp.get_stage_checkpoint.return_value = None

    sm = InvestigationStateMachine(
        case_id="CASE-STOP-ON-ERROR",
        tenant_id="tenant-alpha",
        checkpointer=mock_cp,
        stop_on_error=True,
        retry_handler=RetryHandler(max_retries=0)
    )

    sm.register_handler("intake", lambda ctx: {})
    def fatal_prep(ctx):
        raise ValueError("Fatal corrupted disk image: cannot parse header")
    sm.register_handler("preprocessing", fatal_prep)

    with pytest.raises(ValueError):
        sm.run_pipeline(initial_context={})

    assert sm.case_state == CaseState.FAILED
    assert sm.stage_states["preprocessing"] == StageState.FAILED


def test_retry_handler_jitter_bounds():
    handler = RetryHandler(backoff_factor=2.0, max_backoff=10.0, jitter=True)
    for attempt in range(1, 6):
        for _ in range(20):
            backoff = handler.compute_backoff(attempt, base_seconds=2.0)
            expected_max = min(10.0, 2.0 * (2.0 ** max(0, attempt - 1)))
            expected_min = 0.5 * expected_max
            assert expected_min <= backoff <= expected_max, (
                f"Backoff {backoff} outside jitter bounds [{expected_min}, {expected_max}]"
            )


def test_agent7_prerequisites_all_upstream_required():
    sm = InvestigationStateMachine(case_id="CASE-PREREQ-A7", tenant_id="tenant-alpha")
    
    # Prerequisite list for agent7 in STAGE_DEPENDENCIES:
    # ["agent1", "agent2", "agent3", "agent4", "agent5a", "agent5b", "agent6"]
    upstream_agents = ["agent1", "agent2", "agent3", "agent4", "agent5a", "agent5b", "agent6"]
    
    # Initially none are complete -> cannot run
    can_run, reason = sm.can_run_stage("agent7")
    assert can_run is False
    assert "agent1" in reason

    # Complete 6 out of 7 -> still cannot run
    for ag in upstream_agents[:-1]:
        sm.stage_states[ag] = StageState.COMPLETE
    
    can_run, reason = sm.can_run_stage("agent7")
    assert can_run is False
    assert upstream_agents[-1] in reason

    # Complete the final upstream agent -> now can run
    sm.stage_states[upstream_agents[-1]] = StageState.COMPLETE
    can_run, _ = sm.can_run_stage("agent7")
    assert can_run is True


def test_failed_and_skipped_stages_never_silently_succeed():
    mock_cp = MagicMock(spec=Checkpointer)
    mock_cp.get_stage_checkpoint.return_value = None

    sm = InvestigationStateMachine(
        case_id="CASE-EXPLICIT-STATUS",
        tenant_id="tenant-alpha",
        checkpointer=mock_cp,
        stop_on_error=False,
        retry_handler=RetryHandler(max_retries=0)
    )

    # intake succeeds, preprocessing fails
    sm.register_handler("intake", lambda ctx: {"intake": "ok"})
    def broken_prep(ctx):
        raise ValueError("Corrupt file format")
    sm.register_handler("preprocessing", broken_prep)
    # fcr depends on preprocessing; agent1 depends on fir_ingestion
    sm.register_handler("fcr", lambda ctx: {"fcr": "ok"})
    sm.register_handler("agent1", lambda ctx: {"a1": "ok"})

    summary = sm.run_pipeline(initial_context={})

    # preprocessing must be explicitly FAILED
    assert sm.stage_states["preprocessing"] == StageState.FAILED
    assert summary["stage_statuses"]["preprocessing"] == "FAILED"

    # fcr and agent1 must be explicitly SKIPPED because prerequisite failed
    assert sm.stage_states["fcr"] == StageState.SKIPPED
    assert summary["stage_statuses"]["fcr"] == "SKIPPED"
    assert sm.stage_states["agent1"] == StageState.SKIPPED
    assert summary["stage_statuses"]["agent1"] == "SKIPPED"

    # Completed stage count must ONLY count actually completed/resumed stages (intake = 1)
    assert summary["completed_stage_count"] == 1
    assert summary["failed_stage_count"] == 1
    assert summary["case_state"] == "complete"  # Non-stop-on-error degraded completion


def test_checkpointer_crash_between_redis_and_postgres_writes():
    """
    Scenario:
    1. Redis write succeeds, but PostgreSQL write throws an exception (simulating crash/disconnect).
    2. Verify save_stage_checkpoint handles exception and returns True (resilient fallback).
    3. Verify retrieval retrieves checkpoint from Redis without data loss.
    """
    mock_redis = MagicMock()
    stored_redis = {}
    mock_redis.set_checkpoint.side_effect = lambda k, s, v: stored_redis.update({f"{k}:{s}": v})
    mock_redis.get_checkpoint.side_effect = lambda k, s: stored_redis.get(f"{k}:{s}")

    mock_pg_conn = MagicMock()
    mock_pg_conn.cursor.side_effect = RuntimeError("PostgreSQL socket connection killed")

    cp = Checkpointer(postgres_conn=mock_pg_conn, redis_client=mock_redis)

    case_id = "CASE-CRASH-WRITE-001"
    tenant_id = "tenant-crash"
    stage = "agent2"
    state = {"graph_nodes": 15, "edges": 20}

    # Save should complete resiliently via Redis even though PG crashed
    ok = cp.save_stage_checkpoint(case_id, stage, state=state, tenant_id=tenant_id)
    assert ok is True

    # Retrieval should succeed from Redis
    retrieved = cp.get_stage_checkpoint(case_id, stage, tenant_id=tenant_id)
    assert retrieved is not None
    assert retrieved["checkpoint"]["graph_nodes"] == 15


def test_duplicate_side_effect_prevention():
    """
    Verifies that when a valid checkpoint exists, re-running the stage
    never invokes the underlying handler, preventing duplicate side-effects.
    """
    mock_cp = MagicMock(spec=Checkpointer)
    # Checkpoint already exists for agent4
    mock_cp.get_stage_checkpoint.return_value = {
        "status": "COMPLETED",
        "checkpoint": {"side_effect_count": 1, "status": "COMPLETED"}
    }

    sm = InvestigationStateMachine(
        case_id="CASE-NO-DUPLICATE",
        tenant_id="tenant-alpha",
        checkpointer=mock_cp
    )

    external_api_calls = 0
    def side_effect_handler(ctx):
        nonlocal external_api_calls
        external_api_calls += 1
        return {"side_effect_count": external_api_calls}

    sm.register_handler("intake", lambda ctx: {})
    sm.stage_states["agent2"] = StageState.COMPLETE
    sm.register_handler("agent4", side_effect_handler)

    result = sm.execute_stage("agent4", context={}, resume=True)

    # Handler was bypassed, side effect count remained 0
    assert external_api_calls == 0
    assert result["side_effect_count"] == 1
    assert sm.stage_states["agent4"] == StageState.RESUMED

