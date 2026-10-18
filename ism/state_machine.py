"""
Investigation State Machine (ISM) — DAG Workflow & Per-Case Orchestrator
========================================================================
Coordinates forensic pipeline stages and AI agents using a dependency-directed
acyclic graph (DAG) with fork-join scheduling, crash recovery, retries, and
failure isolation.

Features:
  1. Strict per-case and per-stage lifecycle states:
     CaseState: PENDING -> RUNNING -> COMPLETE / FAILED / WAITING_FOR_REVIEW
     StageState: PENDING -> RUNNING -> COMPLETE / RESUMED / FAILED / SKIPPED
  2. Fork-Join Parallel Dependency Scheduling:
     - Sequential: intake -> preprocessing -> fcr -> fir_ingestion
     - Initial Triage & Graph: agent1, agent2
     - Fork: [agent3, agent4, agent5a]
     - Branch Continuation: agent5b (after agent4), agent6 (after agent3)
     - Join: agent7 (synthesis & verification over all upstream outputs)
     - Terminal: report_generation
  3. Seamless Checkpointer Integration:
     Persists each completed stage to PostgreSQL `ism_state` and Redis fast-cache.
     Checks idempotency keys to resume uninterrupted across application restarts.
  4. Transient Failure Retries with Backoff:
     Delegates to FailureClassifier and RetryHandler.
  5. Error Isolation Boundary:
     Failures in optional enrichment stages (e.g. Agent 5a or Agent 5b) do not
     terminate independent investigation branches when stop_on_error=False.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Dict, Any, List, Optional, Callable, Set, Tuple
from datetime import datetime, timezone

from ism.checkpointer import Checkpointer, build_ism_idempotency_key
from ism.failure_classifier import FailureClassifier, FailureType
from ism.retry_handler import RetryHandler

logger = logging.getLogger("ArgusISM.StateMachine")


class CaseState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    PAUSED = "paused"
    WAITING_FOR_REVIEW = "waiting_for_review"


class StageState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETED"
    RESUMED = "RESUMED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


# Canonical Stage Dependencies (DAG)
# stage_name -> list of prerequisite stage names that MUST be COMPLETE or RESUMED
STAGE_DEPENDENCIES: Dict[str, List[str]] = {
    "intake": [],
    "preprocessing": ["intake"],
    "fcr": ["preprocessing"],
    "fir_ingestion": ["fcr"],
    "agent1": ["fir_ingestion"],
    "agent2": ["fir_ingestion"],
    "agent3": ["agent2"],
    "agent4": ["agent2"],
    "agent5a": ["agent2"],
    "agent5b": ["agent4"],
    "agent6": ["agent3"],
    "agent7": ["agent1", "agent2", "agent3", "agent4", "agent5a", "agent5b", "agent6"],
    "report_generation": ["agent7"],
}


class InvestigationStateMachine:
    """
    State machine controller governing investigation progress for a single case session.
    """

    def __init__(
        self,
        case_id: str,
        tenant_id: str = "default",
        evidence_ids: Optional[List[str]] = None,
        pipeline_version: str = "1.0.0",
        checkpointer: Optional[Checkpointer] = None,
        retry_handler: Optional[RetryHandler] = None,
        failure_classifier: Optional[FailureClassifier] = None,
        stop_on_error: bool = False,
    ):
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id is required for InvestigationStateMachine.")

        self.case_id = str(case_id).strip()
        self.tenant_id = str(tenant_id).strip() or "default"
        self.evidence_ids = sorted(evidence_ids) if evidence_ids else []
        self.pipeline_version = str(pipeline_version)
        self.stop_on_error = bool(stop_on_error)

        self.checkpointer = checkpointer or Checkpointer()
        self.classifier = failure_classifier or FailureClassifier()
        self.retry_handler = retry_handler or RetryHandler(failure_classifier=self.classifier)

        self.idempotency_key = build_ism_idempotency_key(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            evidence_ids=self.evidence_ids,
            pipeline_version=self.pipeline_version,
        )

        # Operational state tracking
        self.case_state: CaseState = CaseState.PENDING
        self.stage_states: Dict[str, StageState] = {
            stage: StageState.PENDING for stage in STAGE_DEPENDENCIES.keys()
        }
        self.stage_outputs: Dict[str, Any] = {}
        self.stage_errors: Dict[str, str] = {}
        self.stage_retry_counts: Dict[str, int] = {stage: 0 for stage in STAGE_DEPENDENCIES.keys()}
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

        # Registered executable step functions
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}

    def register_handler(self, stage_name: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        """Binds an executable handler to a specific pipeline stage."""
        self._handlers[stage_name] = handler

    def can_run_stage(self, stage_name: str) -> Tuple[bool, Optional[str]]:
        """
        Validates DAG prerequisite dependencies for the requested stage.
        Returns: (can_run, reason_if_cannot)
        """
        prereqs = STAGE_DEPENDENCIES.get(stage_name, [])
        for p in prereqs:
            p_state = self.stage_states.get(p)
            if p_state not in (StageState.COMPLETE, StageState.RESUMED):
                # If prerequisite failed and stop_on_error is False, some downstream might be blocked
                return False, f"Prerequisite stage '{p}' is {p_state.value if p_state else 'MISSING'}, not COMPLETED."
        return True, None

    def execute_stage(
        self,
        stage_name: str,
        context: Dict[str, Any],
        resume: bool = True
    ) -> Any:
        """
        Executes a single pipeline stage with checkpoint checking, retry handling,
        and state persistence.
        """
        if stage_name not in STAGE_DEPENDENCIES:
            raise KeyError(f"Unknown stage '{stage_name}'. Valid stages: {list(STAGE_DEPENDENCIES.keys())}")

        can_run, reason = self.can_run_stage(stage_name)
        if not can_run:
            logger.warning("ISM: Skipping stage '%s' for case '%s': %s", stage_name, self.case_id, reason)
            self.stage_states[stage_name] = StageState.SKIPPED
            return None

        # 1. Check for durable checkpoint resume
        if resume:
            cp = self.checkpointer.get_stage_checkpoint(
                case_id=self.case_id,
                stage=stage_name,
                tenant_id=self.tenant_id,
                expected_idempotency_key=self.idempotency_key,
                expected_version=self.pipeline_version,
            )
            if cp and cp.get("status") in ("COMPLETED", StageState.COMPLETE.value) and "checkpoint" in cp:
                logger.info("ISM: Stage '%s' resumed from durable checkpoint for case '%s'.", stage_name, self.case_id)
                self.stage_states[stage_name] = StageState.RESUMED
                self.stage_outputs[stage_name] = cp["checkpoint"]
                return cp["checkpoint"]

        handler = self._handlers.get(stage_name)
        if not handler:
            raise RuntimeError(f"No executable handler registered for stage '{stage_name}'.")

        self.stage_states[stage_name] = StageState.RUNNING
        logger.info("ISM: Running stage '%s' for case '%s' (tenant: %s)...", stage_name, self.case_id, self.tenant_id)

        try:
            # Execute with automated retry handler for transient errors
            result = self.retry_handler.execute(handler, context)
            self.stage_outputs[stage_name] = result
            self.stage_states[stage_name] = StageState.COMPLETE

            # Durably checkpoint successful stage state
            self.checkpointer.save_stage_checkpoint(
                case_id=self.case_id,
                stage=stage_name,
                state=result if isinstance(result, dict) else {"output": str(result)},
                status=StageState.COMPLETE.value,
                retry_count=self.stage_retry_counts[stage_name],
                tenant_id=self.tenant_id,
                idempotency_key=self.idempotency_key,
                pipeline_version=self.pipeline_version,
            )
            logger.info("ISM: Stage '%s' COMPLETED successfully and checkpointed.", stage_name)
            return result

        except Exception as exc:
            self.stage_states[stage_name] = StageState.FAILED
            classification = self.classifier.classify_detailed(exc)
            err_msg = f"{classification.failure_type.value}: {str(exc)}"
            self.stage_errors[stage_name] = err_msg
            logger.error("ISM: Stage '%s' FAILED: %s", stage_name, err_msg)

            # Durably record failure status
            self.checkpointer.save_stage_checkpoint(
                case_id=self.case_id,
                stage=stage_name,
                state={"error": err_msg, "classification": classification.failure_type.value},
                status=StageState.FAILED.value,
                retry_count=self.stage_retry_counts[stage_name] + 1,
                tenant_id=self.tenant_id,
                idempotency_key=self.idempotency_key,
                pipeline_version=self.pipeline_version,
            )

            if self.stop_on_error:
                self.case_state = CaseState.FAILED
                raise
            return None

    def run_pipeline(
        self,
        initial_context: Dict[str, Any],
        resume: bool = True
    ) -> Dict[str, Any]:
        """
        Executes all registered stages according to topological DAG order.
        Supports fork-join execution semantics and failure isolation.
        """
        self.started_at = datetime.now(timezone.utc)
        self.case_state = CaseState.RUNNING
        context = dict(initial_context)
        context["case_id"] = self.case_id
        context["tenant_id"] = self.tenant_id
        context["idempotency_key"] = self.idempotency_key

        # Topological execution sequence conforming to DAG
        execution_order = [
            "intake",
            "preprocessing",
            "fcr",
            "fir_ingestion",
            "agent1",
            "agent2",
            # Fork: independent branch analyses
            "agent3",
            "agent4",
            "agent5a",
            # Continuations
            "agent5b",
            "agent6",
            # Join: supervisor fusion & verification
            "agent7",
            "report_generation",
        ]

        for stage in execution_order:
            if stage in self._handlers:
                # Merge outputs of all prior stages into context
                context["stage_outputs"] = self.stage_outputs
                context[stage + "_prior_output"] = self.stage_outputs.get(stage)
                self.execute_stage(stage, context, resume=resume)

        # Determine final case state
        has_failed = any(s == StageState.FAILED for s in self.stage_states.values())
        critical_stages = ["fir_ingestion", "agent7"]
        critical_failed = any(self.stage_states.get(cs) == StageState.FAILED for cs in critical_stages)

        self.completed_at = datetime.now(timezone.utc)
        if critical_failed:
            self.case_state = CaseState.FAILED
        elif has_failed:
            self.case_state = CaseState.COMPLETE  # Completed with partial/degraded stages
        else:
            self.case_state = CaseState.COMPLETE

        return self.get_summary()

    def get_summary(self) -> Dict[str, Any]:
        """Returns structured session status snapshot for audit and API consumption."""
        return {
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "idempotency_key": self.idempotency_key,
            "case_state": self.case_state.value,
            "pipeline_version": self.pipeline_version,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "stage_statuses": {k: v.value for k, v in self.stage_states.items()},
            "stage_errors": self.stage_errors,
            "completed_stage_count": sum(1 for v in self.stage_states.values() if v in (StageState.COMPLETE, StageState.RESUMED)),
            "failed_stage_count": sum(1 for v in self.stage_states.values() if v == StageState.FAILED),
        }
