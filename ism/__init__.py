"""
Investigation State Management (ISM) Module
===========================================
Cross-cutting backend capabilities for forensic workflow orchestration:
  - Checkpointer: Dual-persistence state and crash-recovery (PostgreSQL + Redis)
  - InvestigationStateMachine: DAG dependency scheduling, lifecycle tracking, fork-join execution
  - FailureClassifier: Deterministic failure inspection and retryability evaluation
  - RetryHandler: Exponential backoff and jitter handler for transient errors
"""

from ism.checkpointer import Checkpointer, build_ism_idempotency_key
from ism.failure_classifier import FailureClassifier, FailureType, FailureClassificationResult
from ism.retry_handler import RetryHandler, RetryExhaustedError
from ism.state_machine import (
    InvestigationStateMachine,
    CaseState,
    StageState,
    STAGE_DEPENDENCIES,
)

__all__ = [
    "Checkpointer",
    "build_ism_idempotency_key",
    "FailureClassifier",
    "FailureType",
    "FailureClassificationResult",
    "RetryHandler",
    "RetryExhaustedError",
    "InvestigationStateMachine",
    "CaseState",
    "StageState",
    "STAGE_DEPENDENCIES",
]
