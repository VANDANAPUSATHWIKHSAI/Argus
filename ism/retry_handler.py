"""
ISM Retry & Backoff Handler
===========================
Executes operations with exponential backoff and jitter for transient failures.
Coordinates directly with FailureClassifier to:
  - Immediately raise non-retryable errors without delaying the pipeline
  - Retry transient failures (network timeouts, temporary DB disconnects, LLM cold-starts)
  - Enforce maximum retry budgets and upper backoff caps
"""

from __future__ import annotations

import time
import random
import logging
import functools
from typing import Callable, Any, Optional, TypeVar

from ism.failure_classifier import FailureClassifier, FailureClassificationResult

logger = logging.getLogger("ArgusISM.RetryHandler")

T = TypeVar("T")


class RetryExhaustedError(RuntimeError):
    """Raised when maximum retries are exhausted for a transient error."""
    def __init__(self, attempts: int, last_exception: Exception, classification: FailureClassificationResult):
        self.attempts = attempts
        self.last_exception = last_exception
        self.classification = classification
        super().__init__(
            f"Operation failed after {attempts} attempts ({classification.failure_type.value}): {last_exception}"
        )


class RetryHandler:
    """
    Manages retry lifecycle with exponential backoff, jitter, and classification gating.
    """

    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        max_backoff: float = 30.0,
        jitter: bool = True,
        failure_classifier: Optional[FailureClassifier] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = float(backoff_factor)
        self.max_backoff = float(max_backoff)
        self.jitter = bool(jitter)
        self.classifier = failure_classifier or FailureClassifier()
        self._sleep_fn = sleep_fn

    def compute_backoff(self, attempt: int, base_seconds: float = 1.0) -> float:
        """
        Computes exponential backoff with optional full jitter.
        Formula: min(max_backoff, base_seconds * (backoff_factor ** attempt))
        """
        raw_backoff = base_seconds * (self.backoff_factor ** max(0, attempt - 1))
        capped = min(self.max_backoff, raw_backoff)
        if self.jitter:
            return random.uniform(0.5 * capped, capped)
        return capped

    def execute(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Executes fn(*args, **kwargs) with retry logic.
        Raises immediately on non-retryable errors.
        """
        attempts = 0
        last_exc: Optional[Exception] = None
        last_classification: Optional[FailureClassificationResult] = None

        while attempts <= self.max_retries:
            attempts += 1
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                last_exc = exc
                classification = self.classifier.classify_detailed(exc)
                last_classification = classification

                # Fail fast if error is non-retryable or attempts exhausted
                if not classification.is_retryable:
                    logger.warning(
                        "ISM RetryHandler: Aborting non-retryable error on attempt %d/%d (%s): %s",
                        attempts, self.max_retries + 1, classification.failure_type.value, exc
                    )
                    raise

                if attempts > self.max_retries:
                    logger.error(
                        "ISM RetryHandler: Retries exhausted (%d attempts) for %s: %s",
                        attempts, classification.failure_type.value, exc
                    )
                    break

                backoff = self.compute_backoff(attempts, classification.recommended_backoff_seconds or 1.0)
                logger.info(
                    "ISM RetryHandler: Transient %s detected on attempt %d/%d. Retrying in %.2fs. Error: %s",
                    classification.failure_type.value, attempts, self.max_retries + 1, backoff, exc
                )
                self._sleep_fn(backoff)

        assert last_exc is not None and last_classification is not None
        raise RetryExhaustedError(attempts - 1, last_exc, last_classification) from last_exc

    def wrap(self, fn: Callable[..., T]) -> Callable[..., T]:
        """Decorator form of RetryHandler.execute."""
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            return self.execute(fn, *args, **kwargs)
        return wrapper
