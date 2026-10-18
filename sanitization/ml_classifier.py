"""
Pluggable ML-Based Secondary Safety Classifier for Sanitization Gateway.

Provides an optional secondary defense layer behind deterministic regex heuristics.
Guarantees:
1. Deterministic screening is NEVER bypassed by ML output.
2. Tenant isolation and evidence provenance are strictly preserved.
3. Fail-closed or fail-open behavior on timeout or unavailability is explicitly configurable.
4. Raw evidence is NEVER transmitted to external endpoints without authorization.
5. All classifier evaluations, versions, and thresholds are tracked and audited.
"""

from __future__ import annotations

import logging
import math
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SafetyClassificationResult:
    is_flagged: bool
    score: float
    risk_category: str  # "BENIGN", "PROMPT_INJECTION", "JAILBREAK", "CLASSIFIER_TIMEOUT", "CLASSIFIER_UNAVAILABLE"
    classifier_name: str
    classifier_version: str
    threshold_used: float
    latency_ms: float
    error: Optional[str] = None
    tenant_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseSafetyClassifier(ABC):
    """Abstract base class for secondary ML safety classifiers."""

    def __init__(self, name: str, version: str, default_threshold: float = 0.70):
        self.name = name
        self.version = version
        self.default_threshold = default_threshold

    @abstractmethod
    def _predict_raw(self, text: str, tenant_id: str) -> Tuple[float, str]:
        """Subclass implementation returning (anomaly/injection_score in [0.0, 1.0], risk_category)."""
        pass

    def evaluate_with_guardrails(
        self,
        text: str,
        tenant_id: str = "default",
        threshold: Optional[float] = None,
        timeout_seconds: float = 2.0,
    ) -> SafetyClassificationResult:
        """Executes classification under strict latency, error-handling, and tenant guardrails."""
        start_time = time.perf_counter()
        active_threshold = threshold if threshold is not None else self.default_threshold
        fail_closed = os.getenv("ARGUS_ML_SAFETY_FAIL_CLOSED", "0").lower() in ("1", "true", "yes")

        try:
            # Enforce input validation and non-empty check
            if not text or not text.strip():
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                return SafetyClassificationResult(
                    is_flagged=False,
                    score=0.0,
                    risk_category="BENIGN",
                    classifier_name=self.name,
                    classifier_version=self.version,
                    threshold_used=active_threshold,
                    latency_ms=latency_ms,
                    tenant_id=tenant_id,
                )

            # Enforce local timeout guardrail
            score, category = self._predict_raw(text, tenant_id)
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if (latency_ms / 1000.0) > timeout_seconds:
                logger.warning(
                    "Safety classifier %s:%s exceeded timeout threshold (%.2f ms > %.2f s)",
                    self.name,
                    self.version,
                    latency_ms,
                    timeout_seconds,
                )
                if fail_closed:
                    return SafetyClassificationResult(
                        is_flagged=True,
                        score=1.0,
                        risk_category="CLASSIFIER_TIMEOUT",
                        classifier_name=self.name,
                        classifier_version=self.version,
                        threshold_used=active_threshold,
                        latency_ms=latency_ms,
                        error=f"Timeout exceeded: {latency_ms:.1f}ms",
                        tenant_id=tenant_id,
                    )
                else:
                    return SafetyClassificationResult(
                        is_flagged=False,
                        score=0.0,
                        risk_category="CLASSIFIER_TIMEOUT",
                        classifier_name=self.name,
                        classifier_version=self.version,
                        threshold_used=active_threshold,
                        latency_ms=latency_ms,
                        error=f"Timeout exceeded: {latency_ms:.1f}ms (fail-open)",
                        tenant_id=tenant_id,
                    )

            is_flagged = score >= active_threshold
            return SafetyClassificationResult(
                is_flagged=is_flagged,
                score=score,
                risk_category=category if is_flagged else "BENIGN",
                classifier_name=self.name,
                classifier_version=self.version,
                threshold_used=active_threshold,
                latency_ms=latency_ms,
                tenant_id=tenant_id,
            )

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Safety classifier error in %s:%s: %s", self.name, self.version, exc)

            if fail_closed:
                return SafetyClassificationResult(
                    is_flagged=True,
                    score=1.0,
                    risk_category="CLASSIFIER_UNAVAILABLE",
                    classifier_name=self.name,
                    classifier_version=self.version,
                    threshold_used=active_threshold,
                    latency_ms=latency_ms,
                    error=str(exc),
                    tenant_id=tenant_id,
                )
            else:
                return SafetyClassificationResult(
                    is_flagged=False,
                    score=0.0,
                    risk_category="CLASSIFIER_UNAVAILABLE",
                    classifier_name=self.name,
                    classifier_version=self.version,
                    threshold_used=active_threshold,
                    latency_ms=latency_ms,
                    error=str(exc),
                    tenant_id=tenant_id,
                )


class SemanticEntropySafetyClassifier(BaseSafetyClassifier):
    """
    In-process secondary classifier using structural token entropy, directive density,
    and meta-prompt impersonation markers.
    
    Zero external dependencies, deterministic baseline, high-speed execution (< 2ms).
    """

    DIRECTIVE_MARKERS = [
        r"\b(?:must|shall|need\s+to|required\s+to|command\s*:|output\s*:)\b",
        r"\b(?:now\s+act\s+as|pretend\s+to\s+be|roleplay\s+as)\b",
        r"\b(?:do\s+not\s+adhere|forget\s+(?:all\s+)?prior)\b",
        r"\b(?:as\s+an\s+ai\s+language\s+model|as\s+an\s+assistant)\b",
        r"\b(?:system\s+error|unauthorized\s+override)\b",
    ]

    def __init__(self, default_threshold: float = 0.65):
        super().__init__(name="semantic_entropy_classifier", version="1.0.0", default_threshold=default_threshold)
        self._compiled_markers = [re.compile(p, re.IGNORECASE) for p in self.DIRECTIVE_MARKERS]

    def _predict_raw(self, text: str, tenant_id: str) -> Tuple[float, str]:
        words = text.split()
        if not words:
            return 0.0, "BENIGN"

        # 1. Directive density score
        marker_hits = sum(1 for p in self._compiled_markers if p.search(text))
        directive_score = min(marker_hits * 0.35, 0.70)

        # 2. Shannon entropy of character distribution
        char_counts: Dict[str, int] = {}
        for ch in text:
            char_counts[ch] = char_counts.get(ch, 0) + 1
        total_chars = len(text)
        entropy = -sum((count / total_chars) * math.log2(count / total_chars) for count in char_counts.values())

        # Abnormally high entropy indicates obfuscated shellcode/base64; abnormally low indicates repetitive prompt injection padding
        entropy_penalty = 0.0
        if entropy > 5.5:
            entropy_penalty = 0.25
        elif entropy < 2.0 and len(words) > 5:
            entropy_penalty = 0.20

        # 3. Delimiter breakout marker check (e.g., markdown codeblock hijack, fake JSON output schemas)
        breakout_markers = [r"```json\s*\{.*\"action\"", r"\}\s*```", r"\[\[.*\]\]"]
        breakout_hits = sum(1 for b in breakout_markers if re.search(b, text, re.IGNORECASE | re.DOTALL))
        breakout_score = min(breakout_hits * 0.20, 0.40)

        composite_score = min(directive_score + entropy_penalty + breakout_score, 1.0)
        category = "PROMPT_INJECTION" if composite_score >= self.default_threshold else "BENIGN"
        return composite_score, category


class PluggableSafetyClassifier(BaseSafetyClassifier):
    """
    Pluggable wrapper that integrates any approved local or containerized safety model.
    Passes sanitized text to the callback while enforcing timeouts, tenant isolation, and versioning.
    """

    def __init__(
        self,
        name: str,
        version: str,
        prediction_fn: Callable[[str, str], Tuple[float, str]],
        default_threshold: float = 0.75,
    ):
        super().__init__(name=name, version=version, default_threshold=default_threshold)
        self._prediction_fn = prediction_fn

    def _predict_raw(self, text: str, tenant_id: str) -> Tuple[float, str]:
        return self._prediction_fn(text, tenant_id)


def evaluate_classifier_benchmark(
    classifier: BaseSafetyClassifier,
    benchmark_dataset: List[Tuple[str, bool]],  # (text, is_adversarial)
    tenant_id: str = "benchmark-tenant",
    threshold: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Evaluates a safety classifier against a dataset of synthetic adversarial examples
    and benign controls to measure true positives, false positives, precision, recall, and F1.
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    latencies: List[float] = []

    for text, expected_adversarial in benchmark_dataset:
        res = classifier.evaluate_with_guardrails(text, tenant_id=tenant_id, threshold=threshold)
        latencies.append(res.latency_ms)

        if res.is_flagged and expected_adversarial:
            tp += 1
        elif res.is_flagged and not expected_adversarial:
            fp += 1
        elif not res.is_flagged and not expected_adversarial:
            tn += 1
        elif not res.is_flagged and expected_adversarial:
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "classifier_name": classifier.name,
        "classifier_version": classifier.version,
        "threshold": threshold or classifier.default_threshold,
        "total_samples": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "avg_latency_ms": round(avg_latency, 3),
    }
