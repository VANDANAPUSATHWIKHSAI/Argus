"""
Automated Model Quality Evaluator.
Evaluates model outputs against ground truth forensic cases across:
- Hallucination rate
- Attribution precision
- Timeline completeness
- Citation accuracy
- Fact-to-evidence consistency
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Evaluator:
    """Evaluates AI forensic agent outputs against versioned ground truth cases."""

    def __init__(
        self,
        model_name: str = "qwen3:8b",
        model_version: str = "1.0.0",
        prompt_version: str = "2.0.0",
        dataset_version: str = "2026.10-baseline",
    ):
        self.model_name = model_name
        self.model_version = model_version
        self.prompt_version = prompt_version
        self.dataset_version = dataset_version

    def evaluate_case(
        self,
        predicted: Dict[str, Any],
        ground_truth: Dict[str, Any],
    ) -> Dict[str, float]:
        """Evaluates a single prediction against ground truth claims and citations."""
        pred_claims = predicted.get("claims", [])
        gt_claims = ground_truth.get("claims", [])
        pred_citations = set(predicted.get("citations", []))
        gt_citations = set(ground_truth.get("citations", []))

        # 1. Attribution Precision: Proportion of predicted citations that are valid ground truth citations
        if pred_citations:
            valid_citations = pred_citations.intersection(gt_citations)
            attribution_precision = len(valid_citations) / len(pred_citations)
        else:
            attribution_precision = 1.0 if not gt_citations else 0.0

        # 2. Citation Recall: Proportion of ground truth citations captured
        if gt_citations:
            citation_recall = len(pred_citations.intersection(gt_citations)) / len(gt_citations)
        else:
            citation_recall = 1.0

        # 3. Hallucination Rate: Proportion of predicted claims with zero grounding or contradicting evidence
        hallucinated_count = 0
        for claim in pred_claims:
            is_supported = any(
                gt in claim or claim in gt or ("evidence_id" in claim and "evidence_id" in gt)
                for gt in gt_claims
            )
            # Check for explicitly fabricated flags
            if not is_supported or "hallucinated" in str(claim).lower():
                hallucinated_count += 1

        hallucination_rate = (
            (hallucinated_count / len(pred_claims)) if pred_claims else 0.0
        )

        # 4. Timeline Completeness: Proportion of ground truth events represented in prediction
        gt_events = ground_truth.get("timeline_events", [])
        pred_events = predicted.get("timeline_events", [])
        if gt_events:
            captured_events = sum(
                1 for ge in gt_events if any(pe.get("event") == ge.get("event") for pe in pred_events)
            )
            timeline_completeness = captured_events / len(gt_events)
        else:
            timeline_completeness = 1.0

        return {
            "attribution_precision": round(attribution_precision, 4),
            "citation_recall": round(citation_recall, 4),
            "hallucination_rate": round(hallucination_rate, 4),
            "timeline_completeness": round(timeline_completeness, 4),
        }

    def run_suite(
        self,
        test_cases: List[Dict[str, Any]],
        model_metadata: Optional[Dict[str, Any]] = None,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Runs the complete evaluation suite across a list of test cases."""
        run_id = f"eval-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        meta = model_metadata or {}

        case_results = []
        metric_sums: Dict[str, float] = {
            "attribution_precision": 0.0,
            "citation_recall": 0.0,
            "hallucination_rate": 0.0,
            "timeline_completeness": 0.0,
        }

        total_cases = len(test_cases)
        for tc in test_cases:
            pred = tc.get("prediction", {})
            gt = tc.get("ground_truth", {})
            res = self.evaluate_case(pred, gt)
            case_results.append({
                "case_id": tc.get("case_id", "unknown"),
                "metrics": res,
            })
            for k in metric_sums:
                metric_sums[k] += res[k]

        aggregates = {
            k: round(v / total_cases, 4) if total_cases > 0 else 0.0
            for k, v in metric_sums.items()
        }

        return {
            "run_id": run_id,
            "timestamp": timestamp,
            "tenant_id": tenant_id,
            "total_cases": total_cases,
            "model_name": meta.get("model_name", self.model_name),
            "model_version": meta.get("model_version", self.model_version),
            "prompt_version": meta.get("prompt_version", self.prompt_version),
            "dataset_version": meta.get("dataset_version", self.dataset_version),
            "aggregate_metrics": aggregates,
            "case_results": case_results,
            "status": "COMPLETED",
        }
