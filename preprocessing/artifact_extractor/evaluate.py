"""
evaluate.py — Artifact Extractor Evaluation Harness
======================================================
Scores ArtifactExtractor against the labeled gold corpus in
test_corpus_expanded.json using span-based matching (IoU >= 0.5).

Usage (CLI):
    python -m preprocessing.artifact_extractor.evaluate --split frozen_test
    python -m preprocessing.artifact_extractor.evaluate --all
    python -m preprocessing.artifact_extractor.evaluate --split validation --no-history

Requires the real GLiNER model to be cached locally.  Guard execution behind:
    ARGUS_RUN_MODEL_INTEGRATION_TESTS=1

Do NOT run against frozen_test to make threshold or fine-tuning decisions.
frozen_test is a sealed evaluation set — run it for final reporting only.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap — allow running as both a module and a direct script
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from preprocessing.schemas import Artifact, ExtractedEntity
from preprocessing.artifact_extractor.extractor import (
    ArtifactExtractor,
    GLINER_MODEL_ID,
    GLINER_REVISION,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CORPUS_PATH = _HERE / "test_corpus_expanded.json"
HISTORY_PATH = _HERE / "eval_history.jsonl"

# !! IMPORTANT !! This constant marks the frozen evaluation set.
# frozen_test MUST NOT be used for threshold-tuning, hyperparameter search,
# or any fine-tuning decision. It exists solely for final, comparable reporting.
FROZEN_TEST_SPLIT = "frozen_test"

# Minimum IoU overlap for a prediction to count as a true-positive match
IOU_THRESHOLD = 0.5

# Absolute F1 drop that triggers a regression warning
REGRESSION_F1_DROP_THRESHOLD = 0.05


# ---------------------------------------------------------------------------
# Label normalisation — maps the extractor's internal types back to the
# three canonical gold labels used in the corpus.
# ---------------------------------------------------------------------------

def normalize_predicted_label(entity_type: str) -> str:
    """Map extractor's internal entity_type to a gold-corpus label."""
    t = (entity_type or "").lower().strip()
    if t in ("malware", "malware_candidate"):
        return "malware"
    if t in ("threat_actor", "threat-actor"):
        return "threat-actor"
    if t in ("command-line", "command_line", "executable"):
        return "command-line"
    return t  # unknown — will simply never match a gold span


def normalize_gold_label(label: str) -> str:
    """Normalise gold labels for consistent comparison."""
    t = (label or "").lower().strip()
    return t


# ---------------------------------------------------------------------------
# Span utilities
# ---------------------------------------------------------------------------

def iou(pred_start: int, pred_end: int, gold_start: int, gold_end: int) -> float:
    """Compute character-level Intersection-over-Union of two spans."""
    intersection_start = max(pred_start, gold_start)
    intersection_end = min(pred_end, gold_end)
    if intersection_start >= intersection_end:
        return 0.0
    intersection = intersection_end - intersection_start
    union = (pred_end - pred_start) + (gold_end - gold_start) - intersection
    return intersection / union if union > 0 else 0.0


# ---------------------------------------------------------------------------
# Metrics accumulator
# ---------------------------------------------------------------------------

class MetricsAccumulator:
    """Accumulates TP/FP/FN counts per label and computes P/R/F1."""

    def __init__(self) -> None:
        self._tp: Dict[str, int] = defaultdict(int)
        self._fp: Dict[str, int] = defaultdict(int)
        self._fn: Dict[str, int] = defaultdict(int)

    def record_tp(self, label: str) -> None:
        self._tp[label] += 1

    def record_fp(self, label: str) -> None:
        self._fp[label] += 1

    def record_fn(self, label: str) -> None:
        self._fn[label] += 1

    def per_label_metrics(self) -> Dict[str, Dict]:
        labels = set(self._tp) | set(self._fp) | set(self._fn)
        out: Dict[str, Dict] = {}
        for lbl in sorted(labels):
            tp = self._tp[lbl]
            fp = self._fp[lbl]
            fn = self._fn[lbl]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0 else 0.0
            )
            out[lbl] = {
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            }
        return out

    def micro_average(self) -> Dict:
        total_tp = sum(self._tp.values())
        total_fp = sum(self._fp.values())
        total_fn = sum(self._fn.values())
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0 else 0.0
        )
        return {
            "tp": total_tp, "fp": total_fp, "fn": total_fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }


# ---------------------------------------------------------------------------
# Main harness
# ---------------------------------------------------------------------------

class EvaluationHarness:
    """
    Evaluation harness for ArtifactExtractor.

    Runs the extractor against every example in a given split of
    test_corpus_expanded.json and produces:
      - Per entity-type and micro-averaged P/R/F1 (validation / frozen_test)
      - Adversarial suppression accuracy (adversarial_holdout)
      - A stamped JSON record appended to eval_history.jsonl
      - A regression warning if frozen_test F1 drops > 0.05 vs. the most
        recent prior run at the same model revision.
    """

    FROZEN_TEST_SPLIT = FROZEN_TEST_SPLIT  # re-exported for callers

    def __init__(self, extractor: Optional[ArtifactExtractor] = None) -> None:
        self._extractor = extractor or ArtifactExtractor()
        self._corpus: Dict[str, List[dict]] = self._load_corpus()

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_corpus() -> Dict[str, List[dict]]:
        if not CORPUS_PATH.exists():
            raise FileNotFoundError(
                f"Gold corpus not found at {CORPUS_PATH}. "
                "Expected preprocessing/artifact_extractor/test_corpus_expanded.json"
            )
        with open(CORPUS_PATH, encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _git_commit() -> str:
        """Best-effort git HEAD hash — empty string on failure."""
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=str(_PROJECT_ROOT),
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode().strip()
        except Exception:
            return ""

    def _gliner_version(self) -> str:
        try:
            import gliner
            return getattr(gliner, "__version__", "unknown")
        except ImportError:
            return "not-installed"

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def _run_on_example(self, text: str) -> List[ExtractedEntity]:
        """Wrap a raw text string in a minimal Artifact and extract."""
        art = Artifact(
            evidence_id="eval-harness",
            source_tool="evaluate.py",
            artifact_type="narrative",
            raw_fields={"description": text},
        )
        # include_suppressed=False so only active entities are scored
        # (suppressed/downgraded entities represent intentional rejections)
        return self._extractor.extract([art], "eval-harness", include_suppressed=False)

    # ------------------------------------------------------------------
    # Span matching
    # ------------------------------------------------------------------

    def _match_predictions_to_gold(
        self,
        predictions: List[ExtractedEntity],
        gold_entities: List[dict],
    ) -> Tuple[List[Tuple[ExtractedEntity, dict]], List[ExtractedEntity], List[dict]]:
        """
        Greedy span-based matching with IoU >= IOU_THRESHOLD.

        Returns:
            matched   — (pred, gold) pairs
            unmatched_preds  — false positives
            unmatched_golds  — false negatives
        """
        # Filter predictions to only the three canonical labels
        scored_preds = [
            p for p in predictions
            if normalize_predicted_label(p.entity_type)
               in ("malware", "threat-actor", "command-line")
        ]

        # For matching, use normalized labels on both sides.
        remaining_gold = list(gold_entities)
        matched: List[Tuple[ExtractedEntity, dict]] = []
        unmatched_preds: List[ExtractedEntity] = []

        for pred in scored_preds:
            pred_label = normalize_predicted_label(pred.entity_type)
            best_iou = 0.0
            best_gold_idx = -1

            for gi, gold in enumerate(remaining_gold):
                if normalize_gold_label(gold["label"]) != pred_label:
                    continue
                overlap = iou(pred.char_start, pred.char_end,
                              gold["start"], gold["end"])
                if overlap >= IOU_THRESHOLD and overlap > best_iou:
                    best_iou = overlap
                    best_gold_idx = gi

            if best_gold_idx >= 0:
                matched.append((pred, remaining_gold[best_gold_idx]))
                remaining_gold.pop(best_gold_idx)
            else:
                unmatched_preds.append(pred)

        return matched, unmatched_preds, remaining_gold

    # ------------------------------------------------------------------
    # Standard F1 evaluation (validation + frozen_test)
    # ------------------------------------------------------------------

    def evaluate_split(self, split: str) -> Dict:
        """
        Evaluate precision/recall/F1 on a standard split.

        IMPORTANT: Do NOT use the frozen_test split for threshold-tuning or
        any fine-tuning decision.  Call this for frozen_test only when
        producing a final, comparable report via `run_full_report()`.
        """
        examples = self._corpus.get(split)
        if examples is None:
            raise ValueError(
                f"Split '{split}' not found in corpus. "
                f"Available: {list(self._corpus.keys())}"
            )

        acc = MetricsAccumulator()

        for ex in examples:
            text = ex["text"]
            gold_entities = ex.get("entities", [])
            predictions = self._run_on_example(text)

            matched, unmatched_preds, unmatched_golds = self._match_predictions_to_gold(
                predictions, gold_entities
            )

            for pred, gold in matched:
                label = normalize_gold_label(gold["label"])
                acc.record_tp(label)

            for pred in unmatched_preds:
                label = normalize_predicted_label(pred.entity_type)
                acc.record_fp(label)

            for gold in unmatched_golds:
                label = normalize_gold_label(gold["label"])
                acc.record_fn(label)

        return {
            "split": split,
            "n_examples": len(examples),
            "per_label": acc.per_label_metrics(),
            "micro": acc.micro_average(),
        }

    # ------------------------------------------------------------------
    # Adversarial suppression accuracy
    # ------------------------------------------------------------------

    def evaluate_adversarial_split(self) -> Dict:
        """
        Score the adversarial_holdout split.

        Scoring semantics (encoded in the gold corpus):
          - Gold entities list = the CORRECT expected active entities after
            post-processing (persona validation, generic-term suppression,
            defensive-software normalisation).
          - An example with an empty gold entities list means the extractor
            should produce ZERO active entities for that text (any remaining
            entity = false positive).
          - Matching uses the same IoU >= 0.5 + label-normalisation as the
            standard splits; the difference is in the interpretation:
            a correct suppression (nothing extracted, nothing expected) counts
            toward "correct decisions", while a missed suppression
            (something extracted when nothing expected) counts as a wrong decision.

        Reported metrics:
          - correct_decisions   — examples where active outputs match gold exactly
                                  at the binary level (≥1 TP or both empty)
          - wrong_decisions     — examples with at least one FP or FN
          - suppression_accuracy — correct_decisions / n_examples
          - Also reports standard P/R/F1 (micro) for completeness.
        """
        examples = self._corpus.get("adversarial_holdout", [])
        acc = MetricsAccumulator()
        correct_decisions = 0

        for ex in examples:
            text = ex["text"]
            gold_entities = ex.get("entities", [])
            predictions = self._run_on_example(text)

            matched, unmatched_preds, unmatched_golds = self._match_predictions_to_gold(
                predictions, gold_entities
            )

            # Record counts
            for pred, gold in matched:
                label = normalize_gold_label(gold["label"])
                acc.record_tp(label)

            for pred in unmatched_preds:
                label = normalize_predicted_label(pred.entity_type)
                acc.record_fp(label)

            for gold in unmatched_golds:
                label = normalize_gold_label(gold["label"])
                acc.record_fn(label)

            # A decision is "correct" for this example if:
            #   - gold is empty AND no active predictions  (correct suppression)
            #   - gold is non-empty AND all gold matched, no leftover FP
            if not unmatched_preds and not unmatched_golds:
                correct_decisions += 1

        n = len(examples)
        suppression_accuracy = correct_decisions / n if n > 0 else 0.0

        return {
            "split": "adversarial_holdout",
            "n_examples": n,
            "correct_decisions": correct_decisions,
            "wrong_decisions": n - correct_decisions,
            "suppression_accuracy": round(suppression_accuracy, 4),
            "micro": acc.micro_average(),
            "per_label": acc.per_label_metrics(),
        }

    # ------------------------------------------------------------------
    # Full report
    # ------------------------------------------------------------------

    def run_full_report(
        self,
        splits: Optional[List[str]] = None,
        write_history: bool = True,
    ) -> Dict:
        """
        Run evaluation on the requested splits and return a stamped report.

        Passing splits=None evaluates all three splits.

        NOTE: frozen_test is a sealed set — this method is the only intended
        call site for that split.  Any code path that reads frozen_test results
        for tuning decisions violates this contract.
        """
        if splits is None:
            splits = ["validation", FROZEN_TEST_SPLIT, "adversarial_holdout"]

        results: Dict[str, Dict] = {}

        for split in splits:
            print(f"\n[evaluate.py] Scoring split: {split} …", flush=True)
            if split == "adversarial_holdout":
                results[split] = self.evaluate_adversarial_split()
            else:
                results[split] = self.evaluate_split(split)
            self._print_split_result(results[split])

        # Build stamped record
        record = {
            "run_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "model_name": GLINER_MODEL_ID,
            "model_revision": GLINER_REVISION,
            "extractor_version": getattr(self._extractor, "_extractor_version", "unknown"),
            "gliner_package_version": self._gliner_version(),
            "git_commit": self._git_commit(),
            "iou_threshold": IOU_THRESHOLD,
            "splits_evaluated": splits,
            "results": results,
        }

        if write_history:
            self._append_history(record)

        # Regression check — only if frozen_test was evaluated
        if FROZEN_TEST_SPLIT in results and write_history:
            self._check_regression(record)

        return record

    # ------------------------------------------------------------------
    # History / regression
    # ------------------------------------------------------------------

    @staticmethod
    def _append_history(record: Dict) -> None:
        with open(HISTORY_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"\n[evaluate.py] Run record appended to {HISTORY_PATH}", flush=True)

    @staticmethod
    def _load_history() -> List[Dict]:
        if not HISTORY_PATH.exists():
            return []
        records = []
        with open(HISTORY_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return records

    def _check_regression(self, current_record: Dict) -> None:
        """
        Compare current frozen_test F1 against the most recent prior run
        at the same model revision.  Emit a warning if F1 dropped > 0.05.
        """
        current_f1 = (
            current_record["results"]
            .get(FROZEN_TEST_SPLIT, {})
            .get("micro", {})
            .get("f1", None)
        )
        if current_f1 is None:
            return

        history = self._load_history()
        same_revision_runs = [
            r for r in history
            if r.get("model_revision") == GLINER_REVISION
            and FROZEN_TEST_SPLIT in r.get("splits_evaluated", [])
            and r["run_id"] != current_record["run_id"]
        ]

        if not same_revision_runs:
            print(
                f"\n[evaluate.py] No prior {FROZEN_TEST_SPLIT} baseline found "
                f"for revision {GLINER_REVISION[:8]}. "
                "Current run becomes the baseline.",
                flush=True,
            )
            return

        # Most recent prior run
        prior = sorted(same_revision_runs, key=lambda r: r.get("timestamp", ""))[-1]
        prior_f1 = (
            prior["results"]
            .get(FROZEN_TEST_SPLIT, {})
            .get("micro", {})
            .get("f1", None)
        )
        if prior_f1 is None:
            return

        drop = prior_f1 - current_f1
        if drop > REGRESSION_F1_DROP_THRESHOLD:
            print(
                f"\n⚠️  REGRESSION WARNING: {FROZEN_TEST_SPLIT} micro-F1 dropped "
                f"{drop:.4f} absolute ({prior_f1:.4f} → {current_f1:.4f}). "
                "This exceeds the 0.05 threshold. Investigate before merging.",
                flush=True,
            )
        else:
            print(
                f"\n✓ Regression check: {FROZEN_TEST_SPLIT} F1 "
                f"{prior_f1:.4f} → {current_f1:.4f} "
                f"(delta = {current_f1 - prior_f1:+.4f}, within threshold).",
                flush=True,
            )

    # ------------------------------------------------------------------
    # Pretty-print
    # ------------------------------------------------------------------

    @staticmethod
    def _print_split_result(result: Dict) -> None:
        split = result["split"]
        n = result["n_examples"]
        print(f"\n{'=' * 60}")
        print(f"  Split: {split}  ({n} examples)")
        print(f"{'=' * 60}")

        if split == "adversarial_holdout":
            sa = result["suppression_accuracy"]
            cd = result["correct_decisions"]
            wd = result["wrong_decisions"]
            print(f"  Suppression accuracy : {sa:.4f}  ({cd}/{n} correct decisions)")
            print(f"  Wrong decisions      : {wd}")
            print(f"\n  Standard P/R/F1 (micro, for reference):")
            m = result["micro"]
            print(
                f"    P={m['precision']:.4f}  R={m['recall']:.4f}  "
                f"F1={m['f1']:.4f}  "
                f"TP={m['tp']}  FP={m['fp']}  FN={m['fn']}"
            )
        else:
            print(f"\n  {'Label':<20} {'P':>7} {'R':>7} {'F1':>7} {'TP':>5} {'FP':>5} {'FN':>5}")
            print(f"  {'-'*20} {'-'*7} {'-'*7} {'-'*7} {'-'*5} {'-'*5} {'-'*5}")
            for lbl, m in result["per_label"].items():
                print(
                    f"  {lbl:<20} {m['precision']:>7.4f} {m['recall']:>7.4f} "
                    f"{m['f1']:>7.4f} {m['tp']:>5} {m['fp']:>5} {m['fn']:>5}"
                )
            m = result["micro"]
            print(f"  {'--- micro ---':<20} {m['precision']:>7.4f} {m['recall']:>7.4f} "
                  f"{m['f1']:>7.4f} {m['tp']:>5} {m['fp']:>5} {m['fn']:>5}")

        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m preprocessing.artifact_extractor.evaluate",
        description=(
            "Artifact Extractor Evaluation Harness. "
            "Requires ARGUS_RUN_MODEL_INTEGRATION_TESTS=1 and cached GLiNER weights."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--split",
        choices=["validation", FROZEN_TEST_SPLIT, "adversarial_holdout"],
        help="Evaluate a single split.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Evaluate all three splits.",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        default=False,
        help="Do not append this run to eval_history.jsonl.",
    )
    parser.add_argument(
        "--json-out",
        metavar="FILE",
        default=None,
        help="Write the full stamped record as JSON to this file.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    if not os.environ.get("ARGUS_RUN_MODEL_INTEGRATION_TESTS"):
        print(
            "ERROR: Set ARGUS_RUN_MODEL_INTEGRATION_TESTS=1 to run the evaluation harness.\n"
            "  The harness requires the real cached GLiNER model weights.",
            file=sys.stderr,
        )
        return 1

    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    splits: Optional[List[str]] = None if args.all else [args.split]
    write_history = not args.no_history

    print("[evaluate.py] Loading ArtifactExtractor …", flush=True)
    harness = EvaluationHarness()

    if not harness._extractor.health_check():
        print(
            "ERROR: ArtifactExtractor health check failed — GLiNER model is not available.\n"
            f"  Model state: {harness._extractor.get_model_state()}\n"
            f"  Degraded reason: {harness._extractor._degraded_reason}",
            file=sys.stderr,
        )
        return 1

    record = harness.run_full_report(splits=splits, write_history=write_history)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[evaluate.py] Full record written to {out_path}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
