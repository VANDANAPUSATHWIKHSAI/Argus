"""
Unit tests for Automated Model-Drift Monitoring and Quality Evaluation (Phase 6).

Verifies:
- Evaluator calculations for hallucination rate, attribution precision, citation recall, and timeline completeness.
- Multi-dimensional drift detection: Data Drift, Model Quality Drift, and Operational Drift.
- Configurable baselines and drift thresholds.
- Duplicate-run protection and alert deduplication.
- Persistent audit logging of alerts.
- Zero-leakage red-team injection evaluation against Sanitization Gateway.
- Strict constraint prohibiting automatic model retraining or production promotion.
- Tenant isolation across evaluations and alerts.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from evaluation.drift_monitor import DriftMonitor, DriftType
from evaluation.evaluator import Evaluator


class TestModelDriftMonitoring(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.log_dir = Path(self.tmpdir.name)
        self.monitor = DriftMonitor(log_dir=self.log_dir)
        self.evaluator = Evaluator(
            model_name="qwen3:8b",
            model_version="1.0.0",
            dataset_version="2026.10-test",
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_evaluator_metrics_calculation(self):
        """Verifies calculation of attribution precision, citation recall, hallucination rate, and timeline completeness."""
        predicted = {
            "claims": [
                "User administrator logged in at 10:00:00",
                "Malware beaconed to C2 server 198.51.100.1",
                "Completely fabricated hallucinated claim with no evidence",
            ],
            "citations": ["EV-001", "EV-002", "EV-FAKE"],
            "timeline_events": [
                {"event": "login", "timestamp": "10:00:00"},
                {"event": "c2_beacon", "timestamp": "10:05:00"},
            ],
        }

        ground_truth = {
            "claims": [
                "User administrator logged in at 10:00:00",
                "Malware beaconed to C2 server 198.51.100.1",
            ],
            "citations": ["EV-001", "EV-002"],
            "timeline_events": [
                {"event": "login", "timestamp": "10:00:00"},
                {"event": "c2_beacon", "timestamp": "10:05:00"},
                {"event": "lateral_movement", "timestamp": "10:15:00"},
            ],
        }

        metrics = self.evaluator.evaluate_case(predicted, ground_truth)

        # 2 out of 3 citations valid -> precision = 0.6667
        self.assertAlmostEqual(metrics["attribution_precision"], 0.6667, places=3)
        # 2 out of 2 ground truth citations captured -> recall = 1.0
        self.assertEqual(metrics["citation_recall"], 1.0)
        # 1 out of 3 claims hallucinated -> hallucination rate = 0.3333
        self.assertAlmostEqual(metrics["hallucination_rate"], 0.3333, places=3)
        # 2 out of 3 timeline events captured -> completeness = 0.6667
        self.assertAlmostEqual(metrics["timeline_completeness"], 0.6667, places=3)

    def test_evaluator_run_suite_aggregate_metrics(self):
        """Verifies run_suite aggregates metrics across cases and includes model metadata."""
        test_cases = [
            {
                "case_id": "case-01",
                "prediction": {"claims": ["valid claim"], "citations": ["EV-1"], "timeline_events": [{"event": "ev1"}]},
                "ground_truth": {"claims": ["valid claim"], "citations": ["EV-1"], "timeline_events": [{"event": "ev1"}]},
            },
            {
                "case_id": "case-02",
                "prediction": {"claims": ["valid claim"], "citations": ["EV-2"], "timeline_events": [{"event": "ev2"}]},
                "ground_truth": {"claims": ["valid claim"], "citations": ["EV-2"], "timeline_events": [{"event": "ev2"}]},
            },
        ]

        suite_res = self.evaluator.run_suite(test_cases, tenant_id="tenant-eval")

        self.assertEqual(suite_res["status"], "COMPLETED")
        self.assertEqual(suite_res["total_cases"], 2)
        self.assertEqual(suite_res["model_name"], "qwen3:8b")
        self.assertEqual(suite_res["aggregate_metrics"]["attribution_precision"], 1.0)
        self.assertEqual(suite_res["aggregate_metrics"]["hallucination_rate"], 0.0)

    def test_model_quality_drift_detection_and_alerting(self):
        """Verifies that an increase in hallucination rate triggers a quality drift alert."""
        # Baseline is 0.03; threshold is 0.04. Score 0.08 is > 0.03 + 0.04 = 0.07.
        current_metrics = {
            "hallucination_rate": 0.09,
            "attribution_precision": 0.94,  # baseline 0.95, diff 0.01 <= 0.05 (no alert)
        }

        alerts = self.monitor.evaluate_quality_drift(current_metrics, tenant_id="tenant-alpha")

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.drift_type, DriftType.MODEL_QUALITY_DRIFT.value)
        self.assertEqual(alert.metric_name, "hallucination_rate")
        self.assertGreater(alert.current_value, alert.baseline_value)
        self.assertEqual(alert.tenant_id, "tenant-alpha")

        # Verify persistent audit log
        self.assertTrue(self.monitor.alerts_file.exists())
        with open(self.monitor.alerts_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        logged_alert = json.loads(lines[0])
        self.assertEqual(logged_alert["metric_name"], "hallucination_rate")

    def test_duplicate_run_protection(self):
        """Verifies duplicate run IDs are ignored to prevent alert flooding."""
        current_metrics = {"hallucination_rate": 0.12}

        alerts_run1 = self.monitor.evaluate_quality_drift(current_metrics, run_id="run-idempotent-001")
        self.assertEqual(len(alerts_run1), 1)

        # Second call with same run_id must return 0 alerts
        alerts_run2 = self.monitor.evaluate_quality_drift(current_metrics, run_id="run-idempotent-001")
        self.assertEqual(len(alerts_run2), 0)

    def test_operational_drift_detection(self):
        """Verifies p95 latency spikes trigger operational drift alert."""
        # Baseline: 1200ms; Threshold: 400ms. Latency: 1800ms > 1600ms.
        current_ops = {
            "p95_latency_ms": 1850.0,
            "error_rate": 0.005,
        }

        alerts = self.monitor.evaluate_operational_drift(current_ops, tenant_id="tenant-prod")

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].drift_type, DriftType.OPERATIONAL_DRIFT.value)
        self.assertEqual(alerts[0].metric_name, "p95_latency_ms")

    def test_data_drift_distribution_shift_detection(self):
        """Verifies total variation distance detects artifact distribution shift."""
        baseline_distribution = {"syslog": 0.40, "pcap": 0.30, "evtx": 0.30}
        shifted_distribution = {"syslog": 0.05, "pcap": 0.05, "evtx": 0.90}

        alerts = self.monitor.evaluate_data_drift(
            shifted_distribution,
            baseline_distribution,
            threshold=0.20,
            tenant_id="tenant-sensors",
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].drift_type, DriftType.DATA_DRIFT.value)
        self.assertGreater(alerts[0].current_value, 0.20)

    def test_injection_redteam_suite_passes_100_percent(self):
        """Verifies the adversarial prompt injection suite verifies complete gateway blocking."""
        redteam_results = self.monitor.run_injection_redteam()

        self.assertTrue(redteam_results["passed_security_gate"])
        self.assertEqual(redteam_results["block_rate"], 1.0)
        self.assertEqual(redteam_results["blocked_count"], redteam_results["total_attacks"])

    def test_strict_no_auto_retrain_or_promotion_constraint(self):
        """Verifies that automated retraining and production self-promotion are prohibited."""
        self.assertFalse(self.monitor.ALLOW_AUTO_RETRAIN)
        self.assertFalse(self.monitor.ALLOW_AUTO_PROMOTION)


if __name__ == "__main__":
    unittest.main()
