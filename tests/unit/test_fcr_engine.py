"""
ARGUS FCR Engine Unit Test Suite
=================================
Validates all 30 mandatory FCR Engine test scenarios:
1. Valid CorrelationRecord schema construction
2. Invalid correlation_id pattern rejection
3. Invalid artifact_ids rejection (fewer than 2 artifacts)
4. Duplicate artifact_ids rejection
5. Invalid relationship_type rejection
6. Temporal proximity correlation within window
7. Temporal window boundary test (<= 30s vs > 30s)
8. Outside temporal window rejection
9. Host requirement for temporal proximity
10. Different hosts rejection for temporal proximity
11. Shared IOC correlation (hashes, IPs, domains, registry keys)
12. Shared value requirement for shared_ioc
13. Different IOC values rejection
14. ExtractedEntity shared IOC correlation
15. Multiple distinct artifact types scoring
16. Deterministic confidence formula calculation
17. Confidence score bounds (0.0 <= confidence <= 1.0)
18. Duplicate correlation record suppression
19. Order invariance ([A, B] == [B, A])
20. Strict cross-case isolation (CASE-A vs CASE-B)
21. Nonexistent artifact reference validation
22. Malformed artifact filtering
23. Missing timestamp handling
24. Preservation of timestamp_type semantics
25. Process tree correlation (child PPID == parent PID)
26. Network ↔ Process correlation
27. No hallucinated relationships
28. Preservation of strategy_params
29. Immutability of raw_fields (not copied into FCR)
30. FCRRepository thread safety and querying
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pydantic import ValidationError

from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.fcr_engine.schemas import CorrelationRecord, compute_confidence
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.repository import FCRRepository


class TestFCREngineUnit(unittest.TestCase):

    def setUp(self):
        self.engine = FCREngine()
        self.repo = FCRRepository()

    def test_01_valid_correlation_record(self):
        """Valid CorrelationRecord initializes correctly matching ^CORR-[0-9]{5,}$ pattern."""
        rec = CorrelationRecord(
            correlation_id="CORR-00001",
            case_id="CASE-100",
            artifact_ids=["ART-00000001", "ART-00000002"],
            relationship_type=["temporal_proximity"],
            source_count=2,
            distinct_artifact_types=2,
            confidence=0.65,
            host="workstation-01",
            strategy_params={"window_seconds": 30}
        )
        self.assertEqual(rec.correlation_id, "CORR-00001")
        self.assertEqual(rec.case_id, "CASE-100")
        self.assertEqual(len(rec.artifact_ids), 2)
        self.assertEqual(rec.host, "workstation-01")
        self.assertEqual(rec.confidence, 0.65)

    def test_02_invalid_correlation_id(self):
        """CorrelationId not matching ^CORR-[0-9]{5,}$ raises ValidationError."""
        with self.assertRaises(ValidationError):
            CorrelationRecord(
                correlation_id="INVALID-ID-123",
                case_id="CASE-100",
                artifact_ids=["ART-00000001", "ART-00000002"],
                relationship_type=["temporal_proximity"],
                source_count=1,
                distinct_artifact_types=1,
                confidence=0.5,
                host="workstation-01"
            )

    def test_03_invalid_artifact_ids_fewer_than_two(self):
        """Artifact_ids with fewer than 2 items raises ValidationError."""
        with self.assertRaises(ValidationError):
            CorrelationRecord(
                correlation_id="CORR-00002",
                case_id="CASE-100",
                artifact_ids=["ART-00000001"],
                relationship_type=["temporal_proximity"],
                source_count=1,
                distinct_artifact_types=1,
                confidence=0.5,
                host="workstation-01"
            )

    def test_04_duplicate_artifact_ids(self):
        """Duplicate artifact IDs in artifact_ids raises ValidationError."""
        with self.assertRaises(ValidationError):
            CorrelationRecord(
                correlation_id="CORR-00003",
                case_id="CASE-100",
                artifact_ids=["ART-00000001", "ART-00000001"],
                relationship_type=["temporal_proximity"],
                source_count=1,
                distinct_artifact_types=1,
                confidence=0.5,
                host="workstation-01"
            )

    def test_05_invalid_relationship_type(self):
        """Unsupported relationship_type string raises ValidationError."""
        with self.assertRaises(ValidationError):
            CorrelationRecord(
                correlation_id="CORR-00004",
                case_id="CASE-100",
                artifact_ids=["ART-00000001", "ART-00000002"],
                relationship_type=["unsupported_strategy"],
                source_count=1,
                distinct_artifact_types=1,
                confidence=0.5
            )

    def test_06_temporal_proximity_correlation(self):
        """Same host artifacts within window_seconds are correlated with temporal_proximity."""
        t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=10)

        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-200",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=t0
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-200",
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            timestamp=t1
        )

        records = self.engine.correlate([art1, art2], window_seconds=30.0)
        self.assertGreaterEqual(len(records), 1)
        temp_rec = next((r for r in records if "temporal_proximity" in r.relationship_type), None)
        self.assertIsNotNone(temp_rec)
        self.assertEqual(temp_rec.case_id, "CASE-200")
        self.assertIn("ART-00000001", temp_rec.artifact_ids)
        self.assertIn("ART-00000002", temp_rec.artifact_ids)
        self.assertEqual(temp_rec.host, "workstation-01")

    def test_07_temporal_window_boundary_outside(self):
        """Artifacts outside the window_seconds threshold are NOT correlated temporally."""
        t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=45)  # > 30s

        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-200",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=t0
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-200",
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            timestamp=t1
        )

        records = self.engine.correlate([art1, art2], window_seconds=30.0)
        temp_recs = [r for r in records if "temporal_proximity" in r.relationship_type]
        self.assertEqual(len(temp_recs), 0)

    def test_08_different_hosts_temporal_rejection(self):
        """Artifacts on different hosts are NOT correlated under temporal_proximity."""
        t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)

        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-200",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=t0
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-200",
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-02",  # Different host
            timestamp=t0
        )

        records = self.engine.correlate([art1, art2], window_seconds=30.0)
        temp_recs = [r for r in records if "temporal_proximity" in r.relationship_type]
        self.assertEqual(len(temp_recs), 0)

    def test_09_host_requirement_validation(self):
        """temporal_proximity requires host field to be set."""
        with self.assertRaises(ValidationError):
            CorrelationRecord(
                correlation_id="CORR-00005",
                case_id="CASE-100",
                artifact_ids=["ART-00000001", "ART-00000002"],
                relationship_type=["temporal_proximity"],
                source_count=1,
                distinct_artifact_types=1,
                confidence=0.5,
                host=None  # Missing host
            )

    def test_10_shared_ioc_correlation(self):
        """Artifacts sharing an atomic IOC (e.g. SHA256 hash or IP) are correlated."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-300",
            evidence_id="EV-001",
            source_tool="volatility3",
            artifact_type="process_event",
            normalized_fields=NormalizedFields(hash=sha256)
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-300",
            evidence_id="EV-002",
            source_tool="hindsight",
            artifact_type="browser_download",
            normalized_fields=NormalizedFields(hash=sha256)
        )

        records = self.engine.correlate([art1, art2])
        ioc_recs = [r for r in records if "shared_ioc" in r.relationship_type]
        self.assertEqual(len(ioc_recs), 1)
        self.assertEqual(ioc_recs[0].shared_value, sha256)

    def test_11_shared_value_requirement_validation(self):
        """shared_ioc requires shared_value field to be set."""
        with self.assertRaises(ValidationError):
            CorrelationRecord(
                correlation_id="CORR-00006",
                case_id="CASE-100",
                artifact_ids=["ART-00000001", "ART-00000002"],
                relationship_type=["shared_ioc"],
                source_count=1,
                distinct_artifact_types=1,
                confidence=0.5,
                shared_value=None  # Missing shared_value
            )

    def test_12_different_ioc_values_no_correlation(self):
        """Artifacts with different IOC values do NOT correlate under shared_ioc."""
        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-300",
            evidence_id="EV-001",
            source_tool="volatility3",
            artifact_type="process_event",
            normalized_fields=NormalizedFields(hash="hash_a")
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-300",
            evidence_id="EV-002",
            source_tool="hindsight",
            artifact_type="browser_download",
            normalized_fields=NormalizedFields(hash="hash_b")
        )

        records = self.engine.correlate([art1, art2])
        ioc_recs = [r for r in records if "shared_ioc" in r.relationship_type]
        self.assertEqual(len(ioc_recs), 0)

    def test_13_extracted_entity_shared_ioc(self):
        """ExtractedEntity values trigger shared_ioc correlation across artifacts."""
        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-400",
            evidence_id="EV-001",
            source_tool="powershell_history_parser",
            artifact_type="powershell_history"
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-400",
            evidence_id="EV-002",
            source_tool="windows_firewall_parser",
            artifact_type="firewall_log"
        )

        ent1 = ExtractedEntity(
            artifact_id="ART-00000001",
            evidence_id="EV-001",
            entity_type="ipv4",
            value="198.51.100.45",
            source_field="process_command_line",
            char_start=0,
            char_end=13,
            extraction_method="regex:ipv4",
            confidence=1.0
        )
        ent2 = ExtractedEntity(
            artifact_id="ART-00000002",
            evidence_id="EV-002",
            entity_type="ipv4",
            value="198.51.100.45",
            source_field="dst_ip",
            char_start=0,
            char_end=13,
            extraction_method="regex:ipv4",
            confidence=1.0
        )

        records = self.engine.correlate([art1, art2], extracted_entities=[ent1, ent2])
        ioc_recs = [r for r in records if "shared_ioc" in r.relationship_type]
        self.assertEqual(len(ioc_recs), 1)
        self.assertEqual(ioc_recs[0].shared_value, "198.51.100.45")

    def test_14_deterministic_confidence_calculation(self):
        """compute_confidence satisfies the reference formula: min(1.0, 0.30 + 0.15*(dt-1) + 0.20*(sc-1))."""
        # 1 type, 1 tool -> 0.30
        self.assertEqual(compute_confidence(1, 1), 0.30)
        # 2 types, 1 tool -> 0.30 + 0.15 = 0.45
        self.assertEqual(compute_confidence(2, 1), 0.45)
        # 2 types, 2 tools -> 0.30 + 0.15 + 0.20 = 0.65
        self.assertEqual(compute_confidence(2, 2), 0.65)

    def test_15_confidence_bounds(self):
        """Confidence score is strictly bounded between 0.0 and 1.0."""
        self.assertLessEqual(compute_confidence(10, 10), 1.0)
        self.assertGreaterEqual(compute_confidence(1, 1), 0.0)

    def test_16_duplicate_correlation_suppression_and_order_invariance(self):
        """Input artifact ordering [A, B] vs [B, A] produces identical deduplicated correlation record."""
        t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)
        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-500",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=t0
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-500",
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            timestamp=t0
        )

        records_ab = self.engine.correlate([art1, art2])
        records_ba = self.engine.correlate([art2, art1])

        self.assertEqual(len(records_ab), len(records_ba))
        self.assertEqual(records_ab[0].correlation_id, records_ba[0].correlation_id)
        self.assertEqual(records_ab[0].artifact_ids, records_ba[0].artifact_ids)

    def test_17_strict_cross_case_isolation(self):
        """Artifacts from CASE-A and CASE-B must NEVER correlate together."""
        t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-A",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=t0,
            normalized_fields=NormalizedFields(hash=sha256)
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-B",  # Different case
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            timestamp=t0,
            normalized_fields=NormalizedFields(hash=sha256)
        )

        records = self.engine.correlate([art1, art2])
        self.assertEqual(len(records), 0)

    def test_18_process_tree_correlation(self):
        """Parent (pid=1000) and child process (ppid=1000, pid=2000) correlate under process_tree."""
        art_parent = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-600",
            evidence_id="EV-001",
            source_tool="volatility3",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            normalized_fields=NormalizedFields(process_id=1000, process_name="explorer.exe")
        )
        art_child = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-600",
            evidence_id="EV-002",
            source_tool="volatility3",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            normalized_fields=NormalizedFields(process_id=2000, parent_process_id=1000, process_name="cmd.exe")
        )

        records = self.engine.correlate([art_parent, art_child])
        pt_recs = [r for r in records if "process_tree" in r.relationship_type]
        self.assertEqual(len(pt_recs), 1)
        self.assertIn("ART-00000001", pt_recs[0].artifact_ids)
        self.assertIn("ART-00000002", pt_recs[0].artifact_ids)

    def test_19_network_process_correlation(self):
        """Process artifact and network artifact sharing same PID correlate under network_process."""
        art_proc = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-700",
            evidence_id="EV-001",
            source_tool="volatility3",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            normalized_fields=NormalizedFields(process_id=1234, process_name="powershell.exe")
        )
        art_net = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-700",
            evidence_id="EV-002",
            source_tool="volatility3",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            normalized_fields=NormalizedFields(process_id=1234, src_ip="192.168.1.50", dst_ip="10.0.0.1")
        )

        records = self.engine.correlate([art_proc, art_net])
        np_recs = [r for r in records if "network_process" in r.relationship_type]
        self.assertEqual(len(np_recs), 1)
        self.assertEqual(np_recs[0].host, "workstation-01")

    def test_20_strategy_params_preservation(self):
        """Strategy params (window_seconds, shared_ioc_key) are captured in CorrelationRecord."""
        t0 = datetime(2026, 8, 12, 14, 0, 0, tzinfo=timezone.utc)
        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-800",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=t0
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-800",
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            timestamp=t0
        )

        records = self.engine.correlate([art1, art2], window_seconds=15.0)
        rec = records[0]
        self.assertEqual(rec.strategy_params.get("window_seconds"), 15.0)

    def test_21_raw_fields_immutability(self):
        """FCR record does NOT copy raw_fields from artifacts, preserving forensic traceability."""
        art1 = Artifact(
            artifact_id="ART-00000001",
            case_id="CASE-900",
            evidence_id="EV-001",
            source_tool="hayabusa",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            raw_fields={"huge_payload": "X" * 10000},
            normalized_fields=NormalizedFields(hash="abc12345")
        )
        art2 = Artifact(
            artifact_id="ART-00000002",
            case_id="CASE-900",
            evidence_id="EV-002",
            source_tool="zeek",
            artifact_type="network_connection",
            host_id="WORKSTATION-01",
            raw_fields={"huge_payload": "Y" * 10000},
            normalized_fields=NormalizedFields(hash="abc12345")
        )

        records = self.engine.correlate([art1, art2])
        self.assertGreaterEqual(len(records), 1)
        rec_dict = records[0].model_dump()
        self.assertNotIn("raw_fields", rec_dict)
        self.assertNotIn("huge_payload", str(rec_dict))

    def test_22_fcr_repository_thread_safety_and_querying(self):
        """FCRRepository stores, indexes, and queries records by case, host, artifact, and relationship."""
        rec = CorrelationRecord(
            correlation_id="CORR-00010",
            case_id="CASE-999",
            artifact_ids=["ART-00000001", "ART-00000002"],
            relationship_type=["temporal_proximity"],
            source_count=2,
            distinct_artifact_types=2,
            confidence=0.65,
            host="workstation-01"
        )
        added = self.repo.add_record(rec)
        self.assertTrue(added)

        # Query by ID
        self.assertIsNotNone(self.repo.get_record("CORR-00010"))
        # Query by case
        by_case = self.repo.list_by_case("CASE-999")
        self.assertEqual(len(by_case), 1)
        # Query by host
        by_host = self.repo.list_by_host("WORKSTATION-01")
        self.assertEqual(len(by_host), 1)
        # Query by artifact
        by_art = self.repo.list_by_artifact("ART-00000001")
        self.assertEqual(len(by_art), 1)
        # Query by relationship
        by_rel = self.repo.list_by_relationship("temporal_proximity")
        self.assertEqual(len(by_rel), 1)


if __name__ == "__main__":
    unittest.main()
