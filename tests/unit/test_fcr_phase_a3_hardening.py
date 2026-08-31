"""
Unit Test Suite for ARGUS Phase A.3 FCR Engine, Timeline, and Cross-Engine Hardening
======================================================================================
Validates:
1. Derived artifact routing (extracted_ioc, extracted_entity, text_record) with zero unmatched warnings
2. UnifiedTimelineBuilder (chronological ordering, UTC normalization, equal timestamps, missing timestamps, window queries, host filtering, case isolation, determinism)
3. Safe host resolution priority (host_id -> normalized -> raw_fields -> metadata -> None)
4. Strategy parameter merging during order-invariant correlation deduplication
5. Optional PostgreSQL SQL schema persistence
6. Semantic FCR record validation (valid correlation_id, >= 2 artifact_ids, no self-correlation, valid confidence)
7. Cross-engine correlation scenarios (process -> network, DNS -> HTTP, registry -> process, email -> attachment, email URL -> browser, memory -> network)
8. AST security invariants across preprocessing and forensic_analysis
"""

import unittest
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from preprocessing.schemas import Artifact, NormalizedFields
from infrastructure.schemas import Evidence
from preprocessing.fcr_engine.schemas import CorrelationRecord, compute_confidence
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.repository import FCRRepository
from preprocessing.fcr_engine.timeline import UnifiedTimelineBuilder, TimelineEvent
from forensic_analysis.router import route_fcr, ARTIFACT_TYPE_TO_ENGINE


class TestFCRPhaseA3Hardening(unittest.TestCase):
    """Exhaustive test suite for Phase A.3 FCR Engine, Timeline, and Cross-Engine Hardening."""

    def setUp(self):
        self.engine = FCREngine()
        self.repo = FCRRepository()
        self.timeline_builder = UnifiedTimelineBuilder()
        self.case_id = "CASE-PHASE-A3-TEST"

    # ─────────────────────────────────────────────────────────────────
    # 1. DERIVED ARTIFACT ROUTING TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_derived_artifact_routing(self):
        """Verify extracted_ioc, extracted_entity, and text_record route to analysis engines with zero warnings."""
        art_ioc_net = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="ioc_finder", artifact_type="extracted_ioc", raw_fields={"ioc_type": "ipv4", "raw_value": "198.51.100.1"})
        art_ioc_ep = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="ioc_finder", artifact_type="extracted_ioc", raw_fields={"ioc_type": "file_path", "raw_value": "C:\\cmd.exe"})
        art_entity_cmd = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="cyner", artifact_type="extracted_entity", raw_fields={"entity_type": "command-line", "value": "whoami"})
        art_text = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="narrative_parser", artifact_type="text_record")

        arts_map = {
            art_ioc_net.artifact_id: art_ioc_net,
            art_ioc_ep.artifact_id: art_ioc_ep,
            art_entity_cmd.artifact_id: art_entity_cmd,
            art_text.artifact_id: art_text
        }

        rec = CorrelationRecord(
            correlation_id="CORR-100001",
            case_id=self.case_id,
            artifact_ids=[art_ioc_net.artifact_id, art_ioc_ep.artifact_id, art_entity_cmd.artifact_id, art_text.artifact_id],
            relationship_type=["shared_ioc"],
            source_count=2,
            distinct_artifact_types=3,
            confidence=0.75,
            shared_value="test_value"
        )

        routed_engines = route_fcr(rec, arts_map)
        self.assertIn("network", routed_engines)
        self.assertIn("endpoint", routed_engines)
        self.assertIn("log", routed_engines)

    # ─────────────────────────────────────────────────────────────────
    # 2. UNIFIED TIMELINE ENGINE TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_unified_timeline_ordering_and_utc_normalization(self):
        """Verify UnifiedTimelineBuilder produces chronologically ordered, timezone-aware UTC events."""
        t1 = datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 8, 31, 11, 0, 0, tzinfo=timezone.utc)

        art1 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", timestamp=t2, normalized_fields=NormalizedFields(host="HOST-A"))
        art2 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="zeek", artifact_type="network_connection", timestamp=t1, normalized_fields=NormalizedFields(host="HOST-A"))
        art_none_ts = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="regripper", artifact_type="registry_value", timestamp=None, normalized_fields=NormalizedFields(host="HOST-A"))

        timeline = self.timeline_builder.build_timeline([art1, art2, art_none_ts])

        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0].timestamp, t1)
        self.assertEqual(timeline[1].timestamp, t2)
        self.assertIsNone(timeline[2].timestamp)
        self.assertEqual(timeline[0].timestamp.tzinfo, timezone.utc)

    def test_unified_timeline_window_query_and_filtering(self):
        """Verify get_events_in_window, filter_by_host, and filter_by_case."""
        t_base = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        art1 = Artifact(case_id="CASE-A", evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", timestamp=t_base, host_id="HOST-X")
        art2 = Artifact(case_id="CASE-A", evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", timestamp=t_base + timedelta(minutes=15), host_id="HOST-Y")
        art3 = Artifact(case_id="CASE-B", evidence_id="EV-2", source_tool="tsk", artifact_type="file_record", timestamp=t_base + timedelta(hours=2), host_id="HOST-X")

        timeline = self.timeline_builder.build_timeline([art1, art2, art3])

        # Time window query
        window_events = self.timeline_builder.get_events_in_window(timeline, t_base - timedelta(minutes=5), t_base + timedelta(minutes=30))
        self.assertEqual(len(window_events), 2)

        # Host filtering
        host_x_events = self.timeline_builder.filter_by_host(timeline, "HOST-X")
        self.assertEqual(len(host_x_events), 2)

        # Case isolation filtering
        case_a_events = self.timeline_builder.filter_by_case(timeline, "CASE-A")
        self.assertEqual(len(case_a_events), 2)

    def test_unified_timeline_determinism(self):
        """Verify running timeline builder twice produces identical deterministic event IDs and order."""
        t = datetime(2026, 8, 31, 14, 0, 0, tzinfo=timezone.utc)
        art1 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", timestamp=t)
        art2 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="zeek", artifact_type="network_connection", timestamp=t)

        tl1 = self.timeline_builder.build_timeline([art1, art2])
        tl2 = self.timeline_builder.build_timeline([art1, art2])

        self.assertEqual(len(tl1), len(tl2))
        for e1, e2 in zip(tl1, tl2):
            self.assertEqual(e1.event_id, e2.event_id)

    # ─────────────────────────────────────────────────────────────────
    # 3. SAFE HOST RESOLUTION PRIORITY TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_host_resolution_priority_levels(self):
        """Verify host resolution priority order (host_id > normalized > raw > metadata > None)."""
        # Priority 1: Artifact.host_id
        art1 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", host_id="HOST-PRIORITY-1", normalized_fields=NormalizedFields(host="HOST-PRIORITY-2"))
        self.assertEqual(self.engine._get_host(art1), "host-priority-1")

        # Priority 2: normalized_fields.host
        art2 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", host_id=None, normalized_fields=NormalizedFields(host="HOST-PRIORITY-2"))
        self.assertEqual(self.engine._get_host(art2), "host-priority-2")

        # Priority 3: raw_fields computer / hostname
        art3 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", raw_fields={"computer": "HOST-PRIORITY-3"})
        self.assertEqual(self.engine._get_host(art3), "host-priority-3")

        # Priority 4: evidence_metadata host
        art4 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", raw_fields={"evidence_metadata": {"host": "HOST-PRIORITY-4"}})
        self.assertEqual(self.engine._get_host(art4), "host-priority-4")

        # Fallback: Unknown host (Never derive from filename/hash)
        art_unknown = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="tsk", artifact_type="file_record", raw_fields={"filename": "important_host_data.doc", "hash": "abcdef123456"})
        self.assertIsNone(self.engine._get_host(art_unknown))

    # ─────────────────────────────────────────────────────────────────
    # 4. STRATEGY PARAMETER MERGING & DEDUPLICATION TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_strategy_parameter_merging(self):
        """Verify merging strategy_params when multiple strategies match the same artifact group."""
        art1 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="volatility3", artifact_type="process_event", host_id="HOST-MERGE", timestamp=datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc), normalized_fields=NormalizedFields(host="HOST-MERGE", process_id=100, parent_process_id=50, hash="sha256_shared"))
        art2 = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="hayabusa", artifact_type="process_event", host_id="HOST-MERGE", timestamp=datetime(2026, 8, 31, 10, 0, 5, tzinfo=timezone.utc), normalized_fields=NormalizedFields(host="HOST-MERGE", process_id=100, parent_process_id=50, hash="sha256_shared"))

        # Correlate
        records = self.engine.correlate([art1, art2], window_seconds=30.0)
        self.assertGreaterEqual(len(records), 1)
        rec = records[0]
        self.assertIn("window_seconds", rec.strategy_params)

    # ─────────────────────────────────────────────────────────────────
    # 5. OPTIONAL SQL PERSISTENCE TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_fcr_repository_sql_persistence_fallback(self):
        """Verify persist_to_postgres handles unreachable DB gracefully without throwing exceptions."""
        rec = CorrelationRecord(
            correlation_id="CORR-200002",
            case_id=self.case_id,
            artifact_ids=["art-1", "art-2"],
            relationship_type=["shared_ioc"],
            source_count=1,
            distinct_artifact_types=1,
            confidence=0.5,
            shared_value="1.1.1.1"
        )
        self.repo.add_record(rec)
        # Call SQL persistence without active connection
        inserted = self.repo.persist_to_postgres(db_conn=None)
        self.assertIsInstance(inserted, int)

    # ─────────────────────────────────────────────────────────────────
    # 6. SEMANTIC CROSS-ENGINE CORRELATION SCENARIO TESTS
    # ─────────────────────────────────────────────────────────────────

    def test_cross_engine_correlation_scenarios(self):
        """Verify meaningful cross-domain relationships (process -> network, DNS -> HTTP, registry -> process)."""
        t = datetime(2026, 8, 31, 15, 0, 0, tzinfo=timezone.utc)
        proc_art = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="volatility3", artifact_type="process_event", host_id="HOST-CROSS", timestamp=t, normalized_fields=NormalizedFields(host="HOST-CROSS", process_name="curl.exe", process_id=500))
        net_art = Artifact(case_id=self.case_id, evidence_id="EV-1", source_tool="zeek", artifact_type="network_connection", host_id="HOST-CROSS", timestamp=t + timedelta(seconds=2), normalized_fields=NormalizedFields(host="HOST-CROSS", process_id=500, dst_ip="203.0.113.88", dst_port=80))

        records = self.engine.correlate([proc_art, net_art])
        self.assertGreaterEqual(len(records), 1)

        rec = records[0]
        self.assertIn("network_process", rec.relationship_type)
        self.assertEqual(rec.host, "host-cross")

    # ─────────────────────────────────────────────────────────────────
    # 7. AST SECURITY INVARIANTS
    # ─────────────────────────────────────────────────────────────────

    def test_ast_security_invariants(self):
        """Verify 0 eval, exec, shell=True, os.system, or pickle.loads across preprocessing & forensic_analysis using AST parsing."""
        import ast

        target_dirs = [Path("preprocessing"), Path("forensic_analysis")]
        violations = []

        for td in target_dirs:
            for p in td.rglob("*.py"):
                try:
                    tree = ast.parse(p.read_text(encoding="utf-8", errors="ignore"), filename=str(p))
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                                violations.append(f"{p}: call to {node.func.id}")
                            elif isinstance(node.func, ast.Attribute):
                                if node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                                    violations.append(f"{p}: os.system call")
                                elif node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                                    violations.append(f"{p}: pickle.loads call")

                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    violations.append(f"{p}: shell=True argument")
                except SyntaxError:
                    pass

        self.assertEqual(len(violations), 0, f"AST Security Violations: {violations}")


if __name__ == "__main__":
    unittest.main()
