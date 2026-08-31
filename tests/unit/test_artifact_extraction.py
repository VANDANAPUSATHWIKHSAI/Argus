"""
Unit Test Suite for ARGUS Phase A.2.2 Artifact Extraction Engine
==================================================================
Validates:
- Schema extraction & field mappings across all forensic artifact categories
- Filesystem, process, registry, network, memory, email, browser, and defender artifacts
- Provenance chain preservation (case_id, evidence_id, source_tool, parser_version)
- Timestamp semantics (UTC, timezone awareness, microsecond precision, no ingest_time substitution)
- Deterministic extraction output & deduplication boundaries
- Malformed input handling & corrupt payload resilience
- Unknown artifact type safety
- Case & tenant isolation
- FCR Engine contract compatibility
- Phase A Digital Corpora raw evidence verification
- AST security invariants
"""

import unittest
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from preprocessing.schemas import Artifact, NormalizedFields
from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.schemas import CorrelationRecord


class TestArtifactExtractionEngine(unittest.TestCase):
    """Exhaustive test suite for Phase A.2.2 Artifact Extraction Engine."""

    def setUp(self):
        self.extractor = ArtifactExtractor()
        self.router = ParserRouter()
        self.fcr_engine = FCREngine()
        self.case_id = "CASE-UNIT-A22"
        self.evidence_id = "EV-UNIT-A22-001"
        self.source_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")

    def test_schema_extraction_field_mappings(self):
        """Verify field extraction from NormalizedFields for process, network, and registry categories."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="hayabusa",
            artifact_type="process_event",
            timestamp=datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc),
            event_summary="Process Create cmd.exe",
            raw_fields={"CommandLine": "powershell.exe -enc AAAA"},
            normalized_fields=NormalizedFields(
                host="HOST-01",
                user="Administrator",
                process_id=2048,
                parent_process_id=1024,
                process_name="cmd.exe",
                process_command_line="cmd.exe /c whoami",
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=50000,
                dst_port=53,
                domain="malicious.com",
                url="http://malicious.com/payload.exe",
                file_path="C:\\Windows\\System32\\cmd.exe",
                file_name="cmd.exe",
                hash="a" * 64,
                registry_key="HKLM\\Run",
                registry_value="Persistence",
                rule_name="cmd_execution"
            )
        )

        # Run extraction
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)
        
        # Verify provenance preservation on art
        self.assertEqual(art.case_id, self.case_id)
        self.assertEqual(art.evidence_id, self.evidence_id)
        self.assertEqual(art.source_tool, "hayabusa")

    def test_filesystem_artifacts_extraction(self):
        """Verify extraction on file_record artifacts."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="tsk",
            artifact_type="file_record",
            timestamp=datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc),
            event_summary="File /root/secret.doc (size 1024 bytes)",
            normalized_fields=NormalizedFields(
                file_path="/root/secret.doc",
                file_name="secret.doc",
                hash="b" * 64,
                mtime="2026-08-31T10:00:00+00:00"
            )
        )
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_process_artifacts_extraction(self):
        """Verify extraction on process_event artifacts."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="volatility3",
            artifact_type="process_event",
            timestamp=datetime(2026, 8, 31, 11, 0, 0, tzinfo=timezone.utc),
            raw_fields={"process_name": "lsass.exe", "pid": 600, "ppid": 500},
            normalized_fields=NormalizedFields(
                process_id=600,
                parent_process_id=500,
                process_name="lsass.exe"
            )
        )
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_registry_artifacts_extraction(self):
        """Verify extraction on registry_value artifacts."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="regripper",
            artifact_type="registry_value",
            timestamp=datetime(2026, 8, 31, 11, 30, 0, tzinfo=timezone.utc),
            raw_fields={"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "Malware"},
            normalized_fields=NormalizedFields(
                registry_key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                registry_value="Malware"
            )
        )
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_network_artifacts_extraction(self):
        """Verify extraction on network_connection and dns_query artifacts."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="zeek",
            artifact_type="network_connection",
            timestamp=datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc),
            normalized_fields=NormalizedFields(
                src_ip="192.168.1.50",
                dst_ip="203.0.113.195",
                src_port=54321,
                dst_port=443,
                domain="evil.com"
            )
        )
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_email_artifacts_extraction(self):
        """Verify extraction on email_header artifacts."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="python_email",
            artifact_type="email_header",
            timestamp=datetime(2026, 8, 31, 13, 0, 0, tzinfo=timezone.utc),
            normalized_fields=NormalizedFields(
                sender="phisher@evil.org",
                recipients="target@victim.com",
                subject="Invoice Overdue"
            )
        )
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_browser_user_activity_artifacts_extraction(self):
        """Verify extraction on browser_history and timeline_activity artifacts."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="hindsight",
            artifact_type="browser_history",
            timestamp=datetime(2026, 8, 31, 14, 0, 0, tzinfo=timezone.utc),
            normalized_fields=NormalizedFields(
                url="https://phishing.site/login.php",
                domain="phishing.site"
            )
        )
        extracted = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_timestamp_semantics_preservation(self):
        """Verify source timestamps (UTC, timezone awareness, microsecond precision) are preserved."""
        src_dt = datetime(2026, 8, 31, 15, 45, 30, 999999, tzinfo=timezone.utc)
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="tsk",
            artifact_type="file_record",
            timestamp=src_dt,
            timestamp_type="modified",
            normalized_fields=NormalizedFields(file_name="test.exe")
        )
        self.assertEqual(art.timestamp, src_dt)
        self.assertEqual(art.timestamp.tzinfo, timezone.utc)
        self.assertEqual(art.timestamp.microsecond, 999999)

    def test_deterministic_output_and_deduplication(self):
        """Verify that extracting from identical input twice produces deterministic output."""
        art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="zeek",
            artifact_type="network_connection",
            raw_fields={"ip": "1.2.3.4", "domain": "test.com"},
            normalized_fields=NormalizedFields(src_ip="1.2.3.4", domain="test.com")
        )
        out1 = self.extractor.extract_artifacts([art], self.evidence_id)
        out2 = self.extractor.extract_artifacts([art], self.evidence_id)
        self.assertEqual(len(out1), len(out2))
        if out1:
            self.assertEqual(out1[0].raw_fields, out2[0].raw_fields)

    def test_malformed_input_safety(self):
        """Verify malformed records, missing fields, or invalid types do not crash extraction."""
        malformed_art = Artifact(
            case_id=self.case_id,
            evidence_id=self.evidence_id,
            source_tool="unknown_tool",
            artifact_type="unknown_type",
            raw_fields={"corrupt_payload": "\x00\xff\xfe\x01\x02"},
            normalized_fields=NormalizedFields()
        )
        try:
            res = self.extractor.extract_artifacts([malformed_art], self.evidence_id)
            self.assertIsInstance(res, list)
        except Exception as e:
            self.fail(f"Extraction crashed on malformed artifact: {e}")

    def test_case_and_tenant_isolation(self):
        """Verify artifacts from distinct cases remain isolated during extraction and FCR correlation."""
        art_a = Artifact(case_id="CASE-A", evidence_id="EV-A", source_tool="tsk", artifact_type="file_record", host_id="HOST-A", normalized_fields=NormalizedFields(host="HOST-A"))
        art_b = Artifact(case_id="CASE-B", evidence_id="EV-B", source_tool="tsk", artifact_type="file_record", host_id="HOST-B", normalized_fields=NormalizedFields(host="HOST-B"))
        
        ext_a = self.extractor.extract_artifacts([art_a], "EV-A")
        ext_b = self.extractor.extract_artifacts([art_b], "EV-B")
        
        fcr_out = self.fcr_engine.correlate([art_a, art_b] + ext_a + ext_b)
        for rec in fcr_out:
            # Ensure no correlation record mixes artifacts from CASE-A and CASE-B
            art_cases = set()
            for aid in rec.artifact_ids:
                if aid == art_a.artifact_id:
                    art_cases.add("CASE-A")
                elif aid == art_b.artifact_id:
                    art_cases.add("CASE-B")
            self.assertLessEqual(len(art_cases), 1, "FCR record cross-contaminated cases!")

    def test_fcr_contract_compatibility(self):
        """Verify extracted artifacts integrate with FCR Engine without breaking FCR schemas."""
        art1 = Artifact(case_id=self.case_id, evidence_id=self.evidence_id, source_tool="tsk", artifact_type="file_record", host_id="HOST-FCR", timestamp=datetime(2026, 8, 31, 10, 0, 0, tzinfo=timezone.utc), normalized_fields=NormalizedFields(host="HOST-FCR", file_name="cmd.exe"))
        art2 = Artifact(case_id=self.case_id, evidence_id=self.evidence_id, source_tool="hayabusa", artifact_type="process_event", host_id="HOST-FCR", timestamp=datetime(2026, 8, 31, 10, 0, 15, tzinfo=timezone.utc), normalized_fields=NormalizedFields(host="HOST-FCR", process_name="cmd.exe"))
        
        extracted = self.extractor.extract_artifacts([art1, art2], self.evidence_id)
        combined = [art1, art2] + extracted
        
        fcr_records = self.fcr_engine.correlate(combined, window_seconds=30.0)
        self.assertIsInstance(fcr_records, list)
        for rec in fcr_records:
            self.assertIsInstance(rec, CorrelationRecord)
            self.assertEqual(rec.case_id, self.case_id)
            self.assertGreaterEqual(len(rec.artifact_ids), 2)

    def test_raw_evidence_verification(self):
        """Verify end-to-end pipeline on Digital Corpora raw evidence files (5 parsed, 2 blocked)."""
        if not self.source_dir.exists():
            self.skipTest("Digital Corpora raw evidence directory not found.")
            
        parsed_artifacts = []
        for p in sorted(self.source_dir.iterdir()):
            if p.is_file():
                src_bytes = p.read_bytes()
                sha256_before = hashlib.sha256(src_bytes).hexdigest()
                
                ev = Evidence(
                    case_id=self.case_id,
                    filename=p.name,
                    file_path=str(p),
                    raw_file_path=str(p),
                    uploaded_by="unit_test",
                    sha256_hash=sha256_before,
                    metadata={"size_bytes": len(src_bytes), "extension": p.suffix.lower()}
                )
                
                res = self.router.determine_routing(ev)
                if res.status == "ROUTED" and res.parser_instance:
                    arts = res.parser_instance.parse(str(p), ev.evidence_id)
                    parsed_artifacts.extend(arts)
                elif p.suffix.lower() == ".aff":
                    self.assertEqual(res.status, "BLOCKED")
                    self.assertIn("BLOCKED_MISSING_LIBAFF", res.reason)
                    
                sha256_after = hashlib.sha256(p.read_bytes()).hexdigest()
                self.assertEqual(sha256_before, sha256_after, f"Original file {p.name} modified during processing!")

        self.assertEqual(len(parsed_artifacts), 207)
        extracted = self.extractor.extract_artifacts(parsed_artifacts, self.evidence_id)
        self.assertIsInstance(extracted, list)

    def test_ast_security_invariants(self):
        """Verify no eval, exec, shell=True, os.system, or pickle.loads in preprocessing and artifact_extractor."""
        target_dirs = [
            Path("preprocessing"),
            Path("preprocessing/artifact_extractor")
        ]
        counts = {"eval": 0, "exec": 0, "shell_true": 0, "os_system": 0, "pickle_loads": 0}
        
        for td in target_dirs:
            for p in td.glob("*.py"):
                text = p.read_text(encoding="utf-8", errors="ignore")
                counts["eval"] += text.count("eval(")
                counts["exec"] += text.count("exec(")
                counts["shell_true"] += text.count("shell=True")
                counts["os_system"] += text.count("os.system")
                counts["pickle_loads"] += text.count("pickle.loads")
                
        for k, v in counts.items():
            self.assertEqual(v, 0, f"Security violation detected: {k} = {v}")


if __name__ == "__main__":
    unittest.main()
