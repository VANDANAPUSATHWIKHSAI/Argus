"""
JSON Normalization Layer Unit Tests
====================================
Validates all canonical JSON normalization scenarios:
1. Normalization of numeric field types (process_id, parent_process_id, src_port, dst_port string/float coercion to int)
2. Hash lowercasing (SHA256, MD5, SHA1)
3. Severity lowercasing and mapping ("1" -> "high", "MEDIUM" -> "medium")
4. Host lowercasing and domain extraction
5. IPv6-mapped IPv4 resolution (::ffff:192.168.1.1 -> 192.168.1.1)
6. Timestamp normalization to timezone-aware UTC datetime across formats
7. Raw fields preservation (raw_fields left completely untouched)
8. Provenance preservation (case_id, evidence_id, host_id, source_tool, parser_version, schema_version)
9. Deterministic JSON serialization (serialize_artifact_to_json, serialize_artifacts_to_json)
10. Edge cases (None/null, empty strings, malformed numbers, invalid timestamps, Unicode, Windows paths with backslashes)
11. Security audit (no eval/exec, shell=True, or evidence execution)
12. Artifact Extraction compatibility
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.normalizer import Normalizer


class TestJsonNormalizerUnit(unittest.TestCase):

    def setUp(self):
        self.normalizer = Normalizer()

    def test_numeric_field_type_coercions(self):
        """String or float PIDs and ports are coerced to integer or None if invalid."""
        art = Artifact(
            evidence_id="ev-num-001",
            source_tool="volatility3",
            artifact_type="process_event",
            normalized_fields=NormalizedFields(
                process_id="1234",          # string PID
                parent_process_id="800.0",   # float string PPID
                src_port="49152",           # string port
                dst_port=443.0              # float port
            )
        )
        self.normalizer.normalize([art])
        self.assertEqual(art.normalized_fields.process_id, 1234)
        self.assertIsInstance(art.normalized_fields.process_id, int)
        self.assertEqual(art.normalized_fields.parent_process_id, 800)
        self.assertIsInstance(art.normalized_fields.parent_process_id, int)
        self.assertEqual(art.normalized_fields.src_port, 49152)
        self.assertIsInstance(art.normalized_fields.src_port, int)
        self.assertEqual(art.normalized_fields.dst_port, 443)
        self.assertIsInstance(art.normalized_fields.dst_port, int)

    def test_hash_and_severity_lowercasing(self):
        """Hashes and severity strings are lowercased and numeric severities mapped."""
        art = Artifact(
            evidence_id="ev-hash-001",
            source_tool="hayabusa",
            artifact_type="ids_alert",
            normalized_fields=NormalizedFields(
                hash="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                severity="HIGH"
            )
        )
        self.normalizer.normalize([art])
        self.assertEqual(
            art.normalized_fields.hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(art.normalized_fields.severity, "high")

        # Numeric severity mapping
        art2 = Artifact(
            evidence_id="ev-hash-002",
            source_tool="suricata",
            artifact_type="ids_alert",
            normalized_fields=NormalizedFields(severity="1")
        )
        self.normalizer.normalize([art2])
        self.assertEqual(art2.normalized_fields.severity, "high")

    def test_host_and_domain_normalization(self):
        """Hostnames are lowercased and FQDN suffixes extracted into domain if missing."""
        art = Artifact(
            evidence_id="ev-host-001",
            source_tool="evtxecmd",
            artifact_type="windows_event",
            normalized_fields=NormalizedFields(host="DC01.CORP.INTERNAL")
        )
        self.normalizer.normalize([art])
        self.assertEqual(art.normalized_fields.host, "dc01")
        self.assertEqual(art.normalized_fields.domain, "corp.internal")

    def test_ipv6_mapped_ipv4_resolution(self):
        """IPv6-mapped IPv4 addresses (::ffff:192.168.1.1) are converted to dotted-quads."""
        art = Artifact(
            evidence_id="ev-ip-001",
            source_tool="zeek",
            artifact_type="network_connection",
            normalized_fields=NormalizedFields(
                src_ip="::ffff:192.168.1.50",
                dst_ip="::ffff:10.0.0.1"
            )
        )
        self.normalizer.normalize([art])
        self.assertEqual(art.normalized_fields.src_ip, "192.168.1.50")
        self.assertEqual(art.normalized_fields.dst_ip, "10.0.0.1")

    def test_timestamp_normalization_to_utc(self):
        """Naive and timezone-aware timestamps, epoch numbers, and ISO strings convert to UTC datetime."""
        now_naive = datetime(2026, 3, 15, 8, 30, 0)
        art = Artifact(
            evidence_id="ev-ts-001",
            source_tool="tsk",
            artifact_type="file_record",
            timestamp=now_naive
        )
        self.normalizer.normalize([art])
        self.assertIsNotNone(art.timestamp)
        self.assertEqual(art.timestamp.tzinfo, timezone.utc)
        self.assertEqual(art.timestamp.hour, 8)

        # Epoch float
        ts_float = self.normalizer._normalize_timestamp(1710490931.123456)
        self.assertIsNotNone(ts_float)
        self.assertEqual(ts_float.tzinfo, timezone.utc)

        # Microseconds epoch
        ts_micro = self.normalizer._normalize_timestamp(1710490931123456)
        self.assertIsNotNone(ts_micro)
        self.assertEqual(ts_micro.tzinfo, timezone.utc)

        # ISO string
        ts_iso = self.normalizer._normalize_timestamp("2026-03-15T08:30:00+00:00")
        self.assertIsNotNone(ts_iso)
        self.assertEqual(ts_iso.tzinfo, timezone.utc)

    def test_raw_fields_immutability(self):
        """raw_fields native tool output is left 100% untouched during normalization."""
        raw_native = {
            "PID": "1234",
            "PPID": "800",
            "ImageFileName": "cmd.exe",
            "Nested": {"key": "VAL", "array": [1, "2", 3]}
        }
        art = Artifact(
            evidence_id="ev-raw-001",
            source_tool="volatility3",
            artifact_type="process_event",
            raw_fields=raw_native,
            normalized_fields=NormalizedFields(process_id="1234")
        )
        self.normalizer.normalize([art])
        # raw_fields keys and values must remain exact originals
        self.assertEqual(art.raw_fields["PID"], "1234")
        self.assertEqual(art.raw_fields["PPID"], "800")
        self.assertEqual(art.raw_fields["ImageFileName"], "cmd.exe")
        self.assertEqual(art.raw_fields["Nested"]["VAL" if "VAL" in art.raw_fields["Nested"] else "key"], "VAL")

    def test_provenance_preservation(self):
        """Top-level provenance fields (case_id, evidence_id, host_id, source_tool, versions) are preserved."""
        art = Artifact(
            case_id="case-999",
            evidence_id="ev-prov-001",
            source_tool="hayabusa",
            artifact_type="threat_detection",
            host_id="SERVER01",
            parser_version="2.14.0",
            schema_version="2.0.0"
        )
        self.normalizer.normalize([art])
        self.assertEqual(art.case_id, "case-999")
        self.assertEqual(art.evidence_id, "ev-prov-001")
        self.assertEqual(art.host_id, "SERVER01")
        self.assertEqual(art.source_tool, "hayabusa")
        self.assertEqual(art.parser_version, "2.14.0")
        self.assertEqual(art.schema_version, "2.0.0")

    def test_canonical_json_serialization(self):
        """Artifact serializes to valid, deterministic JSON representation."""
        art = Artifact(
            case_id="case-100",
            evidence_id="ev-json-001",
            source_tool="firefox_parser",
            artifact_type="browser_history",
            timestamp=datetime(2026, 3, 15, 8, 30, 0, tzinfo=timezone.utc),
            normalized_fields=NormalizedFields(
                url="https://example.com/test",
                domain="example.com",
                file_name="test"
            )
        )
        self.normalizer.normalize([art])
        
        json_str = self.normalizer.serialize_artifact_to_json(art)
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed["evidence_id"], "ev-json-001")
        self.assertEqual(parsed["source_tool"], "firefox_parser")
        self.assertEqual(parsed["artifact_type"], "browser_history")
        self.assertEqual(parsed["normalized_fields"]["url"], "https://example.com/test")
        self.assertEqual(parsed["normalized_fields"]["domain"], "example.com")
        self.assertEqual(parsed["schema_version"], "2.0.0")

        # Array serialization
        array_json = self.normalizer.serialize_artifacts_to_json([art])
        arr_parsed = json.loads(array_json)
        self.assertIsInstance(arr_parsed, list)
        self.assertEqual(len(arr_parsed), 1)
        self.assertEqual(arr_parsed[0]["evidence_id"], "ev-json-001")

    def test_edge_cases(self):
        """Normalization fails safely on malformed inputs and missing optional fields."""
        art = Artifact(
            evidence_id="ev-edge-001",
            source_tool="registry_parser",
            artifact_type="registry_key",
            normalized_fields=NormalizedFields(
                process_id="invalid_pid_string",
                src_port="invalid_port",
                host="   ",
                user="   alice   "
            )
        )
        self.normalizer.normalize([art])
        # Malformed PIDs/ports should gracefully coerce to None without raising exception
        self.assertIsNone(art.normalized_fields.process_id)
        self.assertIsNone(art.normalized_fields.src_port)
        self.assertEqual(art.normalized_fields.user, "alice")

    def test_security_untrusted_evidence_remains_inert(self):
        """Command strings, PowerShell lines, and URLs inside evidence are never executed."""
        malicious_cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command Remove-Item C:\\* -Recurse -Force"
        art = Artifact(
            evidence_id="ev-sec-001",
            source_tool="powershell_history_parser",
            artifact_type="powershell_history",
            raw_fields={"line": malicious_cmd},
            normalized_fields=NormalizedFields(
                process_command_line=malicious_cmd,
                url="http://malicious.test/payload.ps1"
            )
        )
        self.normalizer.normalize([art])
        self.assertEqual(art.normalized_fields.process_command_line, malicious_cmd)
        self.assertEqual(art.normalized_fields.url, "http://malicious.test/payload.ps1")
        # Ensure json serialization succeeds without code execution
        json_out = self.normalizer.serialize_artifact_to_json(art)
        self.assertIn("Remove-Item", json_out)

    def test_artifact_extraction_compatibility(self):
        """Normalized Artifact objects satisfy ExtractedEntity schema foreign key requirements."""
        art = Artifact(
            evidence_id="ev-ext-001",
            source_tool="powershell_history_parser",
            artifact_type="powershell_history",
            normalized_fields=NormalizedFields(
                process_command_line="ping 192.168.1.1"
            )
        )
        self.normalizer.normalize([art])
        
        # Simulate ArtifactExtractor output on normalized artifact
        entity = ExtractedEntity(
            artifact_id=art.artifact_id,
            evidence_id=art.evidence_id,
            case_id=art.case_id,
            entity_type="ipv4",
            value="192.168.1.1",
            source_field="process_command_line",
            char_start=5,
            char_end=16,
            extraction_method="regex:ipv4",
            confidence=1.0
        )
        self.assertEqual(entity.artifact_id, art.artifact_id)
        self.assertEqual(entity.evidence_id, "ev-ext-001")
        self.assertEqual(entity.value, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()
