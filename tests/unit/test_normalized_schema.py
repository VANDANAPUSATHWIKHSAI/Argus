"""
Layer 2 Normalized Evidence Schema Tests
==========================================
Validates all 16 required schema scenarios for the Authoritative ARGUS Layer 2
Normalized Evidence contract:
1. Minimum valid record
2. Complete record
3. Missing case_id (defaults gracefully)
4. Missing evidence_id (raises ValidationError)
5. Missing source_tool (raises ValidationError)
6. Missing artifact_type (raises ValidationError)
7. Missing timestamp handling (nullable)
8. Invalid timestamp parsing
9. timestamp_type preservation (created, modified, accessed, event, etc.)
10. raw_fields preservation (original native values kept intact)
11. parser_version
12. schema_version
13. ingested_at (UTC datetime creation)
14. Normalized correlation fields
15. Parser-specific fields preservation
16. Backward compatibility (confidence_score, pid, ppid, process, device_serial aliases)
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pydantic import ValidationError

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.normalizer import Normalizer


class TestLayer2NormalizedSchema(unittest.TestCase):

    def test_01_minimum_valid_record(self):
        """Minimum valid record requires evidence_id, source_tool, and artifact_type."""
        art = Artifact(
            evidence_id="ev-min-001",
            source_tool="hayabusa",
            artifact_type="log_event"
        )
        self.assertIsNotNone(art.artifact_id)
        self.assertEqual(art.evidence_id, "ev-min-001")
        self.assertEqual(art.source_tool, "hayabusa")
        self.assertEqual(art.artifact_type, "log_event")
        self.assertEqual(art.schema_version, "2.0.0")
        self.assertEqual(art.parser_version, "1.0.0")
        self.assertEqual(art.confidence, 1.0)
        self.assertEqual(art.confidence_score, 1.0)
        self.assertIsNotNone(art.ingested_at)
        self.assertEqual(art.timestamp_type, "event")

    def test_02_complete_record(self):
        """Complete record populates top-level and normalized correlation fields."""
        now = datetime.now(timezone.utc)
        art = Artifact(
            case_id="case-100",
            evidence_id="ev-full-001",
            source_tool="volatility3",
            artifact_type="process_event",
            host_id="WORKSTATION-01",
            timestamp=now,
            timestamp_type="execution",
            event_summary="Process cmd.exe (PID 1234) spawned by explorer.exe",
            raw_fields={"PID": 1234, "PPID": 800, "ImageFileName": "cmd.exe"},
            normalized_fields=NormalizedFields(
                host="WORKSTATION-01",
                user="DOMAIN\\alice",
                process_id=1234,
                parent_process_id=800,
                process_name="cmd.exe",
                process_command_line="cmd.exe /c calc.exe",
                severity="medium",
            ),
            confidence=0.95,
            parser_version="3.0.0",
            schema_version="2.0.0"
        )
        self.assertEqual(art.case_id, "case-100")
        self.assertEqual(art.host_id, "WORKSTATION-01")
        self.assertEqual(art.timestamp_type, "execution")
        self.assertIn("cmd.exe", art.event_summary)
        self.assertEqual(art.normalized_fields.process_id, 1234)
        self.assertEqual(art.normalized_fields.parent_process_id, 800)
        self.assertEqual(art.normalized_fields.pid, 1234)
        self.assertEqual(art.normalized_fields.ppid, 800)
        self.assertEqual(art.confidence_score, 0.95)

    def test_03_missing_case_id_defaults_gracefully(self):
        """case_id is optional with empty string default."""
        art = Artifact(
            evidence_id="ev-001",
            source_tool="zeek",
            artifact_type="network_connection"
        )
        self.assertEqual(art.case_id, "")

    def test_04_missing_evidence_id(self):
        """Missing evidence_id raises ValidationError."""
        with self.assertRaises(ValidationError):
            Artifact(source_tool="zeek", artifact_type="network_connection")  # type: ignore

    def test_05_missing_source_tool(self):
        """Missing source_tool raises ValidationError."""
        with self.assertRaises(ValidationError):
            Artifact(evidence_id="ev-001", artifact_type="network_connection")  # type: ignore

    def test_06_missing_artifact_type(self):
        """Missing artifact_type raises ValidationError."""
        with self.assertRaises(ValidationError):
            Artifact(evidence_id="ev-001", source_tool="zeek")  # type: ignore

    def test_07_missing_timestamp_nullable(self):
        """timestamp is optional and defaults to None."""
        art = Artifact(
            evidence_id="ev-001",
            source_tool="regripper",
            artifact_type="registry_key"
        )
        self.assertIsNone(art.timestamp)

    def test_08_invalid_timestamp_parsing(self):
        """Normalizer handles invalid timestamps gracefully."""
        normalizer = Normalizer()
        res = normalizer._normalize_timestamp("invalid-date-string")
        self.assertIsNone(res)

    def test_09_timestamp_type_preservation(self):
        """timestamp_type preserves specific semantics (created, modified, accessed, etc.)."""
        for ts_type in ("created", "modified", "accessed", "entry-changed", "execution", "event", "received"):
            art = Artifact(
                evidence_id="ev-001",
                source_tool="tsk",
                artifact_type="file_record",
                timestamp_type=ts_type
            )
            self.assertEqual(art.timestamp_type, ts_type)

    def test_10_raw_fields_preservation(self):
        """raw_fields must keep native parser values intact without lossy conversion."""
        native_raw = {
            "ImageFileName": "svchost.exe",
            "PID": 1044,
            "Offset(V)": "0xffff8000a000",
            "NestedData": {"key": "val", "arr": [1, 2, 3]}
        }
        art = Artifact(
            evidence_id="ev-001",
            source_tool="volatility3",
            artifact_type="process_event",
            raw_fields=native_raw,
            normalized_fields=NormalizedFields(process_id=1044, process_name="svchost.exe")
        )
        # Verify raw_fields contains exact original keys
        self.assertEqual(art.raw_fields["ImageFileName"], "svchost.exe")
        self.assertEqual(art.raw_fields["Offset(V)"], "0xffff8000a000")
        self.assertEqual(art.raw_fields["NestedData"]["arr"], [1, 2, 3])

    def test_11_parser_version(self):
        """parser_version stores exact tool or wrapper version string."""
        art = Artifact(
            evidence_id="ev-001",
            source_tool="hayabusa",
            artifact_type="log_event",
            parser_version="2.14.0"
        )
        self.assertEqual(art.parser_version, "2.14.0")

    def test_12_schema_version(self):
        """schema_version identifies Layer 2 normalized contract version."""
        art = Artifact(
            evidence_id="ev-001",
            source_tool="zeek",
            artifact_type="dns_query"
        )
        self.assertEqual(art.schema_version, "2.0.0")

    def test_13_ingested_at(self):
        """ingested_at auto-populates UTC datetime on normalization."""
        art = Artifact(
            evidence_id="ev-001",
            source_tool="suricata",
            artifact_type="ids_alert"
        )
        self.assertIsInstance(art.ingested_at, datetime)
        self.assertEqual(art.ingested_at.tzinfo, timezone.utc)

    def test_14_normalized_correlation_fields(self):
        """All 21 correlation attributes are consistently addressable."""
        nf = NormalizedFields(
            host="workstation-01",
            user="alice",
            process_id=1234,
            parent_process_id=800,
            process_name="powershell.exe",
            process_command_line="powershell.exe -enc AAAA==",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=49152,
            dst_port=443,
            domain="malicious.org",
            url="https://malicious.org/payload.bin",
            file_path="C:\\Windows\\System32\\powershell.exe",
            file_name="powershell.exe",
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            registry_key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            registry_value="Backdoor",
            registry_value_data="C:\\Windows\\temp\\nc.exe",
            usb_serial_number="070825B3E841",
            rule_name="SuspiciousPowerShell",
            severity="high"
        )
        self.assertEqual(nf.host, "workstation-01")
        self.assertEqual(nf.user, "alice")
        self.assertEqual(nf.process_id, 1234)
        self.assertEqual(nf.parent_process_id, 800)
        self.assertEqual(nf.process_name, "powershell.exe")
        self.assertEqual(nf.process_command_line, "powershell.exe -enc AAAA==")
        self.assertEqual(nf.src_ip, "192.168.1.50")
        self.assertEqual(nf.dst_ip, "10.0.0.1")
        self.assertEqual(nf.src_port, 49152)
        self.assertEqual(nf.dst_port, 443)
        self.assertEqual(nf.domain, "malicious.org")
        self.assertEqual(nf.url, "https://malicious.org/payload.bin")
        self.assertEqual(nf.file_path, "C:\\Windows\\System32\\powershell.exe")
        self.assertEqual(nf.file_name, "powershell.exe")
        self.assertEqual(nf.hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(nf.registry_key, "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        self.assertEqual(nf.registry_value, "Backdoor")
        self.assertEqual(nf.registry_value_data, "C:\\Windows\\temp\\nc.exe")
        self.assertEqual(nf.usb_serial_number, "070825B3E841")
        self.assertEqual(nf.rule_name, "SuspiciousPowerShell")
        self.assertEqual(nf.severity, "high")

    def test_15_parser_specific_fields_in_raw_fields(self):
        """Parser-specific un-normalized metadata is preserved in raw_fields."""
        raw = {
            "volatility_plugin": "windows.malfind",
            "vad_tag": "VadS",
            "protection": "PAGE_EXECUTE_READWRITE",
            "hexdump": "4d5a9000..."
        }
        art = Artifact(
            evidence_id="ev-001",
            source_tool="volatility3",
            artifact_type="injection_indicator",
            raw_fields=raw
        )
        self.assertEqual(art.raw_fields["protection"], "PAGE_EXECUTE_READWRITE")

    def test_16_backward_compatibility_aliases(self):
        """pid, ppid, process, device_serial, and confidence_score properties work seamlessly."""
        nf = NormalizedFields(
            pid=1234,
            ppid=800,
            process="cmd.exe",
            device_serial="USB123"
        )
        self.assertEqual(nf.process_id, 1234)
        self.assertEqual(nf.parent_process_id, 800)
        self.assertEqual(nf.process_name, "cmd.exe")
        self.assertEqual(nf.usb_serial_number, "USB123")
        self.assertEqual(nf.pid, 1234)
        self.assertEqual(nf.ppid, 800)
        self.assertEqual(nf.process, "cmd.exe")
        self.assertEqual(nf.device_serial, "USB123")

        art = Artifact(
            evidence_id="ev-001",
            source_tool="zeek",
            artifact_type="conn",
            confidence_score=0.88
        )
        self.assertEqual(art.confidence, 0.88)
        self.assertEqual(art.confidence_score, 0.88)


if __name__ == "__main__":
    unittest.main()
