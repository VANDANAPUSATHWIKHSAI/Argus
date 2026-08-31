"""
Unit Tests for GroupPolicyLogParser & GPO Router Integration
=============================================================
Tests parsing of Group Policy evidence formats:
- gpesvc.log / GroupPolicy.log text debug logs
- gpt.ini configuration files
- Registry.pol binary policy files
- GPO Report XML / EVTX XML
- gpresult.json exports
- Router integration and error handling
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.gpo_parser import (
    GroupPolicyLogParser,
    GroupPolicyLogNotFoundError,
    GroupPolicyLogParserError,
)


class TestGroupPolicyLogParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = GroupPolicyLogParser()
        self.router = ParserRouter()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # 1. Text Debug Log Parsing (gpesvc.log)
    def test_parse_gpesvc_log(self) -> None:
        log_content = (
            "gpesvc(3ec.488) 2026-08-28 12:45:01.234 ProcessGPOs: Starting Group Policy processing...\n"
            "gpesvc(3ec.488) 2026-08-28 12:45:02.100 ApplyGPO: GPO Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9}) applied successfully\n"
            "gpesvc(3ec.488) 2026-08-28 12:45:02.500 Extension Security status: 0\n"
        )
        file_path = self.temp_path / "gpesvc.log"
        file_path.write_text(log_content, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-001")
        self.assertEqual(len(artifacts), 3)

        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "group_policy_log_parser")
        self.assertEqual(art1.artifact_type, "gpo_event")
        self.assertEqual(art1.evidence_id, "ev-gpo-001")
        self.assertIsNotNone(art1.timestamp)
        self.assertEqual(art1.timestamp_type, "logged")
        self.assertIn("gpesvc.log", art1.normalized_fields.file_name)
        self.assertIn("log_line", art1.raw_fields)

        art2 = artifacts[1]
        self.assertEqual(art2.raw_fields["gpo_guid"], "{31B2F340-016D-11D2-945F-00C04FB984F9}")
        self.assertEqual(art2.normalized_fields.process_name, "gpesvc.exe")

    # 2. gpt.ini Configuration File Parsing
    def test_parse_gpt_ini(self) -> None:
        ini_content = (
            "[General]\n"
            "Version=65537\n"
            "displayName=Security Baseline Policy\n"
            "gpoId={31B2F340-016D-11D2-945F-00C04FB984F9}\n"
        )
        file_path = self.temp_path / "gpt.ini"
        file_path.write_text(ini_content, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-002")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "group_policy_log_parser")
        self.assertEqual(art.raw_fields["version"], "65537")
        self.assertEqual(art.raw_fields["display_name"], "Security Baseline Policy")
        self.assertEqual(art.raw_fields["gpo_id"], "{31B2F340-016D-11D2-945F-00C04FB984F9}")
        self.assertEqual(art.normalized_fields.process_command_line, "Security Baseline Policy")

    # 3. Binary Registry.pol File Parsing
    def test_parse_registry_pol(self) -> None:
        # Construct valid Registry.pol binary: Header b"PReg" + Version 1 (DWORD) + [Key;Value;Type;Size;Data]
        header = b"PReg" + (1).to_bytes(4, "little")
        # Entry: [SOFTWARE\Policies\Microsoft\Windows;DisableCMD;4;4;\x01\x00\x00\x00]
        key_bytes = "SOFTWARE\\Policies\\Microsoft\\Windows".encode("utf-16le") + b"\x00\x00"
        val_bytes = "DisableCMD".encode("utf-16le") + b"\x00\x00"
        type_bytes = (4).to_bytes(4, "little")  # REG_DWORD
        size_bytes = (4).to_bytes(4, "little")
        data_bytes = (1).to_bytes(4, "little")

        rec_payload = key_bytes + b";\x00" + val_bytes + b";\x00" + type_bytes + b";\x00" + size_bytes + b";\x00" + data_bytes
        entry_bytes = b"[\x00" + rec_payload + b"]\x00"

        file_bytes = header + entry_bytes
        file_path = self.temp_path / "Registry.pol"
        file_path.write_bytes(file_bytes)

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-003")
        self.assertGreaterEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "group_policy_log_parser")
        self.assertEqual(art.raw_fields["header"], "PReg")
        self.assertEqual(art.raw_fields["key"], "SOFTWARE\\Policies\\Microsoft\\Windows")
        self.assertEqual(art.raw_fields["value_name"], "DisableCMD")
        self.assertEqual(art.normalized_fields.registry_key, "SOFTWARE\\Policies\\Microsoft\\Windows")
        self.assertEqual(art.normalized_fields.registry_value, "DisableCMD")

    # 4. GPO Report XML Parsing
    def test_parse_gpreport_xml(self) -> None:
        xml_content = (
            "<GroupPolicyResults>\n"
            "  <GPO>\n"
            "    <Name>Audit Compliance Policy</Name>\n"
            "    <Identifier>{12345678-1234-1234-1234-1234567890AB}</Identifier>\n"
            "    <State>Applied</State>\n"
            "    <ModifiedTime>2026-08-28T10:00:00Z</ModifiedTime>\n"
            "  </GPO>\n"
            "</GroupPolicyResults>\n"
        )
        file_path = self.temp_path / "gpreport.xml"
        file_path.write_text(xml_content, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-004")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.raw_fields["gpo_name"], "Audit Compliance Policy")
        self.assertEqual(art.raw_fields["gpo_id"], "{12345678-1234-1234-1234-1234567890AB}")
        self.assertEqual(art.raw_fields["state"], "Applied")

    # 5. GPO Operational Event XML Parsing
    def test_parse_gpo_event_xml(self) -> None:
        event_xml = (
            "<Events>\n"
            "  <Event>\n"
            "    <System>\n"
            "      <EventID>5017</EventID>\n"
            "      <TimeCreated SystemTime='2026-08-28T12:00:00.000Z'/>\n"
            "      <Computer>DC01.corp.local</Computer>\n"
            "    </System>\n"
            "    <EventData>\n"
            "      <Data Name='GPOName'>Domain Security Policy</Data>\n"
            "      <Data Name='GPOID'>{31B2F340-016D-11D2-945F-00C04FB984F9}</Data>\n"
            "      <Data Name='CSEName'>Security</Data>\n"
            "      <Data Name='ErrorCode'>0</Data>\n"
            "    </EventData>\n"
            "  </Event>\n"
            "</Events>\n"
        )
        file_path = self.temp_path / "Microsoft-Windows-GroupPolicy%4Operational.xml"
        file_path.write_text(event_xml, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-005")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.raw_fields["event_id"], "5017")
        self.assertEqual(art.raw_fields["gpo_name"], "Domain Security Policy")
        self.assertEqual(art.raw_fields["cse_name"], "Security")
        self.assertEqual(art.normalized_fields.host, "DC01.corp.local")

    # 6. JSON Export Parsing
    def test_parse_gpresult_json(self) -> None:
        json_content = (
            "[\n"
            "  {\n"
            "    \"GPOName\": \"Password Policy\",\n"
            "    \"GPOID\": \"{00000000-0000-0000-0000-000000000001}\",\n"
            "    \"CSEName\": \"Security\",\n"
            "    \"Status\": \"Applied\",\n"
            "    \"Timestamp\": \"2026-08-28T11:00:00Z\"\n"
            "  }\n"
            "]\n"
        )
        file_path = self.temp_path / "gpresult.json"
        file_path.write_text(json_content, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-006")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.raw_fields["GPOName"], "Password Policy")
        self.assertEqual(art.raw_fields["Status"], "Applied")

    # 7. GPO Errors Are Handled Safely as Non-Malicious
    def test_gpo_errors_are_not_malware(self) -> None:
        log_content = (
            "gpesvc(3ec.488) 2026-08-28 12:45:05.000 ProcessGPOs: Extension Security failed with error code 1058\n"
        )
        file_path = self.temp_path / "gpesvc.log"
        file_path.write_text(log_content, encoding="utf-8")

        artifacts = self.parser.parse(str(file_path), evidence_id="ev-gpo-007")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.raw_fields["status_text"], "Failed/Warning")
        self.assertEqual(art.confidence_score, 1.0)

    # 8. Error Handling — File Not Found
    def test_error_handling_not_found(self) -> None:
        missing_path = str(self.temp_path / "non_existent_gpo.log")
        with self.assertRaises(GroupPolicyLogNotFoundError):
            self.parser.parse(missing_path)

    # 9. Error Handling — Empty File
    def test_error_handling_empty_file(self) -> None:
        empty_path = self.temp_path / "empty_gpo.log"
        empty_path.write_text("", encoding="utf-8")
        with self.assertRaises(GroupPolicyLogParserError):
            self.parser.parse(str(empty_path))

    # 10. Router Integration Tests
    def test_router_integration_gpesvc_log(self) -> None:
        ev = Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-r-001",
            filename="gpesvc.log",
            file_path=str(self.temp_path / "gpesvc.log"),
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "GroupPolicyLogParser")
        self.assertIsInstance(self.router.route(ev), GroupPolicyLogParser)

    def test_router_integration_registry_pol_signature(self) -> None:
        pol_file = self.temp_path / "custom_policy.bin"
        pol_file.write_bytes(b"PReg" + (1).to_bytes(4, "little"))
        ev = Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-r-002",
            filename="custom_policy.bin",
            file_path=str(pol_file),
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "GroupPolicyLogParser")
        self.assertEqual(res.detection_method, "signature")

    def test_router_integration_gpt_ini(self) -> None:
        ini_file = self.temp_path / "gpt.ini"
        ini_file.write_text("[General]\nVersion=1\n", encoding="utf-8")
        ev = Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-r-003",
            filename="gpt.ini",
            file_path=str(ini_file),
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "GroupPolicyLogParser")


if __name__ == "__main__":
    unittest.main()
