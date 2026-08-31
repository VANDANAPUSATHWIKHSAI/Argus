"""
Unit tests for WindowsFirewallParser (Source #2) and WindowsDefenderParser (Source #3)
=======================================================================================
- Source #2: Windows Firewall Logs (pfirewall.log)
- Source #3: Windows Defender Logs (Microsoft-Windows-Windows Defender%4Operational.evtx / MPLog)
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.evtx_parser import EvtxParser
from preprocessing.parsers.evtxecmd_parser import EvtxECmdParser
from preprocessing.parsers.firewall_parser import (
    WindowsFirewallParser,
    WindowsFirewallNotFoundError,
    WindowsFirewallParserError,
)
from preprocessing.parsers.defender_parser import (
    WindowsDefenderParser,
    WindowsDefenderNotFoundError,
    WindowsDefenderParserError,
)


class TestWindowsFirewallParserUnit(unittest.TestCase):
    """Unit tests for WindowsFirewallParser."""

    def setUp(self) -> None:
        self.parser = WindowsFirewallParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.tmp_dir.name) / "pfirewall.log"
        self._create_mock_firewall_log(self.log_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_firewall_log(self, path: Path) -> None:
        content = (
            "#Version: 1.5\n"
            "#Software: Microsoft Windows Firewall\n"
            "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmptime info path\n"
            "2026-08-27 12:00:00 ALLOW TCP 192.168.1.50 10.0.0.1 54321 443 60 - - - - - - RECEIVE\n"
            "2026-08-27 12:05:00 DROP UDP 192.168.1.100 192.168.1.255 137 137 78 - - - - - - SEND\n"
        )
        path.write_text(content, encoding="utf-8")

    def test_valid_firewall_log_parsing(self) -> None:
        artifacts = self.parser.parse(str(self.log_file), evidence_id="ev_fw_01")
        # 1-11, 16-17. Valid record, timestamp, action, protocol, IPs, ports, direction, raw, schema, provenance
        self.assertEqual(len(artifacts), 2)

        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "windows_firewall_parser")
        self.assertEqual(art1.artifact_type, "firewall_log")
        self.assertEqual(art1.evidence_id, "ev_fw_01")
        self.assertEqual(art1.raw_fields["action"], "ALLOW")
        self.assertEqual(art1.raw_fields["protocol"], "TCP")
        self.assertEqual(art1.normalized_fields.src_ip, "192.168.1.50")
        self.assertEqual(art1.normalized_fields.dst_ip, "10.0.0.1")
        self.assertEqual(art1.normalized_fields.src_port, 54321)
        self.assertEqual(art1.normalized_fields.dst_port, 443)
        self.assertEqual(art1.timestamp_type, "event")
        self.assertIsNotNone(art1.timestamp)

        art2 = artifacts[1]
        self.assertEqual(art2.raw_fields["action"], "DROP")

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.log"
        with self.assertRaises(WindowsFirewallNotFoundError):
            self.parser.parse(str(missing))


class TestWindowsDefenderParserUnit(unittest.TestCase):
    """Unit tests for WindowsDefenderParser."""

    def setUp(self) -> None:
        self.parser = WindowsDefenderParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.json_file = Path(self.tmp_dir.name) / "defender_events.json"
        self._create_mock_defender_json(self.json_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_defender_json(self, path: Path) -> None:
        data = [
            {
                "event_id": "1116",
                "ThreatName": "Trojan:Win32/Powload.A",
                "ThreatID": "2147723456",
                "Severity": "High",
                "Action": "Quarantined",
                "FilePath": "C:\\Users\\Public\\Downloads\\invoice.exe",
                "ProcessName": "powershell.exe",
                "ProcessID": "2048",
                "User": "analyst_alice",
                "TimeCreated": "2026-08-27T14:30:00Z"
            }
        ]
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_valid_defender_event_parsing(self) -> None:
        artifacts = self.parser.parse(str(self.json_file), evidence_id="ev_def_01")
        # 19-31, 34-35. Valid event, event_id, threat, ID, severity, action, path, proc, user, schema, provenance
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "windows_defender_parser")
        self.assertEqual(art.artifact_type, "defender_log")
        self.assertEqual(art.evidence_id, "ev_def_01")
        self.assertIn("Trojan:Win32/Powload.A", art.event_summary)
        self.assertEqual(art.raw_fields["event_id"], "1116")
        self.assertEqual(art.raw_fields["severity"], "High")
        self.assertEqual(art.raw_fields["action"], "Quarantined")
        self.assertEqual(art.normalized_fields.rule_name, "Trojan:Win32/Powload.A")
        self.assertEqual(art.normalized_fields.process_name, "powershell.exe")
        self.assertIsNotNone(art.normalized_fields.user)
        self.assertIn(art.normalized_fields.user.lower(), ("analyst_alice", "sudeep"))
        self.assertEqual(art.timestamp_type, "event")

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.json"
        with self.assertRaises(WindowsDefenderNotFoundError):
            self.parser.parse(str(missing))


class TestSemanticSafeguards(unittest.TestCase):
    """Semantic Safeguard tests: Neutral Layer 2 evidence output."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_firewall_allow_does_not_produce_malicious_flag(self) -> None:
        path = Path(self.tmp_dir.name) / "pfirewall.log"
        path.write_text("2026-08-27 12:00:00 ALLOW TCP 1.1.1.1 2.2.2.2 80 80 60", encoding="utf-8")
        parser = WindowsFirewallParser()
        artifacts = parser.parse(str(path))
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertNotIn("malicious", art.raw_fields)
        self.assertFalse(getattr(art.normalized_fields, "malicious", False))

    def test_firewall_block_does_not_produce_attack_flag(self) -> None:
        path = Path(self.tmp_dir.name) / "pfirewall.log"
        path.write_text("2026-08-27 12:00:00 DROP TCP 1.1.1.1 2.2.2.2 80 80 60", encoding="utf-8")
        parser = WindowsFirewallParser()
        artifacts = parser.parse(str(path))
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertNotIn("attack", art.raw_fields)
        self.assertNotIn("compromised", art.raw_fields)

    def test_defender_detection_does_not_produce_malware_verdict(self) -> None:
        path = Path(self.tmp_dir.name) / "def.json"
        path.write_text(json.dumps([{"ThreatName": "TestThreat", "Action": "Cleaned"}]), encoding="utf-8")
        parser = WindowsDefenderParser()
        artifacts = parser.parse(str(path))
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertNotIn("verdict", art.raw_fields)

    def test_defender_quarantine_does_not_produce_compromised_flag(self) -> None:
        path = Path(self.tmp_dir.name) / "def.json"
        path.write_text(json.dumps([{"ThreatName": "TestThreat", "Action": "Quarantined"}]), encoding="utf-8")
        parser = WindowsDefenderParser()
        artifacts = parser.parse(str(path))
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertNotIn("compromised", art.raw_fields)


class TestSecurityInertness(unittest.TestCase):
    """Security tests (Points 37-40): Command & script fields remain inert."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("subprocess.run")
    def test_firewall_command_looking_fields_not_executed(self, mock_run: MagicMock) -> None:
        path = Path(self.tmp_dir.name) / "pfirewall.log"
        path.write_text("2026-08-27 12:00:00 ALLOW TCP 1.1.1.1 2.2.2.2 80 80 60 - - - - - - RECEIVE C:\\Windows\\System32\\cmd.exe", encoding="utf-8")
        parser = WindowsFirewallParser()
        artifacts = parser.parse(str(path))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_defender_paths_and_remediation_not_executed(self, mock_run: MagicMock) -> None:
        path = Path(self.tmp_dir.name) / "def.json"
        path.write_text(json.dumps([{"FilePath": "C:\\Windows\\System32\\calc.exe", "Action": "powershell -enc AAAA"}]), encoding="utf-8")
        parser = WindowsDefenderParser()
        artifacts = parser.parse(str(path))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()


class TestRouterCollisionsFirewallDefender(unittest.TestCase):
    """Router collision tests for Firewall and Defender vs standard EVTX and log streams."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_security_evtx_routes_to_evtx_parser(self) -> None:
        ev = Evidence(evidence_id="e1", case_id="c1", filename="Security.evtx", file_path="/Logs/Security.evtx", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "EvtxParser")
        self.assertIsInstance(self.router.route(ev), EvtxParser)

    def test_raw_evtx_routes_to_evtxecmd(self) -> None:
        ev = Evidence(evidence_id="e2", case_id="c1", filename="System.evtx", file_path="/Logs/System.evtx", uploaded_by="analyst", metadata={"stream": "raw"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "EvtxECmdParser")
        self.assertIsInstance(self.router.route(ev), EvtxECmdParser)

    def test_defender_evtx_routes_to_windows_defender_parser(self) -> None:
        ev = Evidence(evidence_id="e3", case_id="c1", filename="Microsoft-Windows-Windows Defender%4Operational.evtx", file_path="/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "WindowsDefenderParser")
        self.assertIsInstance(self.router.route(ev), WindowsDefenderParser)

    def test_pfirewall_log_routes_to_windows_firewall_parser(self) -> None:
        ev = Evidence(evidence_id="e4", case_id="c1", filename="pfirewall.log", file_path="/Firewall/pfirewall.log", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "WindowsFirewallParser")
        self.assertIsInstance(self.router.route(ev), WindowsFirewallParser)

    def test_generic_log_remains_unrouted(self) -> None:
        ev = Evidence(evidence_id="e5", case_id="c1", filename="application.log", file_path="/Logs/application.log", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertNotIn(res.target_parser, ("WindowsFirewallParser", "WindowsDefenderParser"))


if __name__ == "__main__":
    unittest.main()
