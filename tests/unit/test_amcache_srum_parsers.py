"""
Unit tests for AmcacheParser (Source #16) and SrumECmdParser (Source #17)
========================================================================
- Source #16: Amcache (AmcacheParser)
- Source #17: SRUM (SrumECmd)
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.amcache_parser import (
    AmcacheParser,
    AmcacheParserNotFoundError,
    AmcacheParserExecutionError,
)
from preprocessing.parsers.srum_parser import (
    SrumECmdParser,
    SrumECmdNotFoundError,
    SrumECmdExecutionError,
)


class TestAmcacheParserUnit(unittest.TestCase):
    """Unit tests for AmcacheParser."""

    def setUp(self) -> None:
        self.parser = AmcacheParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.hive_file = Path(self.tmp_dir.name) / "Amcache.hve"
        self.hive_file.write_bytes(b"regf" + b"\x00" * 1024)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/AmcacheParser.exe")
    @patch("subprocess.run")
    def test_valid_amcache_json_output(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "Name": "malware.exe",
                "FullPath": "C:\\Windows\\Temp\\malware.exe",
                "SHA1": "a1b2c3d4e5f6789012345678901234567890abcd",
                "Publisher": "Unknown Vendor",
                "ProductName": "Suspicious Tool",
                "Version": "1.0.0.0",
                "FirstSeen": "2026-08-25T14:30:00Z",
                "InstallDate": "2026-08-25T14:30:00Z",
            }
        ]

        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return MagicMock(returncode=0, stdout="Processed 1 records", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_amc_01")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        # 1-7, 12-14. Schema, Provenance, Metadata, Raw Fields, Timestamps
        self.assertEqual(art.source_tool, "amcacheparser")
        self.assertEqual(art.artifact_type, "amcache")
        self.assertEqual(art.evidence_id, "ev_amc_01")
        self.assertEqual(art.normalized_fields.process_name, "malware.exe")
        self.assertEqual(art.normalized_fields.file_name, "malware.exe")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Windows\\Temp\\malware.exe")
        self.assertEqual(art.normalized_fields.hash, "a1b2c3d4e5f6789012345678901234567890abcd")
        self.assertEqual(art.timestamp_type, "first_seen")
        self.assertIsNotNone(art.timestamp)
        self.assertEqual(art.timestamp.year, 2026)

        # Raw field preservation
        self.assertIn("Publisher", art.raw_fields)
        self.assertEqual(art.raw_fields["Publisher"], "Unknown Vendor")
        self.assertEqual(art.raw_fields["ProductName"], "Suspicious Tool")

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1))
    def test_missing_executable_raises_not_found(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(AmcacheParserNotFoundError):
            self.parser.parse(str(self.hive_file))

    @patch("shutil.which", return_value="/usr/bin/AmcacheParser.exe")
    @patch("subprocess.run")
    def test_non_zero_exit_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Corrupted Amcache hive")
        with self.assertRaises(AmcacheParserExecutionError):
            self.parser.parse(str(self.hive_file))

    @patch("shutil.which", return_value="/usr/bin/AmcacheParser.exe")
    @patch("subprocess.run", side_effect=TimeoutError())
    def test_timeout_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(AmcacheParserExecutionError):
            self.parser.parse(str(self.hive_file))

    @patch("shutil.which", return_value="/usr/bin/AmcacheParser.exe")
    @patch("subprocess.run")
    def test_malformed_json_output_handled(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text("{not valid json\n", encoding="utf-8")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_amc_bad")
        self.assertEqual(len(artifacts), 0)


class TestSrumECmdParserUnit(unittest.TestCase):
    """Unit tests for SrumECmdParser."""

    def setUp(self) -> None:
        self.parser = SrumECmdParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.srum_file = Path(self.tmp_dir.name) / "SRUDB.dat"
        self.srum_file.write_bytes(b"\x00" * 2048)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/SrumECmd.exe")
    @patch("subprocess.run")
    def test_valid_srum_json_output(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "ExeInfo": "C:\\Program Files\\Browser\\browser.exe",
                "User": "S-1-5-21-123456789-1001",
                "TableName": "Network Usage",
                "BytesSent": 1048576,
                "BytesRecv": 5242880,
                "Timestamp": "2026-08-27T09:15:00Z",
                "SourceIp": "192.168.1.50",
                "DestinationIp": "93.184.216.34",
                "SourcePort": "54321",
                "DestinationPort": "443",
            },
            {
                "Application": "C:\\Windows\\System32\\svchost.exe",
                "SID": "S-1-5-18",
                "TableName": "Application Resource Usage",
                "ForegroundTime": 120,
                "BackgroundTime": 3600,
                "Timestamp": "2026-08-27T10:00:00Z",
            }
        ]

        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return MagicMock(returncode=0, stdout="Processed 2 records", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.srum_file), evidence_id="ev_srum_01")
        self.assertEqual(len(artifacts), 2)

        # 1-7, 13-15. Schema, Provenance, Identity, Network Usage, Resource Usage
        net_art = artifacts[0]
        self.assertEqual(net_art.source_tool, "srumecmd")
        self.assertEqual(net_art.artifact_type, "srum")
        self.assertEqual(net_art.evidence_id, "ev_srum_01")
        self.assertEqual(net_art.normalized_fields.process_name, "C:\\Program Files\\Browser\\browser.exe")
        self.assertEqual(net_art.normalized_fields.user, "S-1-5-21-123456789-1001")
        self.assertEqual(net_art.normalized_fields.src_ip, "192.168.1.50")
        self.assertEqual(net_art.normalized_fields.dst_ip, "93.184.216.34")
        self.assertEqual(net_art.normalized_fields.src_port, 54321)
        self.assertEqual(net_art.normalized_fields.dst_port, 443)
        self.assertEqual(net_art.timestamp_type, "recorded")
        self.assertEqual(net_art.raw_fields["BytesSent"], 1048576)

        res_art = artifacts[1]
        self.assertEqual(res_art.normalized_fields.process_name, "C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(res_art.normalized_fields.user, "S-1-5-18")
        self.assertEqual(res_art.raw_fields["ForegroundTime"], 120)

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1))
    def test_missing_executable_raises_not_found(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(SrumECmdNotFoundError):
            self.parser.parse(str(self.srum_file))

    @patch("shutil.which", return_value="/usr/bin/SrumECmd.exe")
    @patch("subprocess.run")
    def test_non_zero_exit_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Corrupted ESE DB")
        with self.assertRaises(SrumECmdExecutionError):
            self.parser.parse(str(self.srum_file))

    @patch("shutil.which", return_value="/usr/bin/SrumECmd.exe")
    @patch("subprocess.run", side_effect=TimeoutError())
    def test_timeout_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(SrumECmdExecutionError):
            self.parser.parse(str(self.srum_file))

    @patch("shutil.which", return_value="/usr/bin/SrumECmd.exe")
    @patch("subprocess.run")
    def test_malformed_output_handled(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text("invalid data\n", encoding="utf-8")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        artifacts = self.parser.parse(str(self.srum_file), evidence_id="ev_srum_bad")
        self.assertEqual(len(artifacts), 0)


class TestAmcacheAndSrumRouterIntegration(unittest.TestCase):
    """Router tests for Amcache and SRUM routing."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_amcache_hve_routes_to_amcache_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_amc",
            case_id="case_01",
            filename="Amcache.hve",
            file_path="/evidence/C/Windows/AppCompat/Programs/Amcache.hve",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "AmcacheParser")
        self.assertIsInstance(self.router.route(ev), AmcacheParser)

    def test_srudb_dat_routes_to_srumecmd_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_srum",
            case_id="case_01",
            filename="SRUDB.dat",
            file_path="/evidence/C/Windows/System32/sru/SRUDB.dat",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "SrumECmdParser")
        self.assertIsInstance(self.router.route(ev), SrumECmdParser)

    def test_case_insensitive_and_unicode_paths(self) -> None:
        ev_amc = Evidence(
            evidence_id="ev_amc_uc",
            case_id="case_01",
            filename="amcache.HVE",
            file_path="/evidence/Case Path with Spaces & Unicode 📁/amcache.HVE",
            uploaded_by="analyst",
        )
        res_amc = self.router.determine_routing(ev_amc)
        self.assertEqual(res_amc.status, "ROUTED")
        self.assertEqual(res_amc.target_parser, "AmcacheParser")

        ev_srum = Evidence(
            evidence_id="ev_srum_uc",
            case_id="case_01",
            filename="srudb.DAT",
            file_path="/evidence/Case Path with Spaces & Unicode 📁/srudb.DAT",
            uploaded_by="analyst",
        )
        res_srum = self.router.determine_routing(ev_srum)
        self.assertEqual(res_srum.status, "ROUTED")
        self.assertEqual(res_srum.target_parser, "SrumECmdParser")

    def test_generic_hve_does_not_route_to_amcache(self) -> None:
        ev = Evidence(
            evidence_id="ev_gen_hve",
            case_id="case_01",
            filename="custom.hve",
            file_path="/evidence/custom.hve",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertNotEqual(res.target_parser, "AmcacheParser")

    def test_generic_dat_does_not_route_to_srum(self) -> None:
        ev = Evidence(
            evidence_id="ev_gen_dat",
            case_id="case_01",
            filename="user_data.dat",
            file_path="/evidence/user_data.dat",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertNotEqual(res.target_parser, "SrumECmdParser")


if __name__ == "__main__":
    unittest.main()
