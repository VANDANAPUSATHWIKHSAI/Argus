"""
Unit tests for UsnLogFileParser (Source #19) and ShimCacheParser (Source #20)
=============================================================================
- Source #19: USN Journal / $LogFile (MFTECmd)
- Source #20: ShimCache / AppCompatCache (AppCompatCacheParser)
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.mftecmd_parser import MfteCmdMftParser
from preprocessing.parsers.registry_parser import RegistryParser
from preprocessing.parsers.usn_parser import (
    UsnLogFileParser,
    UsnLogFileParserNotFoundError,
    UsnLogFileParserExecutionError,
)
from preprocessing.parsers.shimcache_parser import (
    ShimCacheParser,
    ShimCacheParserNotFoundError,
    ShimCacheParserExecutionError,
)


class TestUsnLogFileParserUnit(unittest.TestCase):
    """Unit tests for UsnLogFileParser."""

    def setUp(self) -> None:
        self.parser = UsnLogFileParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.usn_file = Path(self.tmp_dir.name) / "$UsnJrnl"
        self.usn_file.write_bytes(b"\x00" * 2048)
        self.logfile_file = Path(self.tmp_dir.name) / "$LogFile"
        self.logfile_file.write_bytes(b"\x00" * 2048)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/MFTECmd.exe")
    @patch("subprocess.run")
    def test_valid_usn_journal_output(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "FileName": "cmd.exe",
                "FullPath": "C:\\Windows\\System32\\cmd.exe",
                "UpdateSequenceNumber": 123456789,
                "FileReferenceNumber": "0x0001000000001234",
                "ParentFileReferenceNumber": "0x0001000000000005",
                "UpdateReason": "DATA_OVERWRITE | FILE_CREATE | CLOSE",
                "Timestamp": "2026-08-27T11:00:00Z",
                "SecurityId": 256,
                "SourceInfo": "0x0",
            },
            {
                "FileName": "temp_script.ps1",
                "FullPath": "C:\\Users\\Public\\temp_script.ps1",
                "UpdateSequenceNumber": 123456790,
                "FileReferenceNumber": "0x0001000000005678",
                "ParentFileReferenceNumber": "0x0001000000000005",
                "UpdateReason": "RENAME_OLD_NAME | RENAME_NEW_NAME | FILE_DELETE",
                "Timestamp": "2026-08-27T11:05:00Z",
            }
        ]

        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return MagicMock(returncode=0, stdout="Processed 2 USN records", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.usn_file), evidence_id="ev_usn_01")
        self.assertEqual(len(artifacts), 2)

        # 1-10, 15-17. Schema, Provenance, Metadata, Reasons, Timestamps
        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "mftecmd_usn")
        self.assertEqual(art1.artifact_type, "usn_journal")
        self.assertEqual(art1.evidence_id, "ev_usn_01")
        self.assertEqual(art1.normalized_fields.file_name, "cmd.exe")
        self.assertEqual(art1.normalized_fields.file_path, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(art1.timestamp_type, "event")
        self.assertIsNotNone(art1.timestamp)
        self.assertIn("DATA_OVERWRITE", art1.raw_fields["UpdateReason"])
        self.assertEqual(art1.raw_fields["FileReferenceNumber"], "0x0001000000001234")
        self.assertEqual(art1.raw_fields["ParentFileReferenceNumber"], "0x0001000000000005")

        # Rename / Delete record
        art2 = artifacts[1]
        self.assertEqual(art2.normalized_fields.file_name, "temp_script.ps1")
        self.assertIn("RENAME_NEW_NAME", art2.raw_fields["UpdateReason"])
        self.assertIn("FILE_DELETE", art2.raw_fields["UpdateReason"])

    @patch("shutil.which", return_value="/usr/bin/MFTECmd.exe")
    @patch("subprocess.run")
    def test_valid_logfile_output(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "FileName": "$LogFile_Tx",
                "FullPath": "C:\\$LogFile",
                "Operation": "WriteData",
                "Timestamp": "2026-08-27T11:10:00Z",
            }
        ]

        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return MagicMock(returncode=0, stdout="Processed 1 LogFile record", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.logfile_file), evidence_id="ev_log_01")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "mftecmd_usn")
        self.assertEqual(art.artifact_type, "logfile")
        self.assertEqual(art.evidence_id, "ev_log_01")

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1))
    def test_missing_executable_raises_not_found(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(UsnLogFileParserNotFoundError):
            self.parser.parse(str(self.usn_file))

    @patch("shutil.which", return_value="/usr/bin/MFTECmd.exe")
    @patch("subprocess.run")
    def test_non_zero_exit_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Corrupted $UsnJrnl")
        with self.assertRaises(UsnLogFileParserExecutionError):
            self.parser.parse(str(self.usn_file))

    @patch("shutil.which", return_value="/usr/bin/MFTECmd.exe")
    @patch("subprocess.run", side_effect=TimeoutError())
    def test_timeout_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(UsnLogFileParserExecutionError):
            self.parser.parse(str(self.usn_file))

    @patch("shutil.which", return_value="/usr/bin/MFTECmd.exe")
    @patch("subprocess.run")
    def test_malformed_json_output_handled(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text("{bad usn json\n", encoding="utf-8")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        artifacts = self.parser.parse(str(self.usn_file), evidence_id="ev_usn_bad")
        self.assertEqual(len(artifacts), 0)


class TestShimCacheParserUnit(unittest.TestCase):
    """Unit tests for ShimCacheParser."""

    def setUp(self) -> None:
        self.parser = ShimCacheParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.shim_file = Path(self.tmp_dir.name) / "SYSTEM"
        self.shim_file.write_bytes(b"regf" + b"\x00" * 1024)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/AppCompatCacheParser.exe")
    @patch("subprocess.run")
    def test_valid_shimcache_json_output(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "Path": "C:\\Program Files\\ExampleApp\\app.exe",
                "LastModifiedTime": "2026-08-20T08:00:00Z",
                "ControlSet": 1,
                "EntryIndex": 0,
                "SourceHive": "SYSTEM",
            }
        ]

        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return MagicMock(returncode=0, stdout="Processed 1 ShimCache entry", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.shim_file), evidence_id="ev_shim_01")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        # 1-6, 11-13. Schema, Provenance, Path, Context, Timestamps
        self.assertEqual(art.source_tool, "appcompatcacheparser")
        self.assertEqual(art.artifact_type, "shimcache")
        self.assertEqual(art.evidence_id, "ev_shim_01")
        self.assertEqual(art.normalized_fields.file_name, "app.exe")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Program Files\\ExampleApp\\app.exe")
        self.assertEqual(art.normalized_fields.process_name, "app.exe")
        self.assertEqual(art.timestamp_type, "modified")
        self.assertEqual(art.raw_fields["ControlSet"], 1)

        # 14. Verify no automatic "executed=true" inference
        self.assertNotIn("executed", art.raw_fields)
        self.assertFalse(hasattr(art.normalized_fields, "executed"))

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1))
    def test_missing_executable_raises_not_found(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(ShimCacheParserNotFoundError):
            self.parser.parse(str(self.shim_file))

    @patch("shutil.which", return_value="/usr/bin/AppCompatCacheParser.exe")
    @patch("subprocess.run")
    def test_non_zero_exit_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Corrupted hive")
        with self.assertRaises(ShimCacheParserExecutionError):
            self.parser.parse(str(self.shim_file))

    @patch("shutil.which", return_value="/usr/bin/AppCompatCacheParser.exe")
    @patch("subprocess.run", side_effect=TimeoutError())
    def test_timeout_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(ShimCacheParserExecutionError):
            self.parser.parse(str(self.shim_file))

    @patch("shutil.which", return_value="/usr/bin/AppCompatCacheParser.exe")
    @patch("subprocess.run")
    def test_malformed_output_handled(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        def fake_run(cmd, **kwargs):
            out_dir = Path(cmd[cmd.index("--json") + 1])
            out_file = out_dir / cmd[cmd.index("--jsonf") + 1]
            out_file.write_text("invalid json data\n", encoding="utf-8")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        artifacts = self.parser.parse(str(self.shim_file), evidence_id="ev_shim_bad")
        self.assertEqual(len(artifacts), 0)


class TestUsnAndShimCacheRouterIntegration(unittest.TestCase):
    """Router integration tests for USN Journal and ShimCache."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_usn_jrnl_routes_to_usn_logfile_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_usn",
            case_id="case_01",
            filename="$UsnJrnl",
            file_path="/evidence/$Extend/$UsnJrnl:$J",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "UsnLogFileParser")
        self.assertIsInstance(self.router.route(ev), UsnLogFileParser)

    def test_logfile_routes_to_usn_logfile_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_log",
            case_id="case_01",
            filename="$LogFile",
            file_path="/evidence/$LogFile",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "UsnLogFileParser")
        self.assertIsInstance(self.router.route(ev), UsnLogFileParser)

    def test_shimcache_routes_to_shimcache_parser(self) -> None:
        ev = Evidence(
            evidence_id="ev_shim",
            case_id="case_01",
            filename="AppCompatCache.bin",
            file_path="/evidence/C/Windows/AppCompat/Programs/AppCompatCache.bin",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "ShimCacheParser")
        self.assertIsInstance(self.router.route(ev), ShimCacheParser)

    def test_mft_routes_to_mftecmd_not_usn(self) -> None:
        ev = Evidence(
            evidence_id="ev_mft",
            case_id="case_01",
            filename="$MFT",
            file_path="/evidence/$MFT",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MfteCmdMftParser")
        self.assertIsInstance(self.router.route(ev), MfteCmdMftParser)

    def test_generic_registry_hive_routes_to_registry_not_shimcache(self) -> None:
        ev = Evidence(
            evidence_id="ev_sys",
            case_id="case_01",
            filename="SYSTEM",
            file_path="/evidence/Windows/System32/config/SYSTEM",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")
        self.assertIsInstance(self.router.route(ev), RegistryParser)

    def test_generic_dat_does_not_route_to_shimcache_or_usn(self) -> None:
        ev = Evidence(
            evidence_id="ev_gen_dat",
            case_id="case_01",
            filename="unknown_data.dat",
            file_path="/evidence/unknown_data.dat",
            uploaded_by="analyst",
        )
        res = self.router.determine_routing(ev)
        self.assertNotIn(res.target_parser, ("ShimCacheParser", "UsnLogFileParser"))


if __name__ == "__main__":
    unittest.main()
