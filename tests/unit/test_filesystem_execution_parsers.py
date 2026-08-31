"""
Unit tests for Windows Filesystem / Execution Artifact Parsers
==============================================================
Sources #11-#15:
- Source #11: MFT / NTFS (MfteCmdMftParser)
- Source #12: Prefetch (PecmdPrefetchParser)
- Source #13: LNK Files (LecmdLnkParser)
- Source #14: Jump Lists (JlecmdJumpListParser)
- Source #15: Recycle Bin (RbcmdRecycleBinParser)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.mftecmd_parser import (
    MfteCmdMftParser,
    MfteCmdNotFoundError,
    MfteCmdExecutionError,
)
from preprocessing.parsers.pecmd_parser import (
    PecmdPrefetchParser,
    PecmdNotFoundError,
    PecmdExecutionError,
)
from preprocessing.parsers.lecmd_parser import (
    LecmdLnkParser,
    LecmdNotFoundError,
    LecmdExecutionError,
)
from preprocessing.parsers.jlecmd_parser import (
    JlecmdJumpListParser,
    JlecmdNotFoundError,
    JlecmdExecutionError,
)
from preprocessing.parsers.rbcmd_parser import (
    RbcmdRecycleBinParser,
    RbcmdNotFoundError,
    RbcmdExecutionError,
)


class TestMfteCmdMftParser(unittest.TestCase):
    """Unit tests for MfteCmdMftParser (Source #11)."""

    def setUp(self) -> None:
        self.parser = MfteCmdMftParser(timeout_seconds=5)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.mft_file = Path(self.tmp_dir.name) / "$MFT"
        self.mft_file.write_bytes(b"\x00" * 1024)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/MFTECmd")
    @patch("subprocess.run")
    def test_valid_json_output_parsing(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "RecordNumber": 100,
                "SequenceNumber": 2,
                "FileName": "cmd.exe",
                "FilePath": "C:\\Windows\\System32\\cmd.exe",
                "FileSize": 300000,
                "InUse": True,
                "LastModified0x10": "2026-08-20T10:00:00.0000000+00:00",
                "Created0x10": "2026-08-01T08:00:00.0000000+00:00",
                "LastModified0x30": "2026-08-20T10:05:00.0000000+00:00",
            }
        ]

        def fake_run(cmd, **kwargs):
            tmp_out_dir = Path(cmd[cmd.index("--json") + 1])
            json_file = tmp_out_dir / cmd[cmd.index("--jsonf") + 1]
            json_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.mft_file), evidence_id="ev_mft_01")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "mftecmd")
        self.assertEqual(art.artifact_type, "mft_entry")
        self.assertEqual(art.evidence_id, "ev_mft_01")
        self.assertIn("cmd.exe", art.event_summary)
        self.assertEqual(art.timestamp_type, "modified")
        self.assertEqual(art.normalized_fields.file_name, "cmd.exe")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(art.raw_fields["FileSize"], 300000)
        self.assertEqual(art.raw_fields["RecordNumber"], 100)

    @patch("shutil.which", return_value="/usr/bin/MFTECmd")
    @patch("subprocess.run")
    def test_deleted_file_preservation(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "RecordNumber": 505,
                "FileName": "malware.exe",
                "FilePath": "C:\\Users\\Public\\malware.exe",
                "InUse": False,
                "LastModified0x10": "2026-08-25T14:30:00Z",
            }
        ]

        def fake_run(cmd, **kwargs):
            tmp_out_dir = Path(cmd[cmd.index("--json") + 1])
            json_file = tmp_out_dir / cmd[cmd.index("--jsonf") + 1]
            json_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.mft_file), evidence_id="ev_mft_del")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertIn("Deleted/Unallocated", art.event_summary)
        self.assertFalse(art.raw_fields["InUse"])

    @patch("shutil.which", return_value=None)
    def test_missing_tool_raises_not_found(self, mock_which: MagicMock) -> None:
        with self.assertRaises(MfteCmdNotFoundError):
            self.parser.parse(str(self.mft_file))

    @patch("shutil.which", return_value="/usr/bin/MFTECmd")
    @patch("subprocess.run")
    def test_non_zero_exit_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(["MFTECmd"], 1, stdout="", stderr="Corrupt MFT")
        with self.assertRaises(MfteCmdExecutionError):
            self.parser.parse(str(self.mft_file))

    @patch("shutil.which", return_value="/usr/bin/MFTECmd")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["MFTECmd"], 5))
    def test_timeout_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(MfteCmdExecutionError):
            self.parser.parse(str(self.mft_file))


class TestPecmdPrefetchParser(unittest.TestCase):
    """Unit tests for PecmdPrefetchParser (Source #12)."""

    def setUp(self) -> None:
        self.parser = PecmdPrefetchParser(timeout_seconds=5)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pf_file = Path(self.tmp_dir.name) / "CMD.EXE-12345678.pf"
        self.pf_file.write_bytes(b"SCCA" + b"\x00" * 100)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/PECmd")
    @patch("subprocess.run")
    def test_valid_prefetch_parsing(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "ExecutableName": "CMD.EXE",
                "RunCount": 42,
                "LastRun": "2026-08-26T12:00:00.0000000+00:00",
                "ExecutablePath": "\\VOLUME{01}\\WINDOWS\\SYSTEM32\\CMD.EXE",
                "Hash": "12345678",
            }
        ]

        def fake_run(cmd, **kwargs):
            tmp_out_dir = Path(cmd[cmd.index("--json") + 1])
            json_file = tmp_out_dir / cmd[cmd.index("--jsonf") + 1]
            json_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.pf_file), evidence_id="ev_pf_01")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.source_tool, "pecmd")
        self.assertEqual(art.artifact_type, "prefetch")
        self.assertEqual(art.timestamp_type, "execution")
        self.assertEqual(art.normalized_fields.process_name, "CMD.EXE")
        self.assertEqual(art.normalized_fields.file_name, "CMD.EXE")
        self.assertEqual(art.raw_fields["RunCount"], 42)

    @patch("shutil.which", return_value=None)
    def test_missing_tool_raises_not_found(self, mock_which: MagicMock) -> None:
        with self.assertRaises(PecmdNotFoundError):
            self.parser.parse(str(self.pf_file))


class TestLecmdLnkParser(unittest.TestCase):
    """Unit tests for LecmdLnkParser (Source #13)."""

    def setUp(self) -> None:
        self.parser = LecmdLnkParser(timeout_seconds=5)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.lnk_file = Path(self.tmp_dir.name) / "test.lnk"
        self.lnk_file.write_bytes(b"\x4c\x00\x00\x00" + b"\x00" * 100)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/LECmd")
    @patch("subprocess.run")
    def test_valid_lnk_parsing(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "TargetPath": "C:\\Windows\\System32\\cmd.exe",
                "Arguments": "/c powershell.exe",
                "SourceCreated": "2026-08-20T09:00:00.0000000+00:00",
                "TargetModified": "2026-08-15T08:00:00.0000000+00:00",
            }
        ]

        def fake_run(cmd, **kwargs):
            tmp_out_dir = Path(cmd[cmd.index("--json") + 1])
            json_file = tmp_out_dir / cmd[cmd.index("--jsonf") + 1]
            json_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.lnk_file), evidence_id="ev_lnk_01")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.source_tool, "lecmd")
        self.assertEqual(art.artifact_type, "lnk")
        self.assertEqual(art.timestamp_type, "created")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(art.normalized_fields.process_command_line, "C:\\Windows\\System32\\cmd.exe /c powershell.exe")

    @patch("shutil.which", return_value=None)
    def test_missing_tool_raises_not_found(self, mock_which: MagicMock) -> None:
        with self.assertRaises(LecmdNotFoundError):
            self.parser.parse(str(self.lnk_file))


class TestJlecmdJumpListParser(unittest.TestCase):
    """Unit tests for JlecmdJumpListParser (Source #14)."""

    def setUp(self) -> None:
        self.parser = JlecmdJumpListParser(timeout_seconds=5)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.jl_file = Path(self.tmp_dir.name) / "1b4dd67f29fe0386.automaticDestinations-ms"
        self.jl_file.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/JLECmd")
    @patch("subprocess.run")
    def test_valid_jumplist_parsing(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "AppId": "1b4dd67f29fe0386",
                "AppIdDescription": "Windows Command Processor",
                "TargetPath": "C:\\Logs\\investigation.txt",
                "Accessed": "2026-08-26T15:00:00.0000000+00:00",
            }
        ]

        def fake_run(cmd, **kwargs):
            tmp_out_dir = Path(cmd[cmd.index("--json") + 1])
            json_file = tmp_out_dir / cmd[cmd.index("--jsonf") + 1]
            json_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.jl_file), evidence_id="ev_jl_01")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.source_tool, "jlecmd")
        self.assertEqual(art.artifact_type, "jumplist")
        self.assertEqual(art.timestamp_type, "accessed")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Logs\\investigation.txt")

    @patch("shutil.which", return_value=None)
    def test_missing_tool_raises_not_found(self, mock_which: MagicMock) -> None:
        with self.assertRaises(JlecmdNotFoundError):
            self.parser.parse(str(self.jl_file))


class TestRbcmdRecycleBinParser(unittest.TestCase):
    """Unit tests for RbcmdRecycleBinParser (Source #15)."""

    def setUp(self) -> None:
        self.parser = RbcmdRecycleBinParser(timeout_seconds=5)
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.rb_file = Path(self.tmp_dir.name) / "$I12345.dat"
        self.rb_file.write_bytes(b"\x01\x00\x00\x00" + b"\x00" * 100)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("shutil.which", return_value="/usr/bin/RBCmd")
    @patch("subprocess.run")
    def test_valid_recycle_bin_parsing(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture_records = [
            {
                "FilePath": "C:\\Users\\Victim\\Secret.docx",
                "FileSize": 45096,
                "DeletedOn": "2026-08-25T18:00:00.0000000+00:00",
            }
        ]

        def fake_run(cmd, **kwargs):
            tmp_out_dir = Path(cmd[cmd.index("--json") + 1])
            json_file = tmp_out_dir / cmd[cmd.index("--jsonf") + 1]
            json_file.write_text(json.dumps(fixture_records), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="OK", stderr="")

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.rb_file), evidence_id="ev_rb_01")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.source_tool, "rbcmd")
        self.assertEqual(art.artifact_type, "recycle_bin")
        self.assertEqual(art.timestamp_type, "deleted")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Users\\Victim\\Secret.docx")
        self.assertEqual(art.raw_fields["FileSize"], 45096)
        self.assertTrue(art.normalized_fields.deleted)

    @patch("shutil.which", return_value=None)
    def test_missing_tool_raises_not_found(self, mock_which: MagicMock) -> None:
        with self.assertRaises(RbcmdNotFoundError):
            self.parser.parse(str(self.rb_file))


class TestRouterIntegrationGroup(unittest.TestCase):
    """Router integration tests for Sources #11-#15."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_mft_routes_to_mftecmd(self) -> None:
        ev = Evidence(evidence_id="e11", case_id="c1", filename="$MFT", file_path="/evidence/$MFT", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MfteCmdMftParser")
        self.assertIsInstance(self.router.route(ev), MfteCmdMftParser)

    def test_prefetch_routes_to_pecmd(self) -> None:
        ev = Evidence(evidence_id="e12", case_id="c1", filename="CMD.EXE-1234.pf", file_path="/evidence/CMD.EXE-1234.pf", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "PecmdPrefetchParser")
        self.assertIsInstance(self.router.route(ev), PecmdPrefetchParser)

    def test_lnk_routes_to_lecmd(self) -> None:
        ev = Evidence(evidence_id="e13", case_id="c1", filename="cmd.lnk", file_path="/evidence/cmd.lnk", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "LecmdLnkParser")
        self.assertIsInstance(self.router.route(ev), LecmdLnkParser)

    def test_jumplist_routes_to_jlecmd(self) -> None:
        ev = Evidence(evidence_id="e14", case_id="c1", filename="1b4dd67f29fe0386.automaticDestinations-ms", file_path="/evidence/1b4dd67f29fe0386.automaticDestinations-ms", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "JlecmdJumpListParser")
        self.assertIsInstance(self.router.route(ev), JlecmdJumpListParser)

    def test_recycle_bin_routes_to_rbcmd(self) -> None:
        ev = Evidence(evidence_id="e15", case_id="c1", filename="$I12345.dat", file_path="/evidence/$Recycle.Bin/$I12345.dat", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RbcmdRecycleBinParser")
        self.assertIsInstance(self.router.route(ev), RbcmdRecycleBinParser)


if __name__ == "__main__":
    unittest.main()
