"""
Unit Tests for EvtxECmdParser (EVTX Raw Stream) & Stream Separation
=====================================================================
Validates Source 4 (EvtxECmd raw stream parser) and stream separation with Source 5 (Hayabusa).
Mocks external subprocess calls so tests run deterministically without requiring EvtxECmd installation.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

from preprocessing.parsers.evtxecmd_parser import (
    EvtxECmdParser,
    EvtxECmdNotFoundError,
    EvtxECmdExecutionError,
)
from preprocessing.parsers.evtx_parser import EvtxParser
from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence


class TestEvtxECmdParserUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = EvtxECmdParser(timeout_seconds=5)
        self.tmp_dir = tempfile.mkdtemp(prefix="test_evtxecmd_")
        self.evtx_path = Path(self.tmp_dir) / "Security.evtx"
        self.evtx_path.write_bytes(b"ElfFile\x00dummy_evtx_content")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ── 1. Valid EvtxECmd Output & Field Preservation ───────────────────────

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run")
    def test_valid_evtxecmd_json_output(self, mock_run: MagicMock, mock_which: MagicMock):
        # Setup mock subprocess output
        def fake_run(cmd, **kwargs):
            # Extract output json file from cmd flags
            json_dir = cmd[cmd.index("--json") + 1]
            json_file = cmd[cmd.index("--jsonf") + 1]
            target = Path(json_dir) / json_file
            data = [
                {
                    "EventId": 4624,
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "Channel": "Security",
                    "Computer": "DC01.corp.local",
                    "RecordId": 10042,
                    "Level": "Information",
                    "TimeCreated": "2024-03-15T10:20:30.123456+00:00",
                    "Payload": {"TargetUserName": "Administrator", "WorkstationName": "WORKSTATION01"},
                    "ProcessID": 512,
                    "IpAddress": "192.168.1.50"
                },
                {
                    "EventId": 4625,
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "Channel": "Security",
                    "Computer": "DC01.corp.local",
                    "RecordId": 10043,
                    "Level": "Warning",
                    "TimeCreated": "2024-03-15T10:21:00Z",
                    "Payload": {"TargetUserName": "Guest"},
                    "ProcessID": 512,
                    "IpAddress": "10.0.0.99"
                }
            ]
            target.write_text(json.dumps(data), encoding="utf-8")
            res = Mock()
            res.returncode = 0
            res.stdout = "Processed 2 event records."
            res.stderr = ""
            return res

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.evtx_path), evidence_id="ev-100")

        self.assertEqual(len(artifacts), 2)

        art1 = artifacts[0]
        self.assertEqual(art1.evidence_id, "ev-100")
        self.assertEqual(art1.source_tool, "evtxecmd")
        self.assertEqual(art1.artifact_type, "log_event")
        self.assertEqual(art1.timestamp_type, "event")
        self.assertEqual(art1.raw_fields["EventId"], 4624)
        self.assertEqual(art1.raw_fields["Provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(art1.raw_fields["Channel"], "Security")
        self.assertEqual(art1.raw_fields["Computer"], "DC01.corp.local")
        self.assertEqual(art1.raw_fields["RecordId"], 10042)
        self.assertIn("tool_version", art1.raw_fields)

        # Normalized correlation fields
        self.assertEqual(art1.normalized_fields.host, "DC01.corp.local")
        self.assertEqual(art1.normalized_fields.user, "Administrator")
        self.assertEqual(art1.normalized_fields.process_id, 512)
        self.assertEqual(art1.normalized_fields.src_ip, "192.168.1.50")

    # ── 2. CSV Output Fallback ──────────────────────────────────────────────

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run")
    def test_evtxecmd_csv_output_parsing(self, mock_run: MagicMock, mock_which: MagicMock):
        def fake_run(cmd, **kwargs):
            json_dir = cmd[cmd.index("--json") + 1]
            csv_target = Path(json_dir) / "out.csv"
            csv_content = (
                "EventId,Provider,Channel,Computer,RecordId,TimeCreated,IpAddress\n"
                "7045,Service Control Manager,System,SERVER01,999,2024-03-15T12:00:00Z,172.16.0.5\n"
            )
            csv_target.write_text(csv_content, encoding="utf-8")
            res = Mock()
            res.returncode = 0
            res.stdout = ""
            res.stderr = ""
            return res

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.evtx_path), evidence_id="ev-csv-01")
        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.source_tool, "evtxecmd")
        self.assertEqual(art.raw_fields["EventId"], "7045")
        self.assertEqual(art.normalized_fields.host, "SERVER01")

    # ── 3. Malformed and Missing Record Resilience ──────────────────────────

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run")
    def test_malformed_and_missing_timestamp_records(self, mock_run: MagicMock, mock_which: MagicMock):
        def fake_run(cmd, **kwargs):
            json_dir = cmd[cmd.index("--json") + 1]
            json_file = cmd[cmd.index("--jsonf") + 1]
            target = Path(json_dir) / json_file
            # Line 1: valid, Line 2: malformed JSON text, Line 3: valid but missing timestamp
            target.write_text(
                '{"EventId": 1102, "Channel": "Security", "TimeCreated": "2024-03-15T10:00:00Z"}\n'
                'MALFORMED_JSON_STRING_HERE\n'
                '{"EventId": 4688, "Channel": "Security"}\n',
                encoding="utf-8"
            )
            res = Mock()
            res.returncode = 0
            return res

        mock_run.side_effect = fake_run

        artifacts = self.parser.parse(str(self.evtx_path), evidence_id="ev-malformed")
        # Should gracefully skip malformed line and parse the 2 valid records
        self.assertEqual(len(artifacts), 2)
        self.assertEqual(artifacts[0].raw_fields["EventId"], 1102)
        self.assertIsNotNone(artifacts[0].timestamp)
        self.assertEqual(artifacts[1].raw_fields["EventId"], 4688)
        self.assertIsNone(artifacts[1].timestamp)  # missing timestamp handled gracefully

    # ── 4. Error & Edge Case Executions ─────────────────────────────────────

    @patch("shutil.which", return_value=None)
    def test_missing_evtxecmd_binary_raises_not_found(self, mock_which: MagicMock):
        with self.assertRaises(EvtxECmdNotFoundError):
            self.parser.parse(str(self.evtx_path))

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run")
    def test_non_zero_exit_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock):
        res = Mock()
        res.returncode = 1
        res.stdout = ""
        res.stderr = "Fatal error reading EVTX structure"
        mock_run.return_value = res

        with self.assertRaises(EvtxECmdExecutionError) as ctx:
            self.parser.parse(str(self.evtx_path))
        self.assertIn("Fatal error", str(ctx.exception))

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="EvtxECmd", timeout=5))
    def test_timeout_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock):
        with self.assertRaises(EvtxECmdExecutionError) as ctx:
            self.parser.parse(str(self.evtx_path))
        self.assertIn("timed out", str(ctx.exception))

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run")
    def test_empty_output_returns_empty_list(self, mock_run: MagicMock, mock_which: MagicMock):
        res = Mock()
        res.returncode = 0
        res.stdout = "Processed 0 records."
        mock_run.return_value = res

        artifacts = self.parser.parse(str(self.evtx_path))
        self.assertEqual(artifacts, [])

    # ── 5. Stream Separation (EvtxECmd Raw vs Hayabusa Threat-Hunted) ──────

    @patch("shutil.which", return_value="EvtxECmd.exe")
    @patch("subprocess.run")
    def test_same_evtx_processed_through_both_streams_remains_separate(
        self, mock_run: MagicMock, mock_which: MagicMock
    ):
        # 1. Setup mock EvtxECmd run
        def fake_run(cmd, **kwargs):
            json_dir = cmd[cmd.index("--json") + 1]
            json_file = cmd[cmd.index("--jsonf") + 1]
            target = Path(json_dir) / json_file
            data = [{"EventId": 4688, "Channel": "Security", "TimeCreated": "2024-03-15T10:00:00Z"}]
            target.write_text(json.dumps(data), encoding="utf-8")
            res = Mock()
            res.returncode = 0
            return res

        mock_run.side_effect = fake_run

        evidence_id = "ev-shared-999"

        # Stream A: EvtxECmd Raw Stream
        raw_parser = EvtxECmdParser()
        raw_artifacts = raw_parser.parse(str(self.evtx_path), evidence_id=evidence_id)

        # Stream B: Hayabusa Threat-Hunted Stream (via EvtxParser mock / direct invocation)
        hayabusa_parser = EvtxParser()
        def fake_hayabusa(src, tmp_path):
            tmp_path.write_text(
                json.dumps({
                    "Timestamp": "2024-03-15T10:00:00Z",
                    "RuleTitle": "Suspicious Process Creation",
                    "Level": "high",
                    "Computer": "DC01",
                    "Channel": "Security",
                    "EventID": 4688,
                }) + "\n",
                encoding="utf-8"
            )

        with patch.object(hayabusa_parser, "_run_hayabusa", side_effect=fake_hayabusa):
            hunted_artifacts = hayabusa_parser.parse(str(self.evtx_path), evidence_id=evidence_id)

        # Assertions for Stream Separation
        self.assertEqual(len(raw_artifacts), 1)
        self.assertEqual(len(hunted_artifacts), 1)

        raw_art = raw_artifacts[0]
        hunted_art = hunted_artifacts[0]

        # 1. Both retain the exact same evidence_id
        self.assertEqual(raw_art.evidence_id, evidence_id)
        self.assertEqual(hunted_art.evidence_id, evidence_id)

        # 2. Source tool identifies the separate streams cleanly
        self.assertEqual(raw_art.source_tool, "evtxecmd")
        self.assertEqual(hunted_art.source_tool, "hayabusa")
        self.assertNotEqual(raw_art.source_tool, hunted_art.source_tool)

        # 3. Router dispatches correctly based on metadata
        router = ParserRouter()
        raw_ev = Evidence(
            case_id="c1", uploaded_by="u1", evidence_id=evidence_id,
            filename="Security.evtx", file_path=str(self.evtx_path),
            metadata={"stream": "raw"}
        )
        hunted_ev = Evidence(
            case_id="c1", uploaded_by="u1", evidence_id=evidence_id,
            filename="Security.evtx", file_path=str(self.evtx_path),
            metadata={}
        )

        res_raw = router.determine_routing(raw_ev)
        res_hunted = router.determine_routing(hunted_ev)

        self.assertEqual(res_raw.target_parser, "EvtxECmdParser")
        self.assertEqual(res_hunted.target_parser, "EvtxParser")


if __name__ == "__main__":
    unittest.main()
