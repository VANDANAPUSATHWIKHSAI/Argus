"""
Targeted tests for Layer 2 repairs:
- DEF-01: Stale Magic-byte Unsupported Routing
- DEF-02: Wrong Explicit MSG Routing
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.timeline_parser import ActivitiesCacheParser
from preprocessing.parsers.stickynotes_parser import StickyNotesParser
from preprocessing.parsers.notification_parser import NotificationDbParser
from preprocessing.parsers.windows_search_parser import WindowsSearchParser
from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.parsers.mftecmd_parser import MfteCmdMftParser
from preprocessing.parsers.usn_parser import UsnLogFileParser
from preprocessing.parsers.msg_parser import MsgEmailParser
from preprocessing.parsers.email_parser import EmailParser

class TestRouterLayer2Repairs(unittest.TestCase):

    def setUp(self) -> None:
        self.router = ParserRouter()
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_temp_file(self, filename: str, content: bytes) -> str:
        file_path = os.path.join(self.tmp_dir.name, filename)
        with open(file_path, "wb") as f:
            f.write(content)
        return file_path

    def _make_evidence(self, filename: str, path: str, metadata: dict | None = None) -> Evidence:
        return Evidence(
            case_id="case-layer2-repairs",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-repairs",
            filename=filename,
            file_path=path,
            metadata=metadata or {}
        )

    # ── DEF-01 Tests ────────────────────────────────────────────────────────

    def test_sqlite_magic_activities_cache(self):
        sqlite_magic = b"SQLite format 3\x00" + b"\x00" * 16
        path = self._create_temp_file("ActivitiesCache.db", sqlite_magic)
        ev = self._make_evidence("ActivitiesCache.db", path)
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "ActivitiesCacheParser")
        self.assertIsInstance(self.router.route(ev), ActivitiesCacheParser)

    def test_sqlite_magic_plum_sqlite(self):
        sqlite_magic = b"SQLite format 3\x00" + b"\x00" * 16
        path = self._create_temp_file("plum.sqlite", sqlite_magic)
        ev = self._make_evidence("plum.sqlite", path)
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "StickyNotesParser")
        self.assertIsInstance(self.router.route(ev), StickyNotesParser)

    def test_sqlite_magic_stickynotes_sqlite(self):
        sqlite_magic = b"SQLite format 3\x00" + b"\x00" * 16
        path = self._create_temp_file("StickyNotes.sqlite", sqlite_magic)
        ev = self._make_evidence("StickyNotes.sqlite", path)
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "StickyNotesParser")
        self.assertIsInstance(self.router.route(ev), StickyNotesParser)

    def test_sqlite_magic_wpndatabase(self):
        sqlite_magic = b"SQLite format 3\x00" + b"\x00" * 16
        path = self._create_temp_file("wpndatabase.db", sqlite_magic)
        ev = self._make_evidence("wpndatabase.db", path)
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "NotificationDbParser")
        self.assertIsInstance(self.router.route(ev), NotificationDbParser)

    def test_ese_magic_windows_edb(self):
        ese_magic = b"\x00\x00\x00\x00\xef\x22\x20\x00" + b"\x00" * 24
        path = self._create_temp_file("Windows.edb", ese_magic)
        ev = self._make_evidence("Windows.edb", path)
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WindowsSearchParser")
        self.assertIsInstance(self.router.route(ev), WindowsSearchParser)

    def test_generic_sqlite_unknown_filename(self):
        sqlite_magic = b"SQLite format 3\x00" + b"\x00" * 16
        path = self._create_temp_file("unknown_app.db", sqlite_magic)
        ev = self._make_evidence("unknown_app.db", path)
        res = self.router.determine_routing(ev)
        self.assertIn(res.status, ("UNKNOWN", "AMBIGUOUS"))
        self.assertNotEqual(res.target_parser, "ActivitiesCacheParser")
        self.assertNotEqual(res.target_parser, "StickyNotesParser")
        self.assertNotEqual(res.target_parser, "NotificationDbParser")

    def test_generic_ese_unknown_filename(self):
        ese_magic = b"\x00\x00\x00\x00\xef\x22\x20\x00" + b"\x00" * 24
        path = self._create_temp_file("unknown_database.edb", ese_magic)
        ev = self._make_evidence("unknown_database.edb", path)
        res = self.router.determine_routing(ev)
        self.assertIn(res.status, ("UNKNOWN", "AMBIGUOUS"))
        self.assertNotEqual(res.target_parser, "WindowsSearchParser")

    def test_existing_firefox_sqlite_routing(self):
        sqlite_magic = b"SQLite format 3\x00" + b"\x00" * 16
        path = self._create_temp_file("places.sqlite", sqlite_magic)
        ev = self._make_evidence("places.sqlite", path)
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev), FirefoxParser)

        path_cookies = self._create_temp_file("cookies.sqlite", sqlite_magic)
        ev_cookies = self._make_evidence("cookies.sqlite", path_cookies)
        res_cookies = self.router.determine_routing(ev_cookies)
        self.assertEqual(res_cookies.status, "ROUTED")
        self.assertEqual(res_cookies.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev_cookies), FirefoxParser)

    def test_existing_mft_usn_logfile_routing(self):
        ev_mft = self._make_evidence("$MFT", "/some/path/$MFT")
        res_mft = self.router.determine_routing(ev_mft)
        self.assertEqual(res_mft.status, "ROUTED")
        self.assertEqual(res_mft.target_parser, "MfteCmdMftParser")
        self.assertIsInstance(self.router.route(ev_mft), MfteCmdMftParser)

        ev_usn = self._make_evidence("$UsnJrnl:$J", "/some/path/$UsnJrnl:$J")
        res_usn = self.router.determine_routing(ev_usn)
        self.assertEqual(res_usn.status, "ROUTED")
        self.assertEqual(res_usn.target_parser, "UsnLogFileParser")
        self.assertIsInstance(self.router.route(ev_usn), UsnLogFileParser)

        ev_log = self._make_evidence("$LogFile", "/some/path/$LogFile")
        res_log = self.router.determine_routing(ev_log)
        self.assertEqual(res_log.status, "ROUTED")
        self.assertEqual(res_log.target_parser, "UsnLogFileParser")
        self.assertIsInstance(self.router.route(ev_log), UsnLogFileParser)

    # ── DEF-02 Tests ────────────────────────────────────────────────────────

    def test_explicit_msg_metadata_routing(self):
        # 1. metadata evidence_type="msg" -> MsgEmailParser (ROUTED)
        ev = self._make_evidence("evidence.bin", "/some/path/evidence.bin", metadata={"evidence_type": "msg"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MsgEmailParser")
        self.assertIsInstance(self.router.route(ev), MsgEmailParser)

    def test_explicit_eml_metadata_routing(self):
        # 2. metadata evidence_type="eml" -> EmailParser (ROUTED)
        ev = self._make_evidence("evidence.bin", "/some/path/evidence.bin", metadata={"evidence_type": "eml"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EmailParser")
        self.assertIsInstance(self.router.route(ev), EmailParser)

    def test_msg_filename_routing(self):
        # 3. filename ending in .msg -> MsgEmailParser (ROUTED)
        ev = self._make_evidence("message.msg", "/some/path/message.msg")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MsgEmailParser")
        self.assertIsInstance(self.router.route(ev), MsgEmailParser)

    def test_eml_filename_routing(self):
        # 4. filename ending in .eml -> EmailParser (ROUTED)
        ev = self._make_evidence("message.eml", "/some/path/message.eml")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EmailParser")
        self.assertIsInstance(self.router.route(ev), EmailParser)

    def test_explicit_msg_metadata_never_instantiates_email_parser(self):
        # 5. Explicit msg metadata must NEVER instantiate EmailParser.
        ev = self._make_evidence("message.msg", "/some/path/message.msg", metadata={"evidence_type": "msg"})
        res = self.router.determine_routing(ev)
        self.assertNotEqual(res.target_parser, "EmailParser")
        self.assertNotIsInstance(self.router.route(ev), EmailParser)

    def test_explicit_eml_metadata_never_instantiates_msg_email_parser(self):
        # 6. Explicit eml metadata must NEVER instantiate MsgEmailParser.
        ev = self._make_evidence("message.eml", "/some/path/message.eml", metadata={"evidence_type": "eml"})
        res = self.router.determine_routing(ev)
        self.assertNotEqual(res.target_parser, "MsgEmailParser")
        self.assertNotIsInstance(self.router.route(ev), MsgEmailParser)

if __name__ == "__main__":
    unittest.main()
