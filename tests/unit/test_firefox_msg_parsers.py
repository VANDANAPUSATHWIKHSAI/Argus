"""
Unit Tests for Firefox Custom SQLite Parser & Outlook MSG Parser
==================================================================
Validates Source 8 (Firefox places.sqlite, cookies.sqlite, formhistory.sqlite)
and Source 10 (Outlook .msg extract-msg parser) with router integration.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

from preprocessing.parsers.firefox_parser import (
    FirefoxParser,
    FirefoxParserError,
    FirefoxDatabaseCorruptError,
)
from preprocessing.parsers.msg_parser import (
    MsgEmailParser,
    MsgParserError,
    MsgParserDependencyError,
    MsgParserCorruptError,
)
from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence


class TestFirefoxParserUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = FirefoxParser()
        self.tmp_dir = tempfile.mkdtemp(prefix="test_firefox_")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_sqlite(self, filename: str, setup_sql: str) -> Path:
        db_path = Path(self.tmp_dir) / filename
        conn = sqlite3.connect(db_path)
        conn.executescript(setup_sql)
        conn.commit()
        conn.close()
        return db_path

    # ── 1. places.sqlite Browsing History ───────────────────────────────────

    def test_valid_places_sqlite_parsing(self):
        sql = """
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            rev_host TEXT,
            visit_count INTEGER,
            hidden INTEGER,
            typed INTEGER,
            last_visit_date INTEGER
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            from_visit INTEGER,
            place_id INTEGER,
            visit_date INTEGER,
            visit_type INTEGER
        );
        INSERT INTO moz_places VALUES (1, 'https://example.com/login', 'Example Login', 'moc.elpmaxe.', 3, 0, 1, 1710498030000000);
        INSERT INTO moz_places VALUES (2, 'https://evil.com/phish', 'Phishing Site', 'moc.live.', 1, 0, 0, 1710498060000000);

        INSERT INTO moz_historyvisits VALUES (101, 0, 1, 1710498030000000, 1);
        INSERT INTO moz_historyvisits VALUES (102, 101, 1, 1710498040000000, 2);
        INSERT INTO moz_historyvisits VALUES (103, 0, 2, 1710498060000000, 1);
        """
        db_path = self._create_sqlite("places.sqlite", sql)

        artifacts = self.parser.parse(str(db_path), evidence_id="ev-ff-01")
        self.assertEqual(len(artifacts), 3)

        art1 = artifacts[0]
        self.assertEqual(art1.evidence_id, "ev-ff-01")
        self.assertEqual(art1.source_tool, "firefox_sqlite")
        self.assertEqual(art1.artifact_type, "browser_history")
        self.assertEqual(art1.timestamp_type, "visit")
        self.assertIsNotNone(art1.timestamp)
        self.assertEqual(art1.raw_fields["url"], "https://example.com/login")
        self.assertEqual(art1.raw_fields["title"], "Example Login")
        self.assertEqual(art1.raw_fields["visit_count"], 3)
        self.assertEqual(art1.normalized_fields.url, "https://example.com/login")
        self.assertEqual(art1.normalized_fields.host, "example.com")

    # ── 2. cookies.sqlite Parsing ───────────────────────────────────────────

    def test_cookies_sqlite_parsing(self):
        sql = """
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            baseDomain TEXT,
            originAttributes TEXT,
            name TEXT,
            value TEXT,
            host TEXT,
            path TEXT,
            expiry INTEGER,
            lastAccessed INTEGER,
            creationTime INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER
        );
        INSERT INTO moz_cookies VALUES (
            1, 'target.com', '', 'session_token', 'secret123', '.target.com', '/',
            1750000000, 1710498030000000, 1710498000000000, 1, 1
        );
        """
        db_path = self._create_sqlite("cookies.sqlite", sql)

        artifacts = self.parser.parse(str(db_path), evidence_id="ev-cookie-01")
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "firefox_sqlite")
        self.assertEqual(art.artifact_type, "browser_cookie")
        self.assertEqual(art.timestamp_type, "creation")
        self.assertEqual(art.raw_fields["name"], "session_token")
        self.assertEqual(art.raw_fields["value"], "secret123")  # Value preserved without alteration
        self.assertEqual(art.normalized_fields.host, "target.com")

    # ── 3. Malformed and Empty DB Handling ─────────────────────────────────

    def test_corrupt_sqlite_raises_error(self):
        corrupt_path = Path(self.tmp_dir) / "corrupt.sqlite"
        corrupt_path.write_bytes(b"NOT_A_SQLITE_DATABASE_HEADER")

        with self.assertRaises(FirefoxDatabaseCorruptError):
            self.parser.parse(str(corrupt_path))

    def test_missing_tables_returns_empty_list(self):
        sql = "CREATE TABLE dummy_table (id INTEGER);"
        db_path = self._create_sqlite("places.sqlite", sql)

        artifacts = self.parser.parse(str(db_path))
        self.assertEqual(artifacts, [])

    def test_empty_places_table_returns_empty_list(self):
        sql = """
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, from_visit INTEGER);
        """
        db_path = self._create_sqlite("places.sqlite", sql)

        artifacts = self.parser.parse(str(db_path))
        self.assertEqual(artifacts, [])

    def test_nonexistent_file_raises_not_found(self):
        with self.assertRaises(FileNotFoundError):
            self.parser.parse(str(Path(self.tmp_dir) / "nonexistent.sqlite"))


class TestMsgEmailParserUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = MsgEmailParser()
        self.tmp_dir = tempfile.mkdtemp(prefix="test_msg_")
        self.msg_path = Path(self.tmp_dir) / "phish.msg"
        self.msg_path.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1dummy_ole_msg_stream")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # ── 1. Valid MSG Parsing ────────────────────────────────────────────────

    def test_valid_msg_parsing_with_mock(self):
        mock_msg_obj = Mock()
        mock_msg_obj.sender = "attacker@malicious.com"
        mock_msg_obj.to = "ceo@corp.local"
        mock_msg_obj.cc = "cfo@corp.local"
        mock_msg_obj.bcc = ""
        mock_msg_obj.subject = "URGENT Wire Transfer"
        mock_msg_obj.body = "Please execute the attached wire transfer immediately."
        mock_msg_obj.date = "2024-03-15 14:30:00+00:00"
        mock_msg_obj.receivedTime = "2024-03-15 14:30:05+00:00"
        mock_msg_obj.messageId = "<12345@malicious.com>"
        mock_msg_obj.header = {"X-Originating-IP": "198.51.100.25"}

        mock_att = Mock()
        mock_att.longFilename = "invoice.pdf.exe"
        mock_att.filename = "invoice.pdf.exe"
        mock_att.mimetype = "application/x-msdownload"
        mock_att.size = 1048576
        mock_msg_obj.attachments = [mock_att]

        mock_extract_msg = Mock()
        mock_extract_msg.openMsg.return_value = mock_msg_obj

        with patch("preprocessing.parsers.msg_parser.extract_msg", mock_extract_msg):
            artifacts = self.parser.parse(str(self.msg_path), evidence_id="ev-msg-01")

        self.assertEqual(len(artifacts), 1)
        art = artifacts[0]
        self.assertEqual(art.evidence_id, "ev-msg-01")
        self.assertEqual(art.source_tool, "extract_msg")
        self.assertEqual(art.artifact_type, "email")
        self.assertEqual(art.timestamp_type, "sent")
        self.assertEqual(art.raw_fields["sender"], "attacker@malicious.com")
        self.assertEqual(art.raw_fields["recipients"], "ceo@corp.local")
        self.assertEqual(art.raw_fields["subject"], "URGENT Wire Transfer")
        self.assertIn("wire transfer", art.raw_fields["body"])
        self.assertEqual(len(art.raw_fields["attachments"]), 1)
        self.assertEqual(art.raw_fields["attachments"][0]["filename"], "invoice.pdf.exe")

        # Normalized fields
        self.assertEqual(art.normalized_fields.sender, "attacker@malicious.com")
        self.assertEqual(art.normalized_fields.recipients, "ceo@corp.local")
        self.assertEqual(art.normalized_fields.subject, "URGENT Wire Transfer")

    # ── 2. Error and Dependency Handling ───────────────────────────────────

    def test_missing_dependency_raises_dependency_error(self):
        with patch("preprocessing.parsers.msg_parser.extract_msg", None):
            with self.assertRaises(MsgParserDependencyError):
                self.parser.parse(str(self.msg_path))

    def test_corrupt_msg_raises_corrupt_error(self):
        mock_extract_msg = Mock()
        mock_extract_msg.openMsg.side_effect = Exception("Invalid OLE header")

        with patch("preprocessing.parsers.msg_parser.extract_msg", mock_extract_msg):
            with self.assertRaises(MsgParserCorruptError):
                self.parser.parse(str(self.msg_path))

    def test_nonexistent_file_raises_not_found(self):
        with patch("preprocessing.parsers.msg_parser.extract_msg", Mock()):
            with self.assertRaises(FileNotFoundError):
                self.parser.parse(str(Path(self.tmp_dir) / "missing.msg"))


class TestFirefoxAndMsgRouterIntegration(unittest.TestCase):

    def setUp(self) -> None:
        self.router = ParserRouter()

    def _make_evidence(self, filename: str, path: str = "", metadata: dict | None = None) -> Evidence:
        return Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-router-test",
            filename=filename,
            file_path=path or filename,
            metadata=metadata or {}
        )

    def test_firefox_places_sqlite_routes_to_firefox_parser(self):
        ev = self._make_evidence("places.sqlite", path="/Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev), FirefoxParser)

    def test_firefox_cookies_sqlite_routes_to_firefox_parser(self):
        ev = self._make_evidence("cookies.sqlite", path="/home/user/.mozilla/firefox/profile/cookies.sqlite")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "FirefoxParser")

    def test_msg_email_routes_to_msg_parser(self):
        ev = self._make_evidence("phish.msg")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MsgEmailParser")
        self.assertIsInstance(self.router.route(ev), MsgEmailParser)


if __name__ == "__main__":
    unittest.main()
