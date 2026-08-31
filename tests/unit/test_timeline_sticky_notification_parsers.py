"""
Unit tests for ActivitiesCacheParser (Source #31), StickyNotesParser (Source #32),
and NotificationDbParser (Source #33)
===================================================================================
- Source #31: Windows Timeline / ActivitiesCache (ActivitiesCache.db)
- Source #32: Sticky Notes (plum.sqlite)
- Source #33: Notification Database (wpndatabase.db)
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
from preprocessing.parsers.timeline_parser import (
    ActivitiesCacheParser,
    ActivitiesCacheNotFoundError,
    ActivitiesCacheParserError,
)
from preprocessing.parsers.stickynotes_parser import (
    StickyNotesParser,
    StickyNotesNotFoundError,
    StickyNotesParserError,
)
from preprocessing.parsers.notification_parser import (
    NotificationDbParser,
    NotificationDbNotFoundError,
    NotificationDbParserError,
)


class TestActivitiesCacheParserUnit(unittest.TestCase):
    """Unit tests for ActivitiesCacheParser (Timeline)."""

    def setUp(self) -> None:
        self.parser = ActivitiesCacheParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_file = Path(self.tmp_dir.name) / "ActivitiesCache.db"
        self._create_mock_timeline_db(self.db_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_timeline_db(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE Activity (
                Id TEXT PRIMARY KEY,
                AppId TEXT,
                AppActivityId TEXT,
                ActivityType INTEGER,
                StartTime TEXT,
                EndTime TEXT,
                LastModifiedTime TEXT,
                ExpirationTime TEXT,
                Payload TEXT,
                ETag INTEGER,
                GroupId TEXT,
                DisplayText TEXT,
                ContentUrl TEXT,
                AppDisplayName TEXT
            )
        """)
        payload = json.dumps({"appPath": "C:\\Program Files\\Example\\app.exe", "displayText": "Example App Activity"})
        cur.execute("""
            INSERT INTO Activity VALUES (
                'act_1001', 'C:\\Program Files\\Example\\app.exe', 'act_sub_1', 5,
                '2026-08-27T08:00:00Z', '2026-08-27T09:00:00Z', '2026-08-27T09:00:00Z', '2026-09-27T00:00:00Z',
                ?, 1, 'grp_1', 'Example App', 'https://example.com/item', 'Example Application'
            )
        """, (payload,))
        conn.commit()
        conn.close()

    def test_valid_activities_cache_record(self) -> None:
        artifacts = self.parser.parse(str(self.db_file), evidence_id="ev_tl_01")
        # 1-7, 11-13. Valid record, App identity, path, user, timestamps, payload, provenance
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "activitiescache_parser")
        self.assertEqual(art.artifact_type, "timeline")
        self.assertEqual(art.evidence_id, "ev_tl_01")
        self.assertEqual(art.normalized_fields.process_name, "app.exe")
        self.assertEqual(art.normalized_fields.file_path, "C:\\Program Files\\Example\\app.exe")
        self.assertEqual(art.normalized_fields.url, "https://example.com/item")
        self.assertEqual(art.timestamp_type, "activity")
        self.assertIsNotNone(art.timestamp)
        self.assertEqual(art.timestamp.year, 2026)
        self.assertIn("appPath", art.raw_fields["payload_decoded"])

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.db"
        with self.assertRaises(ActivitiesCacheNotFoundError):
            self.parser.parse(str(missing))

    def test_malformed_sqlite_raises_parser_error(self) -> None:
        corrupt = Path(self.tmp_dir.name) / "corrupt_timeline.db"
        corrupt.write_bytes(b"not a sqlite database file")
        with self.assertRaises(ActivitiesCacheParserError):
            self.parser.parse(str(corrupt))


class TestStickyNotesParserUnit(unittest.TestCase):
    """Unit tests for StickyNotesParser."""

    def setUp(self) -> None:
        self.parser = StickyNotesParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.user_dir = Path(self.tmp_dir.name) / "Users" / "analyst_mary" / "AppData" / "Local" / "Packages" / "Microsoft.MicrosoftStickyNotes"
        self.user_dir.mkdir(parents=True, exist_ok=True)
        self.db_file = self.user_dir / "plum.sqlite"
        self._create_mock_stickynotes_db(self.db_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_stickynotes_db(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE Note (
                Id TEXT PRIMARY KEY,
                Text TEXT,
                CreatedTime TEXT,
                LastModifiedTime TEXT,
                DeletedTime TEXT,
                IsDeleted INTEGER
            )
        """)
        cur.execute("""
            INSERT INTO Note VALUES (
                'note_101', '<b>Secret Password Note</b>\nServer pass: P@ssw0rd123!',
                '2026-08-25T10:00:00Z', '2026-08-26T12:00:00Z', NULL, 0
            )
        """)
        cur.execute("""
            INSERT INTO Note VALUES (
                'note_102', 'Old deleted note text',
                '2026-08-01T10:00:00Z', '2026-08-02T12:00:00Z', '2026-08-03T00:00:00Z', 1
            )
        """)
        conn.commit()
        conn.close()

    def test_valid_sticky_notes_parsing(self) -> None:
        artifacts = self.parser.parse(str(self.db_file), evidence_id="ev_sn_01")
        # 15-19, 22-24. Valid note, text preservation, title, timestamps, deletion state, provenance
        self.assertEqual(len(artifacts), 2)

        art1 = artifacts[0]
        self.assertEqual(art1.source_tool, "stickynotes_parser")
        self.assertEqual(art1.artifact_type, "sticky_notes")
        self.assertEqual(art1.evidence_id, "ev_sn_01")
        self.assertIsNotNone(art1.normalized_fields.user)
        self.assertIn(art1.normalized_fields.user.lower(), ("analyst_mary", "sudeep"))
        self.assertIn("Secret Password Note", art1.raw_fields["note_text"])
        self.assertFalse(art1.raw_fields["is_deleted"])
        self.assertEqual(art1.timestamp_type, "created")

        art2 = artifacts[1]
        self.assertTrue(art2.raw_fields["is_deleted"])
        self.assertIn("[DELETED]", art2.event_summary)

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.sqlite"
        with self.assertRaises(StickyNotesNotFoundError):
            self.parser.parse(str(missing))

    def test_malformed_sqlite_raises_parser_error(self) -> None:
        corrupt = Path(self.tmp_dir.name) / "corrupt_notes.sqlite"
        corrupt.write_bytes(b"bad sqlite header")
        with self.assertRaises(StickyNotesParserError):
            self.parser.parse(str(corrupt))


class TestNotificationDbParserUnit(unittest.TestCase):
    """Unit tests for NotificationDbParser."""

    def setUp(self) -> None:
        self.parser = NotificationDbParser()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_file = Path(self.tmp_dir.name) / "wpndatabase.db"
        self._create_mock_notification_db(self.db_file)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_mock_notification_db(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE Notification (
                RecordId INTEGER PRIMARY KEY,
                AppId TEXT,
                Payload TEXT,
                ArrivalTime TEXT,
                ExpiryTime TEXT
            )
        """)
        payload = "<toast><visual><binding><text>Security Alert: Malware detected in C:\\Temp\\mal.exe</text></binding></visual></toast>"
        cur.execute("""
            INSERT INTO Notification VALUES (
                501, 'Microsoft.WindowsDefender_cw5n1h2txyewy!Notification',
                ?, '2026-08-27T11:45:00Z', '2026-08-28T11:45:00Z'
            )
        """, (payload,))
        conn.commit()
        conn.close()

    def test_valid_notification_parsing(self) -> None:
        artifacts = self.parser.parse(str(self.db_file), evidence_id="ev_wpn_01")
        # 26-31, 34-36. Valid notification, app/package, payload, timestamps, provenance
        self.assertEqual(len(artifacts), 1)

        art = artifacts[0]
        self.assertEqual(art.source_tool, "notification_db_parser")
        self.assertEqual(art.artifact_type, "notification_db")
        self.assertEqual(art.evidence_id, "ev_wpn_01")
        self.assertIn("Security Alert", art.event_summary)
        self.assertIn("Malware detected", art.raw_fields["payload_text"])
        self.assertEqual(art.timestamp_type, "event")

    def test_missing_file_raises_not_found(self) -> None:
        missing = Path(self.tmp_dir.name) / "nonexistent.db"
        with self.assertRaises(NotificationDbNotFoundError):
            self.parser.parse(str(missing))

    def test_malformed_sqlite_raises_parser_error(self) -> None:
        corrupt = Path(self.tmp_dir.name) / "corrupt_wpn.db"
        corrupt.write_bytes(b"corrupt header data")
        with self.assertRaises(NotificationDbParserError):
            self.parser.parse(str(corrupt))


class TestUntrustedTextSecurity(unittest.TestCase):
    """Security tests (Points 38-40): Untrusted text is NOT executed or evaluated."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @patch("subprocess.run")
    def test_malicious_note_text_not_executed(self, mock_run: MagicMock) -> None:
        db_path = Path(self.tmp_dir.name) / "plum.sqlite"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE Note (Id TEXT, Text TEXT, CreatedTime TEXT)")
        cur.execute("INSERT INTO Note VALUES ('1', 'Invoke-Expression calc.exe; format c:', '2026-08-27T00:00:00Z')")
        conn.commit()
        conn.close()

        parser = StickyNotesParser()
        artifacts = parser.parse(str(db_path))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_malicious_notification_text_not_executed(self, mock_run: MagicMock) -> None:
        db_path = Path(self.tmp_dir.name) / "wpndatabase.db"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE Notification (RecordId INT, AppId TEXT, Payload TEXT, ArrivalTime TEXT)")
        cur.execute("INSERT INTO Notification VALUES (1, 'App', '<script>alert(1)</script>', '2026-08-27T00:00:00Z')")
        conn.commit()
        conn.close()

        parser = NotificationDbParser()
        artifacts = parser.parse(str(db_path))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_malicious_timeline_content_not_executed(self, mock_run: MagicMock) -> None:
        db_path = Path(self.tmp_dir.name) / "ActivitiesCache.db"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE Activity (Id TEXT, AppId TEXT, StartTime TEXT, Payload TEXT)")
        cur.execute("INSERT INTO Activity VALUES ('1', 'App', '2026-08-27T00:00:00Z', '{\"appPath\": \"C:\\\\Windows\\\\System32\\\\cmd.exe /c shutdown /s\"}')")
        conn.commit()
        conn.close()

        parser = ActivitiesCacheParser()
        artifacts = parser.parse(str(db_path))
        self.assertEqual(len(artifacts), 1)
        mock_run.assert_not_called()


class TestUserActivityRouterCollisions(unittest.TestCase):
    """Router collision tests: Verify specific DBs route correctly without generic collision."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_firefox_places_routes_to_firefox_parser(self) -> None:
        ev = Evidence(evidence_id="e1", case_id="c1", filename="places.sqlite", file_path="/profiles/places.sqlite", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev), FirefoxParser)

    def test_firefox_cookies_routes_to_firefox_parser(self) -> None:
        ev = Evidence(evidence_id="e2", case_id="c1", filename="cookies.sqlite", file_path="/profiles/cookies.sqlite", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev), FirefoxParser)

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

    def test_plum_sqlite_routes_to_sticky_notes_parser(self) -> None:
        ev = Evidence(evidence_id="e5", case_id="c1", filename="plum.sqlite", file_path="/evidence/plum.sqlite", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.target_parser, "StickyNotesParser")
        self.assertIsInstance(self.router.route(ev), StickyNotesParser)

    def test_generic_sqlite_database_remains_unrouted(self) -> None:
        ev = Evidence(evidence_id="e6", case_id="c1", filename="custom_app.sqlite", file_path="/evidence/custom_app.sqlite", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertNotIn(res.target_parser, ("FirefoxParser", "ActivitiesCacheParser", "NotificationDbParser", "StickyNotesParser"))

    def test_generic_db_database_remains_unrouted(self) -> None:
        ev = Evidence(evidence_id="e7", case_id="c1", filename="data_store.db", file_path="/evidence/data_store.db", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertNotIn(res.target_parser, ("ActivitiesCacheParser", "NotificationDbParser", "StickyNotesParser"))


if __name__ == "__main__":
    unittest.main()
