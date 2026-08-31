"""
Firefox Browser Artifacts Parser (Custom SQLite Parser)
======================================================
Source 8: Browser Artifacts — Firefox
Source Tool: "firefox_sqlite"
Artifact Types Produced: "browser_history", "browser_cookie", "browser_formhistory"

Reads Firefox SQLite databases read-only (URI mode):
- places.sqlite      (History & Bookmarks)
- cookies.sqlite     (Cookies)
- formhistory.sqlite (Saved Form Entries)

Firefox Timestamps:
  Microseconds since Unix Epoch (1970-01-01 00:00:00 UTC).
"""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class FirefoxParserError(RuntimeError):
    """Raised when parsing a Firefox database fails fatally."""


class FirefoxDatabaseCorruptError(FirefoxParserError):
    """Raised when an unrecoverable SQLite corruption occurs."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class FirefoxParser:
    """Parses Firefox SQLite databases (places.sqlite, cookies.sqlite, formhistory.sqlite)."""

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse a Firefox SQLite database file and return Artifact records.

        Args:
            file_path:   Path to the Firefox SQLite database.
            evidence_id: FK linking back to infrastructure.Evidence.evidence_id.

        Returns:
            List of Artifact records.

        Raises:
            FileNotFoundError:            If file_path does not exist.
            FirefoxDatabaseCorruptError:  If SQLite DB is corrupt or not a valid database.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Firefox database file not found: {file_path}")

        fn_lower = src.name.lower()
        self._tool_version = get_tool_version("firefox")

        conn = self._connect_readonly(src)
        try:
            if "places" in fn_lower:
                return self._parse_places(conn, evidence_id, src.name)
            elif "cookies" in fn_lower:
                return self._parse_cookies(conn, evidence_id, src.name)
            elif "formhistory" in fn_lower:
                return self._parse_formhistory(conn, evidence_id, src.name)
            else:
                # Dispatch places check by default or inspect table names
                tables = self._get_table_names(conn)
                if "moz_historyvisits" in tables and "moz_places" in tables:
                    return self._parse_places(conn, evidence_id, src.name)
                elif "moz_cookies" in tables:
                    return self._parse_cookies(conn, evidence_id, src.name)
                elif "moz_formhistory" in tables:
                    return self._parse_formhistory(conn, evidence_id, src.name)
                else:
                    logger.warning("Unrecognized Firefox database tables in %s: %s", src.name, tables)
                    return []
        finally:
            conn.close()

    # -----------------------------------------------------------------------
    # SQLite Connection & Helper Methods
    # -----------------------------------------------------------------------

    def _connect_readonly(self, path: Path) -> sqlite3.Connection:
        """Open SQLite connection in URI read-only mode to prevent evidence modification."""
        try:
            uri_path = f"file:{path.resolve().as_posix()}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON;")
            # Test validity immediately
            conn.execute("SELECT name FROM sqlite_master LIMIT 1;")
            return conn
        except sqlite3.Error as exc:
            raise FirefoxDatabaseCorruptError(f"Failed to open Firefox SQLite DB {path.name}: {exc}")

    def _get_table_names(self, conn: sqlite3.Connection) -> set[str]:
        """Return set of table names present in database."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            return {row[0] for row in cursor.fetchall()}
        except sqlite3.Error as exc:
            raise FirefoxDatabaseCorruptError(f"Corrupt SQLite database structure: {exc}")

    # -----------------------------------------------------------------------
    # places.sqlite Parsing
    # -----------------------------------------------------------------------

    def _parse_places(self, conn: sqlite3.Connection, evidence_id: str, filename: str) -> list[Artifact]:
        """Parse browsing history from places.sqlite (moz_places + moz_historyvisits)."""
        tables = self._get_table_names(conn)
        if "moz_places" not in tables or "moz_historyvisits" not in tables:
            logger.warning("places.sqlite missing expected tables (moz_places / moz_historyvisits)")
            return []

        query = """
        SELECT 
            p.id AS place_id,
            p.url,
            p.title,
            p.visit_count,
            v.id AS visit_id,
            v.visit_date,
            v.visit_type,
            v.from_visit
        FROM moz_places p
        JOIN moz_historyvisits v ON p.id = v.place_id
        ORDER BY v.visit_date ASC;
        """
        artifacts: list[Artifact] = []
        ver = getattr(self, "_tool_version", get_tool_version("firefox"))

        try:
            cursor = conn.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                rdict = dict(row)
                url = rdict.get("url") or ""
                title = rdict.get("title") or ""
                visit_date_raw = rdict.get("visit_date")
                visit_type = rdict.get("visit_type")
                visit_count = rdict.get("visit_count")

                dt = self._convert_firefox_timestamp(visit_date_raw)
                host = self._extract_host(url)

                summary = f"Visited {title or url or 'page'} (visit_type={visit_type})"
                raw_fields = {**rdict, "tool_version": ver, "source_file": filename}

                norm = NormalizedFields(
                    host=host,
                    url=url,
                    title=title,
                    visit_count=visit_count,
                )

                art = Artifact(
                    evidence_id=evidence_id,
                    source_tool="firefox_sqlite",
                    artifact_type="browser_history",
                    timestamp=dt,
                    timestamp_type="visit",
                    event_summary=summary,
                    parser_version=ver,
                    raw_fields=raw_fields,
                    normalized_fields=norm,
                )
                artifacts.append(art)
        except sqlite3.Error as exc:
            raise FirefoxDatabaseCorruptError(f"Error querying places.sqlite in {filename}: {exc}")

        return artifacts

    # -----------------------------------------------------------------------
    # cookies.sqlite Parsing
    # -----------------------------------------------------------------------

    def _parse_cookies(self, conn: sqlite3.Connection, evidence_id: str, filename: str) -> list[Artifact]:
        """Parse cookie records from cookies.sqlite (moz_cookies)."""
        tables = self._get_table_names(conn)
        if "moz_cookies" not in tables:
            logger.warning("cookies.sqlite missing moz_cookies table")
            return []

        query = "SELECT * FROM moz_cookies;"
        artifacts: list[Artifact] = []
        ver = getattr(self, "_tool_version", get_tool_version("firefox"))

        try:
            cursor = conn.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                rdict = dict(row)
                name = rdict.get("name") or ""
                host = rdict.get("host") or rdict.get("baseDomain") or ""
                creation_raw = rdict.get("creationTime")

                dt = self._convert_firefox_timestamp(creation_raw)
                clean_host = host.lstrip(".")

                summary = f"Cookie '{name}' for domain '{host}'"
                raw_fields = {**rdict, "tool_version": ver, "source_file": filename}

                norm = NormalizedFields(
                    host=clean_host,
                    domain=clean_host,
                )

                art = Artifact(
                    evidence_id=evidence_id,
                    source_tool="firefox_sqlite",
                    artifact_type="browser_cookie",
                    timestamp=dt,
                    timestamp_type="creation",
                    event_summary=summary,
                    parser_version=ver,
                    raw_fields=raw_fields,
                    normalized_fields=norm,
                )
                artifacts.append(art)
        except sqlite3.Error as exc:
            raise FirefoxDatabaseCorruptError(f"Error querying cookies.sqlite in {filename}: {exc}")

        return artifacts

    # -----------------------------------------------------------------------
    # formhistory.sqlite Parsing
    # -----------------------------------------------------------------------

    def _parse_formhistory(self, conn: sqlite3.Connection, evidence_id: str, filename: str) -> list[Artifact]:
        """Parse form history entries from formhistory.sqlite (moz_formhistory)."""
        tables = self._get_table_names(conn)
        if "moz_formhistory" not in tables:
            logger.warning("formhistory.sqlite missing moz_formhistory table")
            return []

        query = "SELECT * FROM moz_formhistory;"
        artifacts: list[Artifact] = []
        ver = getattr(self, "_tool_version", get_tool_version("firefox"))

        try:
            cursor = conn.cursor()
            cursor.execute(query)
            for row in cursor.fetchall():
                rdict = dict(row)
                fieldname = rdict.get("fieldname") or ""
                value = rdict.get("value") or ""
                last_used_raw = rdict.get("lastUsed") or rdict.get("firstUsed")

                dt = self._convert_firefox_timestamp(last_used_raw)

                summary = f"Form field '{fieldname}' with value '{value}'"
                raw_fields = {**rdict, "tool_version": ver, "source_file": filename}

                art = Artifact(
                    evidence_id=evidence_id,
                    source_tool="firefox_sqlite",
                    artifact_type="browser_formhistory",
                    timestamp=dt,
                    timestamp_type="accessed",
                    event_summary=summary,
                    parser_version=ver,
                    raw_fields=raw_fields,
                    normalized_fields=NormalizedFields(),
                )
                artifacts.append(art)
        except sqlite3.Error as exc:
            raise FirefoxDatabaseCorruptError(f"Error querying formhistory.sqlite in {filename}: {exc}")

        return artifacts

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    @staticmethod
    def _convert_firefox_timestamp(microsec: Any) -> Optional[datetime]:
        """Convert Firefox microsecond Unix timestamp to timezone-aware UTC datetime."""
        if microsec is None:
            return None
        try:
            val = float(microsec)
            if val <= 0:
                return None
            if val > 1e11:
                sec = val / 1_000_000.0
            else:
                sec = val
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _extract_host(url: str) -> Optional[str]:
        """Extract hostname from URL."""
        if not url:
            return None
        try:
            parsed = urlparse(url)
            return parsed.netloc or None
        except Exception:
            return None
