"""
StickyNotesParser
=================
Source 32: Sticky Notes (plum.sqlite, StickyNotes.sqlite)
Source Tool: "stickynotes_parser"
Artifact Types Produced: "sticky_notes"

Parses modern Windows Sticky Notes SQLite database artifacts (plum.sqlite / StickyNotes.sqlite).
Extracts note text content, titles, creation timestamps, modification timestamps,
deletion state, and note metadata.

CRITICAL: Note content is untrusted forensic evidence. It is preserved verbatim in raw_fields
without evaluation or code execution. SQLite database is opened read-only.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class StickyNotesNotFoundError(FileNotFoundError):
    """Raised when the specified Sticky Notes database file does not exist."""


class StickyNotesParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt Sticky Notes database content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class StickyNotesParser:
    """Parses modern Windows Sticky Notes SQLite database evidence (plum.sqlite)."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("stickynotes_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Sticky Notes evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise StickyNotesNotFoundError(f"Sticky Notes file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        artifacts: list[Artifact] = []
        ver = self._tool_version

        # Connect read-only URI for SQLite databases
        uri = f"file:{src.resolve().as_posix()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            raise StickyNotesParserError(f"Failed to open Sticky Notes database {src.name}: {exc}")

        try:
            artifacts = self._extract_notes(conn, evidence_id, ver, src, user)
        except sqlite3.Error as exc:
            raise StickyNotesParserError(f"Corrupt or incompatible Sticky Notes database {src.name}: {exc}")
        finally:
            conn.close()

        logger.info("StickyNotesParser total: %d note artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _extract_notes(
        self, conn: sqlite3.Connection, evidence_id: str, ver: str, src: Path, user: Optional[str]
    ) -> list[Artifact]:
        artifacts: list[Artifact] = []

        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('Note', 'Notes')")
        tables = {row[0] for row in cursor.fetchall()}

        if not tables:
            return artifacts

        table_name = "Note" if "Note" in tables else "Notes"

        # Check column names in table
        cursor.execute(f"PRAGMA table_info({table_name})")
        cols = {row[1] for row in cursor.fetchall()}

        text_col = "Text" if "Text" in cols else ("Payload" if "Payload" in cols else "Body")
        created_col = "CreatedTime" if "CreatedTime" in cols else ("CreatedAt" if "CreatedAt" in cols else "Created")
        modified_col = "LastModifiedTime" if "LastModifiedTime" in cols else ("UpdatedAt" if "UpdatedAt" in cols else "Modified")
        deleted_col = "DeletedTime" if "DeletedTime" in cols else ("IsDeleted" if "IsDeleted" in cols else None)

        query_cols = ["Id", text_col]
        if created_col in cols:
            query_cols.append(created_col)
        if modified_col in cols:
            query_cols.append(modified_col)
        if deleted_col and deleted_col in cols:
            query_cols.append(deleted_col)

        query = f"SELECT {', '.join(query_cols)} FROM {table_name}"

        try:
            cursor.execute(query)
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            logger.warning("Query failed on Sticky Notes database %s: %s", src.name, exc)
            return artifacts

        for row in rows:
            rdict = dict(row)
            artifacts.append(self._record_to_artifact(rdict, text_col, created_col, modified_col, deleted_col, evidence_id, ver, src, user))

        return artifacts

    def _record_to_artifact(
        self,
        record: dict,
        text_col: str,
        created_col: str,
        modified_col: str,
        deleted_col: Optional[str],
        evidence_id: str,
        ver: str,
        src: Path,
        user: Optional[str],
    ) -> Artifact:
        note_id = record.get("Id") or ""
        note_text = record.get(text_col) or ""
        is_deleted = bool(record.get(deleted_col)) if deleted_col else False

        title = self._extract_title(note_text)
        summary = f"Sticky Note: {title or note_text[:40]}"
        if is_deleted:
            summary += " [DELETED]"

        raw_ts = record.get(created_col) or record.get(modified_col)
        dt = self._parse_timestamp(raw_ts)

        raw_fields = {**record, "note_text": note_text, "is_deleted": is_deleted, "tool_version": ver}

        norm = NormalizedFields(
            user=user or None,
            file_path=str(src),
            file_name=src.name,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="stickynotes_parser",
            artifact_type="sticky_notes",
            timestamp=dt,
            timestamp_type="created" if record.get(created_col) else "modified",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    @staticmethod
    def _extract_title(text: str) -> str:
        if not text:
            return ""
        clean = re.sub(r"<[^>]+>", "", text).strip()
        lines = [l.strip() for l in clean.splitlines() if l.strip()]
        return lines[0][:60] if lines else clean[:60]

    @staticmethod
    def _extract_user_from_path(path_str: str) -> Optional[str]:
        m = re.search(r"[\\/]Users[\\/]([^\\/]+)[\\/]", path_str, re.IGNORECASE)
        if m:
            user = m.group(1)
            if user.lower() not in ("public", "default", "default user", "all users"):
                return user
        return None

    @staticmethod
    def _parse_timestamp(val: Any) -> Optional[datetime]:
        if not val:
            return None
        if isinstance(val, (int, float)):
            try:
                # Windows FILETIME (100-ns intervals since 1601)
                if val > 1e16:
                    secs = (val - 116444736000000000) / 10000000.0
                    return datetime.fromtimestamp(secs, tz=timezone.utc)
                if val > 1e11:
                    val = val / 1000.0
                return datetime.fromtimestamp(val, tz=timezone.utc)
            except Exception:
                return None
        s = str(val).strip().replace(" ", "T")
        if not s or s == "0":
            return None
        if len(s) > 6 and s[-3] == ":":
            s = s[:-3] + s[-2:]
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(s, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
        return None
