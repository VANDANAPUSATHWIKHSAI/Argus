"""
NotificationDbParser
====================
Source 33: Windows Notification Database (wpndatabase.db)
Source Tool: "notification_db_parser"
Artifact Types Produced: "notification_db"

Parses Windows Push Notification database artifacts (wpndatabase.db).
Extracts app/package identifiers, notification XML/text payloads, arrival timestamps,
expiry timestamps, and notification metadata.

CRITICAL: Notification text is untrusted forensic evidence. It is preserved verbatim in raw_fields.
Notification presence is contextual data and does NOT prove program execution or user click activity.
SQLite database is opened read-only.
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

class NotificationDbNotFoundError(FileNotFoundError):
    """Raised when the specified Notification database file does not exist."""


class NotificationDbParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt Notification database content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class NotificationDbParser:
    """Parses Windows Push Notification database evidence (wpndatabase.db)."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("notification_db_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Notification DB evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise NotificationDbNotFoundError(f"Notification DB file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        artifacts: list[Artifact] = []
        ver = self._tool_version

        # Connect read-only URI for SQLite databases
        uri = f"file:{src.resolve().as_posix()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            raise NotificationDbParserError(f"Failed to open Notification database {src.name}: {exc}")

        try:
            artifacts = self._extract_notifications(conn, evidence_id, ver, src, user)
        except sqlite3.Error as exc:
            raise NotificationDbParserError(f"Corrupt or incompatible Notification database {src.name}: {exc}")
        finally:
            conn.close()

        logger.info("NotificationDbParser total: %d notification artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _extract_notifications(
        self, conn: sqlite3.Connection, evidence_id: str, ver: str, src: Path, user: Optional[str]
    ) -> list[Artifact]:
        artifacts: list[Artifact] = []

        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('Notification', 'Notifications', 'NotificationHandler')")
        tables = {row[0] for row in cursor.fetchall()}

        if not tables:
            return artifacts

        table_name = "Notification" if "Notification" in tables else ("Notifications" if "Notifications" in tables else "NotificationHandler")

        cursor.execute(f"PRAGMA table_info({table_name})")
        cols = {row[1] for row in cursor.fetchall()}

        payload_col = "Payload" if "Payload" in cols else ("Text" if "Text" in cols else "Body")
        arrival_col = "ArrivalTime" if "ArrivalTime" in cols else ("CreatedTime" if "CreatedTime" in cols else "Timestamp")
        expiry_col = "ExpiryTime" if "ExpiryTime" in cols else None
        app_col = "AppId" if "AppId" in cols else ("PrimaryId" if "PrimaryId" in cols else "PackageName")

        query_cols = []
        if "RecordId" in cols:
            query_cols.append("RecordId")
        elif "Id" in cols:
            query_cols.append("Id")

        if app_col in cols:
            query_cols.append(app_col)
        if payload_col in cols:
            query_cols.append(payload_col)
        if arrival_col in cols:
            query_cols.append(arrival_col)
        if expiry_col and expiry_col in cols:
            query_cols.append(expiry_col)

        if not query_cols:
            return artifacts

        query = f"SELECT {', '.join(query_cols)} FROM {table_name}"

        try:
            cursor.execute(query)
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            logger.warning("Query failed on Notification DB %s: %s", src.name, exc)
            return artifacts

        for row in rows:
            rdict = dict(row)
            artifacts.append(self._record_to_artifact(rdict, app_col, payload_col, arrival_col, evidence_id, ver, src, user))

        return artifacts

    def _record_to_artifact(
        self,
        record: dict,
        app_col: str,
        payload_col: str,
        arrival_col: str,
        evidence_id: str,
        ver: str,
        src: Path,
        user: Optional[str],
    ) -> Artifact:
        app_id = record.get(app_col) or ""
        payload = record.get(payload_col) or ""
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")

        clean_text = self._extract_clean_text(str(payload))
        summary = f"Windows Notification ({app_id or 'app'}): {clean_text[:40]}"

        raw_ts = record.get(arrival_col)
        dt = self._parse_timestamp(raw_ts)

        raw_fields = {**record, "payload_text": payload, "tool_version": ver}

        norm = NormalizedFields(
            user=user or None,
            process_name=os.path.basename(str(app_id)) if app_id else None,
            file_path=str(src),
            file_name=src.name,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="notification_db_parser",
            artifact_type="notification_db",
            timestamp=dt,
            timestamp_type="event" if record.get(arrival_col) else "none",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    @staticmethod
    def _extract_clean_text(payload: str) -> str:
        if not payload:
            return ""
        clean = re.sub(r"<[^>]+>", " ", payload)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean

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
