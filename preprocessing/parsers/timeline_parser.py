"""
ActivitiesCacheParser
====================
Source 31: Windows Timeline / ActivitiesCache (ActivitiesCache.db)
Source Tool: "activitiescache_parser"
Artifact Types Produced: "timeline"

Parses Windows 10/11 Timeline / ActivitiesCache.db SQLite database artifacts.
Extracts user activity history (Activity, ActivityOperation), application IDs,
executable paths, start/end timestamps, and activity payload metadata.

CRITICAL: SQLite databases are opened read-only (file:...?mode=ro). Original evidence is never modified.
Timeline records are contextual user history; they are NEVER classified as malicious in Layer 2.
"""

from __future__ import annotations

import json
import logging
import os
import ntpath
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

class ActivitiesCacheNotFoundError(FileNotFoundError):
    """Raised when the specified ActivitiesCache.db file does not exist."""


class ActivitiesCacheParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt database content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class ActivitiesCacheParser:
    """Parses Windows Timeline ActivitiesCache.db SQLite database evidence."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("activitiescache_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse ActivitiesCache.db evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise ActivitiesCacheNotFoundError(f"ActivitiesCache database file not found: {file_path}")

        artifacts: list[Artifact] = []
        ver = self._tool_version

        # Connect read-only URI
        uri = f"file:{src.resolve().as_posix()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            raise ActivitiesCacheParserError(f"Failed to open ActivitiesCache database {src.name}: {exc}")

        try:
            artifacts = self._extract_activities(conn, evidence_id, ver, src)
        except sqlite3.Error as exc:
            raise ActivitiesCacheParserError(f"Corrupt or incompatible ActivitiesCache database {src.name}: {exc}")
        finally:
            conn.close()

        logger.info("ActivitiesCacheParser total: %d timeline artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _extract_activities(
        self, conn: sqlite3.Connection, evidence_id: str, ver: str, src: Path
    ) -> list[Artifact]:
        artifacts: list[Artifact] = []

        # Inspect table schema
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('Activity', 'ActivityOperation')")
        tables = {row[0] for row in cursor.fetchall()}

        if not tables:
            return artifacts

        table_name = "Activity" if "Activity" in tables else "ActivityOperation"

        cursor.execute(f"PRAGMA table_info({table_name})")
        avail_cols = {row[1] for row in cursor.fetchall()}

        potential_cols = [
            "Id", "AppId", "AppActivityId", "ActivityType", "StartTime", "EndTime",
            "LastModifiedTime", "ExpirationTime", "Payload", "ETag", "GroupId",
            "DisplayText", "ContentUrl", "AppDisplayName"
        ]
        select_cols = [c for c in potential_cols if c in avail_cols]
        if not select_cols:
            return artifacts

        query = f"SELECT {', '.join(select_cols)} FROM {table_name}"

        try:
            cursor.execute(query)
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            logger.warning("Query failed on ActivitiesCache database %s: %s", src.name, exc)
            return artifacts

        for row in rows:
            rdict = dict(row)
            artifacts.append(self._record_to_artifact(rdict, evidence_id, ver, src))

        return artifacts

    def _record_to_artifact(self, record: dict, evidence_id: str, ver: str, src: Path) -> Artifact:
        act_id = record.get("Id") or ""
        app_id = record.get("AppId") or ""
        act_type = record.get("ActivityType") or ""
        display_name = record.get("DisplayText") or record.get("AppDisplayName") or ""
        payload_str = record.get("Payload")

        payload_json: dict = {}
        exec_path = None
        if payload_str:
            try:
                if isinstance(payload_str, (bytes, bytearray)):
                    payload_str = payload_str.decode("utf-8", errors="replace")
                payload_json = json.loads(payload_str) if isinstance(payload_str, str) else {}
                if isinstance(payload_json, dict):
                    exec_path = payload_json.get("appPath") or payload_json.get("displayText") or payload_json.get("activeAppId")
            except Exception:
                pass

        app_name = ntpath.basename(str(exec_path).rstrip("\\/")) if exec_path else (ntpath.basename(str(app_id).rstrip("\\/")) if app_id else "Application")
        summary = f"Windows Timeline activity ({act_type or 'user'}): {display_name or app_name}"

        raw_ts = record.get("StartTime") or record.get("LastModifiedTime") or record.get("EndTime")
        dt = self._parse_timestamp(raw_ts)

        raw_fields = {**record, "payload_decoded": payload_json, "tool_version": ver}

        norm = NormalizedFields(
            process_name=app_name if app_name != "Application" else None,
            file_path=exec_path or (app_id if "\\" in str(app_id) else None),
            file_name=app_name if app_name != "Application" else None,
            url=record.get("ContentUrl"),
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="activitiescache_parser",
            artifact_type="timeline",
            timestamp=dt,
            timestamp_type="activity" if record.get("StartTime") else "modified",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    @staticmethod
    def _parse_timestamp(val: Any) -> Optional[datetime]:
        if not val:
            return None
        if isinstance(val, (int, float)):
            try:
                # Unix timestamp (seconds or milliseconds)
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
