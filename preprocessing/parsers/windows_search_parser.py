"""
WindowsSearchParser
===================
Source 34: Windows Search History (Windows.edb / WindowsSearch index)
Source Tool: "windows_search_parser"
Artifact Types Produced: "windows_search"

Parses Windows Search index exports and SQLite/EDB database artifacts.
Extracts search query text, query identifiers, searched item paths/URLs,
result metadata, and timestamps.

CRITICAL: Search query text is untrusted forensic evidence. It is preserved
verbatim in raw_fields without code execution or direct LLM invocation.
Database files are accessed read-only. Search query presence is NOT proof
of intent or application execution.
"""

from __future__ import annotations

import json
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

class WindowsSearchNotFoundError(FileNotFoundError):
    """Raised when the specified Windows Search evidence file does not exist."""


class WindowsSearchParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt Windows Search evidence."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class WindowsSearchParser:
    """Parses Windows Search history and index evidence (Windows.edb / WindowsSearch.db)."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("windows_search_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Windows Search evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise WindowsSearchNotFoundError(f"Windows Search file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        artifacts: list[Artifact] = []
        ver = self._tool_version

        # Handle SQLite or EDB/JSON/CSV exports
        if src.suffix.lower() in (".sqlite", ".db"):
            artifacts = self._parse_sqlite(src, evidence_id, ver, user)
        elif src.suffix.lower() == ".json":
            artifacts = self._parse_json(src, evidence_id, ver, user)
        else:
            artifacts = self._parse_text_export(src, evidence_id, ver, user)

        logger.info("WindowsSearchParser total: %d search artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _parse_sqlite(self, src: Path, evidence_id: str, ver: str, user: Optional[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        uri = f"file:{src.resolve().as_posix()}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            raise WindowsSearchParserError(f"Failed to open Windows Search database {src.name}: {exc}")

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}

            table_name = None
            for candidate in ("SearchHistory", "SystemIndex", "Search", "Queries"):
                if candidate in tables:
                    table_name = candidate
                    break

            if not table_name:
                return artifacts

            cursor.execute(f"PRAGMA table_info({table_name})")
            avail_cols = {row[1] for row in cursor.fetchall()}

            query_col = "Query" if "Query" in avail_cols else ("SearchText" if "SearchText" in avail_cols else "Text")
            url_col = "Url" if "Url" in avail_cols else ("Path" if "Path" in avail_cols else "ItemName")
            ts_col = "Timestamp" if "Timestamp" in avail_cols else ("LastModifiedTime" if "LastModifiedTime" in avail_cols else "Time")

            select_cols = [c for c in ["Id", query_col, url_col, ts_col] if c in avail_cols]
            if not select_cols:
                return artifacts

            query = f"SELECT {', '.join(select_cols)} FROM {table_name}"
            cursor.execute(query)

            for row in cursor.fetchall():
                rdict = dict(row)
                artifacts.append(self._record_to_artifact(rdict, query_col, url_col, ts_col, evidence_id, ver, src, user))
        except sqlite3.Error as exc:
            raise WindowsSearchParserError(f"Corrupt or incompatible Windows Search database {src.name}: {exc}")
        finally:
            conn.close()

        return artifacts

    def _parse_json(self, src: Path, evidence_id: str, ver: str, user: Optional[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        try:
            content = src.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
            records = data if isinstance(data, list) else [data]
        except Exception as exc:
            raise WindowsSearchParserError(f"Failed to parse JSON search export {src.name}: {exc}")

        for rec in records:
            if isinstance(rec, dict):
                artifacts.append(self._record_to_artifact(rec, "query", "url", "timestamp", evidence_id, ver, src, user))
        return artifacts

    def _parse_text_export(self, src: Path, evidence_id: str, ver: str, user: Optional[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            raise WindowsSearchParserError(f"Failed to read search export text {src.name}: {exc}")

        for idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rec = {"query": line, "line_number": idx}
            artifacts.append(self._record_to_artifact(rec, "query", "url", "timestamp", evidence_id, ver, src, user))

        return artifacts

    def _record_to_artifact(
        self,
        record: dict,
        query_col: str,
        url_col: str,
        ts_col: str,
        evidence_id: str,
        ver: str,
        src: Path,
        user: Optional[str],
    ) -> Artifact:
        query_text = str(record.get(query_col) or record.get("query") or record.get("SearchText") or "").strip()
        item_path = str(record.get(url_col) or record.get("url") or record.get("Path") or "").strip()

        summary = f"Windows Search query: {query_text[:50]}" if query_text else f"Windows Search item: {item_path[:50]}"

        raw_ts = record.get(ts_col) or record.get("timestamp") or record.get("Time")
        dt = self._parse_timestamp(raw_ts)

        raw_fields = {**record, "query_text": query_text, "searched_item": item_path, "tool_version": ver}

        norm = NormalizedFields(
            user=user or None,
            file_path=item_path if item_path and "\\" in item_path else str(src),
            file_name=os.path.basename(item_path) if item_path and "\\" in item_path else src.name,
            url=item_path if item_path.startswith("http") else None,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="windows_search_parser",
            artifact_type="windows_search",
            timestamp=dt,
            timestamp_type="event" if raw_ts else "none",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

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
