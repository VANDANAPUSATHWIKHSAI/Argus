"""
Windows Update Log Parser
=========================
Source 38: Windows Update / Patch History
Source Tool: "windows_update_log_parser"
Artifact Types Produced: "windows_update"
Raw Output Format: Text / Log / CSV / JSON (WindowsUpdate.log, CBS.log, ReportingEvents.log, Get-WindowsUpdateLog)

Parses Windows Update logs, CBS logs, SoftwareDistribution event logs, and update history exports.
Extracts KB numbers, package names, update IDs, installation status, and execution timestamps.

CRITICAL: Windows Update logs reflect system patching and updates. Failed or pending updates are
system lifecycle events and are NEVER automatically classified as malware or compromise.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class WindowsUpdateLogNotFoundError(FileNotFoundError):
    """Raised when the specified Windows Update log file does not exist."""


class WindowsUpdateLogParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt update log content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class WindowsUpdateLogParser:
    """Parses Windows Update history artifacts (WindowsUpdate.log, CBS.log, ReportingEvents.log, JSON/CSV exports)."""

    KB_REGEX = re.compile(r"(?<![A-Za-z0-9])(KB\d{6,8})(?![A-Za-z0-9])", re.IGNORECASE)
    TIMESTAMP_REGEXES = (
        # 2026-08-28 10:15:30:123
        re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[:.]\d+)?)"),
        # 2026/08/28 10:15:30
        re.compile(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:[:.]\d+)?)"),
        # 2026-08-28T10:15:30
        re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[:.]\d+)?(?:Z|[+-]\d{2}:\d{2})?)"),
    )

    def __init__(self) -> None:
        self._tool_version = get_tool_version("windows_update_log_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Windows Update log evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise WindowsUpdateLogNotFoundError(f"Windows Update log file not found: {file_path}")

        # Check pre-parsed JSON/CSV files first
        if src.suffix.lower() == ".json":
            return self._parse_json_file(src, evidence_id)
        elif src.suffix.lower() == ".csv":
            return self._parse_csv_file(src, evidence_id)

        # Parse text log (WindowsUpdate.log, CBS.log, ReportingEvents.log)
        content = self._read_log_file(src)
        if not content.strip():
            raise WindowsUpdateLogParserError(f"Empty or unparseable Windows Update log file: {src.name}")

        artifacts = self.parse_content(content, evidence_id=evidence_id, file_path=str(src))
        logger.info("WindowsUpdateLogParser total: %d update artifacts from %s", len(artifacts), src.name)
        return artifacts

    def parse_content(self, content: str | bytes, evidence_id: str = "", file_path: str = "") -> list[Artifact]:
        """Parse in-memory text/JSON/CSV log content."""
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = str(content)

        text_trimmed = text.strip()
        if not text_trimmed:
            return []

        # Try JSON
        if text_trimmed.startswith("[") or text_trimmed.startswith("{"):
            try:
                data = json.loads(text_trimmed)
                records = data if isinstance(data, list) else [data]
                return [
                    self._dict_record_to_artifact(rec, evidence_id, file_path)
                    for rec in records if isinstance(rec, dict)
                ]
            except json.JSONDecodeError:
                pass

        # Parse text log line by line
        artifacts: list[Artifact] = []
        lines = text_trimmed.splitlines()

        for line_num, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            # Check if line contains relevant update signals (KB number, CBS event, Agent update event)
            kb_match = self.KB_REGEX.search(line_str)
            is_wu_line = "windowsupdate" in line_str.lower() or "cbs" in line_str.lower() or "reportingevents" in line_str.lower() or "update" in line_str.lower()

            if kb_match or is_wu_line:
                artifact = self._line_to_artifact(line_str, line_num, evidence_id, file_path)
                if artifact:
                    artifacts.append(artifact)

        return artifacts

    def _read_log_file(self, src: Path) -> str:
        for enc in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
            try:
                return src.read_text(encoding=enc, errors="strict")
            except Exception:
                continue
        return src.read_text(encoding="latin-1", errors="replace")

    def _parse_json_file(self, json_path: Path, evidence_id: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        with json_path.open(encoding="utf-8", errors="replace") as fh:
            content = fh.read().strip()
            if not content:
                return artifacts
            try:
                records = json.loads(content)
                if isinstance(records, list):
                    for rec in records:
                        if isinstance(rec, dict):
                            artifacts.append(self._dict_record_to_artifact(rec, evidence_id, str(json_path)))
            except json.JSONDecodeError as exc:
                raise WindowsUpdateLogParserError(f"Malformed JSON update history file {json_path.name}: {exc}")
        return artifacts

    def _parse_csv_file(self, csv_path: Path, evidence_id: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        with csv_path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if row:
                    artifacts.append(self._dict_record_to_artifact(dict(row), evidence_id, str(csv_path)))
        return artifacts

    def _line_to_artifact(self, line: str, line_num: int, evidence_id: str, file_path: str) -> Optional[Artifact]:
        # Extract timestamp
        dt = self._extract_timestamp(line)

        # Extract KB Number
        kb_match = self.KB_REGEX.search(line)
        kb_number = kb_match.group(1).upper() if kb_match else None

        # Extract status / action
        status = self._extract_status(line)

        # Extract package/update title
        title = kb_number or None
        if "Package_" in line:
            pkg_match = re.search(r"(Package_[^\s\(\)]+)", line)
            if pkg_match:
                title = pkg_match.group(1)

        raw_payload = {
            "log_line": line,
            "line_number": line_num,
            "kb_number": kb_number,
            "status": status,
            "tool_version": self._tool_version,
        }

        file_name = os.path.basename(file_path) if file_path else "WindowsUpdate.log"

        normalized = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            process_command_line=title or kb_number,
            rule_name="windows_update_log",
        )

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="windows_update_log_parser",
            artifact_type="windows_update",
            timestamp=dt,
            timestamp_type="logged",
            line_number=line_num,
            raw_fields=raw_payload,
            normalized_fields=normalized,
            parser_version=self._tool_version,
            confidence_score=1.0,
        )

    def _dict_record_to_artifact(self, rec: dict[str, Any], evidence_id: str, file_path: str) -> Artifact:
        kb_val = rec.get("KBNumber") or rec.get("KB") or rec.get("kb_number") or ""
        if not kb_val and rec.get("Title"):
            kb_match = self.KB_REGEX.search(str(rec["Title"]))
            if kb_match:
                kb_val = kb_match.group(1).upper()

        ts_val = rec.get("Date") or rec.get("Timestamp") or rec.get("Time") or rec.get("InstalledOn")
        dt = self._parse_timestamp_str(str(ts_val)) if ts_val else None

        status = rec.get("Status") or rec.get("Result") or rec.get("ResultCode") or "Unknown"

        raw_payload = dict(rec)
        raw_payload["tool_version"] = self._tool_version

        file_name = os.path.basename(file_path) if file_path else "windows_update_export"

        normalized = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            process_command_line=str(rec.get("Title") or kb_val or ""),
            rule_name="windows_update_log",
        )

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="windows_update_log_parser",
            artifact_type="windows_update",
            timestamp=dt,
            timestamp_type="logged",
            raw_fields=raw_payload,
            normalized_fields=normalized,
            parser_version=self._tool_version,
            confidence_score=1.0,
        )

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        for regex in self.TIMESTAMP_REGEXES:
            m = regex.search(line)
            if m:
                return self._parse_timestamp_str(m.group(1))
        return None

    def _parse_timestamp_str(self, ts_str: str) -> Optional[datetime]:
        ts_clean = ts_str.strip().replace("Z", "+00:00")
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S:%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ):
            try:
                dt = datetime.strptime(ts_clean.split("+")[0].strip(), fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        try:
            dt = datetime.fromisoformat(ts_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None

    def _extract_status(self, line: str) -> str:
        line_lower = line.lower()
        if "installed" in line_lower or "succeeded" in line_lower or "success" in line_lower:
            return "Installed"
        elif "failed" in line_lower or "failure" in line_lower or "error" in line_lower:
            return "Failed"
        elif "pending" in line_lower or "reboot required" in line_lower:
            return "Pending"
        elif "downloading" in line_lower or "downloaded" in line_lower:
            return "Downloaded"
        elif "installing" in line_lower or "in progress" in line_lower:
            return "Installing"
        return "Info"
