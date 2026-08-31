"""
WindowsDefenderParser
=====================
Source 3: Windows Defender Logs (Microsoft-Windows-Windows Defender%4Operational.evtx / MPLog)
Source Tool: "windows_defender_parser"
Artifact Types Produced: "defender_log"

Parses Windows Defender operational event records, MPLog, and threat detection logs.
Extracts event_id (e.g. 1116, 1117, 5001), threat name, threat ID, severity, action,
remediation status, file path, process name, process ID, user, signature version, and engine version.

CRITICAL: Defender records preserve Defender's native threat detections and status fields.
Defender threat detection does NOT constitute an independent ARGUS malware execution verdict,
and quarantine does NOT automatically set compromised=true. File paths and remediation commands
are treated as untrusted evidence and are NEVER executed.
"""

from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class WindowsDefenderNotFoundError(FileNotFoundError):
    """Raised when the specified Windows Defender log or evidence file does not exist."""


class WindowsDefenderParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt Defender log content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class WindowsDefenderParser:
    """Parses Windows Defender operational events and threat detection logs."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("windows_defender_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Defender evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise WindowsDefenderNotFoundError(f"Windows Defender evidence file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        ver = self._tool_version
        artifacts: list[Artifact] = []

        if src.suffix.lower() == ".json":
            artifacts = self._parse_json(src, evidence_id, ver, user)
        elif src.suffix.lower() in (".xml", ".evtx"):
            artifacts = self._parse_xml_or_text(src, evidence_id, ver, user)
        else:
            artifacts = self._parse_mplog_or_text(src, evidence_id, ver, user)

        logger.info("WindowsDefenderParser total: %d defender artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _parse_json(self, src: Path, evidence_id: str, ver: str, user: Optional[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        try:
            content = src.read_text(encoding="utf-8", errors="replace")
            data = json.loads(content)
            records = data if isinstance(data, list) else [data]
        except Exception as exc:
            raise WindowsDefenderParserError(f"Failed to parse Defender JSON log {src.name}: {exc}")

        for rec in records:
            if isinstance(rec, dict):
                artifacts.append(self._record_to_artifact(rec, evidence_id, ver, src, user))
        return artifacts

    def _parse_xml_or_text(self, src: Path, evidence_id: str, ver: str, user: Optional[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        try:
            content = src.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise WindowsDefenderParserError(f"Failed to read Defender XML/EVTX file {src.name}: {exc}")

        # Attempt XML parse
        if "<Event" in content:
            try:
                root = ET.fromstring(content if content.strip().startswith("<") else f"<Events>{content}</Events>")
                events = root.findall(".//Event") if root.tag != "Event" else [root]
                for ev in events:
                    rec = self._parse_xml_event(ev)
                    if rec:
                        artifacts.append(self._record_to_artifact(rec, evidence_id, ver, src, user))
                return artifacts
            except Exception:
                pass

        # Fallback to key-value or line parsing
        return self._parse_mplog_or_text(src, evidence_id, ver, user)

    def _parse_xml_event(self, ev: ET.Element) -> dict[str, Any]:
        rec: dict[str, Any] = {}
        system = ev.find("{*}System")
        if system is not None:
            ev_id = system.find("{*}EventID")
            if ev_id is not None and ev_id.text:
                rec["event_id"] = ev_id.text
            time_created = system.find("{*}TimeCreated")
            if time_created is not None:
                rec["timestamp"] = time_created.attrib.get("SystemTime")

        event_data = ev.find("{*}EventData")
        if event_data is not None:
            for data in event_data.findall("{*}Data"):
                name = data.attrib.get("Name")
                val = data.text
                if name and val:
                    rec[name] = val

        return rec

    def _parse_mplog_or_text(self, src: Path, evidence_id: str, ver: str, user: Optional[str]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            raise WindowsDefenderParserError(f"Failed to read Defender log text {src.name}: {exc}")

        cur_rec: dict[str, Any] = {}
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if "=" in line_str:
                k, _, v = line_str.partition("=")
                cur_rec[k.strip()] = v.strip()
            elif "Threat" in line_str or "DETECTION" in line_str:
                if cur_rec:
                    artifacts.append(self._record_to_artifact(cur_rec, evidence_id, ver, src, user))
                    cur_rec = {}
                cur_rec["threat_name"] = line_str

        if cur_rec:
            artifacts.append(self._record_to_artifact(cur_rec, evidence_id, ver, src, user))

        return artifacts

    def _record_to_artifact(
        self,
        record: dict,
        evidence_id: str,
        ver: str,
        src: Path,
        user: Optional[str],
    ) -> Artifact:
        event_id = record.get("event_id") or record.get("EventID") or record.get("EventId") or "1116"
        threat_name = (
            record.get("threat_name")
            or record.get("ThreatName")
            or record.get("Threat Name")
            or record.get("Threat")
            or "Unknown Threat"
        )
        severity = (
            record.get("severity")
            or record.get("Severity")
            or record.get("SeverityID")
            or record.get("ThreatSeverityID")
            or "Unknown"
        )
        action = record.get("action") or record.get("Action") or record.get("CleaningActionID") or "Detected"
        file_path = record.get("file_path") or record.get("FilePath") or record.get("Path") or record.get("Resources")
        proc_name = record.get("process_name") or record.get("ProcessName") or record.get("Process")
        proc_id = record.get("process_id") or record.get("ProcessID") or record.get("PID")

        raw_ts = record.get("timestamp") or record.get("TimeCreated") or record.get("EventTime")
        dt = self._parse_timestamp(raw_ts)

        proc_basename = os.path.basename(proc_name) if proc_name else None
        file_basename = os.path.basename(file_path) if file_path else None

        summary = f"Windows Defender Event {event_id}: {threat_name} (Severity: {severity}, Action: {action})"

        raw_fields = {
            **record,
            "event_id": event_id,
            "threat_name": threat_name,
            "severity": severity,
            "action": action,
            "file_path": file_path,
            "process_name": proc_name,
            "process_id": proc_id,
            "tool_version": ver,
        }

        pid_int = None
        if proc_id:
            try:
                pid_int = int(proc_id)
            except Exception:
                pass

        norm = NormalizedFields(
            user=user or record.get("user") or record.get("User"),
            process_id=pid_int,
            process_name=proc_basename,
            file_path=file_path or str(src),
            file_name=file_basename or src.name,
            severity=str(severity),
            rule_name=str(threat_name),
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="windows_defender_parser",
            artifact_type="defender_log",
            timestamp=dt,
            timestamp_type="event" if dt else "none",
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
