"""
WerReportParser
===============
Source 35: Windows Error Reporting (Report.wer / WER metadata)
Source Tool: "wer_report_parser"
Artifact Types Produced: "wer_report"

Parses Windows Error Reporting (Report.wer) INI/key-value text files and WER report archives.
Extracts event types (APPCRASH, AppHang), application name, version, executable path,
faulting module name/version, exception codes, process ID, OS build, report timestamp,
and dump references.

CRITICAL: WER records represent crash/error reporting. Exception codes and crash events are
NOT automatically classified as malware. Dump references are recorded in raw_fields as metadata
and are NEVER automatically executed or parsed in this parser.
"""

from __future__ import annotations

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

class WerReportNotFoundError(FileNotFoundError):
    """Raised when the specified Report.wer file or WER archive does not exist."""


class WerReportParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt WER report content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class WerReportParser:
    """Parses Windows Error Reporting (Report.wer) artifacts."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("wer_report_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Report.wer evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise WerReportNotFoundError(f"WER report file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        ver = self._tool_version

        kv_data = self._read_wer_file(src)
        if not kv_data:
            raise WerReportParserError(f"Empty or unparseable WER report: {src.name}")

        artifact = self._build_artifact(kv_data, evidence_id, ver, src, user)
        logger.info("WerReportParser total: 1 WER report artifact from %s", src.name)
        return [artifact]

    def _read_wer_file(self, src: Path) -> dict[str, str]:
        """Reads a Report.wer file (supports UTF-16, UTF-8, and Latin-1 encodings)."""
        content = None
        for enc in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
            try:
                content = src.read_text(encoding=enc, errors="strict")
                break
            except Exception:
                continue

        if content is None:
            try:
                content = src.read_text(encoding="latin-1", errors="replace")
            except Exception as exc:
                raise WerReportParserError(f"Failed to read WER report file {src.name}: {exc}")

        kv: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            kv[key.strip()] = val.strip()

        return kv

    def _build_artifact(
        self, kv: dict[str, str], evidence_id: str, ver: str, src: Path, user: Optional[str]
    ) -> Artifact:
        event_type = kv.get("EventType") or "Crash"
        app_name = kv.get("AppName") or kv.get("AppId") or kv.get("TargetAppPath") or ""
        app_path = kv.get("AppPath") or kv.get("TargetAppId") or kv.get("ExecutablePath") or ""
        mod_name = kv.get("ModName") or kv.get("FaultingModule") or ""
        mod_ver = kv.get("ModVersion") or ""
        exc_code = kv.get("ExceptionCode") or kv.get("Sig[3].Value") or ""
        proc_id = kv.get("ProcessId") or kv.get("Pid") or ""
        report_id = kv.get("ReportIdentifier") or kv.get("ReportId") or ""
        event_time_str = kv.get("EventTime") or kv.get("ReportTime") or ""

        dump_info = self._extract_dump_reference(kv, src)

        app_basename = os.path.basename(app_path) if app_path else (os.path.basename(app_name) if app_name else "Application")
        summary = f"Windows Error Report ({event_type}): {app_basename}"
        if exc_code:
            summary += f" [Exception {exc_code}]"

        dt = self._parse_wer_timestamp(event_time_str)

        raw_fields = {
            **kv,
            "event_type": event_type,
            "app_name": app_name,
            "app_path": app_path,
            "faulting_module": mod_name,
            "module_version": mod_ver,
            "exception_code": exc_code,
            "process_id": proc_id,
            "report_identifier": report_id,
            "dump_reference": dump_info,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            user=user or None,
            process_name=app_basename if app_basename != "Application" else None,
            file_path=app_path or str(src),
            file_name=app_basename if app_basename != "Application" else src.name,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="wer_report_parser",
            artifact_type="wer_report",
            timestamp=dt,
            timestamp_type="event" if dt else "none",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    def _extract_dump_reference(self, kv: dict[str, str], src: Path) -> dict[str, Any]:
        dump_ref: dict[str, Any] = {}
        for k, v in kv.items():
            if "dump" in k.lower() or v.lower().endswith(".dmp") or "memory.dmp" in v.lower():
                dump_ref["dump_key"] = k
                dump_ref["dump_filename"] = os.path.basename(v)
                dump_ref["dump_path"] = v
                break

        # Check if a .dmp file exists in the same folder as Report.wer
        if not dump_ref and src.parent.exists():
            for child in src.parent.iterdir():
                if child.suffix.lower() == ".dmp":
                    dump_ref["dump_filename"] = child.name
                    dump_ref["dump_path"] = str(child)
                    try:
                        dump_ref["dump_size"] = child.stat().st_size
                    except Exception:
                        pass
                    break

        return dump_ref

    @staticmethod
    def _extract_user_from_path(path_str: str) -> Optional[str]:
        m = re.search(r"[\\/]Users[\\/]([^\\/]+)[\\/]", path_str, re.IGNORECASE)
        if m:
            user = m.group(1)
            if user.lower() not in ("public", "default", "default user", "all users"):
                return user
        return None

    @staticmethod
    def _parse_wer_timestamp(val: Any) -> Optional[datetime]:
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
        s = str(val).strip()
        if not s or s == "0":
            return None
        # WER EventTime can be a FILETIME string or ISO-8601
        try:
            val_num = float(s)
            if val_num > 1e16:
                secs = (val_num - 116444736000000000) / 10000000.0
                return datetime.fromtimestamp(secs, tz=timezone.utc)
        except ValueError:
            pass

        s = s.replace(" ", "T")
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
