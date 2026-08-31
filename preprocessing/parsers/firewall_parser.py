"""
WindowsFirewallParser
=====================
Source 2: Windows Firewall Logs (pfirewall.log)
Source Tool: "windows_firewall_parser"
Artifact Types Produced: "firewall_log"

Parses Windows Firewall W3C format log files (pfirewall.log) and firewall log exports.
Extracts timestamp, action (ALLOW, DROP, CLOSE, OPEN), protocol (TCP, UDP, ICMP),
src_ip, dst_ip, src_port, dst_port, direction (SEND, RECEIVE), size, and interface metadata.

CRITICAL: Firewall records are neutral network log events. ALLOW does NOT mean malicious traffic,
and DROP does NOT mean confirmed attack. No DNS lookups or threat intel lookups are performed.
Log evidence files are accessed read-only.
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

class WindowsFirewallNotFoundError(FileNotFoundError):
    """Raised when the specified Windows Firewall log file does not exist."""


class WindowsFirewallParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt firewall log content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class WindowsFirewallParser:
    """Parses Windows Firewall W3C log files (pfirewall.log)."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("windows_firewall_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Firewall evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise WindowsFirewallNotFoundError(f"Windows Firewall log file not found: {file_path}")

        user = self._extract_user_from_path(str(src))
        ver = self._tool_version
        artifacts: list[Artifact] = []

        try:
            content = src.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise WindowsFirewallParserError(f"Failed to read firewall log {src.name}: {exc}")

        fields_header: list[str] = []
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            if line_str.startswith("#Fields:"):
                # Header definition e.g. #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmptime info path
                fields_header = line_str.replace("#Fields:", "").strip().split()
                continue

            if line_str.startswith("#"):
                continue

            parts = line_str.split()
            if len(parts) < 4:
                continue

            rec = self._parse_line(parts, fields_header)
            if rec:
                artifacts.append(self._record_to_artifact(rec, line_str, evidence_id, ver, src, user))

        logger.info("WindowsFirewallParser total: %d firewall artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _parse_line(self, parts: list[str], fields: list[str]) -> Optional[dict[str, Any]]:
        rec: dict[str, Any] = {}

        if fields and len(fields) == len(parts):
            for f_name, val in zip(fields, parts):
                clean_f = f_name.lower().replace("-", "_")
                rec[clean_f] = val if val != "-" else None
            return rec

        # Fallback standard W3C log positioning
        # Date Time Action Protocol Src-IP Dst-IP Src-Port Dst-Port Size ...
        if len(parts) >= 6:
            rec["date"] = parts[0]
            rec["time"] = parts[1]
            rec["action"] = parts[2]
            rec["protocol"] = parts[3]
            rec["src_ip"] = parts[4]
            rec["dst_ip"] = parts[5]
            if len(parts) >= 8:
                rec["src_port"] = parts[6]
                rec["dst_port"] = parts[7]
            if len(parts) >= 9:
                rec["size"] = parts[8]

        return rec if rec.get("action") else None

    def _record_to_artifact(
        self,
        record: dict,
        raw_line: str,
        evidence_id: str,
        ver: str,
        src: Path,
        user: Optional[str],
    ) -> Artifact:
        action = record.get("action") or "UNKNOWN"
        proto = record.get("protocol") or ""
        src_ip = record.get("src_ip")
        dst_ip = record.get("dst_ip")
        src_port = self._to_int(record.get("src_port"))
        dst_port = self._to_int(record.get("dst_port"))
        direction = record.get("path") or record.get("direction") or ""

        date_str = record.get("date") or ""
        time_str = record.get("time") or ""
        dt = self._parse_datetime(date_str, time_str)

        summary = f"Windows Firewall {action.upper()}: {src_ip or 'src'}:{src_port or '*'} -> {dst_ip or 'dst'}:{dst_port or '*'} ({proto})"

        raw_fields = {
            **record,
            "raw_line": raw_line,
            "action": action,
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            user=user or None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            file_path=str(src),
            file_name=src.name,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="windows_firewall_parser",
            artifact_type="firewall_log",
            timestamp=dt,
            timestamp_type="event" if dt else "none",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    @staticmethod
    def _to_int(val: Any) -> Optional[int]:
        if not val or val == "-":
            return None
        try:
            return int(val)
        except Exception:
            return None

    @staticmethod
    def _parse_datetime(d_str: str, t_str: str) -> Optional[datetime]:
        if not d_str:
            return None
        full = f"{d_str} {t_str}".strip() if t_str else d_str.strip()
        full = full.replace(" ", "T")
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(full, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @staticmethod
    def _extract_user_from_path(path_str: str) -> Optional[str]:
        m = re.search(r"[\\/]Users[\\/]([^\\/]+)[\\/]", path_str, re.IGNORECASE)
        if m:
            user = m.group(1)
            if user.lower() not in ("public", "default", "default user", "all users"):
                return user
        return None
