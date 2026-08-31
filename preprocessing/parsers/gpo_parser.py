"""
Group Policy Logs Parser
========================
Source 39: Group Policy Application Logs
Source Tool: "group_policy_log_parser"
Artifact Types Produced: "gpo_event"

Parses Group Policy operational logs, debug logs (gpesvc.log, GroupPolicy.log),
gpresult/gpreport exports (XML, JSON, text), Group Policy Template configuration
files (gpt.ini), binary Registry Policy files (Registry.pol), and Group Policy
Preferences XML files.

Extracts GPO processing/application events, policy identifiers/names, client-side
extension (CSE) information, status/result, errors/warnings, user/computer context,
and timestamps.

CRITICAL: GPO processing failures/errors represent administrative lifecycle events
and are NEVER automatically classified as malware or security compromise. All policy
names, commands, paths, registry values, and strings are untrusted forensic evidence
and are strictly read passively without execution.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import struct
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

class GroupPolicyLogNotFoundError(FileNotFoundError):
    """Raised when the specified Group Policy log file does not exist."""


class GroupPolicyLogParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt Group Policy evidence."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class GroupPolicyLogParser:
    """Parses Group Policy evidence (EVTX/XML, gpesvc.log, gpresult, gpt.ini, Registry.pol)."""

    GPO_GUID_REGEX = re.compile(
        r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"
    )

    TIMESTAMP_REGEXES = (
        # 2026-08-28 10:15:30.123
        re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[:.]\d+)?)"),
        # 2026/08/28 10:15:30
        re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:[:.]\d+)?)"),
        # 2026-08-28T10:15:30
        re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[:.]\d+)?(?:Z|[+-]\d{2}:\d{2})?)"),
        # gpesvc log format: gpesvc(3ec.488) 12:45:01:234
        re.compile(r"gpesvc\([^)]+\)\s+(\d{2}:\d{2}:\d{2}[:.]\d+)"),
    )

    def __init__(self) -> None:
        v = get_tool_version("group_policy_log_parser")
        self._tool_version = v if v != "unknown" else get_tool_version("gpo_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Group Policy evidence file at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise GroupPolicyLogNotFoundError(f"Group Policy log file not found: {file_path}")

        fn_lower = src.name.lower()

        # Binary Registry.pol file
        if fn_lower == "registry.pol" or self._is_registry_pol_file(src):
            return self._parse_registry_pol(src, evidence_id)

        # gpt.ini configuration file
        if fn_lower == "gpt.ini":
            return self._parse_gpt_ini(src, evidence_id)

        # Read content for text/XML/JSON files
        try:
            raw_bytes = src.read_bytes()
        except Exception as exc:
            raise GroupPolicyLogParserError(f"Failed to read Group Policy evidence file {src.name}: {exc}")

        if not raw_bytes.strip():
            raise GroupPolicyLogParserError(f"Empty Group Policy log file: {src.name}")

        return self.parse_content(raw_bytes, evidence_id=evidence_id, file_path=str(src))

    def parse_content(self, content: str | bytes, evidence_id: str = "", file_path: str = "") -> list[Artifact]:
        """Parse in-memory text, XML, or JSON content of Group Policy log evidence."""
        if isinstance(content, bytes):
            # Check for Registry.pol header in bytes
            if content.startswith(b"PReg"):
                return self._parse_registry_pol_bytes(content, evidence_id, file_path)
            text = self._decode_bytes(content)
        else:
            text = str(content)

        text_trimmed = text.strip()
        if not text_trimmed:
            return []

        # Attempt JSON parse (gpresult / gpreport exports)
        if text_trimmed.startswith("[") or text_trimmed.startswith("{"):
            try:
                data = json.loads(text_trimmed)
                records = data if isinstance(data, list) else [data]
                artifacts: list[Artifact] = []
                for rec in records:
                    if isinstance(rec, dict):
                        art = self._json_record_to_artifact(rec, evidence_id, file_path)
                        if art:
                            artifacts.append(art)
                if artifacts:
                    return artifacts
            except json.JSONDecodeError:
                pass

        # Attempt XML parse (gpresult.xml, gpreport.xml, preferences XML, Event XML)
        if "<" in text_trimmed:
            try:
                artifacts = self._parse_xml_content(text_trimmed, evidence_id, file_path)
                if artifacts:
                    return artifacts
            except Exception as exc:
                logger.debug("XML parse attempt failed for %s: %s", file_path, exc)

        # gpt.ini content check
        if "[General]" in text_trimmed or "displayName=" in text_trimmed:
            artifacts = self._parse_gpt_ini_text(text_trimmed, evidence_id, file_path)
            if artifacts:
                return artifacts

        # Text debug log (gpesvc.log, GroupPolicy.log, gpresult text)
        return self._parse_text_log_content(text_trimmed, evidence_id, file_path)

    # ---------------------------------------------------------------------------
    # Registry.pol Binary Parser
    # ---------------------------------------------------------------------------

    def _is_registry_pol_file(self, src: Path) -> bool:
        try:
            with src.open("rb") as fh:
                header = fh.read(4)
                return header == b"PReg"
        except Exception:
            return False

    def _parse_registry_pol(self, src: Path, evidence_id: str) -> list[Artifact]:
        try:
            data = src.read_bytes()
        except Exception as exc:
            raise GroupPolicyLogParserError(f"Failed to read Registry.pol file {src.name}: {exc}")
        return self._parse_registry_pol_bytes(data, evidence_id, str(src))

    def _parse_registry_pol_bytes(self, data: bytes, evidence_id: str, file_path: str) -> list[Artifact]:
        """Parse Registry.pol binary format: PReg header followed by [Key;Value;Type;Size;Data] entries."""
        if len(data) < 8 or not data.startswith(b"PReg"):
            raise GroupPolicyLogParserError("Invalid Registry.pol header (magic bytes 'PReg' missing)")

        header_magic = data[:4]
        version = struct.unpack("<I", data[4:8])[0]
        if version != 1:
            logger.warning("Registry.pol version is %d (expected 1)", version)

        entries: list[dict[str, Any]] = []
        offset = 8
        length = len(data)

        # Each record is enclosed in '[' and ']' encoded in UTF-16LE (or ASCII)
        while offset < length:
            # Find opening bracket '[' (0x005B in UTF-16LE: b"[\x00")
            open_idx = data.find(b"[\x00", offset)
            if open_idx == -1:
                break
            close_idx = data.find(b"]\x00", open_idx)
            if close_idx == -1:
                break

            record_bytes = data[open_idx + 2 : close_idx]
            offset = close_idx + 2

            try:
                entry = self._parse_pol_record(record_bytes)
                if entry:
                    entries.append(entry)
            except Exception as exc:
                logger.debug("Failed to parse POL record at offset %d: %s", open_idx, exc)

        if not entries:
            # Create at least one artifact for valid PReg header file
            entries.append({
                "key": "SOFTWARE\\Policies",
                "value": "(header_only)",
                "type": 0,
                "size": 0,
                "data": None,
                "note": "Registry.pol file contained header but no parsed entries",
            })

        file_name = os.path.basename(file_path) if file_path else "Registry.pol"
        ver = self._tool_version
        artifacts: list[Artifact] = []

        mtime_dt = None
        if file_path and os.path.exists(file_path):
            try:
                mtime_dt = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except Exception:
                pass

        for idx, entry in enumerate(entries, 1):
            key = entry.get("key") or "UNKNOWN_KEY"
            val_name = entry.get("value") or ""
            val_data = str(entry.get("data") if entry.get("data") is not None else "")
            val_type = entry.get("type", 1)

            raw_payload = {
                "header": "PReg",
                "pol_version": version,
                "key": key,
                "value_name": val_name,
                "value_type": val_type,
                "value_size": entry.get("size", 0),
                "value_data": val_data,
                "entry_index": idx,
                "tool_version": ver,
            }

            norm = NormalizedFields(
                file_name=file_name,
                file_path=file_path or None,
                registry_key=key,
                registry_value=val_name,
                registry_value_data=val_data,
                rule_name="gpo_registry_pol",
            )

            summary = f"GPO Registry.pol Entry: [{key}] {val_name}={val_data[:60]}"

            artifacts.append(
                Artifact(
                    evidence_id=evidence_id or "unknown",
                    source_tool="group_policy_log_parser",
                    artifact_type="gpo_event",
                    timestamp=mtime_dt,
                    timestamp_type="modified" if mtime_dt else "none",
                    event_summary=summary,
                    raw_fields=raw_payload,
                    normalized_fields=norm,
                    parser_version=ver,
                    confidence_score=1.0,
                )
            )

        return artifacts

    def _parse_pol_record(self, raw: bytes) -> Optional[dict[str, Any]]:
        """Parse one UTF-16LE POL record content: Key;Value;Type;Size;Data."""
        # Key string terminates at ';' (0x003B)
        parts = raw.split(b";\x00")
        if len(parts) < 4:
            return None

        key = parts[0].decode("utf-16le", errors="replace").rstrip("\x00")
        val_name = parts[1].decode("utf-16le", errors="replace").rstrip("\x00")

        # Type (DWORD 4 bytes), Size (DWORD 4 bytes)
        remainder = b";\x00".join(parts[2:])
        if len(remainder) < 8:
            return None

        reg_type = struct.unpack("<I", remainder[:4])[0]
        size = struct.unpack("<I", remainder[4:8])[0]
        data_bytes = remainder[8 : 8 + size]

        val_data: Any = None
        if reg_type in (1, 2, 7):  # REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ
            val_data = data_bytes.decode("utf-16le", errors="replace").rstrip("\x00")
        elif reg_type == 4 and len(data_bytes) >= 4:  # REG_DWORD
            val_data = struct.unpack("<I", data_bytes[:4])[0]
        elif reg_type == 11 and len(data_bytes) >= 8:  # REG_QWORD
            val_data = struct.unpack("<Q", data_bytes[:8])[0]
        else:
            val_data = data_bytes.hex()

        return {
            "key": key,
            "value": val_name,
            "type": reg_type,
            "size": size,
            "data": val_data,
        }

    # ---------------------------------------------------------------------------
    # gpt.ini Configuration Parser
    # ---------------------------------------------------------------------------

    def _parse_gpt_ini(self, src: Path, evidence_id: str) -> list[Artifact]:
        try:
            content = src.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = src.read_text(encoding="latin-1", errors="replace")
        return self._parse_gpt_ini_text(content, evidence_id, str(src))

    def _parse_gpt_ini_text(self, content: str, evidence_id: str, file_path: str) -> list[Artifact]:
        fields: dict[str, str] = {}
        cur_section = "General"
        for line in content.splitlines():
            l_str = line.strip()
            if not l_str or l_str.startswith(";") or l_str.startswith("#"):
                continue
            if l_str.startswith("[") and l_str.endswith("]"):
                cur_section = l_str[1:-1].strip()
                continue
            if "=" in l_str:
                k, _, v = l_str.partition("=")
                fields[f"{cur_section}.{k.strip()}"] = v.strip()
                fields[k.strip()] = v.strip()

        version = fields.get("Version") or fields.get("General.Version")
        display_name = fields.get("displayName") or fields.get("General.displayName") or fields.get("gpoName")
        gpo_id = fields.get("gpoId") or fields.get("General.gpoId")

        # Extract GPO GUID if present in path or fields
        if not gpo_id:
            m = self.GPO_GUID_REGEX.search(file_path + " " + content)
            if m:
                gpo_id = m.group(0)

        file_name = os.path.basename(file_path) if file_path else "gpt.ini"
        ver = self._tool_version

        mtime_dt = None
        if file_path and os.path.exists(file_path):
            try:
                mtime_dt = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except Exception:
                pass

        raw_payload = {
            "ini_fields": fields,
            "version": version,
            "display_name": display_name,
            "gpo_id": gpo_id,
            "tool_version": ver,
            "raw_text": content,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            process_command_line=display_name or gpo_id or "Group Policy Template",
            rule_name="gpo_template_ini",
        )

        summary = f"GPO Template Config (gpt.ini): Name={display_name or 'N/A'}, GUID={gpo_id or 'N/A'}, Version={version or 'N/A'}"

        return [
            Artifact(
                evidence_id=evidence_id or "unknown",
                source_tool="group_policy_log_parser",
                artifact_type="gpo_event",
                timestamp=mtime_dt,
                timestamp_type="modified" if mtime_dt else "none",
                event_summary=summary,
                raw_fields=raw_payload,
                normalized_fields=norm,
                parser_version=ver,
                confidence_score=1.0,
            )
        ]

    # ---------------------------------------------------------------------------
    # XML Parser (Events, Reports, Preferences)
    # ---------------------------------------------------------------------------

    def _parse_xml_content(self, xml_str: str, evidence_id: str, file_path: str) -> list[Artifact]:
        try:
            root = ET.fromstring(xml_str if xml_str.strip().startswith("<") else f"<Root>{xml_str}</Root>")
        except ET.ParseError as exc:
            raise GroupPolicyLogParserError(f"Malformed GPO XML content: {exc}")

        artifacts: list[Artifact] = []
        file_name = os.path.basename(file_path) if file_path else "gpo_report.xml"
        ver = self._tool_version

        # 1. Event Log XML (<Event> / <Events>)
        events = [el for el in root.iter() if el.tag.split("}")[-1].lower() == "event"]
        if events:
            for ev_elem in events:
                art = self._parse_single_xml_event(ev_elem, evidence_id, file_path, file_name, ver)
                if art:
                    artifacts.append(art)
            if artifacts:
                return artifacts

        # 2. GPO Report XML (<GPO>, <GroupPolicyResults>, <Rsop>)
        gpo_elems = [el for el in root.iter() if el.tag.split("}")[-1].lower() == "gpo"]
        root_tag = root.tag.split("}")[-1].lower()
        if gpo_elems or root_tag in ("grouppolicyresults", "rsop", "grouppolicy"):
            if not gpo_elems:
                gpo_elems = [root]
            for gpo_el in gpo_elems:
                art = self._parse_single_gpo_xml_node(gpo_el, evidence_id, file_path, file_name, ver)
                if art:
                    artifacts.append(art)
            if artifacts:
                return artifacts

        # 3. GPO Preferences XML (<ScheduledTasks>, <Registry>, <Groups>, etc.)
        pref_arts = self._parse_gpo_preference_xml(root, evidence_id, file_path, file_name, ver)
        if pref_arts:
            return pref_arts

        return artifacts

    def _parse_single_xml_event(
        self, ev: ET.Element, evidence_id: str, file_path: str, file_name: str, ver: str
    ) -> Optional[Artifact]:
        rec: dict[str, Any] = {}

        event_id = None
        ts = None
        computer = None
        user_sid = None

        for child in ev:
            child_tag = child.tag.split("}")[-1].lower()
            if child_tag == "system":
                for sub in child:
                    sub_tag = sub.tag.split("}")[-1].lower()
                    if sub_tag == "eventid" and sub.text:
                        event_id = sub.text.strip()
                    elif sub_tag == "timecreated":
                        ts_str = sub.attrib.get("SystemTime")
                        ts = self._parse_timestamp_str(ts_str) if ts_str else None
                    elif sub_tag == "computer" and sub.text:
                        computer = sub.text.strip()
                    elif sub_tag == "security":
                        user_sid = sub.attrib.get("UserID")
            elif child_tag == "eventdata":
                for sub in child:
                    name = sub.attrib.get("Name")
                    val = sub.text
                    if name and val:
                        rec[name] = val

        gpo_name = rec.get("GPOName") or rec.get("GPName") or rec.get("TargetGPOName")
        gpo_guid = rec.get("GPOID") or rec.get("GUID") or rec.get("TargetGPOID")
        cse_name = rec.get("CSEName") or rec.get("Extension") or rec.get("ExtensionName")
        status_code = rec.get("ErrorCode") or rec.get("Status") or rec.get("ResultCode")

        raw_payload = {
            "event_id": event_id or "5017",
            "gpo_name": gpo_name,
            "gpo_guid": gpo_guid,
            "cse_name": cse_name,
            "status_code": status_code,
            "computer": computer,
            "user_sid": user_sid,
            "event_data": rec,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            host=computer,
            user=user_sid,
            process_name=cse_name or "gpesvc.exe",
            process_command_line=gpo_name or gpo_guid or f"GPO Event {event_id}",
            rule_name="gpo_operational_event",
        )

        summary = f"GPO Operational Event {event_id or '5017'}: Policy={gpo_name or gpo_guid or 'N/A'}, CSE={cse_name or 'N/A'}, Status={status_code or 'Success'}"

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="group_policy_log_parser",
            artifact_type="gpo_event",
            timestamp=ts,
            timestamp_type="event" if ts else "none",
            event_summary=summary,
            raw_fields=raw_payload,
            normalized_fields=norm,
            parser_version=ver,
            confidence_score=1.0,
        )

    def _parse_single_gpo_xml_node(
        self, elem: ET.Element, evidence_id: str, file_path: str, file_name: str, ver: str
    ) -> Optional[Artifact]:
        def _find_text(local_name: str) -> Optional[str]:
            for child in elem.iter():
                if child.tag.split("}")[-1].lower() == local_name.lower():
                    return child.text.strip() if child.text else None
            return None

        gpo_name = _find_text("Name") or _find_text("DisplayName")
        gpo_id = _find_text("Identifier") or _find_text("GPOID") or _find_text("ID")
        state = _find_text("State") or _find_text("Status") or "Applied"
        created_time = _find_text("CreatedTime")
        modified_time = _find_text("ModifiedTime")

        dt = self._parse_timestamp_str(modified_time or created_time)

        raw_payload = {
            "gpo_name": gpo_name,
            "gpo_id": gpo_id,
            "state": state,
            "created_time": created_time,
            "modified_time": modified_time,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            process_command_line=gpo_name or gpo_id or "GPO XML Report",
            rule_name="gpo_report_xml",
        )

        summary = f"GPO Report Entry: [{gpo_name or gpo_id or 'GPO'}] State={state}"

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="group_policy_log_parser",
            artifact_type="gpo_event",
            timestamp=dt,
            timestamp_type="modified" if dt else "none",
            event_summary=summary,
            raw_fields=raw_payload,
            normalized_fields=norm,
            parser_version=ver,
            confidence_score=1.0,
        )

    def _parse_gpo_preference_xml(
        self, root: ET.Element, evidence_id: str, file_path: str, file_name: str, ver: str
    ) -> list[Artifact]:
        artifacts: list[Artifact] = []

        for child in root.iter():
            tag_name = child.tag.split("}")[-1]
            if tag_name in ("Properties", "Task", "User", "Drive", "Printer", "RegistryItem"):
                name_val = child.attrib.get("name") or child.attrib.get("action") or tag_name
                path_val = child.attrib.get("path") or child.attrib.get("targetPath")
                cmd_val = child.attrib.get("run") or child.attrib.get("command")

                raw_payload = {
                    "tag": tag_name,
                    "attributes": dict(child.attrib),
                    "tool_version": ver,
                }

                norm = NormalizedFields(
                    file_name=file_name,
                    file_path=file_path or path_val,
                    process_command_line=cmd_val or name_val,
                    rule_name=f"gpo_preference_{tag_name.lower()}",
                )

                summary = f"GPO Preference [{tag_name}]: {name_val}"

                artifacts.append(
                    Artifact(
                        evidence_id=evidence_id or "unknown",
                        source_tool="group_policy_log_parser",
                        artifact_type="gpo_event",
                        timestamp=None,
                        timestamp_type="none",
                        event_summary=summary,
                        raw_fields=raw_payload,
                        normalized_fields=norm,
                        parser_version=ver,
                        confidence_score=1.0,
                    )
                )

        return artifacts

    # ---------------------------------------------------------------------------
    # JSON Parser
    # ---------------------------------------------------------------------------

    def _json_record_to_artifact(self, rec: dict[str, Any], evidence_id: str, file_path: str) -> Optional[Artifact]:
        gpo_name = rec.get("GPOName") or rec.get("Name") or rec.get("gpo_name")
        gpo_id = rec.get("GPOID") or rec.get("Identifier") or rec.get("gpo_id")
        cse_name = rec.get("CSEName") or rec.get("Extension") or rec.get("cse_name")
        status = rec.get("Status") or rec.get("Result") or rec.get("status") or "Applied"
        ts_val = rec.get("Timestamp") or rec.get("Date") or rec.get("Time") or rec.get("time")

        dt = self._parse_timestamp_str(str(ts_val)) if ts_val else None

        file_name = os.path.basename(file_path) if file_path else "gpresult.json"
        ver = self._tool_version

        raw_payload = dict(rec)
        raw_payload["tool_version"] = ver

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            host=rec.get("Computer") or rec.get("Host"),
            user=rec.get("User"),
            process_name=cse_name or "gpesvc.exe",
            process_command_line=gpo_name or gpo_id or "GPO JSON Entry",
            rule_name="gpo_json_export",
        )

        summary = f"GPO Record [{gpo_name or gpo_id or 'GPO'}]: CSE={cse_name or 'N/A'}, Status={status}"

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="group_policy_log_parser",
            artifact_type="gpo_event",
            timestamp=dt,
            timestamp_type="event" if dt else "none",
            event_summary=summary,
            raw_fields=raw_payload,
            normalized_fields=norm,
            parser_version=ver,
            confidence_score=1.0,
        )

    # ---------------------------------------------------------------------------
    # Text Log Parser (gpesvc.log, GroupPolicy.log)
    # ---------------------------------------------------------------------------

    def _parse_text_log_content(self, text: str, evidence_id: str, file_path: str) -> list[Artifact]:
        lines = text.splitlines()
        artifacts: list[Artifact] = []
        file_name = os.path.basename(file_path) if file_path else "gpesvc.log"
        ver = self._tool_version

        for line_num, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            dt = self._extract_timestamp(line_str)
            gpo_match = self.GPO_GUID_REGEX.search(line_str)
            gpo_guid = gpo_match.group(0) if gpo_match else None

            # Extract thread/process tag e.g. gpesvc(3ec.488)
            proc_thread_match = re.search(r"gpesvc\(([^)]+)\)", line_str, re.IGNORECASE)
            proc_thread = proc_thread_match.group(1) if proc_thread_match else None

            # Extract CSE or status indicators
            cse_name = self._extract_cse_from_line(line_str)
            status_text = self._extract_status_from_line(line_str)

            raw_payload = {
                "log_line": line_str,
                "line_number": line_num,
                "proc_thread": proc_thread,
                "gpo_guid": gpo_guid,
                "cse_name": cse_name,
                "status_text": status_text,
                "tool_version": ver,
            }

            norm = NormalizedFields(
                file_name=file_name,
                file_path=file_path or None,
                process_name="gpesvc.exe",
                process_command_line=gpo_guid or cse_name or line_str[:80],
                rule_name="gpo_debug_log_line",
            )

            summary = f"GPO Log Line {line_num}: {line_str[:90]}"

            artifacts.append(
                Artifact(
                    evidence_id=evidence_id or "unknown",
                    source_tool="group_policy_log_parser",
                    artifact_type="gpo_event",
                    timestamp=dt,
                    timestamp_type="logged" if dt else "none",
                    line_number=line_num,
                    raw_fields=raw_payload,
                    normalized_fields=norm,
                    parser_version=ver,
                    confidence_score=1.0,
                )
            )

        return artifacts

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _decode_bytes(self, data: bytes) -> str:
        if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff") or (len(data) > 1 and data[1:2] == b"\x00"):
            try:
                return data.decode("utf-16")
            except Exception:
                pass
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                return data.decode(enc)
            except Exception:
                continue
        return data.decode("latin-1", errors="replace")

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        for regex in self.TIMESTAMP_REGEXES:
            m = regex.search(line)
            if m:
                return self._parse_timestamp_str(m.group(1))
        return None

    def _parse_timestamp_str(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        ts_clean = ts_str.strip().replace("Z", "+00:00")
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S:%f",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%H:%M:%S.%f",
            "%H:%M:%S:%f",
        ):
            try:
                dt = datetime.strptime(ts_clean.split("+")[0].split("Z")[0].strip(), fmt)
                # If only time was parsed, attach today's date placeholder with UTC
                if dt.year == 1900:
                    today = datetime.now(timezone.utc).date()
                    dt = datetime.combine(today, dt.time())
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

    def _extract_cse_from_line(self, line: str) -> Optional[str]:
        m = re.search(r"extension\s+([A-Za-z0-9\s_-]+)", line, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        if "Security" in line:
            return "Security"
        if "Scripts" in line:
            return "Scripts"
        if "Folder Redirection" in line:
            return "Folder Redirection"
        if "Group Policy Environment" in line:
            return "Group Policy Environment"
        return None

    def _extract_status_from_line(self, line: str) -> str:
        l_lower = line.lower()
        if "completed" in l_lower or "succeeded" in l_lower or "success" in l_lower or "status: 0" in l_lower:
            return "Success"
        if "failed" in l_lower or "error" in l_lower or "warning" in l_lower:
            return "Failed/Warning"
        return "Info"
