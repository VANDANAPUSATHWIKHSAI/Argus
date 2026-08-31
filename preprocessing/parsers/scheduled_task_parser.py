"""
Windows Scheduled Task Parser
=============================
Source 21: Windows Scheduled Tasks (XML / Task Files from C:\\Windows\\System32\\Tasks\\ and C:\\Windows\\Tasks\\)

Source tool: "scheduled_task_parser"
Artifact type produced: "scheduled_task"

Parses native Windows Scheduled Task XML files safely, extracting:
- RegistrationInfo (Author, Description, URI, Date, Version)
- Triggers (CalendarTrigger, TimeTrigger, LogonTrigger, BootTrigger, EventTrigger, IdleTrigger, RegistrationTrigger)
- Principals (UserId, Account, LogonType, RunLevel)
- Settings (Enabled, Hidden, ExecutionTimeLimit, Priority, etc.)
- Actions (Exec: Command, Arguments, WorkingDirectory; ComHandler: ClassId, Data; SendEmail; ShowMessage)

Actions and commands are treated as UNTRUSTED FORENSIC EVIDENCE and are never executed.
"""

from __future__ import annotations

import logging
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import ntpath
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


class ScheduledTaskParseError(ValueError):
    """Raised when a Scheduled Task XML file cannot be parsed."""


class ScheduledTaskParser:
    """Parses Windows Scheduled Task XML and task files into Artifact records."""

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the Scheduled Task file at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Scheduled Task file not found: {file_path}")

        try:
            content = src.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise ScheduledTaskParseError(f"Could not read task file {file_path}: {exc}")

        if not content.strip():
            raise ScheduledTaskParseError(f"Scheduled Task file is empty: {file_path}")

        return self.parse_content(content, evidence_id=evidence_id, file_path=str(src))

    def parse_content(self, content: str, evidence_id: str = "", file_path: str = "") -> list[Artifact]:
        """Parse raw Scheduled Task XML string content into Artifact records."""
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ScheduledTaskParseError(f"Malformed Scheduled Task XML: {exc}")

        # Remove namespace prefix for uniform querying
        tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
        if tag.lower() != "task":
            raise ScheduledTaskParseError(f"XML root element is '{tag}', expected 'Task'")

        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        def _find_elem(parent: ET.Element, path: str) -> Optional[ET.Element]:
            parts = path.split("/")
            curr = parent
            for p in parts:
                child = curr.find(f"{ns}{p}")
                if child is None:
                    child = curr.find(p)
                if child is None:
                    return None
                curr = child
            return curr

        def _text(parent: ET.Element, path: str) -> Optional[str]:
            el = _find_elem(parent, path)
            return el.text.strip() if (el is not None and el.text) else None

        # RegistrationInfo
        author = _text(root, "RegistrationInfo/Author")
        description = _text(root, "RegistrationInfo/Description")
        uri = _text(root, "RegistrationInfo/URI")
        date_str = _text(root, "RegistrationInfo/Date")
        version = _text(root, "RegistrationInfo/Version")

        # Principals
        user_id = _text(root, "Principals/Principal/UserId")
        account = _text(root, "Principals/Principal/Account")
        logon_type = _text(root, "Principals/Principal/LogonType")
        run_level = _text(root, "Principals/Principal/RunLevel")
        user_principal = user_id or account

        # Settings
        enabled_str = _text(root, "Settings/Enabled")
        hidden_str = _text(root, "Settings/Hidden")
        enabled = enabled_str.lower() == "true" if enabled_str else True
        hidden = hidden_str.lower() == "true" if hidden_str else False

        # Triggers
        triggers: list[dict] = []
        triggers_elem = _find_elem(root, "Triggers")
        if triggers_elem is not None:
            for trig in triggers_elem:
                trig_type = trig.tag.split("}")[-1] if "}" in trig.tag else trig.tag
                start_b = _text(trig, "StartBoundary")
                end_b = _text(trig, "EndBoundary")
                trig_enabled = _text(trig, "Enabled")
                rep_interval = _text(trig, "Repetition/Interval")
                triggers.append({
                    "trigger_type": trig_type,
                    "start_boundary": start_b,
                    "end_boundary": end_b,
                    "enabled": trig_enabled,
                    "repetition_interval": rep_interval,
                })

        # Actions
        actions: list[dict] = []
        actions_elem = _find_elem(root, "Actions")
        if actions_elem is not None:
            for act in actions_elem:
                act_type = act.tag.split("}")[-1] if "}" in act.tag else act.tag
                if act_type.lower() == "exec":
                    cmd = _text(act, "Command")
                    args = _text(act, "Arguments")
                    work_dir = _text(act, "WorkingDirectory")
                    actions.append({
                        "action_type": "Exec",
                        "command": cmd,
                        "arguments": args,
                        "working_directory": work_dir,
                    })
                elif act_type.lower() == "comhandler":
                    clsid = _text(act, "ClassId")
                    data = _text(act, "Data")
                    actions.append({
                        "action_type": "ComHandler",
                        "class_id": clsid,
                        "data": data,
                    })
                else:
                    actions.append({
                        "action_type": act_type,
                        "raw_xml": ET.tostring(act, encoding="unicode"),
                    })

        # Derive task name
        task_name = Path(file_path).name if file_path else (uri or "ScheduledTask")

        # Parse timestamp
        timestamp = _parse_iso_ts(date_str) if date_str else None
        if timestamp is None and file_path and os.path.exists(file_path):
            try:
                mtime = os.path.getmtime(file_path)
                timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc)
            except Exception:
                pass

        ver = get_tool_version("scheduled_task_parser")

        # Build raw_fields
        raw_fields: dict[str, Any] = {
            "task_name": task_name,
            "task_path": file_path or uri,
            "author": author,
            "description": description,
            "uri": uri,
            "registration_date": date_str,
            "version": version,
            "user_id": user_id,
            "account": account,
            "logon_type": logon_type,
            "run_level": run_level,
            "enabled": enabled,
            "hidden": hidden,
            "triggers": triggers,
            "actions": actions,
            "tool_version": ver,
            "raw_xml": content,
        }

        # Build primary normalized command line
        primary_cmd = None
        primary_proc = None
        for act in actions:
            if act.get("action_type") == "Exec" and act.get("command"):
                c = act["command"]
                a = act.get("arguments")
                primary_proc = ntpath.basename(str(c).rstrip("\\/"))
                primary_cmd = f"{c} {a}" if a else c
                break

        norm = NormalizedFields(
            file_name=task_name,
            file_path=file_path or uri,
            process_name=primary_proc,
            process_command_line=primary_cmd,
            user=user_principal,
            rule_name="scheduled_task_xml",
        )

        summary = f"Scheduled Task [{task_name}]: author={author or 'N/A'}, action={primary_cmd or 'N/A'}"

        art = Artifact(
            evidence_id=evidence_id,
            source_tool="scheduled_task_parser",
            artifact_type="scheduled_task",
            timestamp=timestamp,
            timestamp_type="created" if date_str else "modified",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

        return [art]


def _parse_iso_ts(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    normalised = raw.strip().replace("Z", "+0000").replace(" ", "T")
    if len(normalised) > 6 and normalised[-3] == ":":
        normalised = normalised[:-3] + normalised[-2:]
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(normalised, fmt)
        except ValueError:
            continue
    return None
