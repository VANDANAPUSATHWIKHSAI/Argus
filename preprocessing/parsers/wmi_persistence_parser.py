"""
WmiPersistenceParser
====================
Source 30: WMI Persistence (OBJECTS.DATA, WMI Event Subscriptions)
Source Tool: "wmi_persistence"
Artifact Types Produced: "wmi_persistence"

Parses WMI repository artifacts (e.g. OBJECTS.DATA) or structured WMI export files
(JSON, MOF, XML) for WMI Event Filters, Event Consumers (CommandLineEventConsumer,
ActiveScriptEventConsumer), and FilterToConsumerBindings.

CRITICAL: WMI persistence constructs are parsed as raw deterministic evidence.
Extracted script texts and command lines are NEVER executed or dynamically evaluated.
"""

from __future__ import annotations

import json
import logging
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

class WmiPersistenceNotFoundError(FileNotFoundError):
    """Raised when the specified WMI evidence file does not exist."""


class WmiPersistenceParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt WMI data."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class WmiPersistenceParser:
    """Parses WMI persistence artifacts including Event Filters, Consumers, and Bindings."""

    def __init__(self) -> None:
        self._tool_version = get_tool_version("wmi_persistence")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse WMI persistence evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise WmiPersistenceNotFoundError(f"WMI evidence file not found: {file_path}")

        artifacts: list[Artifact] = []
        ver = self._tool_version

        # Case 1: Structured JSON input export
        if src.suffix.lower() == ".json":
            artifacts = self._parse_json_export(src, evidence_id, ver)
        # Case 2: Binary OBJECTS.DATA or MOF/text repository
        else:
            artifacts = self._parse_binary_or_mof(src, evidence_id, ver)

        logger.info("WmiPersistenceParser total: %d raw artifacts from %s", len(artifacts), src.name)
        return artifacts

    def _parse_json_export(self, src: Path, evidence_id: str, ver: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        try:
            content = src.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                return artifacts
            data = json.loads(content)
            records = data if isinstance(data, list) else [data]
            for rec in records:
                if isinstance(rec, dict):
                    artifacts.append(self._record_to_artifact(rec, evidence_id, ver, src))
        except Exception as exc:
            logger.warning("Error parsing WMI JSON export %s: %s", src.name, exc)
        return artifacts

    def _parse_binary_or_mof(self, src: Path, evidence_id: str, ver: str) -> list[Artifact]:
        raw_bytes = src.read_bytes()
        if not raw_bytes:
            return []

        text = raw_bytes.decode("latin-1", errors="replace")
        artifacts: list[Artifact] = []

        # Extract EventFilter queries
        filters = re.findall(r"SELECT\s+.*?\s+FROM\s+[\w_]+", text, re.IGNORECASE)

        # Extract CommandLineEventConsumer templates / executables
        cmd_templates = re.findall(
            r"CommandLineTemplate\s*=\s*[\"']([^\"']+)[\"']|"
            r"([C-Z]:\\[^\x00-\x1f\"'\r\n]+\.(?:exe|bat|ps1|vbs|cmd))",
            text, re.IGNORECASE
        )

        # Extract ActiveScriptEventConsumer script texts
        script_texts = re.findall(r"ScriptText\s*=\s*[\"']([^\"']+)[\"']", text, re.IGNORECASE)

        # Extract FilterToConsumerBinding relationships
        bindings = re.findall(r"(__FilterToConsumerBinding|Filter\s*=\s*[\"'][^\"']+[\"'])", text, re.IGNORECASE)

        # Combine into deterministic WMI artifacts
        if filters or cmd_templates or script_texts or bindings:
            for idx, f_query in enumerate(filters or ["__EventFilter"]):
                cmd_line = None
                if cmd_templates:
                    match = cmd_templates[min(idx, len(cmd_templates) - 1)]
                    cmd_line = match[0] or match[1]

                script_content = script_texts[min(idx, len(script_texts) - 1)] if script_texts else None

                rec = {
                    "event_filter_query": f_query,
                    "command_line": cmd_line,
                    "script_content": script_content,
                    "consumer_type": "ActiveScriptEventConsumer" if script_content else "CommandLineEventConsumer",
                    "namespace": "root\\subscription",
                    "source_file": src.name,
                }
                artifacts.append(self._record_to_artifact(rec, evidence_id, ver, src))
        else:
            # Fallback raw record for non-empty OBJECTS.DATA
            rec = {
                "raw_text_snippet": text[:500],
                "namespace": "root\\default",
                "source_file": src.name,
            }
            artifacts.append(self._record_to_artifact(rec, evidence_id, ver, src))

        return artifacts

    def _record_to_artifact(self, record: dict, evidence_id: str, ver: str, src: Path) -> Artifact:
        consumer_name = record.get("consumer_name") or record.get("Name") or "WMI_Event_Consumer"
        filter_query = record.get("event_filter_query") or record.get("Query") or ""
        cmd_line = record.get("command_line") or record.get("CommandLineTemplate") or record.get("ExecutablePath") or ""
        script = record.get("script_content") or record.get("ScriptText") or ""
        consumer_type = record.get("consumer_type") or "WMIEventConsumer"
        namespace = record.get("namespace") or record.get("EventNamespace") or "root\\subscription"
        user = record.get("creator") or record.get("CreatorSID") or record.get("User") or ""

        summary = f"WMI Persistence artifact ({consumer_type}): {consumer_name}"

        raw_fields = {
            **record,
            "event_filter_query": filter_query,
            "command_line": cmd_line,
            "script_content": script,
            "consumer_name": consumer_name,
            "consumer_type": consumer_type,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            user=user or None,
            process_name=self._extract_proc_name(cmd_line),
            process_command_line=cmd_line or script or None,
            file_path=str(src),
            file_name=src.name,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="wmi_persistence",
            artifact_type="wmi_persistence",
            timestamp=None,  # WMI persistence records often lack discrete execution timestamps
            timestamp_type="none",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    @staticmethod
    def _extract_proc_name(cmd_line: str) -> Optional[str]:
        if not cmd_line:
            return None
        m = re.search(r"([a-zA-Z0-9_\-]+\.exe)", cmd_line, re.IGNORECASE)
        return m.group(1) if m else None
