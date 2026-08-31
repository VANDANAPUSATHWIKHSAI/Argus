"""
Windows Event Log (EVTX) Raw Parser using EvtxECmd
===================================================
Source 4: Windows Event Logs (EVTX) — RAW
Source Tool: "evtxecmd"
Artifact Types Produced: "log_event"
Raw Output Format: JSON / JSONL / CSV output from Eric Zimmerman's EvtxECmd

EvtxECmd Reference:
  https://github.com/EricZimmerman/EvtxECmd
  CLI: EvtxECmd.exe -f <evtx_path> --json <tmp_dir> --jsonf output.json

Preserves complete raw event stream without loss, capturing every Event ID,
provider, channel, record ID, and XML/EventData field regardless of whether
a threat-detection rule matched.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class EvtxECmdNotFoundError(FileNotFoundError):
    """Raised when the `EvtxECmd` binary cannot be found on PATH."""


class EvtxECmdExecutionError(RuntimeError):
    """Raised when EvtxECmd exits with a non-zero return code or fails."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class EvtxECmdParser:
    """Parses Windows Event Log (.evtx) files via EvtxECmd into Artifact records.

    Preserves full raw event ground-truth without truncation or Sigma-only filtering.
    """

    _BINARIES: tuple[str, ...] = ("EvtxECmd.exe", "EvtxECmd", "evtxecmd", "EvtxECmd.dll")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the .evtx file at *file_path* via EvtxECmd and return Artifact records.

        Args:
            file_path:   Absolute path to the .evtx file to analyse.
            evidence_id: FK linking back to infrastructure.Evidence.evidence_id.

        Returns:
            List of Artifact objects (source_tool="evtxecmd", artifact_type="log_event").

        Raises:
            EvtxECmdNotFoundError:  EvtxECmd binary not found on system PATH.
            EvtxECmdExecutionError: EvtxECmd binary exited with a non-zero code.
            FileNotFoundError:      *file_path* does not exist.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        binary = self._find_binary()
        self._tool_version = get_tool_version("evtxecmd")

        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_evtxecmd_"))
        try:
            output_file = tmp_dir / "out.json"
            self._run_evtxecmd(binary, src, tmp_dir, output_file)
            artifacts = self._parse_output(tmp_dir, output_file, evidence_id)
            logger.info("EvtxECmdParser total: %d raw artifacts from %s", len(artifacts), src.name)
            return artifacts
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # Binary Discovery & Subprocess Execution
    # -----------------------------------------------------------------------

    def _find_binary(self) -> str:
        """Find candidate EvtxECmd binary on system PATH or dotnet wrapper."""
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved

        raise EvtxECmdNotFoundError(
            f"EvtxECmd binary not found on PATH. Tried: {', '.join(self._BINARIES)}. "
            "Install Eric Zimmerman's EvtxECmd from https://ericzimmerman.github.io "
            "and ensure it is accessible on PATH."
        )

    def _run_evtxecmd(self, binary: str, evtx_path: Path, tmp_dir: Path, output_json: Path) -> None:
        """Execute EvtxECmd safely without shell execution."""
        # EvtxECmd flags:
        #   -f <file>     Input EVTX file
        #   --json <dir>  Output directory for JSON
        #   --jsonf <fn>  Output filename for JSON
        cmd = [
            binary,
            "-f", str(evtx_path),
            "--json", str(tmp_dir),
            "--jsonf", output_json.name,
        ]
        logger.debug("Running EvtxECmd: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            raise EvtxECmdNotFoundError(f"EvtxECmd binary {binary} disappeared from PATH mid-run.")
        except subprocess.TimeoutExpired:
            raise EvtxECmdExecutionError(
                f"EvtxECmd execution timed out after {self.timeout_seconds} seconds on file {evtx_path.name}"
            )

        if result.returncode != 0:
            raise EvtxECmdExecutionError(
                f"EvtxECmd exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )

    # -----------------------------------------------------------------------
    # Parsing Output
    # -----------------------------------------------------------------------

    def _parse_output(self, tmp_dir: Path, json_file: Path, evidence_id: str) -> list[Artifact]:
        """Read JSON/JSONL output from EvtxECmd and convert records to Artifact objects."""
        artifacts: list[Artifact] = []

        # Find actual output file (EvtxECmd may add suffix or produce CSV fallback)
        target_file = json_file
        if not target_file.exists():
            matches = list(tmp_dir.glob("*.json")) + list(tmp_dir.glob("*.jsonl"))
            if matches:
                target_file = matches[0]

        if target_file.exists():
            artifacts = self._parse_json_file(target_file, evidence_id)
        else:
            # Check if CSV output was generated instead
            csv_matches = list(tmp_dir.glob("*.csv"))
            if csv_matches:
                artifacts = self._parse_csv_file(csv_matches[0], evidence_id)
            else:
                logger.warning("EvtxECmd ran but produced no output file in %s", tmp_dir)

        return artifacts

    def _parse_json_file(self, json_path: Path, evidence_id: str) -> list[Artifact]:
        """Parse JSON or JSONL lines file."""
        artifacts: list[Artifact] = []
        with json_path.open(encoding="utf-8", errors="replace") as fh:
            content = fh.read().strip()
            if not content:
                return artifacts

            # Try parsing array of JSON objects first
            if content.startswith("["):
                try:
                    records = json.loads(content)
                    if isinstance(records, list):
                        for rec in records:
                            if isinstance(rec, dict):
                                artifacts.append(self._record_to_artifact(rec, evidence_id))
                        return artifacts
                except json.JSONDecodeError:
                    pass

            # Fallback to line-by-line JSONL reading
            for lineno, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line or line in ("[", "]"):
                    continue
                if line.endswith(","):
                    line = line[:-1].strip()
                try:
                    rec = json.loads(line)
                    if isinstance(rec, dict):
                        artifacts.append(self._record_to_artifact(rec, evidence_id))
                except json.JSONDecodeError as exc:
                    logger.warning("Skipping malformed EvtxECmd JSON line %d: %s", lineno, exc)

        return artifacts

    def _parse_csv_file(self, csv_path: Path, evidence_id: str) -> list[Artifact]:
        """Parse CSV rows if EvtxECmd emitted CSV."""
        artifacts: list[Artifact] = []
        with csv_path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for lineno, row in enumerate(reader, start=1):
                if not row:
                    continue
                artifacts.append(self._record_to_artifact(row, evidence_id))
        return artifacts

    # -----------------------------------------------------------------------
    # Record to Artifact Mapping
    # -----------------------------------------------------------------------

    def _record_to_artifact(self, record: dict, evidence_id: str) -> Artifact:
        """Map one raw EvtxECmd record dict to an Artifact."""
        eid = record.get("EventId") or record.get("EventID") or record.get("EventId")
        provider = record.get("Provider") or record.get("Source") or ""
        channel = record.get("Channel") or record.get("LogName") or "Security"
        computer = record.get("Computer") or record.get("MachineName") or ""
        rec_id = record.get("RecordId") or record.get("EventRecordID") or record.get("RecordNumber")

        summary_parts = []
        if eid:
            summary_parts.append(f"Event ID {eid}")
        if provider:
            summary_parts.append(f"({provider})")
        if channel:
            summary_parts.append(f"in {channel}")
        if computer:
            summary_parts.append(f"on {computer}")
        summary = " ".join(summary_parts) if summary_parts else f"Raw EVTX log event in {channel}"

        ts = self._parse_timestamp(record)
        ver = getattr(self, "_tool_version", get_tool_version("evtxecmd"))

        return Artifact(
            evidence_id=evidence_id,
            source_tool="evtxecmd",
            artifact_type="log_event",
            timestamp=ts,
            timestamp_type="event",
            event_summary=summary,
            parser_version=ver,
            raw_fields={**record, "tool_version": ver},
            normalized_fields=self._normalize(record, channel, provider, computer),
        )

    @staticmethod
    def _normalize(record: dict, channel: str, provider: str, computer: str) -> NormalizedFields:
        """Extract correlation fields from EvtxECmd fields."""
        # Top level + Payload / EventData extraction
        event_data = record.get("EventData") or record.get("Payload") or {}
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except Exception:
                event_data = {}

        if not isinstance(event_data, dict):
            event_data = {}

        def _get(*keys: str) -> Optional[str]:
            for k in keys:
                v = record.get(k) or event_data.get(k)
                if v is not None and str(v).strip() != "":
                    return str(v).strip()
            return None

        def _get_int(*keys: str) -> Optional[int]:
            v_str = _get(*keys)
            if v_str is not None:
                try:
                    return int(v_str, 0)
                except (ValueError, TypeError):
                    pass
            return None

        host = computer or _get("Computer", "MachineName", "Host")
        user = _get("UserId", "UserName", "User", "TargetUserName", "SubjectUserName", "WorkstationName")
        pid = _get_int("ProcessID", "ProcessId", "NewProcessId", "TargetProcessId")
        ppid = _get_int("ParentProcessId", "ProcessId")
        proc_name = _get("Image", "ProcessName", "ExecutableInfo", "Application")
        cmdline = _get("CommandLine", "ProcessCommandLine")
        src_ip = _get("IpAddress", "SourceAddress", "SrcIp", "ClientAddress")
        dst_ip = _get("DestAddress", "DstIp", "ServerAddress")
        src_port = _get_int("IpPort", "SourcePort")
        dst_port = _get_int("DestPort")
        file_path = _get("TargetFilename", "Path", "FilePath", "FileName")
        reg_key = _get("TargetObject", "KeyPath")
        severity = _get("Level", "Severity")

        rule_name = provider or channel

        return NormalizedFields(
            host=host,
            user=user,
            process_id=pid,
            parent_process_id=ppid,
            process_name=proc_name,
            process_command_line=cmdline,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            file_path=file_path,
            registry_key=reg_key,
            rule_name=rule_name,
            severity=severity,
        )

    def _parse_timestamp(self, record: dict) -> Optional[datetime]:
        """Extract and convert event timestamp to timezone-aware UTC datetime."""
        for key in ("TimeCreated", "Timestamp", "Time", "Date", "ExecutedOn"):
            raw = record.get(key)
            if raw:
                if isinstance(raw, (int, float)):
                    if raw == 0:
                        continue
                    try:
                        return datetime.fromtimestamp(raw, tz=timezone.utc)
                    except Exception:
                        pass
                s = str(raw).strip()
                if not s or s == "0":
                    continue
                s = s.replace(" UTC", "+0000").replace("UTC", "+0000").replace(" ", "T")
                if len(s) > 6 and s[-3] == ":":
                    s = s[:-3] + s[-2:]
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S",
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
