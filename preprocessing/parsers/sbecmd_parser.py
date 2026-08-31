"""
SBECmd ShellBags Parser
=======================
Source 25: ShellBags
Source Tool: "sbecmd"
Artifact Types Produced: "shellbags"
Raw Output Format: JSON / JSONL / CSV output from Eric Zimmerman's SBECmd

SBECmd Reference:
  https://github.com/EricZimmerman/SBECmd
  CLI: SBECmd.exe -f <hive_path> --csv <tmp_dir> --csvf output.csv
"""

from __future__ import annotations

import csv
import json
import logging
import os
import ntpath
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

class SbecmdNotFoundError(FileNotFoundError):
    """Raised when the `SBECmd` binary cannot be found on PATH."""


class SbecmdExecutionError(RuntimeError):
    """Raised when SBECmd exits with a non-zero return code or fails."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class SBECmdParser:
    """Parses Windows ShellBags (from Registry hives or exported SBECmd files) into Artifact records."""

    _BINARIES: tuple[str, ...] = ("SBECmd.exe", "SBECmd", "sbecmd")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse a ShellBags registry hive or SBECmd output file and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"ShellBags file not found: {file_path}")

        # If input is already a JSON or CSV file (pre-parsed output)
        if src.suffix.lower() == ".json":
            return self._parse_json_file(src, evidence_id)
        elif src.suffix.lower() == ".csv":
            return self._parse_csv_file(src, evidence_id)

        # Otherwise invoke SBECmd binary
        binary = self._find_binary()
        tool_version = get_tool_version("sbecmd")

        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_sbecmd_"))
        try:
            output_csv = tmp_dir / "out.csv"
            self._run_sbecmd(binary, src, tmp_dir, output_csv)
            artifacts = self._parse_output(tmp_dir, output_csv, evidence_id, tool_version)
            logger.info("SBECmdParser total: %d raw artifacts from %s", len(artifacts), src.name)
            return artifacts
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def parse_content(self, content: bytes | str, evidence_id: str = "", file_path: str = "") -> list[Artifact]:
        """Parse in-memory CSV/JSON or raw text content."""
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = str(content)

        text_trimmed = text.strip()
        tool_version = get_tool_version("sbecmd")

        # Try JSON
        if text_trimmed.startswith("[") or text_trimmed.startswith("{"):
            try:
                data = json.loads(text_trimmed)
                records = data if isinstance(data, list) else [data]
                return [
                    self._record_to_artifact(rec, evidence_id, tool_version, file_path)
                    for rec in records if isinstance(rec, dict)
                ]
            except json.JSONDecodeError:
                pass

        # Try CSV parsing
        artifacts: list[Artifact] = []
        lines = text_trimmed.splitlines()
        if lines:
            reader = csv.DictReader(lines)
            for row in reader:
                if row:
                    artifacts.append(self._record_to_artifact(dict(row), evidence_id, tool_version, file_path))
        return artifacts

    def _find_binary(self) -> str:
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise SbecmdNotFoundError(
            f"SBECmd binary not found on PATH. Tried: {', '.join(self._BINARIES)}."
        )

    def _run_sbecmd(self, binary: str, hive_path: Path, tmp_dir: Path, output_csv: Path) -> None:
        cmd = [
            binary,
            "-f", str(hive_path),
            "--csv", str(tmp_dir),
            "--csvf", output_csv.name,
        ]
        logger.debug("Running SBECmd: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except FileNotFoundError:
            raise SbecmdNotFoundError(f"SBECmd binary {binary} disappeared from PATH mid-run.")
        except subprocess.TimeoutExpired:
            raise SbecmdExecutionError(
                f"SBECmd execution timed out after {self.timeout_seconds} seconds on file {hive_path.name}"
            )

        if result.returncode != 0:
            raise SbecmdExecutionError(
                f"SBECmd exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )

    def _parse_output(self, tmp_dir: Path, csv_file: Path, evidence_id: str, tool_version: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        target_file = csv_file
        if not target_file.exists():
            csv_matches = list(tmp_dir.glob("*.csv"))
            if csv_matches:
                target_file = csv_matches[0]

        if target_file.exists():
            artifacts = self._parse_csv_file(target_file, evidence_id, tool_version)
        else:
            json_matches = list(tmp_dir.glob("*.json")) + list(tmp_dir.glob("*.jsonl"))
            if json_matches:
                artifacts = self._parse_json_file(json_matches[0], evidence_id, tool_version)

        return artifacts

    def _parse_csv_file(self, csv_path: Path, evidence_id: str, tool_version: Optional[str] = None) -> list[Artifact]:
        if tool_version is None:
            tool_version = get_tool_version("sbecmd")

        artifacts: list[Artifact] = []
        with csv_path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if row:
                    artifacts.append(self._record_to_artifact(dict(row), evidence_id, tool_version, str(csv_path)))
        return artifacts

    def _parse_json_file(self, json_path: Path, evidence_id: str, tool_version: Optional[str] = None) -> list[Artifact]:
        if tool_version is None:
            tool_version = get_tool_version("sbecmd")

        artifacts: list[Artifact] = []
        with json_path.open(encoding="utf-8", errors="replace") as fh:
            content = fh.read().strip()
            if not content:
                return artifacts

            if content.startswith("["):
                try:
                    records = json.loads(content)
                    if isinstance(records, list):
                        for rec in records:
                            if isinstance(rec, dict):
                                artifacts.append(self._record_to_artifact(rec, evidence_id, tool_version, str(json_path)))
                        return artifacts
                except json.JSONDecodeError:
                    pass

            # JSONL fallback
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        rec = json.loads(line)
                        if isinstance(rec, dict):
                            artifacts.append(self._record_to_artifact(rec, evidence_id, tool_version, str(json_path)))
                    except json.JSONDecodeError:
                        continue

        return artifacts

    def _record_to_artifact(self, record: dict[str, Any], evidence_id: str, tool_version: str, file_path: str = "") -> Artifact:
        # Extract folder path / value
        abs_path = (
            record.get("AbsolutePath")
            or record.get("Path")
            or record.get("Value")
            or record.get("ValueName")
            or ""
        )

        folder_name = ""
        if abs_path:
            folder_name = ntpath.basename(abs_path.rstrip("\\/"))

        # Extract timestamps
        ts_val = (
            record.get("LastInteracted")
            or record.get("Accessed")
            or record.get("AccessedOn")
            or record.get("Modified")
            or record.get("ModifiedOn")
            or record.get("Created")
            or record.get("CreatedOn")
            or record.get("FirstInteracted")
        )

        dt = self._parse_timestamp(ts_val)

        # Assign timestamp_type: accessed/modified/created (NEVER executed)
        ts_type = "accessed"
        if record.get("LastInteracted") or record.get("Accessed") or record.get("AccessedOn") or record.get("FirstInteracted"):
            ts_type = "accessed"
        elif record.get("Modified") or record.get("ModifiedOn"):
            ts_type = "modified"
        elif record.get("Created") or record.get("CreatedOn"):
            ts_type = "created"

        # User extraction if present in record or path
        user_name = record.get("User") or record.get("Username") or record.get("Account") or None
        if not user_name and abs_path and "Users\\" in abs_path:
            try:
                parts = abs_path.split("Users\\")[1].split("\\")
                if parts:
                    user_name = parts[0]
            except Exception:
                pass

        raw_payload = dict(record)
        raw_payload["tool_version"] = tool_version

        normalized = NormalizedFields(
            file_name=folder_name or None,
            file_path=abs_path or None,
            user=user_name,
            rule_name="shellbags_sbecmd",
        )

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="sbecmd",
            artifact_type="shellbags",
            timestamp=dt,
            timestamp_type=ts_type,
            raw_fields=raw_payload,
            normalized_fields=normalized,
            parser_version=tool_version,
            confidence_score=1.0,
        )

    def _parse_timestamp(self, ts_str: Optional[Any]) -> Optional[datetime]:
        if not ts_str:
            return None
        if isinstance(ts_str, datetime):
            if ts_str.tzinfo is None:
                return ts_str.replace(tzinfo=timezone.utc)
            return ts_str

        ts_str = str(ts_str).strip()
        if not ts_str:
            return None

        # Common format cleanups
        ts_clean = ts_str.replace("Z", "+00:00")
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
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
