"""
RBCmd Recycle Bin Parser
========================
Source 15: Recycle Bin ($I / $R artifacts)
Source Tool: "rbcmd"
Artifact Types Produced: "recycle_bin"
Raw Output Format: JSON / JSONL / CSV output from Eric Zimmerman's RBCmd

RBCmd Reference:
  https://github.com/EricZimmerman/RBCmd
  CLI: RBCmd.exe -f <rb_path> --json <tmp_dir> --jsonf output.json
"""

from __future__ import annotations

import csv
import json
import logging
import os
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

class RbcmdNotFoundError(FileNotFoundError):
    """Raised when the `RBCmd` binary cannot be found on PATH."""


class RbcmdExecutionError(RuntimeError):
    """Raised when RBCmd exits with a non-zero return code or fails."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class RbcmdRecycleBinParser:
    """Parses Windows Recycle Bin ($I / $R) files via RBCmd into Artifact records."""

    _BINARIES: tuple[str, ...] = ("RBCmd.exe", "RBCmd", "rbcmd")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse a Recycle Bin artifact file via RBCmd and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Recycle Bin file not found: {file_path}")

        binary = self._find_binary()
        self._tool_version = get_tool_version("rbcmd")

        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_rbcmd_"))
        try:
            output_file = tmp_dir / "out.json"
            self._run_rbcmd(binary, src, tmp_dir, output_file)
            artifacts = self._parse_output(tmp_dir, output_file, evidence_id)
            logger.info("RbcmdRecycleBinParser total: %d raw artifacts from %s", len(artifacts), src.name)
            return artifacts
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _find_binary(self) -> str:
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise RbcmdNotFoundError(
            f"RBCmd binary not found on PATH. Tried: {', '.join(self._BINARIES)}."
        )

    def _run_rbcmd(self, binary: str, rb_path: Path, tmp_dir: Path, output_json: Path) -> None:
        cmd = [
            binary,
            "-f", str(rb_path),
            "--json", str(tmp_dir),
            "--jsonf", output_json.name,
        ]
        logger.debug("Running RBCmd: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            raise RbcmdNotFoundError(f"RBCmd binary {binary} disappeared from PATH mid-run.")
        except subprocess.TimeoutExpired:
            raise RbcmdExecutionError(
                f"RBCmd execution timed out after {self.timeout_seconds} seconds on file {rb_path.name}"
            )

        if result.returncode != 0:
            raise RbcmdExecutionError(
                f"RBCmd exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )

    def _parse_output(self, tmp_dir: Path, json_file: Path, evidence_id: str) -> list[Artifact]:
        artifacts: list[Artifact] = []

        target_file = json_file
        if not target_file.exists():
            matches = list(tmp_dir.glob("*.json")) + list(tmp_dir.glob("*.jsonl"))
            if matches:
                target_file = matches[0]

        if target_file.exists():
            artifacts = self._parse_json_file(target_file, evidence_id)
        else:
            csv_matches = list(tmp_dir.glob("*.csv"))
            if csv_matches:
                artifacts = self._parse_csv_file(csv_matches[0], evidence_id)

        return artifacts

    def _parse_json_file(self, json_path: Path, evidence_id: str) -> list[Artifact]:
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
                                artifacts.append(self._record_to_artifact(rec, evidence_id))
                        return artifacts
                except json.JSONDecodeError:
                    pass

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
                    logger.warning("Skipping malformed RBCmd line %d: %s", lineno, exc)

        return artifacts

    def _parse_csv_file(self, csv_path: Path, evidence_id: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        with csv_path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if not row:
                    continue
                artifacts.append(self._record_to_artifact(row, evidence_id))
        return artifacts

    def _record_to_artifact(self, record: dict, evidence_id: str) -> Artifact:
        orig_path = record.get("FilePath") or record.get("FileName") or record.get("OriginalFileName") or ""
        orig_name = os.path.basename(orig_path) if orig_path else (record.get("FileName") or "")
        file_size = self._parse_int(record.get("FileSize") or record.get("Size"))
        deleted_on = record.get("DeletedOn") or record.get("DeletionTimestamp") or record.get("Deleted")

        summary = f"Recycle Bin deleted file: {orig_path or 'unknown path'} (size: {file_size if file_size is not None else 'N/A'} bytes)"

        dt = self._parse_timestamp(deleted_on)
        ver = getattr(self, "_tool_version", get_tool_version("rbcmd"))

        raw_fields = {**record, "tool_version": ver}

        norm = NormalizedFields(
            file_name=orig_name or None,
            file_path=orig_path or None,
            deleted=True,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="rbcmd",
            artifact_type="recycle_bin",
            timestamp=dt,
            timestamp_type="deleted",
            event_summary=summary,
            parser_version=ver,
            raw_fields=raw_fields,
            normalized_fields=norm,
        )

    @staticmethod
    def _parse_timestamp(val: Any) -> Optional[datetime]:
        if not val:
            return None
        if isinstance(val, (int, float)):
            try:
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

    @staticmethod
    def _parse_int(val: Any) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(str(val).strip(), 0)
        except (ValueError, TypeError):
            return None
