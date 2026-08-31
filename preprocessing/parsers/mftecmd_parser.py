"""
MFTECmd MFT Parser
==================
Source 11: MFT / NTFS
Source Tool: "mftecmd"
Artifact Types Produced: "mft_entry"
Raw Output Format: JSON / JSONL / CSV output from Eric Zimmerman's MFTECmd

MFTECmd Reference:
  https://github.com/EricZimmerman/MFTECmd
  CLI: MFTECmd.exe -f <mft_path> --json <tmp_dir> --jsonf output.json

Preserves complete raw MFT records including $STANDARD_INFORMATION (0x10) and
$FILE_NAME (0x30) timestamp structures, sequence numbers, parent records,
allocation status, and file size.
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

class MfteCmdNotFoundError(FileNotFoundError):
    """Raised when the `MFTECmd` binary cannot be found on PATH."""


class MfteCmdExecutionError(RuntimeError):
    """Raised when MFTECmd exits with a non-zero return code or fails."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class MfteCmdMftParser:
    """Parses $MFT files via MFTECmd into Artifact records."""

    _BINARIES: tuple[str, ...] = ("MFTECmd.exe", "MFTECmd", "mftecmd")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse $MFT evidence at *file_path* via MFTECmd and return Artifact records.

        Args:
            file_path:   Absolute path to the $MFT file.
            evidence_id: FK linking back to infrastructure.Evidence.evidence_id.

        Returns:
            List of Artifact records (source_tool="mftecmd", artifact_type="mft_entry").
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"MFT evidence file not found: {file_path}")

        binary = self._find_binary()
        self._tool_version = get_tool_version("mftecmd")

        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_mftecmd_"))
        try:
            output_file = tmp_dir / "out.json"
            self._run_mftecmd(binary, src, tmp_dir, output_file)
            artifacts = self._parse_output(tmp_dir, output_file, evidence_id)
            logger.info("MfteCmdMftParser total: %d raw artifacts from %s", len(artifacts), src.name)
            return artifacts
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _find_binary(self) -> str:
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise MfteCmdNotFoundError(
            f"MFTECmd binary not found on PATH. Tried: {', '.join(self._BINARIES)}."
        )

    def _run_mftecmd(self, binary: str, mft_path: Path, tmp_dir: Path, output_json: Path) -> None:
        cmd = [
            binary,
            "-f", str(mft_path),
            "--json", str(tmp_dir),
            "--jsonf", output_json.name,
        ]
        logger.debug("Running MFTECmd: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            raise MfteCmdNotFoundError(f"MFTECmd binary {binary} disappeared from PATH mid-run.")
        except subprocess.TimeoutExpired:
            raise MfteCmdExecutionError(
                f"MFTECmd execution timed out after {self.timeout_seconds} seconds on file {mft_path.name}"
            )

        if result.returncode != 0:
            raise MfteCmdExecutionError(
                f"MFTECmd exited with code {result.returncode}.\n"
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
                    logger.warning("Skipping malformed MFTECmd line %d: %s", lineno, exc)

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
        fn = record.get("FileName") or record.get("Name") or ""
        fp = record.get("FilePath") or record.get("EntryName") or fn
        rec_num = record.get("RecordNumber") or record.get("EntryNumber")
        in_use = record.get("InUse")
        if in_use is None:
            in_use = record.get("IsAllocated", True)

        is_deleted = not bool(in_use) if isinstance(in_use, bool) else (str(in_use).lower() in ("false", "0"))
        status_str = "Deleted/Unallocated" if is_deleted else "Allocated/Active"

        summary = f"MFT Record #{rec_num or 'N/A'}: {fp} ({status_str})"

        # Timestamps: SI (0x10) vs FN (0x30)
        si_mod = record.get("LastModified0x10") or record.get("LastModified") or record.get("Modified0x10")
        si_cr = record.get("Created0x10") or record.get("Created")
        fn_mod = record.get("LastModified0x30") or record.get("FileNameLastModified")

        ts_raw = si_mod or si_cr or fn_mod
        dt = self._parse_timestamp(ts_raw)
        ts_type = "modified" if si_mod else ("created" if si_cr else "modified")

        ver = getattr(self, "_tool_version", get_tool_version("mftecmd"))

        raw_fields = {**record, "tool_version": ver}

        norm = NormalizedFields(
            file_name=fn or None,
            file_path=fp or None,
            deleted=is_deleted,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="mftecmd",
            artifact_type="mft_entry",
            timestamp=dt,
            timestamp_type=ts_type,
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
