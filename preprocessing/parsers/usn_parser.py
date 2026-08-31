"""
UsnLogFileParser
================
Source 19: USN Journal / $LogFile ($UsnJrnl:$J, $LogFile)
Source Tool: "mftecmd_usn"
Artifact Types Produced: "usn_journal", "logfile"
Raw Output Format: JSON / JSONL / CSV output from Eric Zimmerman's MFTECmd

MFTECmd Reference:
  https://github.com/EricZimmerman/MFTECmd
  CLI: MFTECmd.exe -f <$UsnJrnl:$J> --json <tmp_dir> --jsonf output.json

Extracts NTFS USN Journal change reason flags (DATA_OVERWRITE, FILE_CREATE,
FILE_DELETE, RENAME_OLD_NAME, RENAME_NEW_NAME, etc.), file reference numbers,
parent reference numbers, timestamps, and $LogFile transactional records.
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

class UsnLogFileParserNotFoundError(FileNotFoundError):
    """Raised when the `MFTECmd` binary cannot be found on PATH."""


class UsnLogFileParserExecutionError(RuntimeError):
    """Raised when MFTECmd fails or exits with a non-zero exit code during USN/LogFile parsing."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class UsnLogFileParser:
    """Parses $UsnJrnl:$J and $LogFile evidence via Eric Zimmerman's MFTECmd."""

    _BINARIES: tuple[str, ...] = ("MFTECmd.exe", "MFTECmd", "mftecmd")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse $UsnJrnl:$J or $LogFile evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"USN/$LogFile file not found: {file_path}")

        binary = self._find_binary()
        self._tool_version = get_tool_version("mftecmd")

        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_usn_"))
        try:
            output_file = tmp_dir / "out.json"
            self._run_mftecmd(binary, src, tmp_dir, output_file)
            artifacts = self._parse_output(tmp_dir, output_file, evidence_id, src.name)
            logger.info("UsnLogFileParser total: %d raw artifacts from %s", len(artifacts), src.name)
            return artifacts
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _find_binary(self) -> str:
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise UsnLogFileParserNotFoundError(
            f"MFTECmd binary not found on PATH. Tried: {', '.join(self._BINARIES)}."
        )

    def _run_mftecmd(self, binary: str, evidence_path: Path, tmp_dir: Path, output_json: Path) -> None:
        cmd = [
            binary,
            "-f", str(evidence_path),
            "--json", str(tmp_dir),
            "--jsonf", output_json.name,
        ]
        logger.debug("Running MFTECmd for USN/$LogFile: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            raise UsnLogFileParserNotFoundError(f"MFTECmd binary {binary} disappeared from PATH mid-run.")
        except (subprocess.TimeoutExpired, TimeoutError):
            raise UsnLogFileParserExecutionError(
                f"MFTECmd execution timed out after {self.timeout_seconds} seconds on file {evidence_path.name}"
            )

        if result.returncode != 0:
            raise UsnLogFileParserExecutionError(
                f"MFTECmd exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )

    def _parse_output(self, tmp_dir: Path, json_file: Path, evidence_id: str, src_filename: str) -> list[Artifact]:
        artifacts: list[Artifact] = []

        target_file = json_file
        if not target_file.exists():
            matches = list(tmp_dir.glob("*.json")) + list(tmp_dir.glob("*.jsonl"))
            if matches:
                target_file = matches[0]

        if target_file.exists():
            artifacts = self._parse_json_file(target_file, evidence_id, src_filename)
        else:
            csv_matches = list(tmp_dir.glob("*.csv"))
            if csv_matches:
                artifacts = self._parse_csv_file(csv_matches[0], evidence_id, src_filename)

        return artifacts

    def _parse_json_file(self, json_path: Path, evidence_id: str, src_filename: str) -> list[Artifact]:
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
                                artifacts.append(self._record_to_artifact(rec, evidence_id, src_filename))
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
                        artifacts.append(self._record_to_artifact(rec, evidence_id, src_filename))
                except json.JSONDecodeError as exc:
                    logger.warning("Skipping malformed MFTECmd USN line %d: %s", lineno, exc)

        return artifacts

    def _parse_csv_file(self, csv_path: Path, evidence_id: str, src_filename: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        with csv_path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if not row:
                    continue
                artifacts.append(self._record_to_artifact(row, evidence_id, src_filename))
        return artifacts

    def _record_to_artifact(self, record: dict, evidence_id: str, src_filename: str) -> Artifact:
        fn = record.get("Name") or record.get("FileName") or ""
        fp = record.get("FullPath") or record.get("FilePath") or fn
        reasons = record.get("UpdateReason") or record.get("Reason") or record.get("ReasonFlags") or ""
        file_ref = record.get("FileReferenceNumber") or record.get("EntryNumber") or ""
        parent_ref = record.get("ParentFileReferenceNumber") or record.get("ParentEntryNumber") or ""

        is_logfile = "logfile" in src_filename.lower()
        art_type = "logfile" if is_logfile else "usn_journal"

        summary = f"{'LogFile' if is_logfile else 'USN Journal'} record for {fn or os.path.basename(fp) or 'file'}"
        if reasons:
            summary += f" ({reasons})"

        raw_ts = record.get("Timestamp") or record.get("TimeStamp") or record.get("UpdateTimestamp")
        dt = self._parse_timestamp(raw_ts)

        ver = getattr(self, "_tool_version", get_tool_version("mftecmd"))
        raw_fields = {**record, "tool_version": ver}

        norm = NormalizedFields(
            file_name=fn or (os.path.basename(fp) if fp else None),
            file_path=fp or None,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="mftecmd_usn",
            artifact_type=art_type,
            timestamp=dt,
            timestamp_type="event",
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
