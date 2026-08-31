"""
AmcacheParser
=============
Source 16: Amcache (Amcache.hve)
Source Tool: "amcacheparser"
Artifact Types Produced: "amcache"
Raw Output Format: JSON / JSONL / CSV output from Eric Zimmerman's AmcacheParser

AmcacheParser Reference:
  https://github.com/EricZimmerman/AmcacheParser
  CLI: AmcacheParser.exe -f <Amcache.hve> --json <tmp_dir> --jsonf output.json

Extracts application presence, executable metadata, file hashes (SHA1), publishers,
file size, and install/first-seen timestamps.
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

class AmcacheParserNotFoundError(FileNotFoundError):
    """Raised when the `AmcacheParser` binary cannot be found on PATH."""


class AmcacheParserExecutionError(RuntimeError):
    """Raised when AmcacheParser exits with a non-zero return code or fails."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class AmcacheParser:
    """Parses Amcache.hve hive files via Eric Zimmerman's AmcacheParser."""

    _BINARIES: tuple[str, ...] = ("AmcacheParser.exe", "AmcacheParser", "amcacheparser")

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse Amcache.hve evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Amcache file not found: {file_path}")

        binary = self._find_binary()
        self._tool_version = get_tool_version("amcacheparser")

        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_amcache_"))
        try:
            output_file = tmp_dir / "out.json"
            self._run_amcacheparser(binary, src, tmp_dir, output_file)
            artifacts = self._parse_output(tmp_dir, output_file, evidence_id)
            logger.info("AmcacheParser total: %d raw artifacts from %s", len(artifacts), src.name)
            return artifacts
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _find_binary(self) -> str:
        for candidate in self._BINARIES:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        raise AmcacheParserNotFoundError(
            f"AmcacheParser binary not found on PATH. Tried: {', '.join(self._BINARIES)}."
        )

    def _run_amcacheparser(self, binary: str, hive_path: Path, tmp_dir: Path, output_json: Path) -> None:
        cmd = [
            binary,
            "-f", str(hive_path),
            "--json", str(tmp_dir),
            "--jsonf", output_json.name,
        ]
        logger.debug("Running AmcacheParser: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            raise AmcacheParserNotFoundError(f"AmcacheParser binary {binary} disappeared from PATH mid-run.")
        except (subprocess.TimeoutExpired, TimeoutError):
            raise AmcacheParserExecutionError(
                f"AmcacheParser execution timed out after {self.timeout_seconds} seconds on file {hive_path.name}"
            )

        if result.returncode != 0:
            raise AmcacheParserExecutionError(
                f"AmcacheParser exited with code {result.returncode}.\n"
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
                    logger.warning("Skipping malformed AmcacheParser line %d: %s", lineno, exc)

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
        fn = record.get("Name") or record.get("FileName") or record.get("ApplicationName") or ""
        fp = record.get("FullPath") or record.get("FilePath") or record.get("Path") or fn
        file_hash = record.get("SHA1") or record.get("FileSHA1") or record.get("Hash") or ""
        publisher = record.get("Publisher") or record.get("CompanyName") or ""
        product = record.get("ProductName") or ""
        version = record.get("Version") or record.get("FileVersion") or ""

        summary = f"Amcache record for {fn or os.path.basename(fp) or 'file'}"
        if publisher:
            summary += f" ({publisher})"

        first_seen = record.get("FirstSeen") or record.get("InstallDate") or record.get("LinkDate") or record.get("FileKeyLastWrite")
        dt = self._parse_timestamp(first_seen)
        ts_type = "first_seen" if record.get("FirstSeen") else ("created" if record.get("InstallDate") else "modified")

        ver = getattr(self, "_tool_version", get_tool_version("amcacheparser"))
        raw_fields = {**record, "tool_version": ver}

        norm = NormalizedFields(
            process_name=fn or (os.path.basename(fp) if fp else None),
            file_name=fn or (os.path.basename(fp) if fp else None),
            file_path=fp or None,
            hash=file_hash or None,
        )

        return Artifact(
            evidence_id=evidence_id,
            source_tool="amcacheparser",
            artifact_type="amcache",
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
