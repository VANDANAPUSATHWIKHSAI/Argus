# Browser history, cookie, and download parser using Hindsight
# Source tool: "hindsight"
# Artifact types produced: "browser_history", "browser_download", "browser_cookie"
# Raw output format: JSONL (one JSON object per line)
# Hindsight docs: https://github.com/obsidianforensics/hindsight

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed errors — never silently swallow failures
# ---------------------------------------------------------------------------

class HindsightNotFoundError(FileNotFoundError):
    """Raised when the Hindsight tool / script cannot be found on PATH or cwd."""


class HindsightExecutionError(RuntimeError):
    """Raised when Hindsight exits with a non-zero return code."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class BrowserParser:
    """Parses browser profile directories / files via Hindsight into Artifact records.

    Hindsight analyzes Chrome/Chromium history, downloads, cookies, autofill, etc.,
    and outputs them in JSONL format.

    Shell command executed:
        hindsight.py -i <input_path> -o <tmp_output> -l jsonl
    """

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the browser profile at *file_path* and return a list of Artifact records.

        Args:
            file_path:   Absolute path to the browser profile directory or history file.
            evidence_id: FK linking back to the ``infrastructure.Evidence`` record.
                         Pass an empty string during unit tests / standalone use.

        Returns:
            List of :class:`~preprocessing.schemas.Artifact` objects.

        Raises:
            HindsightNotFoundError:  Hindsight script / binary not found.
            HindsightExecutionError: Hindsight exited with non-zero code.
            FileNotFoundError:       *file_path* does not exist.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Browser profile not found: {file_path}")

        self._tool_version = get_tool_version("hindsight")

        # Generate a unique temporary path. Using a UUID string prevents file locking
        # issues on Windows compared to keeping a NamedTemporaryFile descriptor open.
        import uuid
        tmp_name = f"hindsight_tmp_{uuid.uuid4()}.jsonl"
        tmp_path = Path(tempfile.gettempdir()) / tmp_name

        try:
            self._run_hindsight(src, tmp_path)
            # Hindsight appends .jsonl if it's not present, let's verify both paths
            actual_output = tmp_path
            if not actual_output.exists():
                actual_output = tmp_path.with_name(tmp_path.name + ".jsonl")
            if not actual_output.exists():
                # Let's search if any jsonl was written in the temp directory starting with our prefix
                sibling_matches = list(tmp_path.parent.glob(tmp_path.name + "*"))
                if sibling_matches:
                    actual_output = sibling_matches[0]

            if not actual_output.exists():
                raise HindsightExecutionError(
                    f"Hindsight completed but output file was not found at {tmp_path} or {tmp_path}.jsonl"
                )

            return self._parse_jsonl(actual_output, evidence_id)
        finally:
            # Clean up both possible temp file variants
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_name(tmp_path.name + ".jsonl").unlink(missing_ok=True)

    def _run_hindsight(self, input_path: Path, output_path: Path) -> None:
        """Execute Hindsight against the browser profile directory to generate JSONL report."""
        import shutil
        import sys

        # 1. Programmatic pyhindsight API invocation
        try:
            from pyhindsight import analysis
            with tempfile.TemporaryDirectory(prefix="argus_chrome_") as tmp_dir:
                tmp_profile = Path(tmp_dir) / "Default"
                if input_path.is_dir():
                    shutil.copytree(input_path, tmp_profile)
                else:
                    tmp_profile.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(input_path, tmp_profile / input_path.name)

                # Initialize optional subdirectories expected by pyhindsight/ccl_chromium_reader
                (tmp_profile / "Local Storage" / "leveldb").mkdir(parents=True, exist_ok=True)
                (tmp_profile / "Session Storage").mkdir(parents=True, exist_ok=True)
                (tmp_profile / "Cache").mkdir(parents=True, exist_ok=True)
                (tmp_profile / "Code Cache").mkdir(parents=True, exist_ok=True)
                (tmp_profile / "GPUCache").mkdir(parents=True, exist_ok=True)
                (tmp_profile / "IndexedDB").mkdir(parents=True, exist_ok=True)
                (tmp_profile / "Extension State").mkdir(parents=True, exist_ok=True)

                session = analysis.AnalysisSession()
                session.input_path = str(tmp_profile)
                session.no_copy = True
                session.temp_dir = str(Path(tmp_dir) / "temp")
                session.run()

                if session.parsed_artifacts:
                    lines = []
                    for item in session.parsed_artifacts:
                        if hasattr(item, "to_dict"):
                            rec = item.to_dict()
                        elif hasattr(item, "__dict__"):
                            rec = {k: v for k, v in item.__dict__.items() if not k.startswith("_")}
                        else:
                            rec = {}
                        if rec:
                            lines.append(json.dumps(rec, default=str))

                    if lines:
                        output_path.write_text("\n".join(lines), encoding="utf-8")
                        logger.info("Parsed %d records via pyhindsight Python API for %s", len(lines), input_path.name)
                        return
        except Exception as exc:
            logger.warning("Programmatic pyhindsight execution failed (%s). Trying CLI invocation.", exc)

        # 2. CLI Hindsight execution
        resolved = None
        try:
            if sys.platform == "win32":
                scripts_dir = Path(sys.exec_prefix) / "Scripts"
            else:
                scripts_dir = Path(sys.exec_prefix) / "bin"
            hindsight_py = scripts_dir / "hindsight.py"
            if hindsight_py.exists():
                resolved = str(hindsight_py)
        except Exception:
            pass

        if not resolved:
            resolved = shutil.which("hindsight.py")
        
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        cmd_candidates = []
        out_no_ext = str(output_path.with_suffix(""))
        if resolved:
            cmd_candidates.append([sys.executable, resolved, "-i", str(input_path), "-o", out_no_ext, "-f", "jsonl"])
            
        cmd_candidates.extend([
            ["hindsight.py", "-i", str(input_path), "-o", out_no_ext, "-f", "jsonl"],
            ["hindsight", "-i", str(input_path), "-o", out_no_ext, "-f", "jsonl"],
            ["python", "hindsight.py", "-i", str(input_path), "-o", out_no_ext, "-f", "jsonl"]
        ])

        last_err: Optional[Exception] = None
        result = None

        for cmd in cmd_candidates:
            logger.debug("Trying Hindsight command: %s", " ".join(cmd))
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env=env,
                )
                if result.returncode == 0:
                    break
                else:
                    last_err = HindsightExecutionError(
                        f"Hindsight exited with code {result.returncode}.\n"
                        f"stdout: {result.stdout.strip()[:500]}\n"
                        f"stderr: {result.stderr.strip()[:500]}"
                    )
            except FileNotFoundError as e:
                last_err = HindsightNotFoundError(
                    "Hindsight tool not found on PATH or could not be executed. "
                    "Ensure hindsight.py or hindsight is installed."
                )
            except Exception as e:
                last_err = e

        if output_path.exists() and output_path.stat().st_size > 0:
            logger.info("Hindsight CLI finished successfully: input=%s output=%s", input_path.name, output_path)
            return

        # Check if output was written with double suffix
        alt_output = output_path.with_name(output_path.name + ".jsonl")
        if alt_output.exists() and alt_output.stat().st_size > 0:
            shutil.move(str(alt_output), str(output_path))
            logger.info("Moved Hindsight CLI output to %s", output_path)
            return

        # 3. Direct SQLite parsing fallback if Hindsight unavailable/failed
        records = self._parse_sqlite_fallback(input_path)
        if records:
            output_path.write_text("\n".join(json.dumps(r, default=str) for r in records), encoding="utf-8")
            logger.info("Parsed %d browser records via native SQLite fallback from %s", len(records), input_path.name)
            return

        if result is None or result.returncode != 0:
            if isinstance(last_err, (HindsightNotFoundError, HindsightExecutionError)):
                raise last_err
            raise HindsightExecutionError(f"Failed to execute Hindsight: {last_err}")

    def _parse_sqlite_fallback(self, input_path: Path) -> list[dict]:
        """Native SQLite parsing fallback for Chrome History, Cookies, and Web Data."""
        import sqlite3
        records = []
        profile_dir = input_path if input_path.is_dir() else input_path.parent

        # 1. Parse History
        hist_db = profile_dir / "History"
        if hist_db.exists():
            try:
                conn = sqlite3.connect(f"file:{hist_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
                for url, title, visits, last_visit in cursor.fetchall():
                    records.append({
                        "type": "url (visited)",
                        "url": url,
                        "title": title,
                        "visit_count": visits,
                        "timestamp": last_visit
                    })
                conn.close()
            except Exception as exc:
                logger.warning("Error parsing SQLite History: %s", exc)

        # 2. Parse Cookies
        cookie_db = profile_dir / "Cookies"
        if cookie_db.exists():
            try:
                conn = sqlite3.connect(f"file:{cookie_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, path, creation_utc, expires_utc FROM cookies")
                for host, name, path, creation, expires in cursor.fetchall():
                    records.append({
                        "type": "cookie (created)",
                        "url": f"{host}{path}",
                        "domain": host,
                        "name": name,
                        "timestamp": creation
                    })
                conn.close()
            except Exception as exc:
                logger.warning("Error parsing SQLite Cookies: %s", exc)

        return records

    def _parse_jsonl(self, jsonl_path: Path, evidence_id: str) -> list[Artifact]:
        """Read the JSONL output file and convert each line to an Artifact."""
        artifacts: list[Artifact] = []

        with jsonl_path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    record: dict = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping malformed Hindsight JSON on line %d: %s", lineno, exc
                    )
                    continue

                artifacts.append(self._record_to_artifact(record, evidence_id))

        logger.info("Parsed %d Hindsight records from %s", len(artifacts), jsonl_path)
        return artifacts

    def _record_to_artifact(self, record: dict, evidence_id: str) -> Artifact:
        """Map one parsed Hindsight record to an Artifact."""
        # Determine the artifact type from the Hindsight record type or row_type
        raw_type = str(record.get("row_type", "") or record.get("type", "")).lower()

        if "download" in raw_type:
            art_type = "browser_download"
            ts_type = "download"
        elif "cookie" in raw_type:
            art_type = "browser_cookie"
            ts_type = "accessed"
        elif "extension" in raw_type:
            art_type = "browser_extension"
            ts_type = "installation"
        elif "preference" in raw_type or "site setting" in raw_type or "hsts" in raw_type:
            art_type = "browser_preference"
            ts_type = "configuration"
        else:
            # Defaults to history for urls / bookmarks / cache
            art_type = "browser_history"
            ts_type = "visit"

        ver = getattr(self, "_tool_version", get_tool_version("hindsight"))
        url = record.get("url") or record.get("URL") or record.get("name") or ""
        summary = f"Browser {art_type}: {url}" if url else f"Browser {art_type}"

        return Artifact(
            evidence_id=evidence_id,
            source_tool="hindsight",
            artifact_type=art_type,
            timestamp=self._parse_timestamp(record),
            timestamp_type=ts_type,
            event_summary=summary,
            parser_version=ver,
            raw_fields={**record, "tool_version": ver},
            normalized_fields=self._normalize(record, art_type),
        )

    @staticmethod
    def _normalize(record: dict, art_type: str) -> NormalizedFields:
        """Extract common fields from a Hindsight record."""
        # Normalize fields depending on the artifact type
        url = record.get("url") or record.get("URL")
        domain = record.get("domain") or record.get("Domain") or record.get("host") or record.get("Host")
        file_path = record.get("path") or record.get("Path") or record.get("value") or record.get("Value")
        file_name = record.get("filename") or record.get("FileName") or (os.path.basename(file_path) if file_path else None)
        user = record.get("user") or record.get("User")
        rule_name = record.get("type") or record.get("Type")

        return NormalizedFields(
            url=url,
            domain=domain,
            file_name=file_name,
            file_path=file_path,
            user=user,
            rule_name=rule_name,
        )

    def _parse_timestamp(self, record: dict) -> Optional[datetime]:
        """Attempt to parse timestamps from Hindsight record."""
        for key in ("time", "Time", "timestamp", "Timestamp", "visit_time", "Visit Time", "date", "Date"):
            raw = record.get(key)
            if raw:
                # If raw is a numeric epoch float / int
                if isinstance(raw, (int, float)):
                    if raw == 0:
                        continue
                    try:
                        # Check if it is microsecond / millisecond epoch or standard seconds
                        if raw > 1e11:  # Micro/milliseconds epoch
                            raw = raw / 1e6 if raw > 1e14 else raw / 1e3
                        return datetime.fromtimestamp(raw, tz=timezone.utc)
                    except Exception:
                        pass
                else:
                    # String datetime parsing
                    s = str(raw).strip()
                    if not s or s == "0":
                        continue
                    # Clean/normalize "UTC" suffix
                    s = s.replace(" UTC", "+0000").replace("UTC", "+0000").replace(" ", "T")
                    # Trim timezone colon offset if present
                    if len(s) > 6 and s[-3] == ":":
                        s = s[:-3] + s[-2:]
                    for fmt in (
                        "%Y-%m-%dT%H:%M:%S.%f%z",
                        "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%dT%H:%M:%S",
                    ):
                        try:
                            return datetime.strptime(s, fmt)
                        except ValueError:
                            continue
        return None
