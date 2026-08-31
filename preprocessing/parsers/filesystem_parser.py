# File system / disk image parser using The Sleuth Kit (TSK)
# Source tool: "tsk"
# Artifact types produced: "file_record"
# Raw output format: Bodyfile (pipe-delimited TSV/timeline)
# TSK reference: https://wiki.sleuthkit.org/index.php?title=Body_File

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed errors
# ---------------------------------------------------------------------------

class TSKNotFoundError(FileNotFoundError):
    """Raised when Sleuth Kit binaries (fls/istat) cannot be found on PATH."""


class TSKExecutionError(RuntimeError):
    """Raised when fls or istat exits with a non-zero return code."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class FilesystemParser:
    """Parses filesystem / disk images via Sleuth Kit tools fls and istat.

    Shells out to `fls -r -m / <image>` to generate a bodyfile containing a full
    recursive timeline of metadata. If a file is deleted (flagged), runs `istat`
    to gather specific low-level block allocation and metadata information.
    """

    # Binary candidates for fls and istat
    _FLS_BINARIES = ("fls", "fls.exe")
    _ISTAT_BINARIES = ("istat", "istat.exe")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the filesystem image at *file_path* and return a list of Artifact records.

        Args:
            file_path:   Absolute path to the filesystem image file (.e01, .dd, .img, .iso).
            evidence_id: FK linking back to the ``infrastructure.Evidence`` record.

        Returns:
            List of :class:`~preprocessing.schemas.Artifact` objects (artifact_type="file_record").

        Raises:
            TSKNotFoundError:   TSK fls/istat binaries not found.
            TSKExecutionError:  TSK fls command execution failed.
            FileNotFoundError:  *file_path* does not exist.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Filesystem image not found: {file_path}")

        self._tool_version = get_tool_version("tsk")

        fls_bin = self._find_binary(self._FLS_BINARIES, "fls")
        istat_bin = self._find_binary(self._ISTAT_BINARIES, "istat")

        # ── 1. Run fls to generate bodyfile ────────────────────────────────
        bodyfile_stdout = self._run_fls(fls_bin, src)

        # ── 2. Parse bodyfile lines ────────────────────────────────────────
        artifacts: list[Artifact] = []

        for lineno, line in enumerate(bodyfile_stdout.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue

            parts = line.split("|")
            if len(parts) < 11:
                logger.warning("Skipping malformed fls line %d: %r", lineno, line)
                continue

            # Standard bodyfile format:
            # MD5 | name | inode | mode_as_string | UID | GID | size | atime | mtime | ctime | crtime
            md5_val = parts[0]
            name = parts[1]
            inode = parts[2]
            mode = parts[3]
            uid = parts[4]
            gid = parts[5]
            size_val = parts[6]
            atime_raw = parts[7]
            mtime_raw = parts[8]
            ctime_raw = parts[9]
            crtime_raw = parts[10]

            # Determine if deleted (indicated by * in inode, * in mode, or (deleted) in name)
            deleted = "*" in inode or "*" in mode or "(deleted)" in name.lower()
            clean_inode = inode.replace("*", "").strip()

            # Retrieve dates
            dt_mtime = _epoch_to_dt(mtime_raw)
            dt_atime = _epoch_to_dt(atime_raw)
            dt_ctime = _epoch_to_dt(ctime_raw)
            dt_crtime = _epoch_to_dt(crtime_raw)

            # Choose main timestamp (mtime -> atime -> crtime -> ctime)
            ts = dt_mtime or dt_atime or dt_crtime or dt_ctime

            # Form raw fields dictionary
            raw_fields = {
                "md5": md5_val,
                "name": name,
                "inode": inode,
                "mode": mode,
                "uid": uid,
                "gid": gid,
                "size_bytes": _safe_int(size_val),
                "atime_epoch": _safe_int(atime_raw),
                "mtime_epoch": _safe_int(mtime_raw),
                "ctime_epoch": _safe_int(ctime_raw),
                "crtime_epoch": _safe_int(crtime_raw),
                "deleted": deleted,
                "istat": None,
            }

            # ── 3. Run istat on flagged (deleted) files ────────────────────
            if deleted and clean_inode and clean_inode.isdigit():
                try:
                    istat_output = self._run_istat(istat_bin, src, clean_inode)
                    raw_fields["istat"] = istat_output
                except Exception as e:
                    logger.warning("Failed to run istat for inode %s: %s", clean_inode, e)

            ver = getattr(self, "_tool_version", get_tool_version("tsk"))
            fname = Path(name).name if name else None
            fhash = md5_val if md5_val and md5_val != "0" and len(md5_val) == 32 else None
            summary = f"File {name} (inode {inode}, {size_val} bytes)" if name else f"File inode {inode}"

            artifacts.append(Artifact(
                evidence_id=evidence_id,
                source_tool="tsk",
                artifact_type="file_record",
                timestamp=ts,
                timestamp_type="modified",
                event_summary=summary,
                parser_version=ver,
                raw_fields={**raw_fields, "tool_version": ver},
                normalized_fields=NormalizedFields(
                    file_path=name,
                    file_name=fname,
                    hash=fhash,
                    mtime=dt_mtime.isoformat() if dt_mtime else None,
                    atime=dt_atime.isoformat() if dt_atime else None,
                    ctime=dt_ctime.isoformat() if dt_ctime else None,
                    deleted=deleted,
                    rule_name="file_record",
                )
            ))

        logger.info("Parsed %d filesystem timeline entries from %s", len(artifacts), src.name)
        return artifacts

    # -----------------------------------------------------------------------
    # Binary detection
    # -----------------------------------------------------------------------

    def _find_binary(self, candidates: tuple[str, ...], name: str) -> str:
        """Find candidate binary on system path or local workspace folder."""
        import shutil
        # Check system PATH first
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved

        # Check local workspace tsk/ folder
        try:
            # Path(__file__).resolve().parents[2] is the argus root directory
            project_root = Path(__file__).resolve().parents[2]
            tsk_dir = project_root / "tsk"
            if tsk_dir.exists():
                for folder in tsk_dir.iterdir():
                    if folder.is_dir() and folder.name.startswith("sleuthkit-"):
                        bin_dir = folder / "bin"
                        if bin_dir.exists():
                            for candidate in candidates:
                                resolved = shutil.which(candidate, path=str(bin_dir))
                                if resolved:
                                    return resolved
        except Exception as e:
            logger.debug("Error checking local tsk workspace directory: %s", e)

        raise TSKNotFoundError(
            f"TSK tool '{name}' not found on PATH and not found in tsk/ folder. "
            f"Tried: {', '.join(candidates)}. "
            f"Install The Sleuth Kit and ensure fls/istat are on PATH."
        )

    # -----------------------------------------------------------------------
    # Execution
    # -----------------------------------------------------------------------

    def _run_fls(self, binary: str, image_path: Path) -> str:
        """Run `fls -r -m / <image>` and return stdout."""
        cmd = [binary, "-r", "-m", "/", str(image_path)]
        logger.debug("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except FileNotFoundError:
            raise TSKNotFoundError(f"TSK binary {binary} disappeared from PATH.")

        if result.returncode != 0:
            raise TSKExecutionError(
                f"TSK fls failed with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:300]}\n"
                f"stderr: {result.stderr.strip()[:300]}"
            )
        return result.stdout

    def _run_istat(self, binary: str, image_path: Path, inode: str) -> str:
        """Run `istat <image> <inode>` and return stdout."""
        cmd = [binary, str(image_path), inode]
        logger.debug("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise TSKExecutionError(f"TSK istat failed with code {result.returncode}: {result.stderr}")
        return result.stdout


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _epoch_to_dt(epoch_str: str) -> Optional[datetime]:
    """Parse Unix epoch string to timezone-aware datetime."""
    try:
        val = int(epoch_str)
        if val <= 0:
            return None
        return datetime.fromtimestamp(val, tz=timezone.utc)
    except Exception:
        return None


def _safe_int(val_str: str) -> Optional[int]:
    """Parse string to int safely."""
    try:
        return int(val_str)
    except Exception:
        return None
