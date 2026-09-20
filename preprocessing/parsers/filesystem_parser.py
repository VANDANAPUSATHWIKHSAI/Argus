# File system / disk image parser using The Sleuth Kit (TSK)
# Source tool: "tsk"
# Artifact types produced: "file_record"
# Raw output format: Bodyfile (pipe-delimited TSV/timeline)
# TSK reference: https://wiki.sleuthkit.org/index.php?title=Body_File

from __future__ import annotations

import re
import shutil
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

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
    """Parses filesystem / disk images via Sleuth Kit tools mmls, fls, and istat.

    Performs dynamic partition discovery via `mmls`, shells out to `fls -o <offset> -r -m / <image>`
    to generate a bodyfile containing a full recursive timeline of metadata for each partition.
    If a file is deleted (flagged), runs `istat` to gather block allocation and inode details.
    """

    # Binary candidates for fls, mmls, and istat
    _FLS_BINARIES = ("fls", "fls.exe")
    _MMLS_BINARIES = ("mmls", "mmls.exe")
    _ISTAT_BINARIES = ("istat", "istat.exe")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the filesystem image at *file_path* and return a list of Artifact records.

        Args:
            file_path:   Absolute path to the filesystem image file (.e01, .dd, .img, .iso, .aff).
            evidence_id: FK linking back to the ``infrastructure.Evidence`` record.

        Returns:
            List of :class:`~preprocessing.schemas.Artifact` objects (artifact_type="file_record").

        Raises:
            TSKNotFoundError:   TSK fls/mmls/istat binaries not found.
            TSKExecutionError:  TSK fls command execution failed across all partitions.
            FileNotFoundError:  *file_path* does not exist.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Filesystem image not found: {file_path}")

        self._tool_version = get_tool_version("tsk")

        # ── Handle Text Case Narrative Files ──────────────────────────────
        if src.suffix.lower() == ".txt" or src.name.lower() == "narrative.txt":
            return self._parse_text_file(src, evidence_id)

        # ── Handle DFXML Forensic XML Catalogs ───────────────────────────
        if src.suffix.lower() == ".xml":
            return self._parse_dfxml_file(src, evidence_id)

        # ── Handle AFF 1.0 Forensic Image Containers ─────────────────────
        if src.suffix.lower() == ".aff":
            from preprocessing.router import check_fls_aff_support
            if not check_fls_aff_support():
                return self._parse_aff_file(src, evidence_id)

        fls_bin = self._find_binary(self._FLS_BINARIES, "fls")
        istat_bin = self._find_binary(self._ISTAT_BINARIES, "istat")

        # ── 1. Discover Partitions via mmls ─────────────────────────────
        partition_offsets = self._discover_partition_offsets(src)
        logger.info("Discovered filesystem partition offsets for %s: %r", src.name, partition_offsets)

        # ── 2. Run fls recursively across all discovered partitions ──────
        bodyfiles_data: list[tuple[Optional[str], str, str]] = []  # (offset, command_str, stdout)
        execution_errors = []

        for offset in partition_offsets:
            try:
                stdout, cmd_str = self._run_fls_on_partition(fls_bin, src, offset)
                if stdout.strip():
                    bodyfiles_data.append((offset, cmd_str, stdout))
            except TSKExecutionError as err:
                execution_errors.append(str(err))

        if not bodyfiles_data:
            if execution_errors:
                error_msg = "; ".join(execution_errors)
                raise TSKExecutionError(
                    f"TSK fls extraction failed across all partition offsets for image {src.name}. Errors: {error_msg}"
                )
            else:
                raise TSKExecutionError(f"TSK fls returned 0 bodyfile records for image {src.name}.")

        # ── 3. Parse bodyfile lines into normalized Artifact records ─────
        artifacts: list[Artifact] = []

        for offset, cmd_str, bodyfile_stdout in bodyfiles_data:
            for lineno, line in enumerate(bodyfile_stdout.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue

                parts = line.split("|")
                if len(parts) < 11:
                    logger.warning("Skipping malformed fls line %d: %r", lineno, line)
                    continue

                # Bodyfile format:
                # MD5 | name | inode | mode | UID | GID | size | atime | mtime | ctime | crtime
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

                deleted = "*" in inode or "*" in mode or "(deleted)" in name.lower()
                clean_inode = inode.replace("*", "").strip()

                dt_mtime = _epoch_to_dt(mtime_raw)
                dt_atime = _epoch_to_dt(atime_raw)
                dt_ctime = _epoch_to_dt(ctime_raw)
                dt_crtime = _epoch_to_dt(crtime_raw)

                # Forensic Timestamp Provenance:
                # Primary evidence timestamp comes directly from metadata (mtime -> crtime -> ctime -> atime)
                # DO NOT substitute current ingestion time if evidence timestamp is missing.
                ts = dt_mtime or dt_crtime or dt_ctime or dt_atime
                ts_type = "modified" if dt_mtime else ("created" if dt_crtime else ("changed" if dt_ctime else "accessed"))

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
                    "partition_offset": offset,
                    "command_executed": cmd_str,
                    "raw_fls_line": line,
                    "source_tool": "tsk",
                    "istat": None,
                }

                # Run istat on flagged (deleted) files for block allocation metadata
                if deleted and clean_inode and clean_inode.split("-")[0].isdigit():
                    try:
                        istat_output = self._run_istat(istat_bin, src, clean_inode, offset=offset)
                        raw_fields["istat"] = istat_output
                    except Exception as e:
                        logger.warning("Failed to run istat for inode %s on offset %s: %s", clean_inode, offset, e)

                ver = getattr(self, "_tool_version", get_tool_version("tsk"))
                fname = Path(name).name if name else None
                fhash = md5_val if md5_val and md5_val != "0" and len(md5_val) == 32 else None
                summary = f"File {name} (inode {inode}, {size_val} bytes, offset {offset or '0'})"

                artifacts.append(Artifact(
                    evidence_id=evidence_id,
                    source_tool="tsk",
                    artifact_type="file_record",
                    timestamp=ts,
                    timestamp_type=ts_type,
                    event_summary=summary,
                    parser_version=ver,
                    raw_fields={**raw_fields, "tool_version": ver},
                    normalized_fields=NormalizedFields(
                        file_path=name,
                        file_name=fname,
                        file_size=_safe_int(size_val),
                        hash=fhash,
                        hash_md5=fhash,
                        mtime=dt_mtime.isoformat() if dt_mtime else None,
                        atime=dt_atime.isoformat() if dt_atime else None,
                        ctime=dt_ctime.isoformat() if dt_ctime else None,
                        crtime=dt_crtime.isoformat() if dt_crtime else None,
                        deleted=deleted,
                        rule_name="file_record",
                    )
                ))

        logger.info("Successfully extracted %d bodyfile timeline records from %s", len(artifacts), src.name)
        return artifacts

    def _find_binary(self, candidates: tuple[str, ...], name: str) -> str:
        """Find candidate binary on system path or local workspace folder."""
        import shutil
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved

        try:
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
            f"Install The Sleuth Kit and ensure fls/mmls/istat are on PATH."
        )

    def _discover_partition_offsets(self, image_path: Path) -> list[Optional[str]]:
        """Run `mmls` to discover partition starting sector offsets."""
        try:
            mmls_bin = self._find_binary(self._MMLS_BINARIES, "mmls")
        except TSKNotFoundError:
            return [None]

        cmd = [mmls_bin, str(image_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                return [None]

            offsets: list[Optional[str]] = []
            pattern = re.compile(r'^\s*\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$', re.MULTILINE)
            ignored_keywords = {"unallocated", "meta", "safety table", "gpt header", "partition table", "microsoft reserved partition"}

            for match in pattern.finditer(res.stdout):
                slot_type = match.group(1).lower()
                start_sector = match.group(2)
                desc = match.group(5).lower().strip()

                if slot_type in ("meta", "-------"):
                    continue
                if any(kw in desc for kw in ignored_keywords):
                    continue

                offsets.append(str(int(start_sector)))

            return offsets if offsets else [None]
        except Exception as err:
            logger.warning("mmls partition discovery failed for %s (%s). Defaulting to unpartitioned image mode.", image_path.name, err)
            return [None]

    def _run_fls_on_partition(self, binary: str, image_path: Path, offset: Optional[str]) -> Tuple[str, str]:
        """Run `fls -r -m / <image>` with partition offset parameter."""
        cmd = [binary]
        if offset and offset != "0":
            cmd.extend(["-o", str(offset)])
        cmd.extend(["-r", "-m", "/", str(image_path)])

        cmd_str = " ".join(cmd)
        logger.debug("Executing TSK command: %s", cmd_str)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout, cmd_str

            if image_path.suffix.lower() == ".aff":
                for img_type in ("afflib", "aff"):
                    retry_cmd = [binary]
                    if offset and offset != "0":
                        retry_cmd.extend(["-o", str(offset)])
                    retry_cmd.extend(["-i", img_type, "-r", "-m", "/", str(image_path)])
                    retry_res = subprocess.run(retry_cmd, capture_output=True, text=True, timeout=180)
                    if retry_res.returncode == 0 and retry_res.stdout.strip():
                        return retry_res.stdout, " ".join(retry_cmd)
        except FileNotFoundError:
            raise TSKNotFoundError(f"TSK binary {binary} missing from environment.")

        raise TSKExecutionError(
            f"TSK fls failed with exit code {res.returncode}.\n"
            f"Command: {cmd_str}\n"
            f"stdout: {res.stdout.strip()[:300]}\n"
            f"stderr: {res.stderr.strip()[:300]}"
        )

    def _run_istat(self, binary: str, image_path: Path, inode: str, offset: Optional[str] = None) -> str:
        """Run `istat [-o offset] <image> <inode>` and return stdout."""
        cmd = [binary]
        if offset and offset != "0":
            cmd.extend(["-o", str(offset)])
        cmd.extend([str(image_path), inode])

        logger.debug("Running: %s", " ".join(cmd))
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            raise TSKExecutionError(f"TSK istat failed with code {res.returncode}: {res.stderr}")
        return res.stdout

    def _parse_text_file(self, src: Path, evidence_id: str) -> list[Artifact]:
        """Parse text file or narrative record."""
        content = src.read_text(encoding="utf-8", errors="ignore")
        ver = getattr(self, "_tool_version", get_tool_version("tsk"))
        return [
            Artifact(
                evidence_id=evidence_id,
                source_tool="narrative_text",
                artifact_type="text_record",
                timestamp=datetime.now(timezone.utc),
                timestamp_type="ingest",
                event_summary=content.strip()[:2000],
                parser_version=ver,
                raw_fields={"content": content, "size_bytes": len(content), "filename": src.name},
                normalized_fields=NormalizedFields(
                    file_path=src.name,
                    file_name=src.name,
                    rule_name="text_record",
                )
            )
        ]

    def _parse_dfxml_file(self, src: Path, evidence_id: str) -> list[Artifact]:
        """Parse DFXML (Digital Forensics XML) metadata catalog."""
        import xml.etree.ElementTree as ET
        artifacts: list[Artifact] = []
        ver = getattr(self, "_tool_version", get_tool_version("tsk"))

        import re
        content = src.read_text(encoding="utf-8", errors="ignore")
        fileobjs = re.findall(r'<fileobject>(.*?)</fileobject>', content, re.DOTALL)
        for fo in fileobjs:
            fn_m = re.search(r'<filename>(.*?)</filename>', fo)
            fs_m = re.search(r'<filesize>(.*?)</filesize>', fo)
            mt_m = re.search(r'<mtime>(.*?)</mtime>', fo)
            h_m = re.search(r'<hashdigest type="sha256">(.*?)</hashdigest>', fo) or re.search(r'<hashdigest type="md5">(.*?)</hashdigest>', fo)
            
            fname = fn_m.group(1).strip() if fn_m else None
            fsize = int(fs_m.group(1).strip()) if (fs_m and fs_m.group(1).strip().isdigit()) else None
            mtime_str = mt_m.group(1).strip() if mt_m else None
            hash_val = h_m.group(1).strip() if h_m else None

            if fname:
                artifacts.append(
                    Artifact(
                        evidence_id=evidence_id,
                        source_tool="dfxml_fiwalk",
                        artifact_type="file_record",
                        timestamp=datetime.now(timezone.utc),
                        timestamp_type="recorded",
                        event_summary=f"DFXML Catalog Record: {fname} ({fsize or 0} bytes)",
                        parser_version=ver,
                        raw_fields={"filename": fname, "filesize": fsize, "mtime": mtime_str, "hash": hash_val},
                        normalized_fields=NormalizedFields(
                            file_path=fname,
                            file_name=Path(fname).name,
                            hash=hash_val,
                            mtime=mtime_str,
                            rule_name="dfxml_file_record",
                        )
                    )
                )

        if not artifacts:
            # Fallback text record if XML structure differs
            artifacts = self._parse_text_file(src, evidence_id)

        return artifacts

    def _parse_aff_file(self, src: Path, evidence_id: str) -> list[Artifact]:
        """Parse Advanced Forensic Format (AFF 1.0) container metadata and segment fields."""
        import hashlib, re
        ver = getattr(self, "_tool_version", get_tool_version("tsk"))
        data = src.read_bytes()

        md5_hash = hashlib.md5(data[:65536]).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        printable_strings = re.findall(b'[\x20-\x7e]{5,}', data)
        segments = [s.decode("ascii", errors="ignore") for s in printable_strings[:10]]

        return [
            Artifact(
                evidence_id=evidence_id,
                source_tool="aff_parser",
                artifact_type="file_record",
                timestamp=datetime.fromtimestamp(src.stat().st_mtime, tz=timezone.utc),
                timestamp_type="mtime",
                event_summary=f"AFF 1.0 Forensic Image Container: {src.name} ({len(data):,} bytes)",
                parser_version=ver,
                raw_fields={
                    "filename": src.name,
                    "format": "AFF 1.0 Container",
                    "filesize": len(data),
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "segments_sample": segments
                },
                normalized_fields=NormalizedFields(
                    file_path=src.name,
                    file_name=src.name,
                    file_size=len(data),
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    rule_name="aff_container"
                )
            )
        ]


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
