"""
STAGE 2 — Sandboxed Intake Validation
Checks the file for obvious red flags before it touches the rest of the pipeline.
Includes Docker-based sandbox validation and ClamAV scanning.
"""

import os
import zipfile
import tarfile
import gzip
import io
import mimetypes
from typing import Tuple, Optional
from infrastructure.schemas import Evidence, EvidenceStatus, SandboxResult, CustodyLogEntry

# Docker SDK — imported at module level so it can be patched in unit tests.
# If the docker package is not installed, run_docker_sandbox() will report a
# connection failure flag rather than crashing at import time.
try:
    import docker
except ImportError:  # pragma: no cover
    docker = None  # type: ignore[assignment]

# ClamAV SDK — same pattern.
try:
    import pyclamd
except ImportError:  # pragma: no cover
    pyclamd = None  # type: ignore[assignment]

# Configurable limits
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB
max_size_env = os.getenv("ARGUS_MAX_FILE_SIZE_BYTES")
if max_size_env:
    try:
        MAX_FILE_SIZE_BYTES = int(max_size_env)
    except ValueError:
        MAX_FILE_SIZE_BYTES = DEFAULT_MAX_FILE_SIZE
else:
    MAX_FILE_SIZE_BYTES = DEFAULT_MAX_FILE_SIZE

MAX_ZIP_RATIO         = 100.0                 # compressed:uncompressed ratio limit
ALLOWED_EXTENSIONS    = {
    ".evtx", ".log", ".txt", ".pcap", ".pcapng",
    ".raw", ".dmp", ".mem",                  # memory dumps
    ".eml", ".msg",                          # email
    ".dd", ".img", ".e01",                   # disk images
    ".reg",                                  # registry hives
    ".json", ".xml", ".csv",                 # generic structured
    ".zip", ".tar", ".tgz", ".gz",           # archives
}

# Known dangerous magic bytes (flag, don't reject outright)
DANGEROUS_MAGIC = [
    b"\x4d\x5a",   # MZ — Windows PE executable
]


# ── Recursive Archive / Tar / Gzip bomb detection helpers ────────────────────

def estimate_zip_sizes(file_obj, depth=0, max_depth=5) -> Tuple[int, int]:
    """Recursively estimate zip file sizes without extracting fully to disk."""
    if depth > max_depth:
        return 0, 0
    total_compressed = 0
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(file_obj, "r") as zf:
            for info in zf.infolist():
                total_compressed += info.compress_size
                total_uncompressed += info.file_size
                
                # Recursively parse nested ZIP files
                if info.filename.lower().endswith(".zip"):
                    try:
                        with zf.open(info.filename) as nested_f:
                            nested_data = nested_f.read()
                            nc, nu = estimate_zip_sizes(io.BytesIO(nested_data), depth + 1, max_depth)
                            total_uncompressed += nu
                    except Exception:
                        pass
    except Exception:
        pass
    return total_compressed, total_uncompressed


def estimate_tar_sizes(file_path: str) -> Tuple[int, int]:
    """Recursively estimate tar/tar.gz file sizes, checking nested archives."""
    compressed_size = os.path.getsize(file_path)
    uncompressed_size = 0
    try:
        with tarfile.open(file_path, "r:*") as tf:
            for member in tf.getmembers():
                uncompressed_size += member.size
                if member.isfile():
                    ext = os.path.splitext(member.name)[1].lower()
                    if ext in {".zip", ".tar", ".tgz", ".gz"}:
                        try:
                            f = tf.extractfile(member)
                            if f:
                                nested_data = f.read()
                                if ext == ".zip":
                                    _, nu = estimate_zip_sizes(io.BytesIO(nested_data))
                                    uncompressed_size += nu
                                elif ext in {".tar", ".tgz"}:
                                    with tarfile.open(fileobj=io.BytesIO(nested_data)) as ntf:
                                        uncompressed_size += sum(m.size for m in ntf.getmembers())
                                elif ext == ".gz":
                                    with gzip.GzipFile(fileobj=io.BytesIO(nested_data)) as ngz:
                                        gz_size = 0
                                        while True:
                                            chunk = ngz.read(64 * 1024)
                                            if not chunk:
                                                break
                                            gz_size += len(chunk)
                                        uncompressed_size += gz_size
                        except Exception:
                            pass
    except Exception:
        pass
    return compressed_size, uncompressed_size


def estimate_gz_sizes(file_path: str) -> Tuple[int, int]:
    """Estimate gzip file sizes by decompressing in memory in chunks."""
    compressed_size = os.path.getsize(file_path)
    uncompressed_size = 0
    try:
        with gzip.open(file_path, "rb") as gf:
            while True:
                chunk = gf.read(64 * 1024)
                if not chunk:
                    break
                uncompressed_size += len(chunk)
                # Early stop Gzip bomb checking if ratio is already exceeded
                if compressed_size > 0 and (uncompressed_size / compressed_size) > MAX_ZIP_RATIO:
                    break
    except Exception:
        pass
    return compressed_size, uncompressed_size


def check_archive_bomb(file_path: str, filename: str) -> Tuple[bool, Optional[str]]:
    ext = os.path.splitext(filename)[1].lower()
    comp_size = os.path.getsize(file_path)
    if comp_size == 0:
        return False, None

    if ext == ".zip":
        try:
            with open(file_path, "rb") as f:
                c, u = estimate_zip_sizes(f)
            ratio = u / max(1, c)
            if ratio > MAX_ZIP_RATIO:
                return True, f"zip_bomb_suspected:ratio={int(ratio)}x"
        except Exception as e:
            return False, f"zip_error:{e}"

    elif ext in {".tar", ".tgz"}:
        try:
            c, u = estimate_tar_sizes(file_path)
            ratio = u / max(1, c)
            if ratio > MAX_ZIP_RATIO:
                return True, f"tar_bomb_suspected:ratio={int(ratio)}x"
        except Exception as e:
            return False, f"tar_error:{e}"

    elif ext == ".gz":
        try:
            c, u = estimate_gz_sizes(file_path)
            ratio = u / max(1, c)
            if ratio > MAX_ZIP_RATIO:
                return True, f"gz_bomb_suspected:ratio={int(ratio)}x"
        except Exception as e:
            return False, f"gz_error:{e}"

    return False, None


# ── Sandbox Containment and ClamAV scanning ───────────────────────────────────

def run_docker_sandbox(file_path: str) -> list[str]:
    """
    Run the evidence file through an isolated Alpine container for content
    inspection.  The container:
      - Mounts the evidence file (the HOST path) at /evidence/file as read-only.
      - Disables networking.
      NOTE: docker is imported at module level for testability.
      - Drops to the 'nobody' user.
      - Applies memory and CPU limits.
      - Executes a small, self-contained POSIX sh script that:
          1. Confirms /evidence/file exists and is a regular file.
          2. Confirms the file is non-empty.
          3. Reads the first 16 bytes via 'dd' (data-only, never executed).
          4. Hex-dumps those bytes via 'od' for human-readable logging.
          5. Exits 0 on success, non-zero on any validation failure.
      - The evidence is treated as DATA ONLY — it is never executed, sourced,
        or interpreted as a script, executable, or macro.

    Returns a list of flag strings; empty list means sandbox passed.
    """
    # Self-contained POSIX sh validation script executed inside Alpine.
    # Deliberately avoids external tools that may not be present; uses only
    # POSIX builtins and the standard Alpine coreutils (dd, od, wc, stat).
    # The script NEVER executes, sources, or eval()s the evidence file.
    VALIDATION_SCRIPT = r"""#!/bin/sh
set -e

EVIDENCE_PATH="/evidence/file"

# ── Step 1: Confirm the evidence mount exists and is a regular file ───────────
if [ ! -e "$EVIDENCE_PATH" ]; then
    echo "SANDBOX_ERROR: /evidence/file does not exist" >&2
    exit 2
fi

if [ ! -f "$EVIDENCE_PATH" ]; then
    echo "SANDBOX_ERROR: /evidence/file is not a regular file" >&2
    exit 3
fi

# ── Step 2: Confirm the file is readable ─────────────────────────────────────
if [ ! -r "$EVIDENCE_PATH" ]; then
    echo "SANDBOX_ERROR: /evidence/file is not readable" >&2
    exit 4
fi

# ── Step 3: Confirm the file is non-empty ─────────────────────────────────────
SIZE=$(wc -c < "$EVIDENCE_PATH" 2>/dev/null || echo 0)
if [ "$SIZE" -eq 0 ]; then
    echo "SANDBOX_ERROR: /evidence/file is empty (0 bytes)" >&2
    exit 5
fi

# ── Step 4: Read first 16 bytes as DATA ONLY — never executed ─────────────────
# dd reads raw bytes; od converts to hex for display only.
HEADER_HEX=$(dd if="$EVIDENCE_PATH" bs=1 count=16 2>/dev/null | od -An -tx1 | tr -d ' \n')
echo "SANDBOX_INFO: size=${SIZE} header_hex=${HEADER_HEX}"

# ── Step 5: Accept file — exit 0 ─────────────────────────────────────────────
exit 0
"""

    flags = []
    if docker is None:
        flags.append("sandbox_connection_failed:docker_sdk_not_installed")
        return flags
    try:
        client = docker.from_env()

        # Mount the HOST file as /evidence/file (read-only) inside the container.
        # The mount target is the file itself, not a directory, so the script
        # always finds exactly one evidence file at the known path.
        container = client.containers.run(
            image="alpine:latest",
            command=["sh", "-c", VALIDATION_SCRIPT],
            network_disabled=True,
            read_only=True,
            user="nobody",
            mem_limit="100m",
            nano_cpus=500_000_000,  # 0.5 CPU
            volumes={file_path: {"bind": "/evidence/file", "mode": "ro"}},
            detach=True,
        )
        try:
            res = container.wait(timeout=30)
            exit_code = res.get("StatusCode", 0)
            if exit_code != 0:
                # Collect container stderr/stdout for the flag message
                try:
                    output = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace").strip()
                except Exception:
                    output = ""
                detail = output[:200] if output else f"exit_code={exit_code}"
                flags.append(f"sandbox_container_error:exit_code={exit_code}:{detail}")
            else:
                # Optionally capture info line for debug logging
                try:
                    info = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace").strip()
                    if info:
                        flags.append(f"sandbox_info:{info[:200]}")
                except Exception:
                    pass
        except Exception as e:
            flags.append(f"sandbox_timeout:{e}")
        finally:
            container.remove(force=True)
    except docker.errors.DockerException as e:
        flags.append(f"sandbox_connection_failed:{e}")
    except Exception as e:
        flags.append(f"sandbox_unexpected_error:{e}")
    return flags


def run_clamav_scan(file_path: str) -> list[str]:
    flags = []
    if pyclamd is None:
        flags.append("clamav_scan_error:pyclamd_not_installed")
        return flags
    host = os.getenv("CLAMAV_HOST", "localhost")
    port = int(os.getenv("CLAMAV_PORT", "3310"))
    
    # Fast socket pre-check to avoid blocking on offline ClamAV daemon
    import socket
    try:
        with socket.create_connection((host, port), timeout=0.1):
            is_open = True
    except Exception:
        is_open = False

    if not is_open:
        flags.append("clamav_scan_error:ConnectionRefused:ClamAV_daemon_offline")
        return flags

    try:
        cd = pyclamd.ClamdNetworkSocket(host=host, port=port)
        if not cd.ping():
            flags.append("clamav_ping_failed")
        else:
            scan_res = cd.scan_file(file_path)
            if scan_res:
                status, virus_name = scan_res.get(file_path, ("FOUND", "unknown"))
                flags.append(f"virus_detected:{virus_name}")
    except Exception as e:
        flags.append(f"clamav_scan_error:{type(e).__name__}:{e}")
    return flags


def sandbox_validate(evidence: Evidence) -> Evidence:
    """
    Run safety checks on the file before it moves further in the pipeline.
    Returns Evidence with status=SANDBOXED (pass) or VALIDATION_FAILED (fail).
    """
    flags = []
    start_time = _now_ms()

    try:
        # ── Check 1: file exists, is readable, and is not a symbolic link ──
        if os.path.islink(evidence.file_path):
            flags.append("symbolic_link_rejected")
            return _reject(evidence, flags, start_time)

        if not os.path.isfile(evidence.file_path):
            flags.append("file_not_found")
            return _reject(evidence, flags, start_time)

        # ── Check 2: file size limit ───────────────────────────────
        size = os.path.getsize(evidence.file_path)
        if size == 0:
            flags.append("empty_file")
        if size > MAX_FILE_SIZE_BYTES:
            flags.append(f"file_too_large:{size}_bytes")
            return _reject(evidence, flags, start_time)  # hard stop

        # ── Check 3: extension allow-list ─────────────────────────
        ext = os.path.splitext(evidence.filename)[1].lower()
        if ext and ext not in ALLOWED_EXTENSIONS:
            flags.append(f"unknown_extension:{ext}")

        # ── Check 4: zip/tar/gz bomb detection ───────────────────────────
        is_bomb, bomb_flag = check_archive_bomb(evidence.file_path, evidence.filename)
        if is_bomb:
            flags.append(bomb_flag)
            return _reject(evidence, flags, start_time)  # hard stop
        elif bomb_flag:
            flags.append(bomb_flag)

        # ── Check 5: magic bytes (PE executable) ──────────────────
        with open(evidence.file_path, "rb") as f:
            header = f.read(4)
        for magic in DANGEROUS_MAGIC:
            if header.startswith(magic):
                flags.append(f"executable_magic_bytes:{magic.hex()}")

        # ── Check 6: Docker Sandbox Isolation ───────────────────────
        sandbox_flags = run_docker_sandbox(evidence.file_path)
        flags.extend(sandbox_flags)

        # ── Check 7: ClamAV Malware Scan ────────────────────────────
        clamav_flags = run_clamav_scan(evidence.file_path)
        flags.extend(clamav_flags)

        # If any sandbox containment errors or malware scan flags are detected, reject!
        from config.settings import settings
        app_env = os.getenv("APP_ENV") or settings.app_env
        if app_env == "production":
            reject_triggers = {
                "sandbox_timeout",
                "sandbox_container_error",
                "sandbox_connection_failed",
                "virus_detected",
                "clamav_scan_error",
                "clamav_ping_failed"
            }
        else:
            # In non-production, connection/offline errors are warnings and do not block testing
            reject_triggers = {
                "sandbox_timeout",
                "sandbox_container_error",
                "virus_detected"
            }

        for f_val in flags:
            if any(trigger in f_val for trigger in reject_triggers):
                return _reject(evidence, flags, start_time)

    except Exception as e:
        flags.append(f"validation_error:{type(e).__name__}:{e}")
        return _reject(evidence, flags, start_time)

    # ── All checks passed ──────────────────────────────────────────
    elapsed = _now_ms() - start_time
    result = SandboxResult(passed=True, flags=flags, execution_time_ms=elapsed)
    evidence.sandbox_result = result
    evidence.status = EvidenceStatus.SANDBOXED

    evidence.custody_log.append(CustodyLogEntry(
        actor="sandbox_intake_validator",
        action="sandbox_validated",
        notes=f"flags={flags}",
    ))

    flag_str = f" (flags: {flags})" if flags else ""
    print(f"  [2/5] SANDBOXED  {evidence.filename}{flag_str}")
    return evidence


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reject(evidence: Evidence, flags: list, start_time: int) -> Evidence:
    elapsed = _now_ms() - start_time
    evidence.sandbox_result = SandboxResult(
        passed=False, flags=flags, execution_time_ms=elapsed
    )
    evidence.status = EvidenceStatus.VALIDATION_FAILED

    evidence.custody_log.append(CustodyLogEntry(
        actor="sandbox_intake_validator",
        action="sandbox_rejected",
        notes=f"flags={flags}",
    ))

    print(f"  [2/5] REJECTED   {evidence.filename} — {flags}")
    return evidence


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)
