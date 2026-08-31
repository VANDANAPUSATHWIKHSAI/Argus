# Memory dump parser using Volatility 3
# Source tool: "volatility3"
# Artifact types produced: "process_record", "dll_record", "injection_indicator",
#                          "evasion_indicator"
# Raw output format: JSON (--output=json) or tab-separated table (fallback)
# Volatility 3 docs: https://volatility3.readthedocs.io
# Evasion indicator checks:
#   - All process CreateTime values identical to the second (synthetic timestamps)
#   - DLL LoadTime predates its host process CreateTime (impossible timeline)

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed errors — never silently swallow failures
# ---------------------------------------------------------------------------

class VolatilityNotFoundError(FileNotFoundError):
    """Raised when the `vol` binary cannot be found on PATH."""


class VolatilityExecutionError(RuntimeError):
    """Raised when Volatility 3 exits with a non-zero return code."""


class VolatilitySymbolError(VolatilityExecutionError):
    """Raised when Volatility 3 fails to resolve/download OS symbols."""


# ---------------------------------------------------------------------------
# Plugin descriptors — drives the multi-plugin run loop
# ---------------------------------------------------------------------------

# Each tuple: (plugin_name, artifact_type, column_names_for_table_fallback)
# Column names must match Volatility 3's default table header (case-insensitive).
_PLUGINS: list[tuple[str, str, list[str]]] = [
    (
        "windows.pslist",
        "process_record",
        ["PID", "PPID", "ImageFileName", "CreateTime", "ExitTime", "Handles", "Offset(V)"],
    ),
    (
        "windows.pstree",
        "process_tree_record",
        ["PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"],
    ),
    (
        "windows.psscan",
        "unlinked_process_record",
        ["PID", "PPID", "ImageFileName", "CreateTime", "ExitTime", "Offset(V)"],
    ),
    (
        "windows.cmdline",
        "command_line_record",
        ["PID", "Process", "Args"],
    ),
    (
        "windows.cmdscan",
        "console_command_record",
        ["PID", "Process", "CommandHistory", "Command"],
    ),
    (
        "windows.netscan",
        "network_connection",
        ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"],
    ),
    (
        "windows.malfind",
        "injection_indicator",
        ["PID", "Process", "Start VPN", "End VPN", "Tag", "Protection", "CommitCharge",
         "PrivateMemory", "File output", "Hexdump", "Disasm"],
    ),
    (
        "windows.dlllist",
        "dll_record",
        ["PID", "Process", "Base", "Size", "LoadTime", "Name", "Path"],
    ),
    (
        "windows.handles",
        "handle_record",
        ["PID", "Process", "Offset", "HandleValue", "Type", "GrantedAccess", "Name"],
    ),
    (
        "windows.filescan",
        "file_scan_record",
        ["Offset", "Name", "Access"],
    ),
    (
        "windows.hivelist",
        "hive_record",
        ["Offset", "FileFullPath", "Name"],
    ),
]

# Volatility 3 ISO-8601 datetime (e.g. "2024-03-15 08:22:11.000000 UTC")
_VOL_TS_RE = re.compile(
    r'^(?P<dt>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
    r'(?:\.(?P<frac>\d+))?'
    r'\s*(?P<tz>UTC|[+-]\d{2}:?\d{2}|Z)?$'
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class MemoryParser:
    """Parses raw memory dump files via Volatility 3 into Artifact records.

    Eleven plugins are run in sequence against the same image:

    1. ``windows.pslist``   → artifact_type ``"process_record"``
    2. ``windows.pstree``   → artifact_type ``"process_tree_record"``
    3. ``windows.psscan``   → artifact_type ``"unlinked_process_record"``
    4. ``windows.cmdline``  → artifact_type ``"command_line_record"``
    5. ``windows.cmdscan``  → artifact_type ``"console_command_record"``
    6. ``windows.netscan``  → artifact_type ``"network_connection"``
    7. ``windows.malfind``  → artifact_type ``"injection_indicator"``
    8. ``windows.dlllist``  → artifact_type ``"dll_record"``
    9. ``windows.handles``  → artifact_type ``"handle_record"``
    10. ``windows.filescan`` → artifact_type ``"file_scan_record"``
    11. ``windows.hivelist`` → artifact_type ``"hive_record"``
    """

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the memory dump at *file_path* and return a list of Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Memory dump not found: {file_path}")

        self._tool_version = get_tool_version("volatility3")
        artifacts: list[Artifact] = []
        for plugin, artifact_type, fallback_cols in _PLUGINS:
            plugin_artifacts = self._run_plugin(
                src, plugin, artifact_type, fallback_cols, evidence_id
            )
            artifacts.extend(plugin_artifacts)
            logger.info(
                "Plugin %s produced %d artifacts", plugin, len(plugin_artifacts)
            )

        logger.info(
            "MemoryParser total: %d artifacts from %s", len(artifacts), src.name
        )

        # Post-parse evasion indicator checks (non-raising; append indicators)
        artifacts.extend(_check_memory_timestomping(
            artifacts, evidence_id, tool_version=self._tool_version
        ))
        return artifacts

    # -----------------------------------------------------------------------
    # Per-plugin execution
    # -----------------------------------------------------------------------

    def _run_plugin(
        self,
        dump_path: Path,
        plugin: str,
        artifact_type: str,
        fallback_cols: list[str],
        evidence_id: str,
    ) -> list[Artifact]:
        """Run a single Volatility 3 plugin and return its Artifacts."""
        # Try JSON output first; fall back to table parsing if unsupported.
        raw_output = self._run_vol(dump_path, plugin, json_output=True)

        # Volatility writes JSON to stdout.  A successful JSON run begins with '[' or '{'.
        stripped = raw_output.lstrip()
        if stripped.startswith(("[", "{")):
            return self._parse_json_output(
                raw_output, plugin, artifact_type, evidence_id
            )

        # JSON not supported by this build/plugin — fall back to table.
        logger.debug(
            "Plugin %s: JSON output not recognised, falling back to table parser", plugin
        )
        raw_table = self._run_vol(dump_path, plugin, json_output=False)
        return self._parse_table_output(
            raw_table, plugin, artifact_type, fallback_cols, evidence_id
        )

    def _run_vol(
        self, dump_path: Path, plugin: str, *, json_output: bool
    ) -> str:
        """Execute `vol -f <dump> <plugin> [--output=json]` and return stdout."""
        cmd = ["vol", "-f", str(dump_path), plugin]
        if json_output:
            cmd.append("--output=json")

        logger.debug("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,   # 10-minute ceiling — malfind on large dumps is slow
            )
        except FileNotFoundError:
            raise VolatilityNotFoundError(
                "Volatility 3 (`vol`) binary not found on PATH. "
                "Install via `pip install volatility3` or from "
                "https://github.com/volatilityfoundation/volatility3 "
                "and ensure `vol` is accessible on PATH."
            )

        # Check stdout and stderr for Volatility symbol table resolution/download failures
        combined_output = (result.stdout or "") + "\n" + (result.stderr or "")
        symbol_error_indicators = [
            "SymbolError",
            "Symbol table",
            "translation layer",
            "unable to locate symbols",
            "missing symbol",
            "unsupported OS build",
            "download failed"
        ]
        if any(indicator.lower() in combined_output.lower() for indicator in symbol_error_indicators):
            logger.error(f"Volatility 3 symbol error detected: {combined_output.strip()[:500]}")
            raise VolatilitySymbolError(
                f"Volatility 3 failed to download or resolve OS symbols/translation layers.\n"
                f"Output summary:\n{combined_output.strip()[:1000]}"
            )

        if result.returncode != 0:
            raise VolatilityExecutionError(
                f"Volatility 3 plugin `{plugin}` exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )

        return result.stdout

    # -----------------------------------------------------------------------
    # JSON output parser
    # -----------------------------------------------------------------------

    def _parse_json_output(
        self,
        raw: str,
        plugin: str,
        artifact_type: str,
        evidence_id: str,
    ) -> list[Artifact]:
        """Parse Volatility's ``--output=json`` stdout into Artifacts."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Plugin %s: JSON parse error: %s", plugin, exc)
            return []

        columns: list[str] = data.get("columns", [])
        rows: list[list] = data.get("rows", [])

        artifacts: list[Artifact] = []
        for row in rows:
            record = dict(zip(columns, row))
            artifacts.append(
                self._record_to_artifact(record, plugin, artifact_type, evidence_id)
            )
        return artifacts

    # -----------------------------------------------------------------------
    # Table (fallback) output parser
    # -----------------------------------------------------------------------

    def _parse_table_output(
        self,
        raw: str,
        plugin: str,
        artifact_type: str,
        fallback_cols: list[str],
        evidence_id: str,
    ) -> list[Artifact]:
        """Parse Volatility's default tab/space-aligned table output into Artifacts."""
        lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("#")]
        if len(lines) < 2:
            logger.warning("Plugin %s: table output too short to parse", plugin)
            return []

        header_line = lines[0]
        headers = header_line.split()

        artifacts: list[Artifact] = []
        for line in lines[1:]:
            parts = line.split(None, len(headers) - 1)
            parts += [""] * (len(headers) - len(parts))
            record = dict(zip(headers, parts))
            artifacts.append(
                self._record_to_artifact(record, plugin, artifact_type, evidence_id)
            )
        return artifacts

    # -----------------------------------------------------------------------
    # Field mapping
    # -----------------------------------------------------------------------

    def _record_to_artifact(
        self,
        record: dict,
        plugin: str,
        artifact_type: str,
        evidence_id: str,
    ) -> Artifact:
        """Map one Volatility record dict to an :class:`Artifact`."""
        ver = getattr(self, "_tool_version", get_tool_version("volatility3"))
        proc = (
            record.get("ImageFileName")
            or record.get("Process")
            or record.get("Name")
            or record.get("Owner")
            or record.get("Application")
            or ""
        )
        pid = record.get("PID") or ""
        summary = f"Volatility {plugin}: process {proc} (PID {pid})" if proc else f"Volatility {plugin}"
        ts = self._extract_timestamp(record, plugin)
        ts_type = self._extract_timestamp_type(plugin, ts)
        return Artifact(
            evidence_id=evidence_id,
            source_tool="volatility3",
            artifact_type=artifact_type,
            timestamp=ts,
            timestamp_type=ts_type,
            event_summary=summary,
            parser_version=ver,
            raw_fields={**record, "tool_version": ver},
            normalized_fields=self._normalize(record, plugin),
        )

    @staticmethod
    def _extract_timestamp_type(plugin: str, ts: Optional[datetime]) -> str:
        """Determine semantic timestamp type for the given plugin and timestamp."""
        if any(p in plugin for p in ("pslist", "pstree", "psscan", "dlllist", "cmdline", "cmdscan")):
            return "execution"
        return "event"

    @staticmethod
    def _normalize(record: dict, plugin: str) -> NormalizedFields:
        """Extract the correlation-friendly field subset for each plugin type."""
        # ── pslist / pstree / psscan ─────────────────────────────────────────
        if any(p in plugin for p in ("pslist", "pstree", "psscan")):
            pid  = _to_int(record.get("PID"))
            ppid = _to_int(record.get("PPID"))
            proc = record.get("ImageFileName") or record.get("Process") or record.get("Name") or None
            return NormalizedFields(process=proc, pid=pid, ppid=ppid)

        # ── cmdline ──────────────────────────────────────────────────────────
        if "cmdline" in plugin:
            pid  = _to_int(record.get("PID"))
            proc = record.get("Process") or record.get("ImageFileName") or None
            cmd  = record.get("Args") or record.get("CommandLine") or record.get("Command") or None
            if isinstance(cmd, list):
                cmd = " ".join(str(c) for c in cmd)
            return NormalizedFields(process=proc, pid=pid, process_command_line=cmd)

        # ── cmdscan ──────────────────────────────────────────────────────────
        if "cmdscan" in plugin:
            pid  = _to_int(record.get("PID"))
            proc = record.get("Process") or record.get("Application") or record.get("ImageFileName") or None
            cmd  = record.get("CommandHistory") or record.get("Command") or record.get("Args") or None
            if isinstance(cmd, list):
                cmd = " ".join(str(c) for c in cmd)
            return NormalizedFields(process=proc, pid=pid, process_command_line=cmd)

        # ── netscan ──────────────────────────────────────────────────────────
        if "netscan" in plugin:
            pid      = _to_int(record.get("PID"))
            proc     = record.get("Owner") or record.get("Process") or None
            src_ip   = record.get("LocalAddr") or record.get("LocalIP") or None
            src_port = _to_int(record.get("LocalPort"))
            dst_ip   = record.get("ForeignAddr") or record.get("RemoteIP") or None
            dst_port = _to_int(record.get("ForeignPort") or record.get("RemotePort"))
            return NormalizedFields(
                process=proc, pid=pid,
                src_ip=str(src_ip) if src_ip else None,
                src_port=src_port,
                dst_ip=str(dst_ip) if dst_ip else None,
                dst_port=dst_port,
            )

        # ── dlllist ─────────────────────────────────────────────────────────
        if "dlllist" in plugin:
            pid  = _to_int(record.get("PID"))
            proc = record.get("Process") or None
            path = record.get("Path") or record.get("Name") or None
            return NormalizedFields(process=proc, pid=pid, file_path=path)

        # ── malfind ─────────────────────────────────────────────────────────
        if "malfind" in plugin:
            pid  = _to_int(record.get("PID"))
            proc = record.get("Process") or None
            prot = record.get("Protection") or record.get("protection") or None
            return NormalizedFields(process=proc, pid=pid, severity=prot)

        # ── handles ─────────────────────────────────────────────────────────
        if "handles" in plugin:
            pid  = _to_int(record.get("PID"))
            proc = record.get("Process") or None
            h_name = record.get("Name") or None
            h_type = str(record.get("Type") or "")
            path = h_name if h_name and (h_type in ("File", "Key", "Directory") or "\\" in h_name or "/" in h_name) else None
            return NormalizedFields(process=proc, pid=pid, file_path=path)

        # ── filescan ────────────────────────────────────────────────────────
        if "filescan" in plugin:
            path = record.get("Name") or record.get("Path") or None
            return NormalizedFields(file_path=path)

        # ── hivelist ────────────────────────────────────────────────────────
        if "hivelist" in plugin:
            path = record.get("FileFullPath") or record.get("Name") or None
            return NormalizedFields(file_path=path)

        return NormalizedFields()

    def _extract_timestamp(self, record: dict, plugin: str) -> Optional[datetime]:
        """Pull the most relevant timestamp field from the record, if present."""
        for key in ("CreateTime", "LoadTime", "Created", "Timestamp", "Time"):
            raw = record.get(key)
            if raw:
                ts = _parse_vol_timestamp(raw)
                if ts:
                    return ts
        return None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _to_int(value) -> Optional[int]:
    """Convert a value to int, returning None on failure (handles hex strings)."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip()
    try:
        return int(s, 0)   # base-0 handles "0x..." and plain decimals
    except (ValueError, TypeError):
        return None


def _parse_vol_timestamp(raw) -> Optional[datetime]:
    """Parse a Volatility 3 timestamp string.

    Handles formats such as::

        "2024-03-15 08:22:11.000000 UTC"
        "2024-03-15T08:22:11.000000+00:00"
        0   (integer epoch — returned as None; Volatility uses 0 for absent times)
    """
    if raw is None:
        return None
    # Volatility uses integer 0 / 0.0 to mean "no timestamp"
    if isinstance(raw, (int, float)):
        if raw == 0:
            return None
        try:
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    s = str(raw).strip()
    if not s or s == "0":
        return None

    # Normalise "UTC" suffix → "+0000" so strptime handles it
    s = s.replace(" UTC", "+0000").replace("UTC", "+0000")

    m = _VOL_TS_RE.match(s)
    if not m:
        logger.debug("Unrecognised Volatility timestamp format: %r", raw)
        return None

    dt_str = m.group("dt").replace(" ", "T")
    frac   = m.group("frac") or ""
    tz_str = (m.group("tz") or "").replace(":", "")

    if frac:
        frac = (frac + "000000")[:6]
        iso  = f"{dt_str}.{frac}{tz_str}"
        fmt  = "%Y-%m-%dT%H:%M:%S.%f%z"
    else:
        iso = f"{dt_str}{tz_str}"
        fmt = "%Y-%m-%dT%H:%M:%S%z"

    try:
        return datetime.strptime(iso, fmt)
    except ValueError:
        logger.debug("Failed to parse Volatility timestamp %r", raw)
        return None


# ---------------------------------------------------------------------------
# Evasion indicator: Memory-dump timestomping detection
# ---------------------------------------------------------------------------

def _check_memory_timestomping(
    artifacts: list[Artifact],
    evidence_id: str,
    *,
    tool_version: str = "unknown",
) -> list[Artifact]:
    """Scan Volatility 3 artifacts for timestamp anomalies that may indicate
    timestomping or synthetic-timestamp injection (T1070.006).

    Two patterns are checked:

    1. **All process CreateTime values identical to the second** — In a live
       Windows system, processes start at different times.  If ≥ 3 processes in
       the ``windows.pslist`` output all share the exact same second-precision
       CreateTime, the timestamps are likely synthetic (e.g. set by a memory
       implant or a hibernation-restore artefact).

    2. **DLL LoadTime predates host process CreateTime** — A DLL cannot be
       loaded into a process before that process existed.  If Volatility reports
       a DLL whose ``LoadTime`` is earlier than the ``CreateTime`` of the same
       PID, the DLL timestamp has been manipulated.

    Returns a (possibly empty) list of evasion_indicator Artifacts.
    Errors inside this function are logged as warnings and never raise.
    """
    indicators: list[Artifact] = []

    # ── Separate artifact sets by type ───────────────────────────────────────
    process_records: list[Artifact] = [
        a for a in artifacts if a.artifact_type == "process_record"
    ]
    dll_records: list[Artifact] = [
        a for a in artifacts if a.artifact_type == "dll_record"
    ]

    # ── Check 1: All process CreateTimes identical ────────────────────────────
    process_create_times: list[datetime] = []
    for art in process_records:
        raw_ct = art.raw_fields.get("CreateTime")
        ts = _parse_vol_timestamp(raw_ct)
        if ts is not None:
            process_create_times.append(ts)

    if len(process_create_times) >= 3:
        # Truncate to the second for comparison
        ts_seconds = set(ts.replace(microsecond=0) for ts in process_create_times)
        if len(ts_seconds) == 1:
            identical_ts = next(iter(ts_seconds))
            logger.warning(
                "Evasion indicator: all %d process CreateTime values are identical "
                "to the second (%s) — possible synthetic timestamps in memory dump",
                len(process_create_times), identical_ts.isoformat(),
            )
            indicators.append(Artifact(
                evidence_id=evidence_id,
                source_tool="volatility3",
                artifact_type="evasion_indicator",
                timestamp=identical_ts,
                raw_fields={
                    "indicator":         "all_process_create_times_identical",
                    "common_timestamp":  identical_ts.isoformat(),
                    "process_count":     len(process_create_times),
                    "tool_version":      tool_version,
                    "note": (
                        f"All {len(process_create_times)} processes in windows.pslist "
                        f"share the identical CreateTime ({identical_ts.isoformat()}).  "
                        "In a running Windows system, processes start at different times.  "
                        "Uniform CreateTime values may indicate that timestamps were "
                        "synthetically assigned by a memory implant or were corrupted "
                        "during hibernation/restore (T1070.006).  "
                        "This is an indicator, not a guarantee of tampering."
                    ),
                },
                normalized_fields=NormalizedFields(
                    rule_name="timestomping_all_process_create_times_identical",
                    severity="medium",
                ),
            ))

    # ── Check 2: DLL LoadTime predates host process CreateTime ────────────────
    # Build a PID → CreateTime lookup from process records
    pid_create_time: dict[int, datetime] = {}
    for art in process_records:
        raw_pid = art.raw_fields.get("PID")
        raw_ct  = art.raw_fields.get("CreateTime")
        if raw_pid is None or raw_ct is None:
            continue
        try:
            pid = int(str(raw_pid).strip(), 0)
        except (ValueError, TypeError):
            continue
        ts = _parse_vol_timestamp(raw_ct)
        if ts is not None:
            pid_create_time[pid] = ts

    for art in dll_records:
        try:
            raw_pid  = art.raw_fields.get("PID")
            raw_load = art.raw_fields.get("LoadTime")
            if raw_pid is None or raw_load is None:
                continue
            pid = int(str(raw_pid).strip(), 0)
            load_ts = _parse_vol_timestamp(raw_load)
            if load_ts is None:
                continue
            proc_create_ts = pid_create_time.get(pid)
            if proc_create_ts is None:
                continue

            if load_ts < proc_create_ts:
                dll_name = (
                    art.raw_fields.get("Name")
                    or art.raw_fields.get("Path")
                    or "(unknown)"
                )
                proc_name = art.raw_fields.get("Process") or "(unknown)"
                delta = (proc_create_ts - load_ts).total_seconds()
                logger.warning(
                    "Evasion indicator: DLL %r in PID %d (%s) has LoadTime (%s) "
                    "that predates process CreateTime (%s) by %.1fs — impossible timeline",
                    dll_name, pid, proc_name,
                    load_ts.isoformat(), proc_create_ts.isoformat(), delta,
                )
                indicators.append(Artifact(
                    evidence_id=evidence_id,
                    source_tool="volatility3",
                    artifact_type="evasion_indicator",
                    timestamp=load_ts,
                    raw_fields={
                        "indicator":           "dll_load_time_before_process_create_time",
                        "pid":                 pid,
                        "process_name":        proc_name,
                        "dll_name":            dll_name,
                        "dll_load_time":       load_ts.isoformat(),
                        "process_create_time": proc_create_ts.isoformat(),
                        "delta_seconds":       delta,
                        "tool_version":        tool_version,
                        "note": (
                            f"DLL {dll_name!r} in PID {pid} ({proc_name}) has a "
                            f"LoadTime ({load_ts.isoformat()}) that is {delta:.1f}s "
                            f"earlier than the host process CreateTime "
                            f"({proc_create_ts.isoformat()}).  "
                            "A DLL cannot be loaded into a process before that process "
                            "was created.  This is a strong indicator that the DLL's "
                            "timestamp has been manipulated (T1070.006).  "
                            "This is an indicator, not a guarantee of tampering — "
                            "clock skew or corrupt memory structures can also produce "
                            "this condition."
                        ),
                    },
                    normalized_fields=NormalizedFields(
                        pid=pid,
                        process=proc_name,
                        file_path=dll_name,
                        rule_name="timestomping_dll_load_before_process_create",
                        severity="high",
                    ),
                ))
        except (TypeError, ValueError) as exc:
            logger.warning("Error checking DLL LoadTime for artifact: %s", exc)

    if indicators:
        logger.info(
            "MemoryParser: %d timestomping indicator(s) emitted for evidence_id=%s",
            len(indicators), evidence_id,
        )
    return indicators
