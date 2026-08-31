"""
Windows Registry Parser
======================
Source 6:  Windows Registry (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat)
Source 21: Scheduled Tasks (via Registry / RECmd)
Source 23: UserAssist
Source 24: RecentDocs
Source 26: BAM / DAM
Source 27: MUICache
Source 28: Services
Source 34: Network Configuration

Source tool: "regripper" / "recmd"
Artifact types produced:
  "registry_key", "scheduled_task", "userassist", "recentdocs",
  "bam_dam", "muicache", "windows_service", "network_configuration",
  "usb_device", "evasion_indicator"

Supports RegRipper (rip.pl / rip.exe) and RECmd for deterministic extraction.
Preserves raw values, timestamps (FILETIME / ISO-8601), ROT13 UserAssist decoding,
and accurate timestamp_type semantics.
"""

from __future__ import annotations

import codecs
import csv
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
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

class RegRipperNotFoundError(FileNotFoundError):
    """Raised when neither `rip.pl` nor `rip.exe` can be found on PATH."""


class RegRipperExecutionError(RuntimeError):
    """Raised when RegRipper exits with a non-zero return code."""


class RECmdNotFoundError(FileNotFoundError):
    """Raised when `RECmd.exe` cannot be found on PATH."""


class RECmdExecutionError(RuntimeError):
    """Raised when RECmd exits with a non-zero return code."""


# ---------------------------------------------------------------------------
# Registry Hive Profiles
# ---------------------------------------------------------------------------

DEFAULT_PROFILES: list[str] = [
    "ntuser",    # NTUSER.DAT  — user activity, userassist, run, runmru, recentdocs
    "system",    # SYSTEM      — services, timezone, network interfaces
    "software",  # SOFTWARE    — installed programs, shimcache, appcompat
    "sam",       # SAM         — local user accounts
]

# RegRipper section header: "Launching <plugin_name> v.<version>"
_LAUNCH_RE = re.compile(r'^Launching\s+(\S+)\s+v\.\S+', re.IGNORECASE)

# Key-value pattern inside a plugin block:
_KV_RE = re.compile(r'^(.+?)\s*[:=]\s*(.+)$')
_KEYPATH_RE = re.compile(
    r'^(HKEY_[A-Z_]+|Software|System|SAM|Security|'
    r'CurrentControlSet|CurrentVersion|'
    r'[A-Z]:\\|[A-Z0-9_]+\\[A-Z0-9\\_ ]+)',
    re.IGNORECASE,
)

# Timestamp patterns
_TS_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)


def rot13(s: str) -> str:
    """Perform deterministic ROT13 substitution decoding."""
    try:
        return codecs.encode(s, "rot_13")
    except Exception:
        return s


def parse_filetime(filetime_val: Any) -> Optional[datetime]:
    """Convert a Windows 64-bit FILETIME (100ns intervals since 1601-01-01) to UTC datetime."""
    if filetime_val is None:
        return None
    try:
        ft = int(str(filetime_val).strip(), 0)
        if ft <= 0:
            return None
        # 116444736000000000 is 1601-01-01 to 1970-01-01 in 100ns units
        epoch_100ns = ft - 116444736000000000
        if epoch_100ns < 0:
            return None
        seconds = epoch_100ns / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class RegistryParser:
    """Parses Windows Registry hive files via RECmd / RegRipper into Artifact records.

    RECmd is used as the primary structured extraction workflow. If RECmd is not available
    on PATH, RegRipper (rip.pl / rip.exe) is executed as a fallback.
    """

    _RECMD_BINARIES: tuple[str, ...] = ("RECmd.exe", "RECmd", "recmd")
    _BINARIES: tuple[str, ...] = ("rip.pl", "rip.exe", "rip")

    def __init__(self, profiles: Optional[list[str]] = None) -> None:
        self._profiles = profiles or DEFAULT_PROFILES

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the registry hive at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Registry hive not found: {file_path}")

        # 1. Try RECmd primary workflow
        recmd_bin = self._find_recmd_binary()
        if recmd_bin:
            try:
                self._tool_version = get_tool_version("recmd")
                artifacts = self._parse_with_recmd(recmd_bin, src, evidence_id)
                if artifacts:
                    logger.info("RegistryParser total (RECmd): %d artifacts from %s", len(artifacts), src.name)
                    artifacts.extend(_check_timestomping(
                        artifacts, evidence_id, tool_version=self._tool_version
                    ))
                    return artifacts
            except Exception as e:
                logger.warning("RECmd execution/parsing failed: %s. Falling back to RegRipper.", e)

        # 2. RegRipper fallback path
        binary = self._find_binary()
        self._tool_version = get_tool_version("regripper")

        artifacts: list[Artifact] = []
        success_count = 0
        for profile in self._profiles:
            raw_text = self._run_regripper(binary, src, profile)
            if raw_text is None:
                continue
            success_count += 1
            sections = _split_into_sections(raw_text)
            for section in sections:
                artifacts.extend(
                    _section_to_artifacts(section, evidence_id, tool_version=self._tool_version)
                )
            logger.info(
                "RegRipper profile=%s: %d sections → %d artifacts so far",
                profile, len(sections), len(artifacts),
            )

        if success_count == 0 and len(self._profiles) > 0:
            logger.error("RegistryParser failed: every attempted RegRipper profile failed to execute.")
            raise RegRipperExecutionError(
                "RegRipper failed to execute successfully on all attempted profiles."
            )

        logger.info("RegistryParser total (RegRipper): %d artifacts from %s", len(artifacts), src.name)

        artifacts.extend(_check_timestomping(
            artifacts, evidence_id, tool_version=self._tool_version
        ))
        return artifacts

    def _find_recmd_binary(self) -> Optional[str]:
        for candidate in self._RECMD_BINARIES:
            path = shutil.which(candidate)
            if path and "recmd" in Path(path).name.lower():
                return path
        return None

    def _find_binary(self) -> str:
        for candidate in self._BINARIES:
            if shutil.which(candidate):
                return candidate

        if sys.platform == "win32":
            try:
                res = subprocess.run(
                    ["wsl", "test", "-f", "/usr/lib/regripper/rip.pl"],
                    capture_output=True,
                    timeout=5
                )
                if res.returncode == 0:
                    return "wsl_rip"
            except Exception:
                pass

        raise RegRipperNotFoundError(
            f"RegRipper binary not found on PATH and not found in WSL. Tried: {', '.join(self._BINARIES)}."
        )

    def _run_recmd(self, binary: str, hive_path: Path, out_dir: Path) -> None:
        cmd = [binary, "-f", str(hive_path), "--json", str(out_dir)]
        logger.debug("Running RECmd: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            raise RECmdNotFoundError(f"RECmd binary `{binary}` not found.")

        if result.returncode != 0:
            raise RECmdExecutionError(
                f"RECmd exited with code {result.returncode}.\n"
                f"stdout: {result.stdout[:500]}\nstderr: {result.stderr[:500]}"
            )

    def _parse_with_recmd(self, binary: str, hive_path: Path, evidence_id: str) -> list[Artifact]:
        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_recmd_"))
        try:
            self._run_recmd(binary, hive_path, tmp_dir)
            return self._parse_recmd_output_dir(tmp_dir, evidence_id, self._tool_version)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _parse_recmd_output_dir(self, out_dir: Path, evidence_id: str, tool_version: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        json_files = list(out_dir.glob("*.json")) + list(out_dir.glob("*.jsonl"))
        for jf in json_files:
            artifacts.extend(self._parse_recmd_json_file(jf, evidence_id, tool_version))
        return artifacts

    def _parse_recmd_json_file(self, json_file: Path, evidence_id: str, tool_version: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        content = json_file.read_text(encoding="utf-8", errors="replace")
        if not content.strip():
            return artifacts

        records: list[dict] = []
        content_stripped = content.strip()
        if content_stripped.startswith("["):
            try:
                records = json.loads(content_stripped)
            except json.JSONDecodeError:
                pass
        else:
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for rec in records:
            artifacts.append(_recmd_record_to_artifact(rec, evidence_id, tool_version=tool_version))
        return artifacts

    def _run_regripper(self, binary: str, hive_path: Path, profile: str) -> Optional[str]:
        if binary == "wsl_rip":
            try:
                res = subprocess.run(
                    ["wsl", "wslpath", "-u", hive_path.as_posix()],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if res.returncode == 0:
                    wsl_hive_path = res.stdout.strip()
                else:
                    return None
            except Exception:
                return None
            cmd = ["wsl", "perl", "/usr/lib/regripper/rip.pl", "-r", wsl_hive_path, "-f", profile]
        else:
            cmd = [binary, "-r", str(hive_path), "-f", profile]

        logger.debug("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            raise RegRipperNotFoundError(f"RegRipper binary `{binary}` disappeared from PATH mid-run.")

        if result.returncode != 0:
            logger.warning("RegRipper %s profile=%s exited %d", binary, profile, result.returncode)
            return None

        output = result.stdout
        if not output.strip():
            return None

        return output


def _recmd_record_to_artifact(rec: dict, evidence_id: str, tool_version: str) -> Artifact:
    key_path = rec.get("KeyPath") or rec.get("Key") or rec.get("key_path")
    value_name = rec.get("ValueName") or rec.get("Value") or rec.get("value_name")
    value_data = rec.get("ValueData") or rec.get("Data") or rec.get("value_data")
    if isinstance(value_data, (dict, list)):
        value_data = json.dumps(value_data)
    else:
        value_data = str(value_data) if value_data is not None else None

    plugin = rec.get("PluginName") or rec.get("BatchName") or rec.get("Category") or "recmd"
    ts_raw = rec.get("LastWriteTime") or rec.get("Timestamp") or rec.get("LastWrite")
    ts = parse_filetime(ts_raw) if ts_raw else None
    if ts is None and ts_raw:
        ts = _extract_timestamp(str(ts_raw))

    return _make_artifact(
        evidence_id=evidence_id,
        plugin=plugin,
        plugin_text=json.dumps(rec),
        key_path=key_path,
        value_name=value_name,
        value_data=value_data,
        timestamp=ts,
        tool_version=tool_version,
        source_tool="recmd",
        recmd_record=rec,
    )


# ---------------------------------------------------------------------------
# Section Splitting
# ---------------------------------------------------------------------------

def _split_into_sections(raw_text: str) -> list[dict]:
    sections: list[dict] = []
    current_plugin: Optional[str] = None
    current_lines: list[str] = []

    def _flush():
        if current_plugin:
            sections.append({
                "plugin": current_plugin,
                "plugin_text": "\n".join(current_lines).strip(),
            })

    for line in raw_text.splitlines():
        m = _LAUNCH_RE.match(line)
        if m:
            _flush()
            current_plugin = m.group(1).lower()
            current_lines = [line]
        else:
            if current_plugin is not None:
                current_lines.append(line)

    _flush()
    return sections


# ---------------------------------------------------------------------------
# Section → Artifact Converter
# ---------------------------------------------------------------------------

def _section_to_artifacts(
    section: dict,
    evidence_id: str,
    *,
    tool_version: str = "unknown",
) -> list[Artifact]:
    plugin = section["plugin"]
    plugin_text = section["plugin_text"]
    lines = plugin_text.splitlines()

    ts = _extract_timestamp(plugin_text)
    artifacts: list[Artifact] = []
    current_key_path: Optional[str] = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("-" * 5):
            continue

        if _TS_RE.search(stripped) or re.match(r'^\d{4}-\d{2}-\d{2}', stripped):
            continue

        if _KEYPATH_RE.match(stripped):
            current_key_path = stripped
            continue

        m = _KV_RE.match(stripped)
        if m:
            value_name = m.group(1).strip()
            value_data = m.group(2).strip()
            artifacts.append(_make_artifact(
                evidence_id=evidence_id,
                plugin=plugin,
                plugin_text=plugin_text,
                key_path=current_key_path,
                value_name=value_name,
                value_data=value_data,
                timestamp=ts,
                tool_version=tool_version,
                source_tool="regripper",
            ))
            continue

    if not artifacts:
        artifacts.append(_make_artifact(
            evidence_id=evidence_id,
            plugin=plugin,
            plugin_text=plugin_text,
            key_path=current_key_path,
            value_name=None,
            value_data=None,
            timestamp=ts,
            tool_version=tool_version,
            source_tool="regripper",
        ))

    if plugin in ("usbstor", "mounteddevices"):
        serial, friendly, first, last = _extract_usb_details(plugin_text, current_key_path)
        usb_art = Artifact(
            evidence_id=evidence_id,
            source_tool="regripper",
            artifact_type="usb_device",
            timestamp=ts,
            raw_fields={
                "plugin": plugin,
                "plugin_text": plugin_text,
                "device_serial": serial,
                "friendly_name": friendly,
                "first_connected": first,
                "last_connected": last,
                "tool_version": tool_version,
            },
            normalized_fields=NormalizedFields(
                rule_name=plugin,
                device_serial=serial,
                first_connected=first,
                last_connected=last,
                friendly_name=friendly,
            )
        )
        artifacts.append(usb_art)

    return artifacts


def _extract_usb_details(plugin_text: str, key_path: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    serial: Optional[str] = None
    friendly: Optional[str] = None
    first: Optional[str] = None
    last: Optional[str] = None

    if key_path:
        parts = key_path.split("\\")
        for p in reversed(parts):
            if "&" in p:
                serial = p.split("&")[0]
                break
        if not serial and len(parts) > 1:
            serial = parts[-1]

    for line in plugin_text.splitlines():
        line_lower = line.lower()
        if "friendlyname" in line_lower or "friendly name" in line_lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                friendly = parts[1].strip()
        elif "devicedesc" in line_lower or "device desc" in line_lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                friendly = parts[1].strip()
        elif "serial" in line_lower or "s/n" in line_lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                serial = parts[1].strip()

    timestamps = _TS_RE.findall(plugin_text)
    if timestamps:
        first = timestamps[0]
        last = timestamps[-1] if len(timestamps) > 1 else first

    return serial, friendly, first, last


# ---------------------------------------------------------------------------
# Artifact Factory
# ---------------------------------------------------------------------------

def _make_artifact(
    *,
    evidence_id: str,
    plugin: str,
    plugin_text: str,
    key_path: Optional[str],
    value_name: Optional[str],
    value_data: Optional[str],
    timestamp: Optional[datetime],
    tool_version: str = "unknown",
    source_tool: str = "regripper",
    recmd_record: Optional[dict] = None,
) -> Artifact:
    raw: dict = {
        "plugin": plugin,
        "plugin_text": plugin_text,
        "tool_version": tool_version,
    }
    if recmd_record:
        raw.update(recmd_record)
    if key_path:
        raw["key_path"] = key_path
    if value_name is not None:
        raw["value_name"] = value_name
    if value_data is not None:
        raw["value_data"] = value_data

    display_path: Optional[str] = key_path
    if key_path and value_name:
        display_path = f"{key_path}\\{value_name}"

    p_lower = plugin.lower()
    kp_lower = (key_path or "").lower()

    artifact_type = "registry_key"
    timestamp_type = "modified"

    if p_lower == "userassist" or "userassist" in kp_lower:
        artifact_type = "userassist"
        timestamp_type = "execution"

        encoded_val = value_name or value_data or display_path or ""
        if value_name and value_data:
            encoded_val = f"{value_name}: {value_data}"

        decoded_val = rot13(encoded_val)

        raw["encoded_value"] = encoded_val
        raw["decoded_value"] = decoded_val
        raw["decoding_method"] = "ROT13"

        norm = NormalizedFields(
            file_path=display_path,
            process_name=decoded_val if decoded_val.endswith(".exe") else None,
            process_command_line=decoded_val,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    elif p_lower in ("tasks", "schtasks", "scheduledtasks", "at", "job") or "\\tasks\\" in kp_lower:
        artifact_type = "scheduled_task"
        timestamp_type = "created"
        norm = NormalizedFields(
            file_path=display_path,
            process_command_line=value_data,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    elif p_lower in ("recentdocs", "runmru", "typedpaths", "office") or "\\recentdocs" in kp_lower:
        artifact_type = "recentdocs"
        timestamp_type = "accessed"
        norm = NormalizedFields(
            file_name=value_name,
            file_path=display_path,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    elif p_lower in ("bam", "dam") or "\\services\\bam\\" in kp_lower or "\\services\\dam\\" in kp_lower:
        artifact_type = "bam_dam"
        timestamp_type = "execution"
        norm = NormalizedFields(
            file_path=display_path,
            process_name=value_name,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    elif p_lower == "muicache" or "\\muicache" in kp_lower:
        artifact_type = "muicache"
        timestamp_type = "accessed"
        norm = NormalizedFields(
            file_path=display_path,
            process_name=value_name,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    elif p_lower in ("network", "nic", "networklist", "interfaces", "networkcards") or "\\interfaces\\" in kp_lower or "\\networklist\\" in kp_lower or "\\tcpip\\" in kp_lower:
        artifact_type = "network_configuration"
        timestamp_type = "modified"
        ip_val = value_data if (value_data and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value_data)) else None
        norm = NormalizedFields(
            file_path=display_path,
            src_ip=ip_val,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    elif p_lower in ("services", "svc", "servicedesc") or "\\currentcontrolset\\services\\" in kp_lower:
        artifact_type = "windows_service"
        timestamp_type = "modified"
        norm = NormalizedFields(
            file_path=display_path,
            process_name=value_data if (value_data and value_data.endswith(".exe")) else None,
            process_command_line=value_data,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    else:
        norm = NormalizedFields(
            file_path=display_path,
            registry_key=key_path,
            registry_value=value_name,
            registry_value_data=value_data,
            rule_name=plugin,
        )

    summary = f"Registry [{artifact_type}] ({source_tool}) plugin {plugin}: {display_path or 'N/A'}"

    return Artifact(
        evidence_id=evidence_id,
        source_tool=source_tool,
        artifact_type=artifact_type,
        timestamp=timestamp,
        timestamp_type=timestamp_type,
        event_summary=summary,
        parser_version=tool_version,
        raw_fields=raw,
        normalized_fields=norm,
    )


# ---------------------------------------------------------------------------
# Evasion Indicator: Timestomping Detection
# ---------------------------------------------------------------------------

def _check_timestomping(
    artifacts: list[Artifact],
    evidence_id: str,
    *,
    tool_version: str = "unknown",
) -> list[Artifact]:
    from collections import defaultdict

    indicators: list[Artifact] = []
    by_plugin: dict[str, list[Artifact]] = defaultdict(list)

    for art in artifacts:
        if art.artifact_type not in (
            "registry_key", "userassist", "recentdocs", "bam_dam",
            "muicache", "scheduled_task", "windows_service",
            "network_configuration", "usb_device"
        ):
            continue
        plugin = art.raw_fields.get("plugin") or "unknown"
        by_plugin[plugin].append(art)

    for plugin, arts in by_plugin.items():
        all_timestamps: list[datetime] = []
        plugin_text = ""
        for art in arts:
            pt = art.raw_fields.get("plugin_text") or ""
            if len(pt) > len(plugin_text):
                plugin_text = pt

        raw_ts_strings = _TS_RE.findall(plugin_text)
        for raw in raw_ts_strings:
            ts = _extract_timestamp(raw)
            if ts is not None:
                all_timestamps.append(ts)

        if not all_timestamps:
            continue

        created_ts: Optional[datetime] = None
        modified_ts: Optional[datetime] = None

        for line in plugin_text.splitlines():
            line_l = line.lower().strip()
            ts_in_line_matches = _TS_RE.findall(line)
            if not ts_in_line_matches:
                continue
            ts_in_line = _extract_timestamp(ts_in_line_matches[0])
            if ts_in_line is None:
                continue

            if any(kw in line_l for kw in ("created", "creation", "birth")):
                if created_ts is None or ts_in_line > created_ts:
                    created_ts = ts_in_line
            elif any(kw in line_l for kw in ("modified", "last write", "lastwrite", "last written", "mtime", "modified time")):
                if modified_ts is None or ts_in_line > modified_ts:
                    modified_ts = ts_in_line

        if created_ts is not None and modified_ts is not None:
            if created_ts > modified_ts:
                logger.warning("Evasion indicator: timestomping in plugin %r", plugin)
                indicators.append(Artifact(
                    evidence_id=evidence_id,
                    source_tool="regripper",
                    artifact_type="evasion_indicator",
                    timestamp=created_ts,
                    raw_fields={
                        "indicator": "timestamp_creation_after_modification",
                        "plugin": plugin,
                        "creation_time": created_ts.isoformat(),
                        "modification_time": modified_ts.isoformat(),
                        "delta_seconds": (created_ts - modified_ts).total_seconds(),
                        "tool_version": tool_version,
                        "note": (
                            f"Registry plugin {plugin!r}: creation timestamp ({created_ts.isoformat()}) "
                            f"is later than modification timestamp ({modified_ts.isoformat()}). "
                            "Known indicator of MACB timestomping (T1070.006). "
                            "This is an indicator, not a guarantee of tampering."
                        ),
                    },
                    normalized_fields=NormalizedFields(
                        rule_name="timestomping_creation_after_modification",
                        severity="high",
                    ),
                ))

        if len(all_timestamps) >= 3:
            ts_seconds = set(ts.replace(microsecond=0) for ts in all_timestamps)
            if len(ts_seconds) == 1:
                identical_ts = next(iter(ts_seconds))
                indicators.append(Artifact(
                    evidence_id=evidence_id,
                    source_tool="regripper",
                    artifact_type="evasion_indicator",
                    timestamp=identical_ts,
                    raw_fields={
                        "indicator": "all_timestamps_identical",
                        "plugin": plugin,
                        "common_timestamp": identical_ts.isoformat(),
                        "timestamp_count": len(all_timestamps),
                        "tool_version": tool_version,
                        "note": (
                            f"All {len(all_timestamps)} timestamps in registry plugin {plugin!r} "
                            f"are identical to the second ({identical_ts.isoformat()}). "
                            "This is an indicator, not a guarantee of tampering."
                        ),
                    },
                    normalized_fields=NormalizedFields(
                        rule_name="timestomping_all_timestamps_identical",
                        severity="medium",
                    ),
                ))

    return indicators


# ---------------------------------------------------------------------------
# Timestamp Helper
# ---------------------------------------------------------------------------

def _extract_timestamp(text: str) -> Optional[datetime]:
    m = _TS_RE.search(text)
    if not m:
        return None
    raw = m.group(1)
    normalised = raw.replace("Z", "+0000").replace(" ", "T")
    if len(normalised) > 6 and normalised[-3] == ":":
        normalised = normalised[:-3] + normalised[-2:]
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(normalised, fmt)
        except ValueError:
            continue
    return None
