# PCAP / network capture parser — Zeek + Suricata
# Source tools: "zeek", "suricata"
# Artifact types produced:
#   Zeek:     "network_connection", "dns_query", "http_request"
#   Suricata: "ids_alert"
# Raw output formats:
#   Zeek     — tab-separated Zeek log files (conn.log, dns.log, http.log)
#   Suricata — eve.json (JSONL, one event object per line)
#
# Zeek log format reference:
#   https://docs.zeek.org/en/master/logs/index.html
# Suricata EVE JSON reference:
#   https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


def _to_wsl_path(path: Path) -> str:
    """Convert a Windows Path to a WSL /mnt/<drive>/... path."""
    p = path.resolve()
    if p.drive:
        drive = p.drive.rstrip(":").lower()
        rel = str(p.relative_to(p.anchor)).replace("\\", "/")
        return f"/mnt/{drive}/{rel}"
    return str(p).replace("\\", "/")


# ---------------------------------------------------------------------------
# Typed errors
# ---------------------------------------------------------------------------

class ZeekNotFoundError(FileNotFoundError):
    """Raised when the `zeek` binary cannot be found on PATH."""


class ZeekExecutionError(RuntimeError):
    """Raised when Zeek exits with a non-zero return code."""


class SuricataNotFoundError(FileNotFoundError):
    """Raised when the `suricata` binary cannot be found on PATH."""


class SuricataExecutionError(RuntimeError):
    """Raised when Suricata exits with a non-zero return code."""


# ---------------------------------------------------------------------------
# Zeek log → artifact_type mapping
# Each entry: (log_filename, artifact_type, field_extractor_method_name)
# ---------------------------------------------------------------------------
_ZEEK_LOGS: list[tuple[str, str]] = [
    ("conn.log",  "network_connection"),
    ("dns.log",   "dns_query"),
    ("http.log",  "http_request"),
    ("ssl.log",   "ssl_handshake"),
    ("files.log", "file_transfer"),
    ("weird.log", "network_anomaly"),
]

# Zeek timestamps are Unix epoch floats (e.g. 1710490931.123456)
# Suricata timestamps are ISO-8601 strings (e.g. "2024-03-15T08:22:11.123456+0000")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class PcapParser:
    """Parses PCAP / PCAPNG capture files via Zeek and Suricata into Artifact records.

    Two internal analysis passes are run:

    **Zeek pass** (``_parse_with_zeek``):
        Runs ``zeek -r <pcap>`` in a temporary working directory.
        Reads six log files in Zeek's native tab-separated format:
        - ``conn.log``  → ``artifact_type="network_connection"``
        - ``dns.log``   → ``artifact_type="dns_query"``
        - ``http.log``  → ``artifact_type="http_request"``
        - ``ssl.log``   → ``artifact_type="ssl_handshake"``
        - ``files.log`` → ``artifact_type="file_transfer"``
        - ``weird.log`` → ``artifact_type="network_anomaly"``

    **Suricata pass** (``_parse_with_suricata``):
        Runs ``suricata -r <pcap> -l <tmp_dir>`` (offline replay mode).
        Reads ``eve.json`` — a JSONL file containing alerts, flows, dns, http, tls,
        fileinfo, and custom events without dropping non-alert lines.
    """

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the PCAP file at *file_path* and return a combined list of Artifacts."""
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        self._zeek_version = get_tool_version("zeek")
        self._suricata_version = get_tool_version("suricata")

        artifacts: list[Artifact] = []
        artifacts.extend(self._parse_with_zeek(src, evidence_id))
        artifacts.extend(self._parse_with_suricata(src, evidence_id))

        logger.info(
            "PcapParser total: %d artifacts from %s", len(artifacts), src.name
        )
        return artifacts

    # -----------------------------------------------------------------------
    # Zeek pass
    # -----------------------------------------------------------------------

    def _parse_with_zeek(self, pcap_path: Path, evidence_id: str) -> list[Artifact]:
        """Run Zeek offline against *pcap_path* and parse the resulting log files."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_zeek_"))
        try:
            self._run_zeek(pcap_path, tmp_dir)
            return self._read_zeek_logs(tmp_dir, evidence_id)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _run_zeek(self, pcap_path: Path, cwd: Path) -> None:
        """Execute ``zeek -r <pcap>`` in *cwd*."""
        import sys
        binary = shutil.which("zeek")
        run_cwd = str(cwd)

        if binary:
            cmd = [binary, "-r", str(pcap_path)]
        elif sys.platform == "win32":
            try:
                r = subprocess.run(["wsl", "bash", "-lc", "which zeek"], capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and r.stdout.strip():
                    wsl_pcap = _to_wsl_path(pcap_path)
                    wsl_cwd = _to_wsl_path(cwd)
                    cmd = ["wsl", "bash", "-lc", f"cd '{wsl_cwd}' && zeek -r '{wsl_pcap}'"]
                    run_cwd = None
                else:
                    raise ZeekNotFoundError("Zeek binary not found on PATH or WSL.")
            except FileNotFoundError:
                raise ZeekNotFoundError("Zeek binary not found on PATH or WSL.")
        else:
            cmd = ["zeek", "-r", str(pcap_path)]

        logger.debug("Running Zeek: %s (cwd=%s)", " ".join(cmd), cwd)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=run_cwd,
                timeout=300,
            )
        except FileNotFoundError:
            raise ZeekNotFoundError(
                "Zeek binary not found on PATH. "
                "Install from https://zeek.org/get-zeek and ensure `zeek` is on PATH."
            )
        if result.returncode != 0:
            raise ZeekExecutionError(
                f"Zeek exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )
        logger.info("Zeek finished: pcap=%s cwd=%s", pcap_path.name, cwd)

    def _read_zeek_logs(self, log_dir: Path, evidence_id: str) -> list[Artifact]:
        """Read conn.log, dns.log, http.log, ssl.log, files.log, weird.log from *log_dir*."""
        artifacts: list[Artifact] = []
        for log_name, artifact_type in _ZEEK_LOGS:
            log_path = log_dir / log_name
            if not log_path.exists():
                logger.debug("Zeek log not found (no records): %s", log_path)
                continue
            count_before = len(artifacts)
            artifacts.extend(
                self._parse_zeek_log(log_path, artifact_type, evidence_id)
            )
            logger.info(
                "Zeek %s: %d records", log_name, len(artifacts) - count_before
            )
        return artifacts

    def _parse_zeek_log(
        self, log_path: Path, artifact_type: str, evidence_id: str
    ) -> list[Artifact]:
        """Parse one Zeek tab-separated log file into Artifacts."""
        fields: list[str] = []
        separator = "\t"
        artifacts: list[Artifact] = []

        with log_path.open(encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")

                if line.startswith("#separator"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        sep_raw = parts[1].strip()
                        separator = _decode_zeek_sep(sep_raw)
                    continue

                if line.startswith("#fields"):
                    fields = line[len("#fields"):].strip().split(separator)
                    continue

                if line.startswith("#"):
                    continue

                if not line.strip():
                    continue

                values = line.split(separator)
                values += ["-"] * (len(fields) - len(values))
                record = {
                    k: (None if v in ("-", "(empty)") else v)
                    for k, v in zip(fields, values)
                }

                artifacts.append(
                    self._zeek_record_to_artifact(
                        record, artifact_type, evidence_id
                    )
                )

        return artifacts

    def _zeek_record_to_artifact(
        self, record: dict, artifact_type: str, evidence_id: str
    ) -> Artifact:
        """Map one Zeek record dict to an :class:`Artifact`."""
        ver = getattr(self, "_zeek_version", get_tool_version("zeek"))
        summary = f"Zeek {artifact_type} ({record.get('id.orig_h')}:{record.get('id.orig_p')} -> {record.get('id.resp_h')}:{record.get('id.resp_p')})"
        return Artifact(
            evidence_id=evidence_id,
            source_tool="zeek",
            artifact_type=artifact_type,
            timestamp=_parse_zeek_ts(record.get("ts")),
            timestamp_type="event",
            event_summary=summary,
            parser_version=ver,
            raw_fields={**record, "tool_version": ver},
            normalized_fields=_zeek_normalize(record, artifact_type),
        )

    # -----------------------------------------------------------------------
    # Suricata pass
    # -----------------------------------------------------------------------

    def _parse_with_suricata(
        self, pcap_path: Path, evidence_id: str
    ) -> list[Artifact]:
        """Run Suricata offline against *pcap_path* and parse eve.json events."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="argus_suricata_"))
        try:
            self._run_suricata(pcap_path, tmp_dir)
            eve_path = tmp_dir / "eve.json"
            if not eve_path.exists():
                logger.warning(
                    "Suricata produced no eve.json in %s", tmp_dir
                )
                return []
            return self._parse_eve_json(eve_path, evidence_id)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _run_suricata(self, pcap_path: Path, log_dir: Path) -> None:
        """Execute ``suricata -r <pcap> -l <log_dir> -q``."""
        import sys
        binary = shutil.which("suricata")

        if binary:
            cmd = [
                binary,
                "-r", str(pcap_path),
                "-l", str(log_dir),
                "-q",   # quiet — suppress informational progress output
            ]
        elif sys.platform == "win32":
            try:
                r = subprocess.run(["wsl", "bash", "-lc", "which suricata"], capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and r.stdout.strip():
                    wsl_pcap = _to_wsl_path(pcap_path)
                    wsl_log = _to_wsl_path(log_dir)
                    cmd = ["wsl", "bash", "-lc", f"suricata -r '{wsl_pcap}' -l '{wsl_log}' -q"]
                else:
                    raise SuricataNotFoundError("Suricata binary not found on PATH or WSL.")
            except FileNotFoundError:
                raise SuricataNotFoundError("Suricata binary not found on PATH or WSL.")
        else:
            cmd = ["suricata", "-r", str(pcap_path), "-l", str(log_dir), "-q"]

        logger.debug("Running Suricata: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            raise SuricataNotFoundError(
                "Suricata binary not found on PATH. "
                "Install from https://suricata.io and ensure `suricata` is on PATH."
            )
        if result.returncode != 0:
            raise SuricataExecutionError(
                f"Suricata exited with code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()[:500]}\n"
                f"stderr: {result.stderr.strip()[:500]}"
            )
        logger.info(
            "Suricata finished: pcap=%s log_dir=%s", pcap_path.name, log_dir
        )

    def _parse_eve_json(
        self, eve_path: Path, evidence_id: str
    ) -> list[Artifact]:
        """Read Suricata's eve.json (JSONL) and return Artifact records for ALL event types."""
        artifacts: list[Artifact] = []

        with eve_path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    event: dict = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Suricata eve.json line %d — malformed JSON: %s",
                        lineno, exc,
                    )
                    continue

                artifacts.append(
                    self._suricata_event_to_artifact(event, evidence_id)
                )

        logger.info(
            "Suricata eve.json: %d artifacts from %s",
            len(artifacts), eve_path,
        )
        return artifacts

    def _suricata_event_to_artifact(
        self, event: dict, evidence_id: str
    ) -> Artifact:
        """Map one Suricata EVE event to an :class:`Artifact`."""
        event_type = event.get("event_type", "event")
        ver = getattr(self, "_suricata_version", get_tool_version("suricata"))

        type_map = {
            "alert": "ids_alert",
            "flow": "network_flow",
            "dns": "dns_query",
            "http": "http_request",
            "tls": "ssl_handshake",
            "fileinfo": "file_transfer",
        }
        artifact_type = type_map.get(event_type, "network_event")

        if event_type == "alert":
            alert = event.get("alert", {})
            sig = alert.get("signature") or "IDS Alert"
            summary = f"Suricata alert: {sig} ({event.get('src_ip')} -> {event.get('dest_ip')})"
        else:
            summary = f"Suricata {event_type}: ({event.get('src_ip')}:{event.get('src_port')} -> {event.get('dest_ip')}:{event.get('dest_port')})"

        return Artifact(
            evidence_id=evidence_id,
            source_tool="suricata",
            artifact_type=artifact_type,
            timestamp=_parse_iso_ts(event.get("timestamp")),
            timestamp_type="event",
            event_summary=summary,
            parser_version=ver,
            raw_fields={**event, "tool_version": ver},
            normalized_fields=_suricata_normalize(event),
        )

    _suricata_alert_to_artifact = _suricata_event_to_artifact


# ---------------------------------------------------------------------------
# Module-level field-mapping helpers
# ---------------------------------------------------------------------------

def _decode_zeek_sep(raw: str) -> str:
    """Convert Zeek's separator notation to the actual character."""
    import re as _re
    m = _re.fullmatch(r'\\x([0-9a-fA-F]{2})', raw)
    if m:
        return chr(int(m.group(1), 16))
    return raw


def _zeek_normalize(record: dict, artifact_type: str) -> NormalizedFields:
    """Extract correlation fields from a Zeek record based on artifact_type."""
    if artifact_type == "network_connection":
        return NormalizedFields(
            src_ip=record.get("id.orig_h"),
            dst_ip=record.get("id.resp_h"),
            src_port=_to_int(record.get("id.orig_p")),
            dst_port=_to_int(record.get("id.resp_p")),
        )
    if artifact_type == "dns_query":
        return NormalizedFields(
            src_ip=record.get("id.orig_h"),
            dst_ip=record.get("id.resp_h"),
            domain=record.get("query"),
        )
    if artifact_type == "http_request":
        host = record.get("host")
        uri  = record.get("uri") or ""
        url  = f"http://{host}{uri}" if host else uri or None
        return NormalizedFields(
            src_ip=record.get("id.orig_h"),
            dst_ip=record.get("id.resp_h"),
            dst_port=_to_int(record.get("id.resp_p")),
            domain=host,
            url=url,
        )
    if artifact_type == "ssl_handshake":
        return NormalizedFields(
            src_ip=record.get("id.orig_h"),
            dst_ip=record.get("id.resp_h"),
            src_port=_to_int(record.get("id.orig_p")),
            dst_port=_to_int(record.get("id.resp_p")),
            domain=record.get("server_name"),
        )
    if artifact_type == "file_transfer":
        fn = record.get("filename")
        return NormalizedFields(
            file_name=fn,
            file_path=fn,
        )
    if artifact_type == "network_anomaly":
        return NormalizedFields(
            src_ip=record.get("id.orig_h"),
            dst_ip=record.get("id.resp_h"),
            src_port=_to_int(record.get("id.orig_p")),
            dst_port=_to_int(record.get("id.resp_p")),
        )
    return NormalizedFields()


def _suricata_normalize(event: dict) -> NormalizedFields:
    """Extract correlation fields from a Suricata EVE event."""
    event_type = event.get("event_type")
    src_ip = event.get("src_ip")
    dst_ip = event.get("dest_ip")
    src_port = _to_int(event.get("src_port"))
    dst_port = _to_int(event.get("dest_port"))

    if event_type == "alert":
        alert = event.get("alert", {})
        severity_map = {1: "high", 2: "medium", 3: "low"}
        sev_int = alert.get("severity")
        severity = severity_map.get(sev_int, str(sev_int)) if sev_int is not None else None
        return NormalizedFields(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            rule_name=alert.get("signature"),
            severity=severity,
        )

    if event_type == "dns":
        dns = event.get("dns", {})
        domain = dns.get("rrname") or event.get("rrname")
        return NormalizedFields(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            domain=domain,
        )

    if event_type == "http":
        http = event.get("http", {})
        hostname = http.get("hostname") or event.get("hostname")
        url = http.get("url") or event.get("url")
        if hostname and url and not url.startswith("http"):
            full_url = f"http://{hostname}{url}"
        else:
            full_url = url
        return NormalizedFields(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            domain=hostname,
            url=full_url,
        )

    if event_type == "tls":
        tls = event.get("tls", {})
        sni = tls.get("sni") or event.get("sni")
        return NormalizedFields(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            domain=sni,
        )

    if event_type == "fileinfo":
        fileinfo = event.get("fileinfo", {})
        fn = fileinfo.get("filename") or event.get("filename")
        return NormalizedFields(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            file_name=fn,
            file_path=fn,
        )

    return NormalizedFields(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def _parse_zeek_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse a Zeek Unix-epoch float timestamp string to a datetime."""
    if raw is None:
        return None
    try:
        epoch = float(raw)
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        logger.debug("Unrecognised Zeek timestamp: %r", raw)
        return None


def _parse_iso_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse a Suricata ISO-8601 timestamp string to a datetime.

    Suricata emits e.g. ``"2024-03-15T08:22:11.123456+0000"``.
    """
    if not raw:
        return None
    # Normalise colon in tz offset: +00:00 → +0000
    normalised = raw.strip()
    if len(normalised) > 6 and normalised[-3] == ":":
        normalised = normalised[:-3] + normalised[-2:]
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            return datetime.strptime(normalised, fmt)
        except ValueError:
            continue
    logger.debug("Unrecognised Suricata timestamp: %r", raw)
    return None


def _to_int(value) -> Optional[int]:
    """Convert value to int, returning None on failure."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None
