"""
Preprocessing Artifact Normalizer
==================================
Ensures semantic consistency across Artifact fields produced by different parsers.
Does NOT touch `raw_fields` (evidentiary source of truth).
"""

from __future__ import annotations

import re
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional

from preprocessing.schemas import Artifact, NormalizedFields

logger = logging.getLogger(__name__)


class Normalizer:
    """Consistently normalizes fields across parsed forensic Artifact records.

    1. Normalizes `timestamp` to timezone-aware UTC datetime.
    2. Lowercases `host` and splits FQDN domain suffixes into `domain`.
    3. Normalizes IP addresses (resolves IPv6-mapped IPv4 to IPv4 dotted-quads).
    4. Leaves `raw_fields` completely untouched.
    """

    def normalize(self, artifacts: list[Artifact]) -> list[Artifact]:
        """Normalize a list of Artifact records in-place.

        Args:
            artifacts: List of Artifact objects to process.

        Returns:
            The same list of Artifact objects with normalized values.
        """
        for art in artifacts:
            # 1. Normalize timestamp to timezone-aware UTC
            if art.timestamp is not None:
                art.timestamp = self._normalize_timestamp(art.timestamp)

            # 2. Normalize normalized_fields
            self._normalize_fields(art.normalized_fields)

        return artifacts

    def _normalize_timestamp(self, ts: datetime | str | int | float) -> Optional[datetime]:
        """Convert various timestamp formats to a timezone-aware UTC datetime."""
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc)

        if isinstance(ts, (int, float)):
            try:
                # Handle microsecond / millisecond epochs or standard seconds
                if ts > 1e11:  # Micro/milliseconds epoch
                    ts = ts / 1e6 if ts > 1e14 else ts / 1e3
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except Exception:
                return None

        if isinstance(ts, str):
            s = ts.strip()
            if not s or s == "0":
                return None
            # Standardize UTC suffix
            s = s.replace(" UTC", "+0000").replace("UTC", "+0000").replace(" ", "T")
            if len(s) > 6 and s[-3] == ":":
                s = s[:-3] + s[-2:]
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
            ):
                try:
                    dt = datetime.strptime(s, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.astimezone(timezone.utc)
                except ValueError:
                    continue
        return None

    def serialize_artifact_to_json(self, artifact: Artifact) -> str:
        """Serialize an Artifact to deterministic canonical Layer 2 JSON string."""
        return artifact.model_dump_json(indent=None, exclude_none=False)

    def serialize_artifacts_to_json(self, artifacts: list[Artifact]) -> str:
        """Serialize a list of Artifact records to a canonical JSON array string."""
        import json
        records = [art.model_dump(mode="json") for art in artifacts]
        return json.dumps(records, ensure_ascii=False)

    def _normalize_fields(self, nf: NormalizedFields) -> None:
        """Normalize correlation fields inside NormalizedFields in-place."""
        # 1. Host and Domain normalization
        if nf.host:
            host_str = str(nf.host).strip()
            if not self._is_ip_address(host_str):
                host_lower = host_str.lower()
                if "." in host_lower:
                    parts = host_lower.split(".", 1)
                    nf.host = parts[0]
                    if not nf.domain:
                        nf.domain = parts[1]
                else:
                    nf.host = host_lower

        # Lowercase domain if present
        if nf.domain:
            nf.domain = str(nf.domain).strip().lower()

        # 2. IP address normalization
        if nf.src_ip:
            nf.src_ip = self._normalize_ip(str(nf.src_ip))
        if nf.dst_ip:
            nf.dst_ip = self._normalize_ip(str(nf.dst_ip))

        # 3. Numeric type coercions (int)
        if nf.process_id is not None:
            nf.process_id = self._to_int(nf.process_id)
        if nf.parent_process_id is not None:
            nf.parent_process_id = self._to_int(nf.parent_process_id)
        if nf.src_port is not None:
            nf.src_port = self._to_int(nf.src_port)
        if nf.dst_port is not None:
            nf.dst_port = self._to_int(nf.dst_port)

        # 4. Hash and Severity lowercasing
        if nf.hash:
            nf.hash = str(nf.hash).strip().lower()
        if nf.severity:
            sev_raw = str(nf.severity).strip().lower()
            severity_map = {"1": "high", "2": "medium", "3": "low", "4": "informational"}
            nf.severity = severity_map.get(sev_raw, sev_raw)

        # 5. String field trimming
        if nf.user:
            nf.user = str(nf.user).strip()
        if nf.file_path:
            nf.file_path = str(nf.file_path).strip()
        if nf.file_name:
            nf.file_name = str(nf.file_name).strip()
        if nf.url:
            nf.url = str(nf.url).strip()
        if nf.registry_key:
            nf.registry_key = str(nf.registry_key).strip()

    def _to_int(self, value: object) -> Optional[int]:
        """Safely convert numeric value (string, float, int) to int, or None if invalid."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        try:
            val_str = str(value).strip()
            if not val_str:
                return None
            return int(float(val_str))
        except (ValueError, TypeError, OverflowError):
            return None

    def _normalize_ip(self, ip_str: str) -> str:
        """Normalize IP address format (handles IPv6-mapped IPv4)."""
        ip = ip_str.strip()
        try:
            # Let ipaddress module handle standard conversions
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv6Address):
                # Native mapped property (RFC 4291)
                if addr.ipv4_mapped:
                    return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            # Fallback for scoping (e.g. fe80::1%eth0)
            if "%" in ip:
                ip = ip.split("%")[0]
            # Manual regex check for ::ffff:192.168.1.1
            ip_lower = ip.lower()
            if ip_lower.startswith("::ffff:"):
                part = ip[7:]
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                    return part
            return ip_lower

    def _is_ip_address(self, s: str) -> bool:
        """Return True if string represents an IPv4 or IPv6 address."""
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
            return True
        if ":" in s:
            return True
        return False

