"""
DPAPI / Credential Manager / Windows Vault Parser
=================================================
Source 41: Credential Manager / Windows Vault + DPAPI
Source Tool: "dpapi_vault_parser"
Artifact Types Produced: "credential_metadata"

Parses DPAPI Masterkey files, Windows Credential Manager files, Windows Vault
policy and record files (.vpol, .vcrd), and raw DPAPI protected data blobs.

Extracts credential metadata (target resource, username/identity, owner SID,
masterkey GUID, encryption/hash algorithms, vault name, and timestamps) without
exposing or fabricating plaintext passwords.

CRITICAL:
1. Encrypted DPAPI blobs and credentials explicitly flag protection status
   (decrypted=False, is_protected=True) and NEVER fabricate successful decryption.
2. No brute-forcing, password guessing, or command execution is ever performed.
3. Credential material is treated as high-confidentiality forensic evidence and is
   read strictly in read-only mode.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)

# DPAPI Provider GUID: {DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}
DPAPI_BLOB_HEADER_BYTES = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb"


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class DpapiVaultNotFoundError(FileNotFoundError):
    """Raised when the specified DPAPI/Vault evidence file does not exist."""


class DpapiVaultParserError(RuntimeError):
    """Raised when parsing fails due to unreadable or corrupt DPAPI/Vault content."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class DpapiVaultParser:
    """Parses DPAPI masterkeys, Credential Manager blobs, and Windows Vault files."""

    GUID_REGEX = re.compile(
        r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"
    )

    ALG_MAP: dict[int, str] = {
        0x6601: "DES",
        0x6603: "3DES",
        0x660e: "AES-128",
        0x660f: "AES-192",
        0x6610: "AES-256",
        0x8003: "MD5",
        0x8004: "SHA1",
        0x800c: "SHA-512",
        0x800e: "SHA-256",
        0x6611: "AES-256",
    }

    def __init__(self) -> None:
        v = get_tool_version("dpapi_vault_parser")
        self._tool_version = v if v != "unknown" else get_tool_version("dpapi_parser")

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse DPAPI/Vault evidence at *file_path* and return Artifact records."""
        src = Path(file_path)
        if not src.exists():
            raise DpapiVaultNotFoundError(f"DPAPI/Vault evidence file not found: {file_path}")

        fn_lower = src.name.lower()
        path_lower = str(src).lower()

        try:
            raw_bytes = src.read_bytes()
        except Exception as exc:
            raise DpapiVaultParserError(f"Failed to read DPAPI/Vault evidence file {src.name}: {exc}")

        if not raw_bytes.strip():
            raise DpapiVaultParserError(f"Empty DPAPI/Vault file: {src.name}")

        user_owner = self._extract_sid_or_user_from_path(str(src))

        # 1. Masterkey file (PREFERRED or GUID filename in \Microsoft\Protect\)
        if fn_lower == "preferred" or ("microsoft\\protect" in path_lower or "microsoft/protect" in path_lower):
            return self._parse_masterkey_bytes(raw_bytes, evidence_id, str(src), user_owner)

        # 2. Windows Vault Policy / Record file (.vpol / .vcrd or Policy.vpol)
        if fn_lower.endswith(".vpol") or fn_lower.endswith(".vcrd") or "microsoft\\vault" in path_lower or "microsoft/vault" in path_lower:
            return self._parse_vault_file_bytes(raw_bytes, evidence_id, str(src), user_owner)

        # 3. Windows Credential file (\Microsoft\Credentials\)
        if "microsoft\\credentials" in path_lower or "microsoft/credentials" in path_lower or len(src.name) == 32:
            return self._parse_credential_file_bytes(raw_bytes, evidence_id, str(src), user_owner)

        # 4. Direct DPAPI Blob signature check
        if raw_bytes.startswith(DPAPI_BLOB_HEADER_BYTES) or b"\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb" in raw_bytes[:32]:
            return self._parse_dpapi_blob_bytes(raw_bytes, evidence_id, str(src), user_owner)

        # 5. In-memory text/JSON/CSV fallback
        return self.parse_content(raw_bytes, evidence_id=evidence_id, file_path=str(src))

    def parse_content(self, content: str | bytes, evidence_id: str = "", file_path: str = "") -> list[Artifact]:
        """Parse in-memory DPAPI/Vault binary, JSON, CSV, or text export content."""
        if isinstance(content, bytes):
            if content.startswith(DPAPI_BLOB_HEADER_BYTES) or b"\xd0\x8c\x9d\xdf\x01\x15\xd1\x11" in content[:32]:
                user_owner = self._extract_sid_or_user_from_path(file_path)
                return self._parse_dpapi_blob_bytes(content, evidence_id, file_path, user_owner)
            text = self._decode_bytes(content)
        else:
            text = str(content)

        text_trimmed = text.strip()
        if not text_trimmed:
            return []

        file_name = os.path.basename(file_path) if file_path else "dpapi_export"
        user_owner = self._extract_sid_or_user_from_path(file_path)

        # Attempt JSON parse (e.g. pre-parsed credential metadata export)
        if text_trimmed.startswith("[") or text_trimmed.startswith("{"):
            try:
                data = json.loads(text_trimmed)
                records = data if isinstance(data, list) else [data]
                artifacts: list[Artifact] = []
                for rec in records:
                    if isinstance(rec, dict):
                        art = self._json_record_to_artifact(rec, evidence_id, file_path, user_owner)
                        if art:
                            artifacts.append(art)
                if artifacts:
                    return artifacts
            except json.JSONDecodeError:
                pass

        # Attempt CSV parse
        if "," in text_trimmed and ("target" in text_trimmed.lower() or "username" in text_trimmed.lower() or "guid" in text_trimmed.lower()):
            try:
                reader = csv.DictReader(text_trimmed.splitlines())
                artifacts: list[Artifact] = []
                for row in reader:
                    if row:
                        art = self._json_record_to_artifact(dict(row), evidence_id, file_path, user_owner)
                        if art:
                            artifacts.append(art)
                if artifacts:
                    return artifacts
            except Exception:
                pass

        # Fallback line-by-line key-value text export parse
        return self._parse_text_export(text_trimmed, evidence_id, file_path, user_owner)

    # ---------------------------------------------------------------------------
    # DPAPI Masterkey Parser
    # ---------------------------------------------------------------------------

    def _parse_masterkey_bytes(
        self, data: bytes, evidence_id: str, file_path: str, user_owner: Optional[str]
    ) -> list[Artifact]:
        file_name = os.path.basename(file_path) if file_path else "PREFERRED"
        ver = self._tool_version

        mtime_dt = None
        if file_path and os.path.exists(file_path):
            try:
                mtime_dt = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except Exception:
                pass

        masterkey_guid = None
        version = None
        cipher_alg = None
        hash_alg = None
        rounds = None

        if file_name.lower() == "preferred" and len(data) >= 16:
            # PREFERRED file contains Masterkey GUID string or binary GUID
            try:
                pref_text = data.decode("ascii", errors="ignore").strip()
                m = self.GUID_REGEX.search(pref_text)
                if m:
                    masterkey_guid = m.group(0)
            except Exception:
                pass

        if not masterkey_guid and len(data) >= 36:
            try:
                version = struct.unpack("<I", data[:4])[0]
                # GUID is at offset 4 (16 bytes) or offset 12
                guid_bytes = data[4:20]
                masterkey_guid = str(uuid.UUID(bytes_le=guid_bytes))

                if len(data) >= 48:
                    hash_alg_id = struct.unpack("<I", data[20:24])[0]
                    cipher_alg_id = struct.unpack("<I", data[28:32])[0]
                    rounds = struct.unpack("<I", data[32:36])[0]
                    hash_alg = self.ALG_MAP.get(hash_alg_id, f"0x{hash_alg_id:04x}")
                    cipher_alg = self.ALG_MAP.get(cipher_alg_id, f"0x{cipher_alg_id:04x}")
            except Exception as exc:
                logger.debug("Failed to parse binary masterkey header in %s: %s", file_name, exc)

        if not masterkey_guid:
            # Fallback search for GUID in string
            m = self.GUID_REGEX.search(file_name + " " + data.decode("latin-1", errors="ignore"))
            if m:
                masterkey_guid = m.group(0)

        raw_payload = {
            "masterkey_guid": masterkey_guid,
            "version": version or 1,
            "hash_algorithm": hash_alg or "SHA-1",
            "cipher_algorithm": cipher_alg or "AES-256",
            "pbkdf_rounds": rounds or 8000,
            "owner_sid": user_owner,
            "is_protected": True,
            "decrypted": False,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            user=user_owner,
            process_command_line=masterkey_guid or "DPAPI Masterkey",
            rule_name="dpapi_masterkey",
        )

        summary = f"DPAPI Masterkey [{masterkey_guid or file_name}]: Owner={user_owner or 'N/A'}, Alg={cipher_alg or 'AES-256'}, Decrypted=False"

        return [
            Artifact(
                evidence_id=evidence_id or "unknown",
                source_tool="dpapi_vault_parser",
                artifact_type="credential_metadata",
                timestamp=mtime_dt,
                timestamp_type="modified" if mtime_dt else "none",
                event_summary=summary,
                raw_fields=raw_payload,
                normalized_fields=norm,
                parser_version=ver,
                confidence_score=1.0,
            )
        ]

    # ---------------------------------------------------------------------------
    # Windows Credential Manager File Parser
    # ---------------------------------------------------------------------------

    def _parse_credential_file_bytes(
        self, data: bytes, evidence_id: str, file_path: str, user_owner: Optional[str]
    ) -> list[Artifact]:
        file_name = os.path.basename(file_path) if file_path else "credential_file"
        ver = self._tool_version

        mtime_dt = None
        if file_path and os.path.exists(file_path):
            try:
                mtime_dt = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except Exception:
                pass

        target_name = None
        username = None
        masterkey_guid = None

        # Extract UTF-16LE strings in credential file header
        u16_strings = self._extract_utf16_strings(data)
        if u16_strings:
            target_name = u16_strings[0] if len(u16_strings) > 0 else None
            username = u16_strings[1] if len(u16_strings) > 1 else None

        # Extract DPAPI Masterkey GUID if present in blob portion
        m = self.GUID_REGEX.search(data.decode("latin-1", errors="ignore"))
        if m:
            masterkey_guid = m.group(0)

        # Parse FILETIME if present at offset 16-24
        filetime_dt = None
        if len(data) >= 24:
            ft_raw = struct.unpack("<Q", data[16:24])[0]
            filetime_dt = self._filetime_to_dt(ft_raw)

        dt = filetime_dt or mtime_dt

        raw_payload = {
            "credential_file": file_name,
            "target_name": target_name or file_name,
            "username": username or user_owner,
            "owner_sid": user_owner,
            "masterkey_guid": masterkey_guid,
            "is_protected": True,
            "decrypted": False,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            user=username or user_owner,
            process_command_line=target_name or file_name,
            rule_name="credential_blob",
        )

        summary = f"Windows Credential Blob [{target_name or file_name}]: User={username or user_owner or 'N/A'}, Decrypted=False"

        return [
            Artifact(
                evidence_id=evidence_id or "unknown",
                source_tool="dpapi_vault_parser",
                artifact_type="credential_metadata",
                timestamp=dt,
                timestamp_type="modified" if dt else "none",
                event_summary=summary,
                raw_fields=raw_payload,
                normalized_fields=norm,
                parser_version=ver,
                confidence_score=1.0,
            )
        ]

    # ---------------------------------------------------------------------------
    # Windows Vault File Parser (.vpol / .vcrd)
    # ---------------------------------------------------------------------------

    def _parse_vault_file_bytes(
        self, data: bytes, evidence_id: str, file_path: str, user_owner: Optional[str]
    ) -> list[Artifact]:
        file_name = os.path.basename(file_path) if file_path else "vault_file"
        ver = self._tool_version

        mtime_dt = None
        if file_path and os.path.exists(file_path):
            try:
                mtime_dt = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except Exception:
                pass

        vault_guid = None
        schema_guid = None
        target = None
        identity = None

        guids = self.GUID_REGEX.findall(data.decode("latin-1", errors="ignore"))
        if guids:
            vault_guid = guids[0]
            if len(guids) > 1:
                schema_guid = guids[1]

        u16_strings = self._extract_utf16_strings(data)
        if u16_strings:
            target = u16_strings[0]
            if len(u16_strings) > 1:
                identity = u16_strings[1]

        raw_payload = {
            "vault_file": file_name,
            "vault_guid": vault_guid,
            "schema_guid": schema_guid,
            "target_resource": target or file_name,
            "identity": identity or user_owner,
            "owner_sid": user_owner,
            "is_protected": True,
            "decrypted": False,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            user=identity or user_owner,
            registry_key=vault_guid,
            process_command_line=target or file_name,
            rule_name="windows_vault_record",
        )

        summary = f"Windows Vault Record [{target or file_name}]: Vault={vault_guid or 'N/A'}, User={identity or user_owner or 'N/A'}, Decrypted=False"

        return [
            Artifact(
                evidence_id=evidence_id or "unknown",
                source_tool="dpapi_vault_parser",
                artifact_type="credential_metadata",
                timestamp=mtime_dt,
                timestamp_type="modified" if mtime_dt else "none",
                event_summary=summary,
                raw_fields=raw_payload,
                normalized_fields=norm,
                parser_version=ver,
                confidence_score=1.0,
            )
        ]

    # ---------------------------------------------------------------------------
    # Raw DPAPI Protected Blob Parser
    # ---------------------------------------------------------------------------

    def _parse_dpapi_blob_bytes(
        self, data: bytes, evidence_id: str, file_path: str, user_owner: Optional[str]
    ) -> list[Artifact]:
        file_name = os.path.basename(file_path) if file_path else "dpapi_blob.bin"
        ver = self._tool_version

        mtime_dt = None
        if file_path and os.path.exists(file_path):
            try:
                mtime_dt = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc)
            except Exception:
                pass

        version = struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 1
        provider_guid = "{DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}"
        masterkey_guid = None
        cipher_alg = "AES-256"
        hash_alg = "SHA-512"

        if len(data) >= 36:
            try:
                # Masterkey GUID is 16 bytes at offset 20
                mk_bytes = data[20:36]
                masterkey_guid = str(uuid.UUID(bytes_le=mk_bytes))
            except Exception:
                pass

        if len(data) >= 44:
            try:
                cipher_alg_id = struct.unpack("<I", data[36:40])[0]
                hash_alg_id = struct.unpack("<I", data[40:44])[0]
                cipher_alg = self.ALG_MAP.get(cipher_alg_id, f"0x{cipher_alg_id:04x}")
                hash_alg = self.ALG_MAP.get(hash_alg_id, f"0x{hash_alg_id:04x}")
            except Exception:
                pass

        raw_payload = {
            "blob_header": "DPAPI_BLOB",
            "version": version,
            "provider_guid": provider_guid,
            "masterkey_guid": masterkey_guid,
            "cipher_algorithm": cipher_alg,
            "hash_algorithm": hash_alg,
            "payload_bytes_len": len(data),
            "owner_sid": user_owner,
            "is_protected": True,
            "decrypted": False,
            "tool_version": ver,
        }

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            user=user_owner,
            registry_key=provider_guid,
            process_command_line=masterkey_guid or "DPAPI Protected Data Blob",
            rule_name="dpapi_protected_blob",
        )

        summary = f"DPAPI Protected Blob: Masterkey={masterkey_guid or 'N/A'}, Alg={cipher_alg}, Decrypted=False"

        return [
            Artifact(
                evidence_id=evidence_id or "unknown",
                source_tool="dpapi_vault_parser",
                artifact_type="credential_metadata",
                timestamp=mtime_dt,
                timestamp_type="modified" if mtime_dt else "none",
                event_summary=summary,
                raw_fields=raw_payload,
                normalized_fields=norm,
                parser_version=ver,
                confidence_score=1.0,
            )
        ]

    # ---------------------------------------------------------------------------
    # JSON / Export Record Parser
    # ---------------------------------------------------------------------------

    def _json_record_to_artifact(
        self, rec: dict[str, Any], evidence_id: str, file_path: str, user_owner: Optional[str]
    ) -> Optional[Artifact]:
        target = rec.get("Target") or rec.get("target") or rec.get("TargetName") or rec.get("Resource")
        username = rec.get("Username") or rec.get("user") or rec.get("User") or rec.get("Identity")
        mk_guid = rec.get("MasterKeyGUID") or rec.get("masterkey_guid") or rec.get("GUID")
        decrypted = bool(rec.get("decrypted", False))
        ts_val = rec.get("LastModified") or rec.get("Timestamp") or rec.get("Date")

        dt = self._parse_timestamp_str(str(ts_val)) if ts_val else None

        file_name = os.path.basename(file_path) if file_path else "credential_export"
        ver = self._tool_version

        raw_payload = dict(rec)
        raw_payload["is_protected"] = not decrypted
        raw_payload["decrypted"] = decrypted
        raw_payload["tool_version"] = ver

        norm = NormalizedFields(
            file_name=file_name,
            file_path=file_path or None,
            user=username or user_owner,
            process_command_line=target or mk_guid or "Credential Export Entry",
            rule_name="credential_export_record",
        )

        summary = f"Credential Metadata [{target or 'Credential'}]: User={username or user_owner or 'N/A'}, Decrypted={decrypted}"

        return Artifact(
            evidence_id=evidence_id or "unknown",
            source_tool="dpapi_vault_parser",
            artifact_type="credential_metadata",
            timestamp=dt,
            timestamp_type="event" if dt else "none",
            event_summary=summary,
            raw_fields=raw_payload,
            normalized_fields=norm,
            parser_version=ver,
            confidence_score=1.0,
        )

    # ---------------------------------------------------------------------------
    # Text Export Parser
    # ---------------------------------------------------------------------------

    def _parse_text_export(
        self, text: str, evidence_id: str, file_path: str, user_owner: Optional[str]
    ) -> list[Artifact]:
        lines = text.splitlines()
        file_name = os.path.basename(file_path) if file_path else "dpapi_export.txt"
        ver = self._tool_version
        artifacts: list[Artifact] = []

        cur_rec: dict[str, Any] = {}
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if "=" in line_str or ":" in line_str:
                sep = "=" if "=" in line_str else ":"
                k, _, v = line_str.partition(sep)
                cur_rec[k.strip()] = v.strip()
            elif "credential" in line_str.lower() or "masterkey" in line_str.lower():
                if cur_rec:
                    art = self._json_record_to_artifact(cur_rec, evidence_id, file_path, user_owner)
                    if art:
                        artifacts.append(art)
                    cur_rec = {}
                cur_rec["Target"] = line_str

        if cur_rec:
            art = self._json_record_to_artifact(cur_rec, evidence_id, file_path, user_owner)
            if art:
                artifacts.append(art)

        return artifacts

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _decode_bytes(self, data: bytes) -> str:
        if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff") or (len(data) > 1 and data[1:2] == b"\x00"):
            try:
                return data.decode("utf-16")
            except Exception:
                pass
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                return data.decode(enc)
            except Exception:
                continue
        return data.decode("latin-1", errors="replace")

    def _extract_utf16_strings(self, data: bytes) -> list[str]:
        results: list[str] = []
        try:
            # Find contiguous UTF-16LE printable string sequences
            pattern = re.compile(b"(?:[\x20-\x7e]\x00){3,}")
            matches = pattern.findall(data)
            for m in matches:
                decoded = m.decode("utf-16le", errors="ignore").strip()
                if len(decoded) >= 3 and not decoded.startswith("{"):
                    results.append(decoded)
        except Exception:
            pass
        return results

    def _extract_sid_or_user_from_path(self, path_str: str) -> Optional[str]:
        # Match S-1-5... SID in path first
        sid_match = re.search(r"(S-1-5-[0-9-]+)", path_str, re.IGNORECASE)
        if sid_match:
            return sid_match.group(1).rstrip("-")

        # Match user folder in path (exclude system / default / temp folders)
        m = re.search(r"[\\/]Users[\\/]([^\\/]+)[\\/]", path_str, re.IGNORECASE)
        if m:
            u = m.group(1)
            if u.lower() not in ("public", "default", "default user", "all users", "temp", "appdata"):
                return u
        return None

    def _filetime_to_dt(self, ft: int) -> Optional[datetime]:
        if ft <= 0 or ft > 0x7FFFFFFFFFFFFFFF:
            return None
        try:
            secs = (ft - 116444736000000000) / 10000000.0
            return datetime.fromtimestamp(secs, tz=timezone.utc)
        except Exception:
            return None

    def _parse_timestamp_str(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        ts_clean = ts_str.strip().replace("Z", "+00:00")
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ):
            try:
                dt = datetime.strptime(ts_clean.split("+")[0].split("Z")[0].strip(), fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        try:
            dt = datetime.fromisoformat(ts_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None
