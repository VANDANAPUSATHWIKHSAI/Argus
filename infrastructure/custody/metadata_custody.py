"""
STAGE 4 — Metadata Extraction + Chain of Custody
Extracts file metadata and appends to the evidentiary custody log (append-only).
"""

import os
import mimetypes
import hashlib
from datetime import datetime
from infrastructure.schemas import Evidence, EvidenceStatus, CustodyLogEntry


def extract_metadata_and_log_custody(evidence: Evidence) -> Evidence:
    """
    1. Extract file-level metadata into evidence.metadata
    2. Append ONE CustodyLogEntry — custody_log is APPEND-ONLY, never edit past entries
    3. Set status = METADATA_EXTRACTED
    """
    ext = os.path.splitext(evidence.filename)[1].lower()
    mime_type, _ = mimetypes.guess_type(evidence.filename)

    # Retrieve pre-extracted metadata from Stage 3
    pre_metadata = evidence.metadata or {}
    size_bytes = pre_metadata.get("size_bytes", 0)
    format_specific = pre_metadata.get("format_specific", {})

    evidence.metadata = {
        "size_bytes":        size_bytes,
        "extension":         ext,
        "mime_type":         mime_type or "application/octet-stream",
        "original_filename": evidence.filename,
        "uploaded_at":       evidence.upload_timestamp.isoformat(),
        "sha256_hash":       evidence.sha256_hash,
        "encrypted":         evidence.encrypted,
        # Format-specific metadata below (add more as parsers are built)
        **format_specific,
    }

    # ── Append custody log entry (NEVER remove or edit past entries) ─
    evidence.custody_log.append(CustodyLogEntry(
        actor="metadata_custody",
        action="metadata_extracted",
        notes=f"size={size_bytes}B mime={mime_type or 'unknown'}",
    ))

    evidence.status = EvidenceStatus.METADATA_EXTRACTED
    print(f"  [4/5] METADATA   {evidence.filename}  "
          f"size={size_bytes}B  mime={mime_type or 'unknown'}")
    return evidence


def _format_metadata(file_path: str, ext: str) -> dict:
    """
    Format-specific metadata extraction.
    Each block is independent — a failure in one doesn't break the others.
    """
    extra = {}

    # ── ZIP / archive ─────────────────────────────────────────────
    if ext == ".zip":
        try:
            import zipfile
            with zipfile.ZipFile(file_path, "r") as zf:
                extra["zip_entry_count"] = len(zf.infolist())
                extra["zip_entries"] = [i.filename for i in zf.infolist()[:20]]
        except Exception:
            pass

    # ── PCAP ──────────────────────────────────────────────────────
    elif ext in {".pcap", ".pcapng"}:
        try:
            # Basic header-only read (no pyshark needed for metadata)
            with open(file_path, "rb") as f:
                magic = f.read(4)
            pcap_magic = {
                b"\xd4\xc3\xb2\xa1": "pcap_le",
                b"\xa1\xb2\xc3\xd4": "pcap_be",
                b"\x0a\x0d\x0d\x0a": "pcapng",
            }
            extra["pcap_format"] = pcap_magic.get(magic, "unknown")
        except Exception:
            pass

    # ── Windows Event Log (.evtx) ─────────────────────────────────
    elif ext == ".evtx":
        extra["format_note"] = "Windows Event Log — parsed by evtx_parser in preprocessing"

    # ── Memory dump ───────────────────────────────────────────────
    elif ext in {".raw", ".dmp", ".mem"}:
        extra["format_note"] = "Memory dump — parsed by Volatility 3 in preprocessing"

    # ── Email ─────────────────────────────────────────────────────
    elif ext in {".eml", ".msg"}:
        if ext == ".eml":
            try:
                import email
                with open(file_path, "rb") as f:
                    msg = email.message_from_bytes(f.read())
                extra["email_from"]    = msg.get("From",    "")
                extra["email_to"]      = msg.get("To",      "")
                extra["email_subject"] = msg.get("Subject", "")
                extra["email_date"]    = msg.get("Date",    "")
            except Exception:
                pass

    return extra
