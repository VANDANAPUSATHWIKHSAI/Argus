"""
Outlook MSG Email Parser using extract-msg
===========================================
Source 10: Email — .msg / Outlook
Source Tool: "extract_msg"
Artifact Types Produced: "email"

Uses extract-msg to parse binary OLE .msg files, preserving:
- Sender, Recipients (To, CC, BCC), Subject, Message-ID
- Sent/Received timestamps
- Original unsanitized body text
- Full headers where available
- Attachment metadata (filename, mimetype, size) without execution
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)

# Optional extract_msg import
try:
    import extract_msg
except ImportError:
    extract_msg = None


# ---------------------------------------------------------------------------
# Typed Errors
# ---------------------------------------------------------------------------

class MsgParserError(RuntimeError):
    """Base exception for MSG email parser errors."""


class MsgParserDependencyError(MsgParserError):
    """Raised when extract-msg is not installed in Python environment."""


class MsgParserCorruptError(MsgParserError):
    """Raised when an OLE MSG container is corrupt or cannot be parsed."""


# ---------------------------------------------------------------------------
# Parser Class
# ---------------------------------------------------------------------------

class MsgEmailParser:
    """Parses Outlook .msg files via extract-msg into Artifact records."""

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse an Outlook .msg file and return Artifact records.

        Args:
            file_path:   Path to the .msg file.
            evidence_id: FK linking back to infrastructure.Evidence.evidence_id.

        Returns:
            List of Artifact records (source_tool="extract_msg", artifact_type="email").

        Raises:
            FileNotFoundError:          If file_path does not exist.
            MsgParserDependencyError:  If extract-msg is missing.
            MsgParserCorruptError:     If the OLE container is corrupt or unparseable.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"MSG file not found: {file_path}")

        if extract_msg is None:
            raise MsgParserDependencyError(
                "The 'extract-msg' package is required to parse .msg files. "
                "Install it via: pip install extract-msg"
            )

        ver = get_tool_version("extract_msg")
        file_hash = self._hash_file(src)

        try:
            msg = extract_msg.openMsg(str(src))
        except Exception as exc:
            raise MsgParserCorruptError(f"Failed to open MSG container {src.name}: {exc}")

        try:
            sender = getattr(msg, "sender", None) or getattr(msg, "from_", None) or ""
            recipients = getattr(msg, "to", None) or ""
            cc = getattr(msg, "cc", None) or ""
            bcc = getattr(msg, "bcc", None) or ""
            subject = getattr(msg, "subject", None) or ""
            body = getattr(msg, "body", None) or ""
            date_raw = getattr(msg, "date", None)
            recv_date_raw = getattr(msg, "receivedTime", None)
            msg_id = getattr(msg, "messageId", None) or ""

            # Extract header dict/str if available
            headers = {}
            if hasattr(msg, "header") and msg.header:
                try:
                    headers = dict(msg.header)
                except Exception:
                    headers = {"raw_header": str(msg.header)}

            # Extract attachment metadata without executing or opening attachments
            attachments = []
            if hasattr(msg, "attachments") and msg.attachments:
                for att in msg.attachments:
                    att_info = {
                        "filename": getattr(att, "longFilename", None) or getattr(att, "filename", None) or "unnamed",
                        "short_filename": getattr(att, "shortFilename", None) or "",
                        "mimetype": getattr(att, "mimetype", None) or getattr(att, "mime_type", None) or "",
                        "size": getattr(att, "size", 0),
                        "cid": getattr(att, "cid", None) or "",
                    }
                    attachments.append(att_info)

            # Timestamps
            sent_dt = self._parse_date(date_raw)
            recv_dt = self._parse_date(recv_date_raw)
            primary_dt = sent_dt or recv_dt
            ts_type = "sent" if sent_dt else ("received" if recv_dt else "sent")

            summary = f"Email from '{sender}' to '{recipients}' — Subject: {subject}"

            raw_fields = {
                "sender": sender,
                "recipients": recipients,
                "cc": cc,
                "bcc": bcc,
                "subject": subject,
                "body": body,
                "message_id": msg_id,
                "sent_date": str(date_raw) if date_raw else None,
                "received_date": str(recv_date_raw) if recv_date_raw else None,
                "headers": headers,
                "attachments": attachments,
                "file_hash": file_hash,
                "source_file": src.name,
                "tool_version": ver,
            }

            norm = NormalizedFields(
                sender=sender,
                recipients=recipients,
                subject=subject,
                hash=file_hash,
                file_name=src.name,
            )

            art = Artifact(
                evidence_id=evidence_id,
                source_tool="extract_msg",
                artifact_type="email",
                timestamp=primary_dt,
                timestamp_type=ts_type,
                event_summary=summary,
                parser_version=ver,
                raw_fields=raw_fields,
                normalized_fields=norm,
            )

            msg.close()
            return [art]

        except Exception as exc:
            try:
                msg.close()
            except Exception:
                pass
            raise MsgParserCorruptError(f"Error parsing MSG fields in {src.name}: {exc}")

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_date(val: Any) -> Optional[datetime]:
        """Convert datetime or date string to timezone-aware UTC datetime."""
        if val is None:
            return None
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc)
        s = str(val).strip()
        if not s:
            return None
        for fmt in (
            "%a, %d %b %Y %H:%M:%S %z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(s, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
        return None

    @staticmethod
    def _hash_file(path: Path) -> str:
        """Compute SHA-256 hash of file."""
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
