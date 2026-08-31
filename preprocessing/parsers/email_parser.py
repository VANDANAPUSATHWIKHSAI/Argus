# Email artifact parser using Python's built-in email library
# Source tool: "python_email"
# Artifact types produced: "email_header", "file_record"
# Raw output format: In-memory parsing of .eml / .msg files
# Email RFC 2822 parsing: https://docs.python.org/3/library/email.html

from __future__ import annotations

import re
import email
from email import policy
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from preprocessing.schemas import Artifact, NormalizedFields
from config.tool_versions import get_tool_version

logger = logging.getLogger(__name__)


class EmailParser:
    """Parses .eml / .msg email files into Artifact records.

    Produces a single ``email_header`` Artifact containing all headers and
    body parts, and one ``file_record`` Artifact per parsed attachment.
    """

    def parse(self, file_path: str, evidence_id: str = "") -> list[Artifact]:
        """Parse the email file at *file_path* and return a list of Artifact records.

        Args:
            file_path:   Absolute path to the email (.eml / .msg) file.
            evidence_id: FK linking back to the ``infrastructure.Evidence`` record.
                         Pass an empty string during unit tests / standalone use.

        Returns:
            List of :class:`~preprocessing.schemas.Artifact` objects.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is not a valid email or exceeds size limits.
        """
        src = Path(file_path)
        if not src.exists():
            raise FileNotFoundError(f"Email file not found: {file_path}")

        self._tool_version = get_tool_version("python_email")

        # Limit parsed email size to 50MB to prevent memory exhaustion (OOM)
        MAX_EMAIL_SIZE = 50 * 1024 * 1024
        if src.stat().st_size > MAX_EMAIL_SIZE:
            raise ValueError(f"Email file exceeds maximum size limit of 50MB: {src.stat().st_size} bytes")

        with open(src, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        # Validate that the file is parseable as an email.
        # Check standard email headers: From, Subject, To, Date, or Message-ID.
        has_min_signal = any(msg.get(h) is not None for h in ("From", "Subject", "To", "Message-ID", "Date", "Received"))
        if not has_min_signal or not msg.keys():
            raise ValueError(f"File {file_path} is not parseable as an email (no standard email headers found).")

        # ── 1. Parse headers ────────────────────────────────────────────────
        from_val = msg.get("From")
        to_val = msg.get("To")
        cc_val = msg.get("Cc")
        bcc_val = msg.get("Bcc")
        subject_val = msg.get("Subject")
        date_val = msg.get("Date")
        msg_id_val = msg.get("Message-ID")

        # Extract all Received headers as a list (chain) for hop tracing
        received_hops = [str(r).strip() for r in msg.get_all("Received", [])]

        headers_dict = {
            "From": str(from_val) if from_val is not None else None,
            "To": str(to_val) if to_val is not None else None,
            "Cc": str(cc_val) if cc_val is not None else None,
            "Bcc": str(bcc_val) if bcc_val is not None else None,
            "Subject": str(subject_val) if subject_val is not None else None,
            "Date": str(date_val) if date_val is not None else None,
            "Message-ID": str(msg_id_val) if msg_id_val is not None else None,
        }

        # Parse Date header to timezone-aware datetime (RFC 2822)
        ts = None
        if date_val:
            try:
                ts = email.utils.parsedate_to_datetime(str(date_val).strip())
            except Exception as e:
                logger.warning("Failed to parse email Date header %r: %s", date_val, e)

        # ── 2. Walk MIME parts for body parts and attachments ───────────────
        body_text: Optional[str] = None
        body_html: Optional[str] = None
        attachments: list[Artifact] = []

        for part in msg.walk():
            # Check content disposition
            disposition = part.get_content_disposition()
            if disposition == 'attachment':
                # Attachment metadata
                filename = part.get_filename() or "unnamed_attachment"
                content_type = part.get_content_type()
                
                # Retrieve payload as raw bytes to compute SHA-256 hash and size
                payload_bytes = part.get_payload(decode=True) or b""
                size_bytes = len(payload_bytes)
                sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

                ver = getattr(self, "_tool_version", get_tool_version("python_email"))
                attachments.append(Artifact(
                    evidence_id=evidence_id,
                    source_tool="python_email",
                    artifact_type="file_record",
                    timestamp=ts,
                    timestamp_type="received",
                    event_summary=f"Email attachment: {filename} ({size_bytes} bytes)",
                    parser_version=ver,
                    raw_fields={
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": size_bytes,
                        "sha256": sha256_hash,
                        "tool_version": ver,
                    },
                    normalized_fields=NormalizedFields(
                        file_path=filename,
                        file_name=filename,
                        hash=sha256_hash,
                    )
                ))
            else:
                # Body text/plain or text/html parts
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body_text = part.get_content()
                    except Exception as e:
                        logger.warning("Failed to extract plain text body content: %s", e)
                elif content_type == "text/html":
                    try:
                        body_html = part.get_content()
                    except Exception as e:
                        logger.warning("Failed to extract HTML body content: %s", e)

        ver = getattr(self, "_tool_version", get_tool_version("python_email"))
        recipients_list = []
        for r_val in (to_val, cc_val, bcc_val):
            if r_val:
                recipients_list.append(str(r_val).strip())
        recipients_str = ", ".join(recipients_list) if recipients_list else None

        # Extract first URL and sender domain into normalized fields
        first_url = None
        if body_text:
            match_url = re.search(r'https?://[^\s<>"]+', body_text)
            if match_url:
                first_url = match_url.group(0).rstrip('.,);')

        first_domain = None
        if from_val:
            match_dom = re.search(r'@([\w.-]+)', str(from_val))
            if match_dom:
                first_domain = match_dom.group(1).lower()

        header_art = Artifact(
            evidence_id=evidence_id,
            source_tool="python_email",
            artifact_type="email_header",
            timestamp=ts,
            timestamp_type="received",
            event_summary=f"Email from {from_val} to {recipients_str} subject '{subject_val}'",
            parser_version=ver,
            raw_fields={
                "headers": headers_dict,
                "received_hops": received_hops,
                "body_text": body_text,
                "body_html": body_html,
                "tool_version": ver,
            },
            normalized_fields=NormalizedFields(
                sender=str(from_val) if from_val else None,
                recipients=recipients_str,
                subject=str(subject_val) if subject_val else None,
                url=first_url,
                domain=first_domain,
            )
        )

        return [header_art] + attachments
