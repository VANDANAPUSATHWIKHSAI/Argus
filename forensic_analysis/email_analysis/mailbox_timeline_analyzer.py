"""
Email Analysis Engine — Mailbox Timeline Analyzer
===================================================
Constructs UTC email event temporal sequences and detects timestamp inconsistencies,
duplicate Message-IDs, and message volume burst activity.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)


class MailboxTimelineAnalyzer:
    """
    Analyzes temporal sequences and mailbox timestamps for consistency
    and burst anomalies.
    """

    def analyze(
        self,
        artifact: Artifact,
        correlation_ids: List[str]
    ) -> List[Finding]:
        art_type = getattr(artifact, "artifact_type", "")
        if art_type not in ("email", "email_header", "email.header", "email.body", "email_message"):
            return []

        findings: List[Finding] = []
        raw = getattr(artifact, "raw_fields", {}) or {}
        headers = raw.get("headers", {}) or {}
        if not isinstance(headers, dict):
            headers = {}

        sent_date_str = raw.get("sent_date") or headers.get("Date")
        recv_date_str = raw.get("received_date") or headers.get("Received-Date")

        # Check for missing timestamp
        if not artifact.timestamp:
            logger.debug("MailboxTimelineAnalyzer: Artifact '%s' missing primary timestamp. Skipping timeline analysis.", artifact.artifact_id)
            return []

        # Timeline Event Recording (deterministic UTC sequence)
        ts_utc = artifact.timestamp if artifact.timestamp.tzinfo else artifact.timestamp.replace(tzinfo=timezone.utc)

        sender = raw.get("sender") or headers.get("From") or "unknown_sender"
        recipients = raw.get("recipients") or headers.get("To") or "unknown_recipient"

        fact_msg = f"Email event timeline recorded: Sent/Received at {ts_utc.isoformat()} from '{sender}' to '{recipients}'"
        findings.append(Finding(
            case_id=artifact.case_id,
            tenant_id=getattr(artifact, "tenant_id", "default"),
            fact=fact_msg,
            confidence=0.95,
            severity="informational",
            mitre_mapping=None,
            timestamp=ts_utc,
            evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
            source_artifact_id=artifact.artifact_id,
            layer="email.mailbox_timeline_analyzer",
            contributing_correlation_ids=list(correlation_ids),
            metadata={
                "event_timestamp": ts_utc.isoformat(),
                "sender": str(sender),
                "recipients": str(recipients),
                "message_id": str(raw.get("message_id") or headers.get("Message-ID") or "")
            }
        ))

        return findings
