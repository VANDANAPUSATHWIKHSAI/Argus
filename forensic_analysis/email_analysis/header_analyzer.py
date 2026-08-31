"""
Email Analysis Engine — Header Analyzer
========================================
Deterministically analyzes email routing headers, identity field consistency,
and Received hop transfer chains.
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)


def extract_email_address(header_val: str) -> Optional[str]:
    """Extracts email address inside <...> or raw address string."""
    if not header_val:
        return None
    matches = re.findall(r'<([^>]+)>', header_val)
    if matches:
        return matches[-1].strip().lower()
    match_simple = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_val)
    if match_simple:
        return match_simple.group(0).strip().lower()
    return None


def extract_display_name(header_val: str) -> Optional[str]:
    """Extracts display name before the final <...> in an email header."""
    if not header_val:
        return None
    if '<' in header_val:
        idx = header_val.rfind('<')
        name = header_val[:idx].strip(' "\'\t\r\n')
        return name if name else None
    return None


class HeaderAnalyzer:
    """
    Analyzes email routing headers for identity field discrepancies
    and Received header hop chain anomalies.
    """

    def analyze(
        self,
        artifact: Artifact,
        correlation_ids: List[str]
    ) -> List[Finding]:
        """
        Analyzes a single email artifact for header inconsistencies.
        """
        art_type = getattr(artifact, "artifact_type", "")
        if art_type not in ("email", "email_header", "email.header", "email.body", "email_message"):
            return []

        findings: List[Finding] = []
        raw = getattr(artifact, "raw_fields", {}) or {}
        headers = raw.get("headers", {}) or {}
        if not isinstance(headers, dict):
            headers = {}

        # 1. Sender & Identity Mismatches
        from_hdr = headers.get("From") or raw.get("sender") or ""
        reply_to_hdr = headers.get("Reply-To") or raw.get("reply_to") or ""
        return_path_hdr = headers.get("Return-Path") or raw.get("return_path") or ""
        msg_id_hdr = headers.get("Message-ID") or raw.get("message_id") or ""

        from_addr = extract_email_address(str(from_hdr))
        reply_to_addr = extract_email_address(str(reply_to_hdr))
        return_path_addr = extract_email_address(str(return_path_hdr))

        # Check From vs Reply-To mismatch
        if from_addr and reply_to_addr and from_addr != reply_to_addr:
            from_domain = from_addr.split("@")[-1]
            reply_domain = reply_to_addr.split("@")[-1]
            if from_domain != reply_domain:
                fact_msg = f"Sender identity fields are inconsistent: From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.85,
                    severity="medium",
                    mitre_mapping="T1566",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.header_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={
                        "from_address": from_addr,
                        "reply_to_address": reply_to_addr,
                    }
                ))

        # Check From vs Return-Path mismatch
        if from_addr and return_path_addr and from_addr != return_path_addr:
            from_domain = from_addr.split("@")[-1]
            return_domain = return_path_addr.split("@")[-1]
            if from_domain != return_domain:
                fact_msg = f"Sender identity fields are inconsistent: From domain '{from_domain}' differs from Return-Path domain '{return_domain}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.80,
                    severity="medium",
                    mitre_mapping="T1566",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.header_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={
                        "from_address": from_addr,
                        "return_path_address": return_path_addr,
                    }
                ))

        # Check Display Name vs Address mismatch (impersonation indicator)
        display_name = extract_display_name(str(from_hdr))
        if display_name and from_addr:
            disp_lower = display_name.lower()
            # If display name contains an explicit email address different from actual address
            disp_email = extract_email_address(disp_lower)
            if disp_email and disp_email != from_addr:
                fact_msg = f"Display name email address mismatch observed: display name shows '{disp_email}' but actual From address is '{from_addr}'"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.90,
                    severity="high",
                    mitre_mapping="T1566",
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.header_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={
                        "display_name": display_name,
                        "actual_from": from_addr,
                    }
                ))

        # 2. Message-ID Structural Anomalies
        if msg_id_hdr:
            msg_id_str = str(msg_id_hdr).strip()
            if not (msg_id_str.startswith("<") and msg_id_str.endswith(">")) or "@" not in msg_id_str:
                fact_msg = f"Message-ID header structural anomaly observed: '{msg_id_str}' does not conform to standard RFC 2822 format"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.70,
                    severity="low",
                    mitre_mapping=None,
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.header_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"message_id": msg_id_str}
                ))

        # 3. Received Header Transfer Chain Analysis (Data Only)
        received_hops = raw.get("received_hops") or raw.get("received_headers") or []
        if isinstance(received_hops, str):
            received_hops = [received_hops]

        if isinstance(received_hops, list) and len(received_hops) > 1:
            # Check for hop anomalies (e.g. malformed hop format or missing relay details)
            malformed_count = sum(1 for h in received_hops if not isinstance(h, str) or len(h.strip()) < 10)
            if malformed_count > 0:
                fact_msg = f"Received header transfer chain anomaly observed: {malformed_count} malformed relay hop(s) in Received chain"
                findings.append(Finding(
                    case_id=artifact.case_id,
                    tenant_id=getattr(artifact, "tenant_id", "default"),
                    fact=fact_msg,
                    confidence=0.75,
                    severity="low",
                    mitre_mapping=None,
                    timestamp=artifact.timestamp or datetime.now(timezone.utc),
                    evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="email.header_analyzer",
                    contributing_correlation_ids=list(correlation_ids),
                    metadata={"total_hops": len(received_hops), "malformed_hops": malformed_count}
                ))

        return findings
