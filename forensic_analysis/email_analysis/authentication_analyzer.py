"""
Email Analysis Engine — Authentication Analyzer
================================================
Deterministically analyzes email authentication headers (SPF, DKIM, DMARC,
Authentication-Results) for authentication failures and alignment discrepancies.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)


class AuthenticationAnalyzer:
    """
    Analyzes SPF, DKIM, DMARC, and Authentication-Results headers for
    deterministic authentication and domain alignment failures.
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

        # Aggregate authentication signals from raw fields or headers
        auth_results_str = (
            raw.get("authentication_results") or
            headers.get("Authentication-Results") or
            headers.get("authentication-results") or ""
        )
        if isinstance(auth_results_str, list):
            auth_results_str = " ".join(str(x) for x in auth_results_str)
        auth_results_lower = str(auth_results_str).lower()

        spf_status = str(raw.get("spf") or headers.get("Received-SPF") or headers.get("spf") or "").lower()
        dkim_status = str(raw.get("dkim") or headers.get("DKIM-Signature") or headers.get("dkim") or "").lower()
        dmarc_status = str(raw.get("dmarc") or headers.get("dmarc") or "").lower()

        # 1. SPF Failure / Softfail
        if "spf=fail" in auth_results_lower or "spf=softfail" in auth_results_lower or "fail" in spf_status or "softfail" in spf_status:
            status_label = "softfail" if ("softfail" in auth_results_lower or "softfail" in spf_status) else "fail"
            fact_msg = f"SPF authentication {status_label} observed in email headers"
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
                layer="email.authentication_analyzer",
                contributing_correlation_ids=list(correlation_ids),
                metadata={"spf_status": status_label, "raw_header": auth_results_str}
            ))

        # 2. DKIM Failure
        if "dkim=fail" in auth_results_lower or ("fail" in dkim_status and "pass" not in dkim_status):
            fact_msg = "DKIM authentication failure observed in email headers"
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
                layer="email.authentication_analyzer",
                contributing_correlation_ids=list(correlation_ids),
                metadata={"dkim_status": "fail", "raw_header": auth_results_str}
            ))

        # 3. DMARC Failure
        if "dmarc=fail" in auth_results_lower or "action=reject" in auth_results_lower or "action=quarantine" in auth_results_lower or "fail" in dmarc_status:
            fact_msg = "DMARC authentication failure observed in email headers"
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
                layer="email.authentication_analyzer",
                contributing_correlation_ids=list(correlation_ids),
                metadata={"dmarc_status": "fail", "raw_header": auth_results_str}
            ))

        # 4. Alignment Failure
        if "alignment=fail" in auth_results_lower:
            fact_msg = "DMARC domain alignment failure observed between From header domain and SPF/DKIM domain"
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
                layer="email.authentication_analyzer",
                contributing_correlation_ids=list(correlation_ids),
                metadata={"alignment_status": "fail", "raw_header": auth_results_str}
            ))

        return findings
