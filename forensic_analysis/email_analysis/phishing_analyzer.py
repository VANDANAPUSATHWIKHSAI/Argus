"""
Email Analysis Engine — Phishing Analyzer
==========================================
Deterministically aggregates email evidence indicators (header discrepancies,
authentication failures, attachment risks, URL anomalies, urgency language)
into explainable composite forensic findings without LLMs or probabilistic models.
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact
from forensic_analysis.email_analysis.header_analyzer import HeaderAnalyzer
from forensic_analysis.email_analysis.authentication_analyzer import AuthenticationAnalyzer
from forensic_analysis.email_analysis.attachment_analyzer import AttachmentAnalyzer
from forensic_analysis.email_analysis.url_analyzer import URLAnalyzer

logger = logging.getLogger(__name__)

URGENCY_KEYWORDS = [
    "password reset", "account suspended", "urgent action required",
    "verify your account", "wire transfer", "update payment details",
    "invoice overdue", "security alert", "immediate response needed",
    "account deactivated", "unauthorized login"
]


class PhishingAnalyzer:
    """
    Deterministically combines email evidence indicators into explainable
    composite findings.
    """

    def __init__(self):
        self.header_analyzer = HeaderAnalyzer()
        self.auth_analyzer = AuthenticationAnalyzer()
        self.att_analyzer = AttachmentAnalyzer()
        self.url_analyzer = URLAnalyzer()

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

        # 1. Run sub-analyzers to harvest individual indicators
        header_findings = self.header_analyzer.analyze(artifact, correlation_ids)
        auth_findings = self.auth_analyzer.analyze(artifact, correlation_ids)
        att_findings = self.att_analyzer.analyze(artifact, correlation_ids)
        url_findings = self.url_analyzer.analyze(artifact, correlation_ids)

        indicator_descriptions: List[str] = []

        if header_findings:
            indicator_descriptions.append("sender/reply-to or display name mismatch")
        if auth_findings:
            indicator_descriptions.append("authentication failure (SPF/DKIM/DMARC)")
        if att_findings:
            indicator_descriptions.append("suspicious/executable attachment")
        if url_findings:
            indicator_descriptions.append("suspicious URL/domain structure")

        # 2. Check for Urgency or Credential Harvester Language in Subject / Body
        subject = str(raw.get("subject") or getattr(artifact.normalized_fields, "subject", "") or "").lower()
        body = str(raw.get("body_text") or raw.get("body") or raw.get("body_html") or "").lower()

        urgency_matched = []
        for kw in URGENCY_KEYWORDS:
            if kw in subject or kw in body:
                urgency_matched.append(kw)

        if urgency_matched:
            indicator_descriptions.append(f"urgency/credential request language ('{urgency_matched[0]}')")

        # 3. Composite Phishing Finding (if >= 2 independent indicators exist)
        if len(indicator_descriptions) >= 2:
            indicators_str = ", ".join(indicator_descriptions)
            fact_msg = f"Multiple phishing indicators observed: {indicators_str}"

            # High confidence when >= 3 indicators or auth failure + sender mismatch
            conf = 0.90 if len(indicator_descriptions) >= 3 else 0.85
            sev = "critical" if len(indicator_descriptions) >= 3 else "high"

            findings.append(Finding(
                case_id=artifact.case_id,
                tenant_id=getattr(artifact, "tenant_id", "default"),
                fact=fact_msg,
                confidence=conf,
                severity=sev,
                mitre_mapping="T1566",
                timestamp=artifact.timestamp or datetime.now(timezone.utc),
                evidence_reference=correlation_ids[0] if correlation_ids else artifact.artifact_id,
                source_artifact_id=artifact.artifact_id,
                layer="email.phishing_analyzer",
                contributing_correlation_ids=list(correlation_ids),
                metadata={
                    "indicator_count": len(indicator_descriptions),
                    "indicators": indicator_descriptions,
                    "urgency_keywords": urgency_matched,
                }
            ))

        return findings
