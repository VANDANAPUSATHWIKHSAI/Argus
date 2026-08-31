"""
Email Analysis Engine — Main Orchestrator Engine
=================================================
Orchestrates all six email sub-analyzers (HeaderAnalyzer, AuthenticationAnalyzer,
AttachmentAnalyzer, URLAnalyzer, PhishingAnalyzer, MailboxTimelineAnalyzer).

Follows the canonical ARGUS engine pattern:
- Consumes FCR records & Artifacts
- Runs sub-analyzers deterministically
- Merges duplicate findings on (case_id, source_artifact_id, layer, fact)
- Preserves contributing_correlation_ids
- Persists to UnifiedEvidenceStore
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

from forensic_analysis.schemas import Finding
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact

from forensic_analysis.email_analysis.header_analyzer import HeaderAnalyzer
from forensic_analysis.email_analysis.authentication_analyzer import AuthenticationAnalyzer
from forensic_analysis.email_analysis.attachment_analyzer import AttachmentAnalyzer
from forensic_analysis.email_analysis.url_analyzer import URLAnalyzer
from forensic_analysis.email_analysis.phishing_analyzer import PhishingAnalyzer
from forensic_analysis.email_analysis.mailbox_timeline_analyzer import MailboxTimelineAnalyzer

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


class EmailAnalysisEngine:
    """
    Layer-3 Deterministic Email Forensic Analysis Engine.
    """

    def __init__(self):
        self.sub_analyzers = [
            HeaderAnalyzer(),
            AuthenticationAnalyzer(),
            AttachmentAnalyzer(),
            URLAnalyzer(),
            PhishingAnalyzer(),
            MailboxTimelineAnalyzer(),
        ]

    def analyze(
        self,
        fcr_input: CorrelationRecord | List[CorrelationRecord],
        artifacts_by_id: Dict[str, Artifact]
    ) -> List[Finding]:
        """
        Processes FCR object(s), resolving referenced email artifacts,
        and running all sub-analyzers.
        """
        if not fcr_input:
            return []

        fcr_list = fcr_input if isinstance(fcr_input, list) else [fcr_input]
        raw_findings: List[Finding] = []

        for fcr in fcr_list:
            if not fcr or not getattr(fcr, "artifact_ids", None):
                continue

            for art_id in fcr.artifact_ids:
                artifact = artifacts_by_id.get(art_id)
                if not artifact:
                    continue

                art_type = getattr(artifact, "artifact_type", "")
                # Check if artifact is relevant to Email analysis engine
                if art_type in ("email", "email_header", "email.header", "email.body", "email_message", "file_record"):
                    # If file_record, ensure source_tool is email parser
                    if art_type == "file_record" and getattr(artifact, "source_tool", "") not in ("python_email", "extract_msg"):
                        continue

                    for analyzer in self.sub_analyzers:
                        try:
                            res = analyzer.analyze(artifact, [fcr.correlation_id])
                            if res:
                                raw_findings.extend(res)
                        except Exception as exc:
                            logger.error(
                                "EmailAnalysisEngine: Sub-analyzer '%s' failed on artifact '%s': %s",
                                analyzer.__class__.__name__, art_id, exc, exc_info=True
                            )

        # Deduplicate findings on (case_id, source_artifact_id, layer, fact)
        deduped: Dict[tuple, Finding] = {}
        for f in raw_findings:
            dedup_key = (f.case_id, f.source_artifact_id, f.layer, f.fact)
            if dedup_key not in deduped:
                deduped[dedup_key] = f
            else:
                existing = deduped[dedup_key]
                # Merge contributing_correlation_ids
                for cid in f.contributing_correlation_ids:
                    if cid not in existing.contributing_correlation_ids:
                        existing.contributing_correlation_ids.append(cid)

        results = list(deduped.values())

        # Sort deterministically
        results.sort(
            key=lambda x: (
                x.timestamp,
                SEVERITY_ORDER.get(x.severity, 5),
                x.layer,
                x.fact
            )
        )

        return results
