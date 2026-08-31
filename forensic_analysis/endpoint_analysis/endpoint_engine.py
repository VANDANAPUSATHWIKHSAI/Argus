"""
Forensic Analysis Layer — Endpoint Analysis Engine Orchestrator
===============================================================
Main entry point for Endpoint forensic analysis in ARGUS.
Orchestrates 6 sub-analyzers:
1. PersistenceAnalyzer
2. FilesystemAnalyzer
3. RegistryAnalyzer
4. BrowserAnalyzer
5. USBAnalyzer
6. UserActivityAnalyzer

Applies deterministic artifact-level deduplication across overlapping FCRs
while preserving all contributing correlation references.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.schemas import Finding

from forensic_analysis.endpoint_analysis.persistence_analyzer import PersistenceAnalyzer
from forensic_analysis.endpoint_analysis.filesystem_analyzer import FilesystemAnalyzer
from forensic_analysis.endpoint_analysis.registry_analyzer import RegistryAnalyzer
from forensic_analysis.endpoint_analysis.browser_analyzer import BrowserAnalyzer
from forensic_analysis.endpoint_analysis.usb_analyzer import USBAnalyzer
from forensic_analysis.endpoint_analysis.user_activity_analyzer import UserActivityAnalyzer

logger = logging.getLogger(__name__)


class EndpointAnalysisEngine:
    """
    Deterministic Endpoint Forensic Analysis Engine.
    Orchestrates the 6 endpoint sub-analyzers over input FCRs and Artifact stores.
    """

    def __init__(self):
        self.persistence_analyzer = PersistenceAnalyzer()
        self.filesystem_analyzer = FilesystemAnalyzer()
        self.registry_analyzer = RegistryAnalyzer()
        self.browser_analyzer = BrowserAnalyzer()
        self.usb_analyzer = USBAnalyzer()
        self.user_activity_analyzer = UserActivityAnalyzer()

    def analyze(
        self,
        fcrs: List[CorrelationRecord],
        artifacts_by_id: Dict[str, Artifact]
    ) -> List[Finding]:
        """
        Processes a list of CorrelationRecords (FCRs), maps referenced Artifacts
        to sub-analyzers, collects findings, and returns deduplicated Findings.
        """
        raw_findings: List[Finding] = []

        for fcr in fcrs:
            fcr_id = getattr(fcr, "correlation_id", "UNKNOWN_FCR")
            case_id = getattr(fcr, "case_id", "UNKNOWN_CASE")
            art_ids = getattr(fcr, "artifact_ids", [])

            # Resolve referenced Artifacts
            resolved_artifacts: List[Artifact] = []
            for art_id in art_ids:
                art = artifacts_by_id.get(art_id)
                if art:
                    resolved_artifacts.append(art)
                else:
                    logger.warning(
                        "EndpointAnalysisEngine: Referenced artifact_id '%s' in FCR '%s' not found in store.",
                        art_id, fcr_id
                    )

            if not resolved_artifacts:
                continue

            # Dispatch artifacts to all 6 sub-analyzers safely
            try:
                raw_findings.extend(self.persistence_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("PersistenceAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.filesystem_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("FilesystemAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.registry_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("RegistryAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.browser_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("BrowserAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.usb_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("USBAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.user_activity_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("UserActivityAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

        # Deterministic artifact-level deduplication across overlapping FCRs
        deduped: Dict[tuple, Finding] = {}
        for finding in raw_findings:
            key = (
                finding.case_id,
                finding.source_artifact_id,
                finding.layer,
                finding.fact,
            )
            if key not in deduped:
                deduped[key] = finding
            else:
                existing = deduped[key]
                # Merge contributing correlation IDs
                for cid in finding.contributing_correlation_ids:
                    if cid and cid not in existing.contributing_correlation_ids:
                        existing.contributing_correlation_ids.append(cid)

        final_findings = list(deduped.values())
        logger.info("EndpointAnalysisEngine: Generated %d deduplicated findings from %d raw findings", len(final_findings), len(raw_findings))
        return final_findings
