"""
Forensic Analysis Layer — Memory Analysis Engine Orchestrator
==============================================================
Main entry point for Memory forensic analysis in ARGUS.
Orchestrates 7 sub-analyzers:
1. ProcessAnalyzer
2. DLLAnalyzer
3. MemoryNetworkAnalyzer
4. InjectionAnalyzer
5. RootkitAnalyzer
6. CredentialAnalyzer
7. TimelineAnalyzer

Applies deterministic artifact-level deduplication across overlapping FCRs
while preserving all contributing correlation references.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.schemas import Finding

from forensic_analysis.memory_analysis.process_analyzer import ProcessAnalyzer
from forensic_analysis.memory_analysis.dll_analyzer import DLLAnalyzer
from forensic_analysis.memory_analysis.network_analyzer import MemoryNetworkAnalyzer
from forensic_analysis.memory_analysis.injection_analyzer import InjectionAnalyzer
from forensic_analysis.memory_analysis.rootkit_analyzer import RootkitAnalyzer
from forensic_analysis.memory_analysis.credential_analyzer import CredentialAnalyzer
from forensic_analysis.memory_analysis.timeline_analyzer import TimelineAnalyzer

logger = logging.getLogger(__name__)


class MemoryAnalysisEngine:
    """
    Deterministic Memory Forensic Analysis Engine.
    Orchestrates the 7 memory sub-analyzers over input FCRs and Artifact stores.
    """

    def __init__(self):
        self.process_analyzer = ProcessAnalyzer()
        self.dll_analyzer = DLLAnalyzer()
        self.network_analyzer = MemoryNetworkAnalyzer()
        self.injection_analyzer = InjectionAnalyzer()
        self.rootkit_analyzer = RootkitAnalyzer()
        self.credential_analyzer = CredentialAnalyzer()
        self.timeline_analyzer = TimelineAnalyzer()

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
                        "MemoryAnalysisEngine: Referenced artifact_id '%s' in FCR '%s' not found in store.",
                        art_id, fcr_id
                    )

            if not resolved_artifacts:
                continue

            # Dispatch artifacts to all 7 sub-analyzers safely
            try:
                raw_findings.extend(self.process_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("ProcessAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.dll_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("DLLAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.network_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("MemoryNetworkAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.injection_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("InjectionAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.rootkit_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("RootkitAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.credential_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("CredentialAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

            try:
                raw_findings.extend(self.timeline_analyzer.analyze(resolved_artifacts, case_id, fcr_ref=fcr_id))
            except Exception as e:
                logger.error("TimelineAnalyzer failed on FCR %s: %s", fcr_id, e, exc_info=True)

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
        logger.info("MemoryAnalysisEngine: Generated %d deduplicated findings from %d raw findings", len(final_findings), len(raw_findings))
        return final_findings
