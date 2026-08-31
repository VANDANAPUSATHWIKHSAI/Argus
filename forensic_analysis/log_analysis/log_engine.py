"""
Log Analysis Engine Orchestrator
================================
Orchestrates deterministic forensic sub-analyzers for log telemetry:
AuthAnalyzer, ProcessCreationAnalyzer, PowerShellAnalyzer, and HayabusaTriageAnalyzer.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from forensic_analysis.log_analysis.auth_analyzer import AuthAnalyzer
from forensic_analysis.log_analysis.process_creation_analyzer import ProcessCreationAnalyzer
from forensic_analysis.log_analysis.powershell_analyzer import PowerShellAnalyzer
from forensic_analysis.log_analysis.hayabusa_triage_analyzer import HayabusaTriageAnalyzer
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)


class LogAnalysisEngine:
    """
    Orchestrates deterministic forensic analysis over normalized log telemetry.
    """

    def __init__(self):
        self.auth_analyzer = AuthAnalyzer()
        self.process_creation_analyzer = ProcessCreationAnalyzer()
        self.powershell_analyzer = PowerShellAnalyzer()
        self.hayabusa_triage_analyzer = HayabusaTriageAnalyzer()

    def analyze(
        self,
        fcr_objects: List[CorrelationRecord],
        artifacts_by_id: Optional[Dict[str, Artifact]] = None
    ) -> List[Finding]:
        """
        Analyse a list of FCR objects (and resolved Artifacts) and return a list of Finding objects.
        """
        if not fcr_objects:
            return []

        artifacts_store = artifacts_by_id or {}
        raw_findings: List[Finding] = []

        for fcr in fcr_objects:
            case_id = fcr.case_id
            fcr_ref = fcr.correlation_id

            # Resolve referenced Artifacts
            fcr_artifacts: List[Artifact] = []
            for art_id in fcr.artifact_ids:
                art = artifacts_store.get(art_id)
                if art:
                    fcr_artifacts.append(art)

            if not fcr_artifacts:
                continue

            # Categorize artifacts by taxonomy
            auth_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("auth_event", "log.auth", "evtx_record")
            ]
            process_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("process_event", "log.process", "sysmon_event")
            ]
            powershell_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("powershell_event", "log.powershell")
            ]
            hayabusa_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("hayabusa_triage", "log.hayabusa")
                or a.source_tool == "hayabusa"
            ]

            # Dispatch to sub-analyzers
            if auth_artifacts:
                raw_findings.extend(self.auth_analyzer.analyze(case_id, auth_artifacts, fcr_ref))

            if process_artifacts:
                raw_findings.extend(self.process_creation_analyzer.analyze(case_id, process_artifacts, fcr_ref))

            if powershell_artifacts:
                raw_findings.extend(self.powershell_analyzer.analyze(case_id, powershell_artifacts, fcr_ref))

            if hayabusa_artifacts:
                raw_findings.extend(self.hayabusa_triage_analyzer.analyze(case_id, hayabusa_artifacts, fcr_ref))

        # Safe deterministic deduplication across overlapping FCRs
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

        # Deterministic ordering by (timestamp, layer, finding_id)
        final_findings.sort(key=lambda f: (f.timestamp, f.layer, f.finding_id))
        return final_findings
