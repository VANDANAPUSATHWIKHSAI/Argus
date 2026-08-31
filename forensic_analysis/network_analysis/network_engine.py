"""
Network Analysis Engine Orchestrator
===================================
Orchestrates deterministic forensic sub-analyzers for network telemetry:
DNSAnalyzer, HTTPAnalyzer, TLSAnalyzer, and SessionReconstructor.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from forensic_analysis.schemas import Finding
from forensic_analysis.network_analysis.dns_analyzer import DNSAnalyzer
from forensic_analysis.network_analysis.http_analyzer import HTTPAnalyzer
from forensic_analysis.network_analysis.tls_analyzer import TLSAnalyzer
from forensic_analysis.network_analysis.session_reconstruction import SessionReconstructor
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)


class NetworkAnalysisEngine:
    """
    Orchestrates deterministic forensic analysis over normalized network telemetry.
    """

    def __init__(self):
        self.dns_analyzer = DNSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.session_reconstructor = SessionReconstructor()

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
            dns_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("dns_query", "network.dns")
            ]
            http_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("http_request", "network.http")
            ]
            tls_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("tls_session", "network.tls")
            ]
            conn_artifacts = [
                a for a in fcr_artifacts
                if a.artifact_type in ("network_connection", "network.conn", "network_flow")
            ]

            # Dispatch to sub-analyzers
            if dns_artifacts:
                raw_findings.extend(self.dns_analyzer.analyze(case_id, dns_artifacts, fcr_ref))

            if http_artifacts:
                raw_findings.extend(self.http_analyzer.analyze(case_id, http_artifacts, fcr_ref))

            if tls_artifacts:
                raw_findings.extend(self.tls_analyzer.analyze(case_id, tls_artifacts, fcr_ref))

            if conn_artifacts:
                raw_findings.extend(self.session_reconstructor.analyze(case_id, conn_artifacts, fcr_ref))

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
