"""
Log Analysis Engine — Hayabusa Triage Analyzer
===============================================
Consumes pre-triaged Hayabusa (Sigma-flagged) security telemetry streams.

ARCHITECTURAL REQUIREMENT:
Hayabusa output is treated as PRE-TRIAGED SECURITY FINDINGS while raw EVTX
remains the primary event source for other analyzers. The stream is processed
separately, preserving Sigma rule and signature details in finding provenance.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)


class HayabusaTriageAnalyzer:
    """
    Analyzes pre-triaged Hayabusa Sigma detection telemetry.
    """

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes Hayabusa pre-triaged security artifacts and converts them into canonical Findings.
        """
        findings: List[Finding] = []

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            rule_name = norm.rule_name or raw.get("rule_title") or raw.get("RuleTitle") or raw.get("RuleName") or "Hayabusa Rule"
            status = norm.severity or raw.get("level") or raw.get("Level") or "medium"
            mitre = raw.get("mitre_mapping") or raw.get("Tactics") or raw.get("Techniques") or "T1003"
            details = artifact.event_summary or raw.get("details") or raw.get("Details") or ""

            ts = artifact.timestamp or datetime.now(timezone.utc)

            fact_msg = (
                f"Hayabusa pre-triaged Sigma alert: rule '{rule_name}' triggered "
                f"on host '{norm.host or 'UNKNOWN'}' ({details[:150]})"
            )

            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=0.95,
                severity=str(status).lower(),
                mitre_mapping=str(mitre),
                timestamp=ts,
                evidence_reference=fcr_ref or artifact.artifact_id,
                source_artifact_id=artifact.artifact_id,
                layer="log.hayabusa_triage_analyzer",
                metadata={
                    "rule_name": rule_name,
                    "details": details,
                    "hayabusa_level": status,
                    "artifact_id": artifact.artifact_id,
                }
            ))

        return findings
