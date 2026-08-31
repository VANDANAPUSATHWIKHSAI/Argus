"""
Memory Analysis — Rootkit & Kernel Structure Analyzer
======================================================
Analyzes kernel structure inconsistencies, hidden processes, and unlinked module indicators:
- memory.rootkit, unlinked_process_record, hidden_modules

Enforces conservative forensic language ("Memory structure inconsistency consistent with possible process/module hiding").
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class RootkitAnalyzer:
    """
    Deterministic analyzer for memory rootkit and kernel anomaly indicators.
    """

    def analyze(
        self,
        artifacts: List[Artifact],
        case_id: str,
        fcr_ref: Optional[str] = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        for artifact in artifacts:
            art_type = (artifact.artifact_type or "").lower()
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}
            ts = artifact.timestamp or datetime.now(timezone.utc)

            if art_type not in ("memory.rootkit", "unlinked_process_record", "hidden_modules"):
                continue

            pid = norm.process_id or raw.get("PID") or raw.get("pid")
            proc_name = norm.process_name or str(raw.get("ImageFileName", "")) or str(raw.get("Name", "")) or "kernel_structure"
            hook_type = str(raw.get("HookType", "")) or str(raw.get("type", "")) or "process_hiding"

            fact_msg = (
                f"Memory structure inconsistency consistent with possible process/module hiding observed: "
                f"target '{proc_name}' (PID {pid or 'N/A'}, anomaly_type='{hook_type}')."
            )

            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=0.90,
                severity="high",
                mitre_mapping="T1014",
                timestamp=ts,
                evidence_reference=fcr_ref or artifact.artifact_id,
                source_artifact_id=artifact.artifact_id,
                layer="memory.rootkit_analyzer",
                metadata={
                    "pid": pid,
                    "target_name": proc_name,
                    "anomaly_type": hook_type,
                    "artifact_id": artifact.artifact_id,
                }
            ))

        return findings
