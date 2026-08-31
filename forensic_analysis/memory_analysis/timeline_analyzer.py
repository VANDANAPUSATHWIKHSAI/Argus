"""
Memory Analysis — Timeline Analyzer
====================================
Constructs deterministic UTC memory-event timelines from memory artifacts:
- Process creation / exit times
- Network connection creation times
- Module load times

Normalizes all timestamps to UTC. Detects temporal sequences (process start -> network connection).
Never invents missing timestamps.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class TimelineAnalyzer:
    """
    Deterministic analyzer for memory event temporal sequences.
    """

    def analyze(
        self,
        artifacts: List[Artifact],
        case_id: str,
        fcr_ref: Optional[str] = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Filter artifacts with valid UTC timestamps
        valid_artifacts: List[tuple[datetime, Artifact]] = []
        for artifact in artifacts:
            ts = artifact.timestamp
            if isinstance(ts, datetime):
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                valid_artifacts.append((ts, artifact))

        if len(valid_artifacts) < 2:
            return findings

        # Sort artifacts deterministically by UTC timestamp
        valid_artifacts.sort(key=lambda x: x[0])

        # Detect temporal sequences: Process creation followed closely by network connection
        for i in range(len(valid_artifacts) - 1):
            ts1, art1 = valid_artifacts[i]
            ts2, art2 = valid_artifacts[i + 1]

            t1_type = (art1.artifact_type or "").lower()
            t2_type = (art2.artifact_type or "").lower()

            if t1_type in ("memory.pslist", "process_record") and t2_type in ("memory.netscan", "network_connection"):
                pid1 = art1.normalized_fields.process_id or art1.raw_fields.get("PID")
                pid2 = art2.normalized_fields.process_id or art2.raw_fields.get("PID")

                if pid1 is not None and pid1 == pid2:
                    delta_sec = (ts2 - ts1).total_seconds()
                    if 0 <= delta_sec <= 60:
                        proc_name = art1.normalized_fields.process_name or str(art1.raw_fields.get("ImageFileName", ""))
                        fact_msg = (
                            f"Rapid temporal sequence in memory: process '{proc_name}' (PID {pid1}) "
                            f"started at {ts1.isoformat()} followed by network connection at {ts2.isoformat()} "
                            f"(delta={delta_sec:.2f}s)."
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.88,
                            severity="medium",
                            mitre_mapping="T1049",
                            timestamp=ts2,
                            evidence_reference=fcr_ref or art1.artifact_id,
                            source_artifact_id=art1.artifact_id,
                            layer="memory.timeline_analyzer",
                            metadata={
                                "pid": pid1,
                                "process_name": proc_name,
                                "start_time": ts1.isoformat(),
                                "net_time": ts2.isoformat(),
                                "delta_sec": delta_sec,
                                "artifact_id": art1.artifact_id,
                            }
                        ))

        return findings
