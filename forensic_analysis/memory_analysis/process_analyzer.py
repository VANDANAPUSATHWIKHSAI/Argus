"""
Memory Analysis — Process Analyzer
===================================
Analyzes Volatility 3 process artifacts:
- pslist, psscan, pstree, cmdline, process_record, unlinked_process_record

Detects:
1. pslist vs psscan discrepancy (unlinked / hidden processes)
2. Orphan processes (inactive/missing parent PID)
3. Parent-child hierarchy anomalies (e.g. lsass.exe parent != wininit.exe)

Strictly enforces conservative forensic language.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)

SYSTEM_EXPECTED_PARENTS = {
    "lsass.exe": ("wininit.exe",),
    "services.exe": ("wininit.exe",),
    "svchost.exe": ("services.exe",),
    "smss.exe": ("system",),
}


class ProcessAnalyzer:
    """
    Deterministic analyzer for memory process artifacts.
    """

    def analyze(
        self,
        artifacts: List[Artifact],
        case_id: str,
        fcr_ref: Optional[str] = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Index processes by PID and artifact type for cross-comparison
        pslist_pids: set[int] = set()
        psscan_artifacts: List[tuple[int, Artifact]] = []
        process_artifacts: List[Artifact] = []

        for artifact in artifacts:
            art_type = (artifact.artifact_type or "").lower()
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            pid = norm.process_id or raw.get("PID") or raw.get("pid")
            if pid is not None:
                try:
                    pid_int = int(pid)
                except (ValueError, TypeError):
                    pid_int = None
            else:
                pid_int = None

            if art_type in ("memory.pslist", "process_record") and pid_int is not None:
                pslist_pids.add(pid_int)

            if art_type in ("memory.psscan", "unlinked_process_record") and pid_int is not None:
                psscan_artifacts.append((pid_int, artifact))

            if art_type in (
                "memory.pslist", "memory.psscan", "memory.pstree", "memory.cmdline",
                "process_record", "process_tree_record", "unlinked_process_record",
                "command_line_record", "process_event"
            ):
                process_artifacts.append(artifact)

        # 1. Detect psscan != pslist discrepancies
        for pid_int, artifact in psscan_artifacts:
            if pid_int not in pslist_pids:
                norm = artifact.normalized_fields
                raw = artifact.raw_fields or {}
                proc_name = norm.process_name or str(raw.get("ImageFileName", "")) or str(raw.get("Process", "")) or "unnamed"
                ppid = norm.parent_process_id or raw.get("PPID") or "N/A"
                ts = artifact.timestamp or datetime.now(timezone.utc)

                fact_msg = (
                    f"Process observed in memory scan but unlinked/absent from active process list: "
                    f"process '{proc_name}' (PID {pid_int}, PPID {ppid})."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.92,
                    severity="high",
                    mitre_mapping="T1057",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="memory.process_analyzer",
                    metadata={
                        "pid": pid_int,
                        "ppid": ppid,
                        "process_name": proc_name,
                        "discrepancy": "psscan_not_in_pslist",
                        "artifact_id": artifact.artifact_id,
                    }
                ))

        # 2. Process hierarchy and parent-child analysis
        pid_to_name: Dict[int, str] = {}
        for artifact in process_artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}
            pid = norm.process_id or raw.get("PID")
            proc_name = norm.process_name or str(raw.get("ImageFileName", "")) or str(raw.get("Process", ""))
            if pid is not None and proc_name:
                try:
                    pid_to_name[int(pid)] = proc_name.lower()
                except (ValueError, TypeError):
                    pass

        for artifact in process_artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}
            ts = artifact.timestamp or datetime.now(timezone.utc)

            pid = norm.process_id or raw.get("PID")
            ppid = norm.parent_process_id or raw.get("PPID")
            proc_name = norm.process_name or str(raw.get("ImageFileName", "")) or str(raw.get("Process", ""))
            cmdline = norm.process_command_line or str(raw.get("Args", "")) or str(raw.get("command_line", ""))

            if pid is None or not proc_name:
                continue

            try:
                pid_int = int(pid)
                ppid_int = int(ppid) if ppid is not None else None
            except (ValueError, TypeError):
                continue

            # Orphan process check
            if ppid_int is not None and ppid_int != 0 and ppid_int not in pid_to_name:
                fact_msg = (
                    f"Orphan process observed in memory: process '{proc_name}' (PID {pid_int}) "
                    f"references missing/inactive parent PID {ppid_int}."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.85,
                    severity="medium",
                    mitre_mapping="T1057",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="memory.process_analyzer",
                    metadata={
                        "pid": pid_int,
                        "ppid": ppid_int,
                        "process_name": proc_name,
                        "anomaly": "orphan_process",
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # Parent-child anomaly check for system processes
            proc_clean = proc_name.lower()
            if proc_clean in SYSTEM_EXPECTED_PARENTS and ppid_int is not None and ppid_int in pid_to_name:
                parent_name = pid_to_name[ppid_int]
                expected_parents = SYSTEM_EXPECTED_PARENTS[proc_clean]
                if parent_name not in expected_parents:
                    fact_msg = (
                        f"Process parent-child hierarchy anomaly observed: process '{proc_name}' (PID {pid_int}) "
                        f"spawned by unexpected parent '{parent_name}' (PID {ppid_int}). Expected parent: {expected_parents}."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.90,
                        severity="medium",
                        mitre_mapping="T1057",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="memory.process_analyzer",
                        metadata={
                            "pid": pid_int,
                            "ppid": ppid_int,
                            "process_name": proc_name,
                            "parent_name": parent_name,
                            "anomaly": "unexpected_parent",
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
