"""
Memory Analysis — DLL & Module Analyzer
========================================
Analyzes memory module listings and loader structures:
- dlllist, ldrmodules, modules, dll_record, dll_load

Detects:
1. Loader inconsistencies (InLoad=False, InInit=False, InMem=True)
2. Modules loaded from user-writable paths (C:\\Users\\, C:\\Temp\\, C:\\ProgramData\\)

Strictly enforces evidence-supported language ("Loaded module from user-writable directory").
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)

USER_WRITABLE_PATHS = (
    "c:\\users\\",
    "c:\\temp\\",
    "c:\\windows\\temp\\",
    "c:\\programdata\\",
    "\\appdata\\",
)


class DLLAnalyzer:
    """
    Deterministic analyzer for memory-resident DLL and module artifacts.
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

            if art_type not in ("memory.dlllist", "memory.ldrmodules", "memory.modules", "dll_record", "dll_load"):
                continue

            pid = norm.process_id or raw.get("PID") or raw.get("pid")
            proc_name = norm.process_name or str(raw.get("Process", "")) or str(raw.get("process_name", ""))
            dll_name = norm.file_name or str(raw.get("Name", "")) or str(raw.get("dll_name", ""))
            dll_path = norm.file_path or str(raw.get("Path", "")) or str(raw.get("dll_path", ""))

            if not dll_name and not dll_path:
                continue

            path_clean = dll_path.lower()
            fname_clean = dll_name.lower()

            # 1. User-writable directory module loading
            if any(wpath in path_clean for wpath in USER_WRITABLE_PATHS):
                fact_msg = (
                    f"Loaded module from user-writable directory observed: binary '{dll_name or path_clean}' "
                    f"path '{dll_path}' in process '{proc_name or 'N/A'}' (PID {pid or 'N/A'})."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.88,
                    severity="medium",
                    mitre_mapping="T1574.001",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="memory.dll_analyzer",
                    metadata={
                        "pid": pid,
                        "process_name": proc_name,
                        "dll_name": dll_name,
                        "dll_path": dll_path,
                        "anomaly": "user_writable_path",
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # 2. Loader inconsistency (ldrmodules checks)
            in_load = raw.get("InLoad")
            in_init = raw.get("InInit")
            in_mem = raw.get("InMem")

            if in_mem is True and (in_load is False or in_init is False):
                fact_msg = (
                    f"Module loader inconsistency observed: DLL '{dll_name or path_clean}' loaded in memory "
                    f"for process '{proc_name or 'N/A'}' (PID {pid or 'N/A'}) but unlinked from standard loader list "
                    f"(InLoad={in_load}, InInit={in_init}, InMem={in_mem})."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.92,
                    severity="high",
                    mitre_mapping="T1574.001",
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="memory.dll_analyzer",
                    metadata={
                        "pid": pid,
                        "process_name": proc_name,
                        "dll_name": dll_name,
                        "in_load": in_load,
                        "in_init": in_init,
                        "in_mem": in_mem,
                        "anomaly": "loader_inconsistency",
                        "artifact_id": artifact.artifact_id,
                    }
                ))

        return findings
