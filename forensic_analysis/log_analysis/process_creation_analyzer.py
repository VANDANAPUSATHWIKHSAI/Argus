"""
Log Analysis Engine — Process Creation Analyzer
================================================
Analyzes Windows EVTX 4688, Sysmon Event ID 1, and process_event telemetry for:
1. Living Off The Land Binaries (LOLBins) using a local versioned lolbas.json snapshot
2. Suspicious parent-child process execution relationships (e.g. Word/Excel/Outlook launching shells).

CRITICAL SECURITY REQUIREMENTS:
Command lines in evidence are treated strictly as DATA ONLY.
No commands are ever executed. No subprocess invocation with shell=True is permitted.
"""

from __future__ import annotations

import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

DEFAULT_LOLBAS_PATH = os.path.join(os.path.dirname(__file__), "lolbas.json")

# Suspicious Parent -> Child Execution Matrix
SUSPICIOUS_PARENT_CHILD: List[Tuple[str, str]] = [
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("mshta.exe", "powershell.exe"),
    ("wscript.exe", "cmd.exe"),
    ("cscript.exe", "powershell.exe"),
]


class ProcessCreationAnalyzer:
    """
    Analyzes process creation events against LOLBAS snapshot and parent-child heuristics.
    """

    def __init__(self, lolbas_path: str = DEFAULT_LOLBAS_PATH):
        self.lolbas_path = lolbas_path
        self.lolbins: Dict[str, Dict[str, str]] = {}
        self.snapshot_version = "UNKNOWN"
        self._load_lolbas()

    def _load_lolbas(self) -> None:
        """Loads local cached versioned lolbas.json snapshot."""
        if not os.path.exists(self.lolbas_path):
            logger.warning(
                "ProcessCreationAnalyzer: LOLBAS snapshot file '%s' not found. LOLBin detection disabled.",
                self.lolbas_path
            )
            return

        try:
            with open(self.lolbas_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.snapshot_version = data.get("snapshot_version", "2026.08.01")
            self.lolbins = data.get("lolbins", {})
            logger.info(
                "ProcessCreationAnalyzer: Loaded LOLBAS snapshot version '%s' (%d binaries).",
                self.snapshot_version, len(self.lolbins)
            )
        except Exception as e:
            logger.warning("ProcessCreationAnalyzer: Failed to parse LOLBAS snapshot '%s': %s", self.lolbas_path, e)

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes process creation artifacts and returns Findings.
        Does NOT execute any command lines found in evidence.
        """
        findings: List[Finding] = []

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            proc_name = (norm.process_name or raw.get("process_name") or raw.get("NewProcessName") or "").strip()
            parent_name = (raw.get("parent_process_name") or raw.get("ParentProcessName") or "").strip()
            cmd_line = norm.process_command_line or raw.get("command_line") or raw.get("CommandLine") or ""

            proc_base = os.path.basename(proc_name).lower() if proc_name else ""
            parent_base = os.path.basename(parent_name).lower() if parent_name else ""

            ts = artifact.timestamp or datetime.now(timezone.utc)

            # 1. LOLBin Detection using loaded snapshot
            if proc_base and proc_base in self.lolbins:
                info = self.lolbins[proc_base]
                category = info.get("category", "Living Off The Land Binary")
                mitre = info.get("mitre_mapping", "T1218")

                fact_msg = (
                    f"LOLBin execution detected (LOLBAS snapshot version={self.snapshot_version}): "
                    f"binary '{proc_base}' ({category}) executed on host '{norm.host or 'UNKNOWN'}' "
                    f"with command line: '{cmd_line[:150]}'"
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.90,
                    severity="high" if proc_base in ("certutil.exe", "mshta.exe") else "medium",
                    mitre_mapping=mitre,
                    timestamp=ts,
                    evidence_reference=fcr_ref or artifact.artifact_id,
                    source_artifact_id=artifact.artifact_id,
                    layer="log.process_creation_analyzer",
                    metadata={
                        "binary": proc_base,
                        "category": category,
                        "command_line": cmd_line,
                        "snapshot_version": self.snapshot_version,
                        "artifact_id": artifact.artifact_id,
                    }
                ))

            # 2. Suspicious Parent-Child Execution Heuristic
            if parent_base and proc_base:
                if (parent_base, proc_base) in SUSPICIOUS_PARENT_CHILD:
                    fact_msg = (
                        f"Suspicious parent-child process relationship detected: "
                        f"parent '{parent_base}' spawned child shell/utility '{proc_base}' "
                        f"with command line: '{cmd_line[:150]}'"
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.95,
                        severity="high",
                        mitre_mapping="T1218",
                        timestamp=ts,
                        evidence_reference=fcr_ref or artifact.artifact_id,
                        source_artifact_id=artifact.artifact_id,
                        layer="log.process_creation_analyzer",
                        metadata={
                            "parent_process": parent_base,
                            "child_process": proc_base,
                            "command_line": cmd_line,
                            "artifact_id": artifact.artifact_id,
                        }
                    ))

        return findings
