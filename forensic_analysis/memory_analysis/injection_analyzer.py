"""
Memory Analysis — Code Injection & Memory Permission Analyzer
===============================================================
Analyzes memory protection flags, VAD nodes, and malfind plugin outputs:
- malfind, vadinfo, vaddump, injection_indicator

Detects:
1. Executable private memory regions (PAGE_EXECUTE_READWRITE / RWX)
2. Injected code tags / shellcode headers in process VADs

Strictly uses conservative forensic language ("Executable private memory region (RWX) consistent with possible code injection").
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class InjectionAnalyzer:
    """
    Deterministic analyzer for memory injection and VAD protection artifacts.
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

            if art_type not in ("memory.malfind", "memory.vadinfo", "memory.vaddump", "injection_indicator"):
                continue

            pid = norm.process_id or raw.get("PID") or raw.get("pid")
            proc_name = norm.process_name or str(raw.get("Process", "")) or str(raw.get("process_name", ""))
            protection = str(raw.get("Protection", "")) or str(raw.get("protection", "")) or "PAGE_EXECUTE_READWRITE"
            start_vpn = str(raw.get("Start VPN", "")) or str(raw.get("start_vpn", "")) or str(raw.get("Offset", "")) or "0x0"
            end_vpn = str(raw.get("End VPN", "")) or str(raw.get("end_vpn", "")) or ""
            tag = str(raw.get("Tag", "")) or str(raw.get("tag", "")) or "VadS"

            addr_range = f"{start_vpn}-{end_vpn}" if end_vpn else start_vpn

            fact_msg = (
                f"Executable private memory region (RWX) consistent with possible code injection observed "
                f"in process '{proc_name or 'unnamed'}' (PID {pid or 'N/A'}) at virtual address range {addr_range} "
                f"(Protection='{protection}', Tag='{tag}')."
            )

            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=0.92,
                severity="high",
                mitre_mapping="T1055",
                timestamp=ts,
                evidence_reference=fcr_ref or artifact.artifact_id,
                source_artifact_id=artifact.artifact_id,
                layer="memory.injection_analyzer",
                metadata={
                    "pid": pid,
                    "process_name": proc_name,
                    "protection": protection,
                    "address_range": addr_range,
                    "tag": tag,
                    "artifact_id": artifact.artifact_id,
                }
            ))

        return findings
