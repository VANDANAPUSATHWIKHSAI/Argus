"""
Memory Analysis — Memory Network Analyzer
==========================================
Analyzes memory-resident network connection structures:
- netscan, netstat, network_connection (source_tool="volatility3")

Extracts memory-resident sockets, protocol states, remote endpoints, and owning PIDs.
Maintains distinct provenance from NetworkAnalysisEngine (PCAP/Zeek network telemetry).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from preprocessing.schemas import Artifact
from forensic_analysis.schemas import Finding

logger = logging.getLogger(__name__)


class MemoryNetworkAnalyzer:
    """
    Deterministic analyzer for memory-resident network artifacts.
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

            # Accept memory.netscan, memory.netstat, or network_connection from volatility3
            if art_type not in ("memory.netscan", "memory.netstat") and not (
                art_type == "network_connection" and artifact.source_tool == "volatility3"
            ):
                continue

            pid = norm.process_id or raw.get("PID") or raw.get("pid")
            proc_name = norm.process_name or str(raw.get("Owner", "")) or str(raw.get("process_name", ""))
            src_ip = norm.src_ip or str(raw.get("LocalAddr", "")) or str(raw.get("src_ip", ""))
            src_port = norm.src_port or raw.get("LocalPort") or raw.get("src_port")
            dst_ip = norm.dst_ip or str(raw.get("ForeignAddr", "")) or str(raw.get("dst_ip", ""))
            dst_port = norm.dst_port or raw.get("ForeignPort") or raw.get("dst_port")
            proto = norm.rule_name or str(raw.get("Proto", "")) or str(raw.get("protocol", "")) or "TCP"
            state = str(raw.get("State", "")) or str(raw.get("state", "")) or "ESTABLISHED"

            if not src_ip and not dst_ip and pid is None:
                continue

            # Check if external IP connection
            is_external = dst_ip and not dst_ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "0.0.0.0", "::"))

            fact_msg = (
                f"Memory-resident network connection state observed: PID {pid or 'N/A'} ({proc_name or 'unnamed'}) "
                f"{proto} {src_ip}:{src_port or '*'} -> {dst_ip}:{dst_port or '*'} (state={state})."
            )

            findings.append(Finding(
                case_id=case_id,
                fact=fact_msg,
                confidence=0.88,
                severity="medium" if is_external else "informational",
                mitre_mapping="T1049" if is_external else None,
                timestamp=ts,
                evidence_reference=fcr_ref or artifact.artifact_id,
                source_artifact_id=artifact.artifact_id,
                layer="memory.network_analyzer",
                metadata={
                    "pid": pid,
                    "process_name": proc_name,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "state": state,
                    "is_external": is_external,
                    "artifact_id": artifact.artifact_id,
                }
            ))

        return findings
