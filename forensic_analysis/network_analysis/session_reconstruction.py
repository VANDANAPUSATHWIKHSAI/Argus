"""
Network Analysis Engine — Session Reconstruction
================================================
Groups network connection records (conn.log / network_connection) into logical network
sessions by host tuple and temporal adjacency, detecting sustained high-volume outbound
data transfer heuristics. Uses guarded terminology.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

DEFAULT_SESSION_GAP_SECONDS = 300
DEFAULT_EXFILTRATION_BYTES_THRESHOLD = 10_000_000  # 10 MB


class SessionReconstructor:
    """
    Groups network connections into sessions and flags high-volume outbound transfers.
    """

    def __init__(
        self,
        session_gap_seconds: int = DEFAULT_SESSION_GAP_SECONDS,
        exfiltration_bytes_threshold: int = DEFAULT_EXFILTRATION_BYTES_THRESHOLD,
    ):
        self.session_gap_seconds = session_gap_seconds
        self.exfiltration_bytes_threshold = exfiltration_bytes_threshold

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Groups connection artifacts into logical sessions and identifies high-volume outbound transfer heuristics.
        """
        findings: List[Finding] = []

        # Group by host pair: (src_ip, dst_ip)
        pair_artifacts: Dict[Tuple[str, str], List[Artifact]] = defaultdict(list)

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            src = norm.src_ip or norm.host or raw.get("id.orig_h") or "UNKNOWN_SRC"
            dst = norm.dst_ip or norm.domain or raw.get("id.resp_h") or "UNKNOWN_DST"

            pair_artifacts[(str(src), str(dst))].append(artifact)

        # Process each host pair and sessionize by temporal gap
        for (src, dst), conn_list in pair_artifacts.items():
            sorted_conns = sorted(
                conn_list,
                key=lambda a: a.timestamp or datetime.now(timezone.utc)
            )

            current_session: List[Artifact] = []
            sessions: List[List[Artifact]] = []

            for conn in sorted_conns:
                conn_ts = conn.timestamp or datetime.now(timezone.utc)
                if not current_session:
                    current_session.append(conn)
                else:
                    prev_ts = current_session[-1].timestamp or datetime.now(timezone.utc)
                    if (conn_ts - prev_ts).total_seconds() <= self.session_gap_seconds:
                        current_session.append(conn)
                    else:
                        sessions.append(current_session)
                        current_session = [conn]

            if current_session:
                sessions.append(current_session)

            # Evaluate total outbound volume per session
            for session in sessions:
                total_orig_bytes = 0
                for conn in session:
                    raw = conn.raw_fields or {}
                    norm = conn.normalized_fields
                    orig_b = raw.get("orig_bytes") or raw.get("request_body_len") or 0
                    try:
                        total_orig_bytes += int(orig_b)
                    except (ValueError, TypeError):
                        pass

                if total_orig_bytes >= self.exfiltration_bytes_threshold:
                    mb_size = total_orig_bytes / (1024 * 1024)
                    start_ts = session[0].timestamp or datetime.now(timezone.utc)
                    end_ts = session[-1].timestamp or datetime.now(timezone.utc)
                    duration_s = max(1.0, (end_ts - start_ts).total_seconds())

                    fact_msg = (
                        f"Possible sustained outbound transfer: observed {mb_size:.2f} MB "
                        f"transmitted from '{src}' to '{dst}' across {len(session)} connections "
                        f"over a {duration_s:.1f}s window (threshold >= {self.exfiltration_bytes_threshold / (1024*1024):.1f} MB)."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.82,
                        severity="high" if mb_size > 50 else "medium",
                        mitre_mapping="T1041",
                        timestamp=start_ts,
                        evidence_reference=fcr_ref or session[0].artifact_id,
                        source_artifact_id=session[0].artifact_id,
                        layer="network.session_reconstruction",
                        metadata={
                            "source_host": src,
                            "destination_host": dst,
                            "total_bytes": total_orig_bytes,
                            "megabytes": round(mb_size, 2),
                            "connection_count": len(session),
                            "duration_seconds": round(duration_s, 1),
                            "sample_artifact_id": session[0].artifact_id,
                        }
                    ))

        return findings
