"""
Network Analysis Engine — HTTP Analyzer
========================================
Detects beaconing communication patterns over HTTP using deterministic feature heuristics:
repeated identical User-Agent, URI path, destination IP/host, multiple observations,
and regular time intervals (low inter-arrival jitter).
"""

from __future__ import annotations

import math
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

DEFAULT_MIN_BEACON_OBSERVATIONS = 4
DEFAULT_MAX_JITTER_COEFFICIENT = 0.25


class HTTPAnalyzer:
    """
    Analyzes normalized HTTP logs (http_request / network.http) for deterministic C2 beaconing.
    """

    def __init__(
        self,
        min_observations: int = DEFAULT_MIN_BEACON_OBSERVATIONS,
        max_jitter_coefficient: float = DEFAULT_MAX_JITTER_COEFFICIENT,
    ):
        self.min_observations = min_observations
        self.max_jitter_coefficient = max_jitter_coefficient

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes HTTP transaction artifacts and returns beaconing Findings.
        """
        findings: List[Finding] = []

        # Group HTTP requests by flow signature: (user_agent, uri_path, dst_host)
        flows: Dict[Tuple[str, str, str], List[Tuple[datetime, str]]] = defaultdict(list)

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            user_agent = raw.get("user_agent") or raw.get("user_agent_header") or norm.registry_value or "UNKNOWN_UA"
            uri_path = norm.url or raw.get("uri") or raw.get("path") or "/"
            dst_host = norm.dst_ip or norm.domain or norm.host or "UNKNOWN_DST"

            ts = artifact.timestamp or datetime.now(timezone.utc)
            flows[(str(user_agent), str(uri_path), str(dst_host))].append((ts, artifact.artifact_id))

        # Evaluate each flow for beaconing regularity
        for (ua, uri, dst), flow_events in flows.items():
            if len(flow_events) < self.min_observations:
                continue

            # Sort by timestamp
            sorted_events = sorted(flow_events, key=lambda x: x[0])
            timestamps = [t[0] for t in sorted_events]

            # Compute inter-arrival intervals in seconds
            intervals = [
                (timestamps[i] - timestamps[i - 1]).total_seconds()
                for i in range(1, len(timestamps))
            ]

            if not intervals or any(i <= 0 for i in intervals):
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            jitter_coeff = std_dev / mean_interval

            if jitter_coeff <= self.max_jitter_coefficient:
                first_art_id = sorted_events[0][1]
                fact_msg = (
                    f"HTTP beaconing behavior detected: repeated requests ({len(sorted_events)} connections) "
                    f"to destination '{dst}' with URI path '{uri}' and User-Agent '{ua[:50]}'. "
                    f"Mean interval = {mean_interval:.1f}s, jitter coefficient = {jitter_coeff:.3f} "
                    f"(threshold <= {self.max_jitter_coefficient})."
                )
                findings.append(Finding(
                    case_id=case_id,
                    fact=fact_msg,
                    confidence=0.92,
                    severity="high",
                    mitre_mapping="T1071.001",
                    timestamp=timestamps[0],
                    evidence_reference=fcr_ref or first_art_id,
                    source_artifact_id=first_art_id,
                    layer="network.http_analyzer",
                    metadata={
                        "user_agent": ua,
                        "uri_path": uri,
                        "destination": dst,
                        "observation_count": len(sorted_events),
                        "mean_interval_seconds": round(mean_interval, 2),
                        "jitter_coefficient": round(jitter_coeff, 4),
                        "artifact_id": first_art_id,
                    }
                ))

        return findings
