"""
Log Analysis Engine — Auth Analyzer
====================================
Analyzes authentication events (EVTX 4624, 4625, 4648 / log.auth) for:
1. Brute-force logon attempts (N failed logons within a time window)
2. Impossible-travel style temporal anomaly lateral movement.

LIMITATION DISCLAIMER:
The impossible-travel heuristic flags accounts authenticating across multiple distinct
hosts within an extremely short time window. This is a forensic temporal anomaly heuristic,
NOT a physical geolocation claim.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

from forensic_analysis.schemas import Finding
from preprocessing.schemas import Artifact

logger = logging.getLogger(__name__)

DEFAULT_FAILED_LOGON_THRESHOLD = 5
DEFAULT_TIME_WINDOW_SECONDS = 300
DEFAULT_IMPOSSIBLE_TRAVEL_WINDOW_SECONDS = 60


class AuthAnalyzer:
    """
    Analyzes authentication telemetry for brute-force patterns and temporal movement anomalies.
    """

    def __init__(
        self,
        failed_logon_threshold: int = DEFAULT_FAILED_LOGON_THRESHOLD,
        time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
        impossible_travel_window_seconds: int = DEFAULT_IMPOSSIBLE_TRAVEL_WINDOW_SECONDS,
    ):
        self.failed_logon_threshold = failed_logon_threshold
        self.time_window_seconds = time_window_seconds
        self.impossible_travel_window_seconds = impossible_travel_window_seconds

    def analyze(
        self,
        case_id: str,
        artifacts: List[Artifact],
        fcr_ref: str
    ) -> List[Finding]:
        """
        Analyzes authentication event artifacts and returns Findings.
        """
        findings: List[Finding] = []

        # 1. Group Failed Logons (EVTX 4625) by (target_account, source_host/IP)
        failed_logons: Dict[Tuple[str, str], List[Tuple[datetime, str]]] = defaultdict(list)

        # 2. Track Successful Logons (EVTX 4624 / 4648) by target_account: list[(timestamp, target_host, artifact_id)]
        successful_logons: Dict[str, List[Tuple[datetime, str, str]]] = defaultdict(list)

        for artifact in artifacts:
            norm = artifact.normalized_fields
            raw = artifact.raw_fields or {}

            event_id = str(raw.get("event_id") or raw.get("EventID") or "")
            account = norm.user or raw.get("TargetUserName") or raw.get("user") or "UNKNOWN_USER"
            src = norm.src_ip or norm.host or raw.get("IpAddress") or raw.get("WorkstationName") or "UNKNOWN_SRC"
            target_host = norm.host or raw.get("Computer") or "UNKNOWN_HOST"
            ts = artifact.timestamp or datetime.now(timezone.utc)

            is_failure = (
                event_id == "4625"
                or raw.get("status") == "failed"
                or "failed" in str(artifact.event_summary or "").lower()
            )
            is_success = (
                event_id in ("4624", "4648")
                or raw.get("status") == "success"
                or "successful" in str(artifact.event_summary or "").lower()
            )

            if is_failure:
                failed_logons[(str(account), str(src))].append((ts, artifact.artifact_id))
            elif is_success:
                successful_logons[str(account)].append((ts, str(target_host), artifact.artifact_id))

        # Evaluate Brute Force Attempts
        for (account, src), attempts in failed_logons.items():
            if len(attempts) < self.failed_logon_threshold:
                continue

            sorted_attempts = sorted(attempts, key=lambda x: x[0])
            for i in range(len(sorted_attempts)):
                window = [
                    a for a in sorted_attempts[i:]
                    if (a[0] - sorted_attempts[i][0]).total_seconds() <= self.time_window_seconds
                ]
                if len(window) >= self.failed_logon_threshold:
                    start_ts = window[0][0]
                    first_art_id = window[0][1]
                    fact_msg = (
                        f"Brute-force authentication pattern detected: account '{account}' experienced "
                        f"{len(window)} failed logon attempts from source '{src}' within "
                        f"{(window[-1][0] - start_ts).total_seconds():.1f}s (threshold >= {self.failed_logon_threshold} failures)."
                    )
                    findings.append(Finding(
                        case_id=case_id,
                        fact=fact_msg,
                        confidence=0.92,
                        severity="high",
                        mitre_mapping="T1110",
                        timestamp=start_ts,
                        evidence_reference=fcr_ref or first_art_id,
                        source_artifact_id=first_art_id,
                        layer="log.auth_analyzer",
                        metadata={
                            "account": account,
                            "source": src,
                            "failed_attempts_count": len(window),
                            "artifact_id": first_art_id,
                        }
                    ))
                    break  # Flag once per group window

        # Evaluate Impossible Travel / Anomaly Lateral Movement
        for account, logons in successful_logons.items():
            if len(logons) < 2:
                continue

            sorted_logons = sorted(logons, key=lambda x: x[0])
            for i in range(1, len(sorted_logons)):
                prev_ts, prev_host, _ = sorted_logons[i - 1]
                curr_ts, curr_host, curr_art_id = sorted_logons[i]

                time_diff = (curr_ts - prev_ts).total_seconds()

                # Flag if different target hosts accessed within short window
                if prev_host != curr_host and prev_host != "UNKNOWN_HOST" and curr_host != "UNKNOWN_HOST":
                    if time_diff <= self.impossible_travel_window_seconds:
                        fact_msg = (
                            f"Impossible-travel temporal anomaly detected: account '{account}' authenticated "
                            f"to distinct hosts ('{prev_host}' -> '{curr_host}') within {time_diff:.1f}s "
                            f"(threshold <= {self.impossible_travel_window_seconds}s). "
                            f"Note: This is a temporal anomaly forensic heuristic, not a physical geolocation claim."
                        )
                        findings.append(Finding(
                            case_id=case_id,
                            fact=fact_msg,
                            confidence=0.88,
                            severity="medium",
                            mitre_mapping="T1078",
                            timestamp=curr_ts,
                            evidence_reference=fcr_ref or curr_art_id,
                            source_artifact_id=curr_art_id,
                            layer="log.auth_analyzer",
                            metadata={
                                "account": account,
                                "previous_host": prev_host,
                                "current_host": curr_host,
                                "time_delta_seconds": round(time_diff, 1),
                                "artifact_id": curr_art_id,
                            }
                        ))

        return findings
