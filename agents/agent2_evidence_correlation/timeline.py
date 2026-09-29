"""
Agent 2 — Deterministic Timeline Builder
=========================================
Extracts timestamps from FIR findings, orders them chronologically,
and constructs temporal clusters and anomaly signals without LLM hallucination.
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from agents.agent2_evidence_correlation.schemas import TemporalCluster

logger = logging.getLogger(__name__)


class TimelineBuilder:
    """
    Deterministic timeline builder for FIR findings.
    """

    def __init__(self, time_window_seconds: float = 3600.0):
        self.time_window_seconds = time_window_seconds

    def build_timeline(self, findings: List[Any]) -> Tuple[List[Any], List[TemporalCluster]]:
        """
        Takes raw/sanitized FIR findings, extracts valid timestamps,
        sorts findings chronologically, and returns:
        (sorted_findings, list_of_temporal_clusters)
        """
        dated_findings: List[Tuple[datetime, Any, str]] = []
        undated_findings: List[Any] = []

        for finding in findings:
            dt = self._extract_timestamp(finding)
            fid = self._extract_finding_id(finding)
            if dt is not None:
                dated_findings.append((dt, finding, fid))
            else:
                undated_findings.append(finding)

        # Sort chronologically by timestamp
        dated_findings.sort(key=lambda x: x[0])
        sorted_findings = [item[1] for item in dated_findings] + undated_findings

        if not dated_findings:
            return sorted_findings, []

        # Build clusters
        clusters: List[TemporalCluster] = []
        current_cluster_ids: List[str] = []
        cluster_start: datetime = dated_findings[0][0]
        cluster_end: datetime = dated_findings[0][0]
        prev_cluster_end: Optional[datetime] = None

        cluster_index = 1

        for i, (dt, finding, fid) in enumerate(dated_findings):
            if not current_cluster_ids:
                current_cluster_ids.append(fid)
                cluster_start = dt
                cluster_end = dt
                continue

            time_diff = (dt - cluster_end).total_seconds()
            if time_diff <= self.time_window_seconds:
                current_cluster_ids.append(fid)
                cluster_end = dt
            else:
                # Finalize previous cluster
                span = (cluster_end - cluster_start).total_seconds()
                gap = (cluster_start - prev_cluster_end).total_seconds() if prev_cluster_end else None
                overlap = span == 0.0 and len(current_cluster_ids) > 1

                clusters.append(
                    TemporalCluster(
                        cluster_id=f"TC-{cluster_index:03d}",
                        start_time=cluster_start,
                        end_time=cluster_end,
                        finding_ids=current_cluster_ids,
                        time_span_seconds=span,
                        gap_from_previous_seconds=gap,
                        overlap_noted=overlap
                    )
                )
                prev_cluster_end = cluster_end
                cluster_index += 1

                # Start new cluster
                current_cluster_ids = [fid]
                cluster_start = dt
                cluster_end = dt

        # Finalize last cluster
        if current_cluster_ids:
            span = (cluster_end - cluster_start).total_seconds()
            gap = (cluster_start - prev_cluster_end).total_seconds() if prev_cluster_end else None
            overlap = span == 0.0 and len(current_cluster_ids) > 1

            clusters.append(
                TemporalCluster(
                    cluster_id=f"TC-{cluster_index:03d}",
                    start_time=cluster_start,
                    end_time=cluster_end,
                    finding_ids=current_cluster_ids,
                    time_span_seconds=span,
                    gap_from_previous_seconds=gap,
                    overlap_noted=overlap
                )
            )

        return sorted_findings, clusters

    def _extract_finding_id(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return finding.get("finding_id") or finding.get("id") or "F-UNKNOWN"
        elif hasattr(finding, "finding_id"):
            return getattr(finding, "finding_id")
        elif hasattr(finding, "id"):
            return getattr(finding, "id")
        return "F-UNKNOWN"

    def _extract_timestamp(self, finding: Any) -> Optional[datetime]:
        raw_ts = None
        if isinstance(finding, dict):
            raw_ts = finding.get("timestamp") or finding.get("created_at") or finding.get("event_time")
        elif hasattr(finding, "timestamp"):
            raw_ts = getattr(finding, "timestamp")
        elif hasattr(finding, "created_at"):
            raw_ts = getattr(finding, "created_at")

        if raw_ts is None:
            return None

        if isinstance(raw_ts, datetime):
            if raw_ts.tzinfo is None:
                return raw_ts.replace(tzinfo=timezone.utc)
            return raw_ts

        if isinstance(raw_ts, (int, float)):
            try:
                return datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            except Exception:
                return None

        if isinstance(raw_ts, str):
            try:
                # Try standard ISO format
                clean_str = raw_ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_str)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass
            
            # Common forensic date formats fallback
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S",
                "%d-%m-%Y %H:%M:%S"
            ]
            for fmt in formats:
                try:
                    dt = datetime.strptime(raw_ts, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        return None
