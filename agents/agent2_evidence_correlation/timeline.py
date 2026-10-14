"""
Agent 2 — Deterministic Timeline Builder
=========================================
Extracts timestamps from FIR findings, orders them chronologically,
and constructs Master Investigation Timeline events and temporal clusters.
"""

import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from agents.agent2_evidence_correlation.schemas import TemporalCluster, TimelineEvent

logger = logging.getLogger(__name__)


class TimelineBuilder:
    """
    Deterministic master investigation timeline builder for FIR findings.
    """

    def __init__(self, time_window_seconds: float = 3600.0):
        self.time_window_seconds = time_window_seconds

    def build_timeline(
        self, findings: List[Any]
    ) -> Tuple[List[Any], List[TemporalCluster], List[TimelineEvent]]:
        """
        Takes raw/sanitized FIR findings, extracts valid timestamps,
        sorts findings chronologically, and returns:
        (sorted_findings, list_of_temporal_clusters, list_of_master_timeline_events)
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

        # Sort chronologically by timestamp, then by finding ID for deterministic repeatability
        dated_findings.sort(key=lambda x: (x[0], x[2]))
        sorted_findings = [item[1] for item in dated_findings] + undated_findings

        # Build Master Investigation Timeline events for dated findings
        master_timeline: List[TimelineEvent] = []
        for i, (dt, finding, fid) in enumerate(dated_findings):
            ev_ids = self._extract_evidence_ids(finding)
            layer = self._extract_layer(finding)
            host = self._extract_host(finding)
            user = self._extract_user(finding)
            proc = self._extract_process(finding)
            fact_desc = self._extract_text(finding)
            ts_conflict = self._check_timestamp_conflict(finding, dated_findings, i)

            master_timeline.append(
                TimelineEvent(
                    event_id=fid,
                    timestamp=dt,
                    timestamp_type="event_time",
                    evidence_ids=ev_ids,
                    source=layer,
                    host=host,
                    user=user,
                    process=proc,
                    event_description=fact_desc,
                    timestamp_conflict=ts_conflict,
                    provenance={
                        "finding_id": fid,
                        "layer": layer,
                        "evidence_reference": ev_ids,
                        "source_artifact_id": self._extract_artifact_id(finding)
                    }
                )
            )

        # Include undated findings in master_timeline as undated events
        for finding in undated_findings:
            fid = self._extract_finding_id(finding)
            ev_ids = self._extract_evidence_ids(finding)
            layer = self._extract_layer(finding)
            host = self._extract_host(finding)
            user = self._extract_user(finding)
            proc = self._extract_process(finding)
            fact_desc = self._extract_text(finding)

            master_timeline.append(
                TimelineEvent(
                    event_id=fid,
                    timestamp=None,
                    timestamp_type="undated",
                    evidence_ids=ev_ids,
                    source=layer,
                    host=host,
                    user=user,
                    process=proc,
                    event_description=fact_desc,
                    timestamp_conflict=False,
                    provenance={
                        "finding_id": fid,
                        "layer": layer,
                        "evidence_reference": ev_ids,
                        "source_artifact_id": self._extract_artifact_id(finding)
                    }
                )
            )

        # Enforce strict final chronological sorting (dated ascending, then by event_id, followed by undated)
        master_timeline.sort(
            key=lambda ev: (ev.timestamp is None, ev.timestamp or datetime.max.replace(tzinfo=timezone.utc), ev.event_id)
        )

        if not dated_findings:
            return sorted_findings, [], master_timeline

        # Build temporal clusters
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

        return sorted_findings, clusters, master_timeline

    def _extract_finding_id(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return finding.get("finding_id") or finding.get("id") or "F-UNKNOWN"
        elif hasattr(finding, "finding_id"):
            return getattr(finding, "finding_id")
        elif hasattr(finding, "id"):
            return getattr(finding, "id")
        return "F-UNKNOWN"

    def _extract_evidence_ids(self, finding: Any) -> List[str]:
        fid = self._extract_finding_id(finding)
        ev_refs = []
        if isinstance(finding, dict):
            ev_refs = finding.get("evidence_reference") or finding.get("cited_evidence_ids") or []
        elif hasattr(finding, "evidence_reference"):
            ev_refs = getattr(finding, "evidence_reference", [])
        if isinstance(ev_refs, str):
            ev_refs = [x.strip() for x in ev_refs.split(",") if x.strip()]
        res = [fid]
        for ref in ev_refs:
            if ref and str(ref) not in res:
                res.append(str(ref))
        return res

    def _extract_layer(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("layer") or "unknown")
        return str(getattr(finding, "layer", "unknown"))

    def _extract_host(self, finding: Any) -> Optional[str]:
        val = None
        if isinstance(finding, dict):
            val = finding.get("host") or finding.get("hostname")
        else:
            val = getattr(finding, "host", None) or getattr(finding, "hostname", None)
        if val:
            return str(val)
        text = self._extract_text(finding)
        match = re.search(r'\bhost(?:name)?[:=\s]+([a-zA-Z0-9_\-\.]+)\b', text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_user(self, finding: Any) -> Optional[str]:
        val = None
        if isinstance(finding, dict):
            val = finding.get("user") or finding.get("username")
        else:
            val = getattr(finding, "user", None) or getattr(finding, "username", None)
        if val:
            return str(val)
        text = self._extract_text(finding)
        match = re.search(r'\buser(?:name)?[:=\s]+([a-zA-Z0-9_\-\.]+)\b', text, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_process(self, finding: Any) -> Optional[str]:
        text = self._extract_text(finding)
        match = re.search(r'\b[a-zA-Z0-9_\-\.]+\.(?:exe|dll|ps1|bat|vbs|sys|elf)\b', text, re.IGNORECASE)
        return match.group(0) if match else None

    def _extract_text(self, finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("fact") or finding.get("sanitized_fact") or "")
        elif hasattr(finding, "sanitized_fact") and getattr(finding, "sanitized_fact"):
            return str(getattr(finding, "sanitized_fact"))
        elif hasattr(finding, "fact"):
            return str(getattr(finding, "fact"))
        return ""

    def _extract_artifact_id(self, finding: Any) -> Optional[str]:
        if isinstance(finding, dict):
            return finding.get("source_artifact_id") or finding.get("artifact_id")
        return getattr(finding, "source_artifact_id", None) or getattr(finding, "artifact_id", None)

    def _check_timestamp_conflict(self, finding: Any, dated_findings: List[Tuple[datetime, Any, str]], current_idx: int) -> bool:
        art_id = self._extract_artifact_id(finding)
        if not art_id:
            return False
        cur_dt = dated_findings[current_idx][0]
        for idx, (dt, other_f, fid) in enumerate(dated_findings):
            if idx != current_idx and self._extract_artifact_id(other_f) == art_id:
                if dt != cur_dt:
                    return True
        return False

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

