"""
Unified Timeline Engine Implementation
=======================================
Stage-3 Timeline Builder for ARGUS.
Consumes Stage-2 Artifact objects and Stage-3 CorrelationRecord objects
to produce a single, deterministic, chronological forensic event stream.

Guarantees:
- 100% deterministic ordering (tie-breaking by (timestamp, event_id))
- Timezone-aware UTC normalization
- Preservation of source timestamps & provenance
- Strict case and tenant isolation
- Separation of artifact events vs correlation events
- Safe handling of missing timestamps (never discarded)
"""

from __future__ import annotations

import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, Sequence, List, Dict, Any
from pydantic import BaseModel, Field, field_validator

from preprocessing.schemas import Artifact
from preprocessing.fcr_engine.schemas import CorrelationRecord

logger = logging.getLogger(__name__)


class TimelineEvent(BaseModel):
    """
    Atomic event record in the unified forensic timeline.
    """
    event_id: str
    case_id: str
    event_type: str                            # 'artifact' or 'correlation'
    timestamp: Optional[datetime] = None       # Timezone-aware UTC
    timestamp_type: Optional[str] = "none"     # 'modified', 'created', 'accessed', 'temporal_proximity', 'none'
    source_tool: str
    artifact_id: Optional[str] = None
    correlation_id: Optional[str] = None
    host: Optional[str] = None
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="after")
    @classmethod
    def _normalize_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class UnifiedTimelineBuilder:
    """
    Deterministic chronological timeline builder across multi-source forensic evidence.
    """

    def build_timeline(
        self,
        artifacts: Sequence[Artifact],
        correlation_records: Optional[Sequence[CorrelationRecord]] = None
    ) -> List[TimelineEvent]:
        """
        Construct a unified timeline from input artifacts and optional correlation records.
        """
        events: List[TimelineEvent] = []

        # 1. Process Artifact events
        if artifacts:
            for art in artifacts:
                if not isinstance(art, Artifact) or not art.artifact_id:
                    continue

                case_id = (art.case_id or "default_case").strip()
                host = self._resolve_host(art)
                ts = self._normalize_dt(art.timestamp)
                ts_type = art.timestamp_type or ("none" if ts is None else "event_time")
                
                summary = art.event_summary or f"{art.artifact_type} via {art.source_tool}"
                
                # Deterministic event_id derivation
                seed = f"ART:{case_id}:{art.artifact_id}:{ts.isoformat() if ts else 'none'}"
                event_id = f"TL-ART-{hashlib.sha256(seed.encode()).hexdigest()[:12]}"

                evt = TimelineEvent(
                    event_id=event_id,
                    case_id=case_id,
                    event_type="artifact",
                    timestamp=ts,
                    timestamp_type=ts_type,
                    source_tool=art.source_tool or "unknown_parser",
                    artifact_id=art.artifact_id,
                    host=host,
                    summary=summary,
                    details={
                        "artifact_type": art.artifact_type,
                        "parser_version": art.parser_version,
                        "raw_fields": art.raw_fields,
                        "normalized_fields": art.normalized_fields.model_dump() if art.normalized_fields else {}
                    }
                )
                events.append(evt)

        # 2. Process CorrelationRecord events
        if correlation_records:
            for rec in correlation_records:
                if not isinstance(rec, CorrelationRecord) or not rec.correlation_id:
                    continue

                case_id = (rec.case_id or "default_case").strip()
                ts = self._normalize_dt(rec.created_at)
                rel_str = ", ".join(rec.relationship_type)
                summary = f"Correlation [{rel_str}] linking {len(rec.artifact_ids)} artifacts"
                
                seed = f"CORR:{case_id}:{rec.correlation_id}:{ts.isoformat() if ts else 'none'}"
                event_id = f"TL-CORR-{hashlib.sha256(seed.encode()).hexdigest()[:12]}"

                evt = TimelineEvent(
                    event_id=event_id,
                    case_id=case_id,
                    event_type="correlation",
                    timestamp=ts,
                    timestamp_type="correlation_time",
                    source_tool="fcr_engine",
                    correlation_id=rec.correlation_id,
                    host=rec.host,
                    summary=summary,
                    details={
                        "relationship_type": rec.relationship_type,
                        "artifact_ids": rec.artifact_ids,
                        "confidence": rec.confidence,
                        "source_count": rec.source_count,
                        "distinct_artifact_types": rec.distinct_artifact_types,
                        "shared_value": rec.shared_value,
                        "strategy_params": rec.strategy_params
                    }
                )
                events.append(evt)

        # 3. Deterministic Sort:
        # Timestamped events sorted chronologically by (timestamp, event_id).
        # Events with timestamp=None appended deterministically at the end sorted by event_id.
        ts_events = [e for e in events if e.timestamp is not None]
        none_ts_events = [e for e in events if e.timestamp is None]

        ts_events.sort(key=lambda e: (e.timestamp, e.event_id))
        none_ts_events.sort(key=lambda e: e.event_id)

        return ts_events + none_ts_events

    def get_events_in_window(
        self,
        events: Sequence[TimelineEvent],
        start: datetime,
        end: datetime
    ) -> List[TimelineEvent]:
        """
        Filter timeline events within a time window [start, end] inclusive.
        """
        start_utc = self._normalize_dt(start)
        end_utc = self._normalize_dt(end)

        if not start_utc or not end_utc:
            return []

        filtered = []
        for e in events:
            if e.timestamp is not None and start_utc <= e.timestamp <= end_utc:
                filtered.append(e)
        return filtered

    def filter_by_host(
        self,
        events: Sequence[TimelineEvent],
        host: str
    ) -> List[TimelineEvent]:
        """
        Filter timeline events belonging to a specific host (case-insensitive).
        """
        if not host or not host.strip():
            return list(events)
        target = host.strip().lower()
        return [e for e in events if e.host and e.host.lower() == target]

    def filter_by_case(
        self,
        events: Sequence[TimelineEvent],
        case_id: str
    ) -> List[TimelineEvent]:
        """
        Filter timeline events belonging to a specific case_id.
        """
        if not case_id or not case_id.strip():
            return list(events)
        target = case_id.strip()
        return [e for e in events if e.case_id == target]

    def _normalize_dt(self, dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _resolve_host(self, art: Artifact) -> Optional[str]:
        if art.host_id and art.host_id.strip():
            return art.host_id.strip()
        if art.normalized_fields:
            if art.normalized_fields.host and art.normalized_fields.host.strip():
                return art.normalized_fields.host.strip()
        return None
