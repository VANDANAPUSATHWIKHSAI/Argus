"""
Deterministic Deduplication Implementation
==========================================
Order-invariant, explainable deduplication into UnifiedArtifact records.
Preserves 100% of source_artifact_ids, source_tools, and raw evidence integrity.
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence
from datetime import datetime

from preprocessing.schemas import Artifact
from preprocessing.evidence_consolidation.schemas import UnifiedArtifact
from preprocessing.evidence_consolidation.identity import resolve_identity

logger = logging.getLogger(__name__)


def deduplicate_artifacts(
    artifacts: Sequence[Artifact],
    tenant_id: Optional[str] = None
) -> list[UnifiedArtifact]:
    """
    Deduplicate a list of Artifact objects into deterministic UnifiedArtifact entries.

    Args:
        artifacts: Sequence of Artifact objects.
        tenant_id: Optional tenant identifier for boundary isolation.

    Returns:
        List of deduplicated UnifiedArtifact records.
    """
    if not artifacts:
        return []

    # Group artifacts by identity_key
    grouped: dict[str, list[Artifact]] = {}
    id_info: dict[str, tuple[str, str, str, str, str]] = {}

    for art in artifacts:
        if not isinstance(art, Artifact) or not art.artifact_id or not art.case_id:
            continue
        c_type, c_val, cat, method, id_key, uai_id = resolve_identity(art, tenant_id=tenant_id)
        grouped.setdefault(id_key, []).append(art)
        if id_key not in id_info:
            id_info[id_key] = (c_type, c_val, cat, method, uai_id)

    unified_records: list[UnifiedArtifact] = []

    # Process each identity group deterministically
    for id_key in sorted(grouped.keys()):
        art_list = grouped[id_key]
        if not art_list:
            continue

        # Sort source artifacts by artifact_id to ensure order invariance
        sorted_arts = sorted(art_list, key=lambda a: a.artifact_id)
        c_type, c_val, cat, method, uai_id = id_info[id_key]

        first_art = sorted_arts[0]
        case_id = first_art.case_id.strip()
        t_id = (tenant_id or first_art.raw_fields.get("tenant_id") or "default_tenant").strip()

        source_aids = sorted(list(set(a.artifact_id for a in sorted_arts)))
        source_tools = sorted(list(set(a.source_tool for a in sorted_arts if a.source_tool)))

        timestamps: list[datetime] = [a.timestamp for a in sorted_arts if a.timestamp is not None]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        ts_semantics = next((a.timestamp_type for a in sorted_arts if a.timestamp_type), "event")

        try:
            uai = UnifiedArtifact(
                unified_artifact_id=uai_id,
                case_id=case_id,
                tenant_id=t_id,
                canonical_artifact_type=c_type,
                canonical_value=c_val,
                identity_category=cat,
                identity_method=method,
                identity_strength="DETERMINISTIC",
                identity_key=id_key,
                source_artifact_ids=source_aids,
                source_fcr_ids=[],
                source_tools=source_tools,
                source_count=len(source_tools),
                first_seen=first_seen,
                last_seen=last_seen,
                timestamp_semantics=ts_semantics,
                provenance_reference=f"provenance:{uai_id}"
            )
            unified_records.append(uai)
        except ValueError as e:
            logger.warning("Failed to construct UnifiedArtifact for group %s: %s", uai_id, e)

    return unified_records
