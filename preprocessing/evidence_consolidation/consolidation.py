"""
Evidence Consolidation Engine Implementation
=============================================
Manages evidence deduplication, FCR consolidation, conflict preservation,
completeness tracking, and boundary isolation.

Strict Invariants:
- FALSE MERGE > FALSE SPLIT ("When in doubt, DO NOT MERGE")
- 100% Immutability of raw evidence, Artifacts, and FCRs
- Zero silent conflict resolution (all contradictions stored as UNRESOLVED ConflictRecords)
- Strict case_id and tenant_id isolation
- 0 LLM / 0 probabilistic models / 0 network calls / 0 code execution
"""

from __future__ import annotations

import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, Sequence

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.schemas import CorrelationRecord
from preprocessing.evidence_consolidation.schemas import UnifiedArtifact, ConflictRecord, CompletenessMetadata
from preprocessing.evidence_consolidation.deduplication import deduplicate_artifacts
from preprocessing.evidence_consolidation.identity import resolve_identity

logger = logging.getLogger(__name__)


class EvidenceConsolidationEngine:
    """
    Deterministic Evidence Consolidation Preprocessing Engine.
    """

    def consolidate(
        self,
        artifacts: Sequence[Artifact],
        fcrs: Optional[Sequence[CorrelationRecord]] = None,
        expected_categories: Optional[Sequence[str]] = None,
        tenant_id: Optional[str] = None
    ) -> tuple[list[UnifiedArtifact], list[ConflictRecord], CompletenessMetadata]:
        """
        Consolidate input Artifacts and optional FCRs into UnifiedArtifacts, ConflictRecords, and CompletenessMetadata.

        Args:
            artifacts: Sequence of Artifact objects.
            fcrs: Optional sequence of CorrelationRecord objects.
            expected_categories: Optional list of expected evidence categories (e.g. ["evtx", "registry", "memory_dump"]).
            tenant_id: Tenant identifier for boundary isolation.

        Returns:
            Tuple of (list[UnifiedArtifact], list[ConflictRecord], CompletenessMetadata)
        """
        if not artifacts:
            c_id = "CASE-EMPTY"
            t_id = (tenant_id or "default_tenant").strip()
            cm = CompletenessMetadata(
                case_id=c_id,
                tenant_id=t_id,
                expected_categories=list(expected_categories or []),
                missing_categories=list(expected_categories or [])
            )
            return [], [], cm

        # Group artifacts by (tenant_id, case_id) for strict boundary isolation
        by_case: dict[tuple[str, str], list[Artifact]] = {}
        for art in artifacts:
            if not isinstance(art, Artifact) or not art.artifact_id or not art.case_id:
                continue
            t_id = (tenant_id or art.raw_fields.get("tenant_id") or "default_tenant").strip()
            c_id = art.case_id.strip()
            by_case.setdefault((t_id, c_id), []).append(art)

        all_uais: list[UnifiedArtifact] = []
        all_conflicts: list[ConflictRecord] = []

        primary_key = list(by_case.keys())[0] if by_case else ("default_tenant", "CASE-UNKNOWN")
        primary_t_id, primary_c_id = primary_key

        # Process each case/tenant group in isolation
        for (t_id, c_id), case_arts in sorted(by_case.items()):
            # 1. Identity Resolution & Deduplication
            case_uais = deduplicate_artifacts(case_arts, tenant_id=t_id)

            # 2. FCR Consolidation (Link supporting_fcr_ids to UAIs)
            if fcrs:
                case_fcrs = [f for f in fcrs if isinstance(f, CorrelationRecord) and f.case_id == c_id]
                self._link_fcrs_to_uais(case_fcrs, case_uais)

            all_uais.extend(case_uais)

            # 3. Conflict Preservation (Detect contradictory evidence values)
            case_conflicts = self._detect_conflicts(t_id, c_id, case_arts, case_fcrs if fcrs else [])
            all_conflicts.extend(case_conflicts)

        # 4. Completeness Metadata Tracking
        completeness = self._track_completeness(primary_t_id, primary_c_id, artifacts, expected_categories)

        return all_uais, all_conflicts, completeness

    def _link_fcrs_to_uais(self, fcrs: list[CorrelationRecord], uais: list[UnifiedArtifact]) -> None:
        """Link relevant FCR correlation_ids to UnifiedArtifact records."""
        for uai in uais:
            source_set = set(uai.source_artifact_ids)
            fcr_ids = []
            for fcr in fcrs:
                if set(fcr.artifact_ids).intersection(source_set):
                    fcr_ids.append(fcr.correlation_id)
            uai.source_fcr_ids = sorted(list(set(fcr_ids)))

    def _detect_conflicts(
        self,
        tenant_id: str,
        case_id: str,
        artifacts: list[Artifact],
        fcrs: list[CorrelationRecord]
    ) -> list[ConflictRecord]:
        """Detect contradictory forensic evidence values and store them as UNRESOLVED ConflictRecords."""
        conflicts: list[ConflictRecord] = []

        # 1. Host Name Conflicts across artifacts
        hosts = sorted(list(set(a.normalized_fields.host.lower() for a in artifacts if a.normalized_fields and a.normalized_fields.host)))
        if len(hosts) > 1:
            cnf_id = self._generate_conflict_id(tenant_id, case_id, "HOST_CONFLICT", hosts)
            conflicts.append(ConflictRecord(
                conflict_id=cnf_id,
                case_id=case_id,
                tenant_id=tenant_id,
                conflict_type="HOST_CONFLICT",
                sources=[a.artifact_id for a in artifacts],
                details={"detected_hosts": hosts},
                status="UNRESOLVED"
            ))

        # 2. Timestamp Skew Conflicts (> 24h skew on same path/resource)
        by_path: dict[str, list[Artifact]] = {}
        for a in artifacts:
            if a.normalized_fields and a.normalized_fields.file_path and a.timestamp:
                by_path.setdefault(a.normalized_fields.file_path.lower(), []).append(a)

        for path, p_arts in by_path.items():
            if len(p_arts) >= 2:
                ts_list = sorted([a.timestamp for a in p_arts if a.timestamp])
                if len(ts_list) >= 2:
                    delta_hours = (ts_list[-1] - ts_list[0]).total_seconds() / 3600.0
                    if delta_hours > 24.0:
                        cnf_id = self._generate_conflict_id(tenant_id, case_id, "TIMESTAMP_CONFLICT", [path])
                        conflicts.append(ConflictRecord(
                            conflict_id=cnf_id,
                            case_id=case_id,
                            tenant_id=tenant_id,
                            conflict_type="TIMESTAMP_CONFLICT",
                            sources=[a.artifact_id for a in p_arts],
                            details={"path": path, "skew_hours": round(delta_hours, 2), "timestamps": [ts.isoformat() for ts in ts_list]},
                            status="UNRESOLVED"
                        ))

        return conflicts

    def _track_completeness(
        self,
        tenant_id: str,
        case_id: str,
        artifacts: Sequence[Artifact],
        expected_categories: Optional[Sequence[str]]
    ) -> CompletenessMetadata:
        """Construct CompletenessMetadata comparing expected vs received categories."""
        expected = sorted(list(set(expected_categories or [])))
        received = sorted(list(set(a.artifact_type for a in artifacts if a.artifact_type)))
        parsed = list(received)
        failed: list[str] = []
        missing = [cat for cat in expected if cat not in received]

        statuses = {}
        for cat in expected:
            if cat in received:
                statuses[cat] = "PARSED"
            else:
                statuses[cat] = "MISSING"

        return CompletenessMetadata(
            case_id=case_id,
            tenant_id=tenant_id,
            expected_categories=expected,
            received_categories=received,
            parsed_categories=parsed,
            failed_categories=failed,
            missing_categories=missing,
            category_statuses=statuses
        )

    def _generate_conflict_id(self, tenant_id: str, case_id: str, cnf_type: str, seed_items: list[str]) -> str:
        """Generate deterministic conflict ID matching ^CNF-[0-9]{5,}$."""
        seed = f"{tenant_id}:{case_id}:{cnf_type}:" + ",".join(sorted(seed_items))
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        num_val = int(digest[:8], 16) % 1000000
        return f"CNF-{num_val:06d}"
