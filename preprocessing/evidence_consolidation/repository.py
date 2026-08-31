"""
Evidence Consolidation Repository Implementation
=================================================
Thread-safe repository storing and indexing UnifiedArtifact, ConflictRecord,
and CompletenessMetadata. Provides the to_fir_handoff() helper adapter.
"""

from __future__ import annotations

import threading
import logging
from typing import Optional, Sequence

from preprocessing.evidence_consolidation.schemas import UnifiedArtifact, ConflictRecord, CompletenessMetadata
from fir.schemas import FIRFinding

logger = logging.getLogger(__name__)


class EvidenceConsolidationRepository:
    """
    Thread-safe repository for Evidence Consolidation data structures.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Primary storage
        self._uais: dict[str, UnifiedArtifact] = {}
        self._conflicts: dict[str, ConflictRecord] = {}
        self._completeness: dict[str, CompletenessMetadata] = {}

        # Secondary indexes for UnifiedArtifact
        self._by_case: dict[str, list[str]] = {}
        self._by_tenant: dict[str, list[str]] = {}
        self._by_artifact: dict[str, list[str]] = {}
        self._by_fcr: dict[str, list[str]] = {}
        self._by_type: dict[str, list[str]] = {}

        # Conflict index by case_id
        self._conflicts_by_case: dict[str, list[str]] = {}

    def add_unified_artifact(self, uai: UnifiedArtifact) -> UnifiedArtifact:
        """Store a single UnifiedArtifact, updating all indexes."""
        if not isinstance(uai, UnifiedArtifact):
            raise TypeError("uai must be an instance of UnifiedArtifact")

        with self._lock:
            uid = uai.unified_artifact_id
            self._uais[uid] = uai

            self._by_case.setdefault(uai.case_id, []).append(uid)
            self._by_tenant.setdefault(uai.tenant_id, []).append(uid)
            self._by_type.setdefault(uai.canonical_artifact_type, []).append(uid)

            for aid in uai.source_artifact_ids:
                self._by_artifact.setdefault(aid, []).append(uid)

            for fcr_id in uai.source_fcr_ids:
                self._by_fcr.setdefault(fcr_id, []).append(uid)

            logger.debug("Stored UnifiedArtifact %s (case=%s, type=%s)", uid, uai.case_id, uai.canonical_artifact_type)
            return uai

    def add_unified_artifacts(self, uais: Sequence[UnifiedArtifact]) -> list[UnifiedArtifact]:
        """Store multiple UnifiedArtifact instances."""
        added = []
        with self._lock:
            for uai in uais:
                added.append(self.add_unified_artifact(uai))
        return added

    def add_conflict(self, conflict: ConflictRecord) -> ConflictRecord:
        """Store a ConflictRecord."""
        if not isinstance(conflict, ConflictRecord):
            raise TypeError("conflict must be an instance of ConflictRecord")

        with self._lock:
            cid = conflict.conflict_id
            self._conflicts[cid] = conflict
            self._conflicts_by_case.setdefault(conflict.case_id, []).append(cid)
            return conflict

    def set_completeness(self, metadata: CompletenessMetadata) -> CompletenessMetadata:
        """Store CompletenessMetadata for a case."""
        if not isinstance(metadata, CompletenessMetadata):
            raise TypeError("metadata must be an instance of CompletenessMetadata")

        with self._lock:
            self._completeness[metadata.case_id] = metadata
            return metadata

    # ── Query API ─────────────────────────────────────────────────────────────

    def get_by_uai(self, unified_artifact_id: str) -> Optional[UnifiedArtifact]:
        """Get UnifiedArtifact by ID."""
        with self._lock:
            return self._uais.get(unified_artifact_id)

    def get_by_case(self, case_id: str) -> list[UnifiedArtifact]:
        """List UnifiedArtifacts for a given case_id."""
        with self._lock:
            uids = self._by_case.get(case_id, [])
            return [self._uais[uid] for uid in uids if uid in self._uais]

    def get_by_tenant(self, tenant_id: str) -> list[UnifiedArtifact]:
        """List UnifiedArtifacts for a given tenant_id."""
        with self._lock:
            uids = self._by_tenant.get(tenant_id, [])
            return [self._uais[uid] for uid in uids if uid in self._uais]

    def get_by_artifact(self, artifact_id: str) -> list[UnifiedArtifact]:
        """List UnifiedArtifacts containing source artifact_id."""
        with self._lock:
            uids = self._by_artifact.get(artifact_id, [])
            return [self._uais[uid] for uid in uids if uid in self._uais]

    def get_by_fcr(self, fcr_id: str) -> list[UnifiedArtifact]:
        """List UnifiedArtifacts referencing FCR correlation_id."""
        with self._lock:
            uids = self._by_fcr.get(fcr_id, [])
            return [self._uais[uid] for uid in uids if uid in self._uais]

    def get_by_type(self, canonical_type: str) -> list[UnifiedArtifact]:
        """List UnifiedArtifacts of a given canonical_artifact_type."""
        with self._lock:
            uids = self._by_type.get(canonical_type, [])
            return [self._uais[uid] for uid in uids if uid in self._uais]

    def get_conflicts(self, case_id: str) -> list[ConflictRecord]:
        """List ConflictRecords for a case."""
        with self._lock:
            cids = self._conflicts_by_case.get(case_id, [])
            return [self._conflicts[cid] for cid in cids if cid in self._conflicts]

    def get_missing_evidence(self, case_id: str) -> Optional[CompletenessMetadata]:
        """Get CompletenessMetadata for a case."""
        with self._lock:
            return self._completeness.get(case_id)

    def get_provenance(self, unified_artifact_id: str) -> dict:
        """Retrieve lineage traceability map for a UnifiedArtifact."""
        uai = self.get_by_uai(unified_artifact_id)
        if not uai:
            return {}
        return {
            "unified_artifact_id": uai.unified_artifact_id,
            "case_id": uai.case_id,
            "tenant_id": uai.tenant_id,
            "canonical_artifact_type": uai.canonical_artifact_type,
            "canonical_value": uai.canonical_value,
            "identity_category": uai.identity_category,
            "identity_method": uai.identity_method,
            "identity_strength": uai.identity_strength,
            "source_artifact_ids": uai.source_artifact_ids,
            "source_fcr_ids": uai.source_fcr_ids,
            "source_tools": uai.source_tools,
            "source_count": uai.source_count,
            "provenance_reference": uai.provenance_reference
        }

    def list_consolidated_evidence(self, case_id: str) -> list[UnifiedArtifact]:
        """Alias for get_by_case."""
        return self.get_by_case(case_id)

    def to_fir_handoff(self, case_id: str) -> list[FIRFinding]:
        """
        Export all UnifiedArtifacts in a case as FIRFinding objects for FIR handoff.
        Does NOT create a second FIR database.
        """
        uais = self.get_by_case(case_id)
        return [uai.to_fir_handoff() for uai in uais]

    def clear(self) -> None:
        """Reset all storage and indexes."""
        with self._lock:
            self._uais.clear()
            self._conflicts.clear()
            self._completeness.clear()
            self._by_case.clear()
            self._by_tenant.clear()
            self._by_artifact.clear()
            self._by_fcr.clear()
            self._by_type.clear()
            self._conflicts_by_case.clear()
