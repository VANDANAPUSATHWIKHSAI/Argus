"""
Forensic Analysis — End-to-End Evidence Reference Validator
===========================================================
Ensures that every evidence reference supplied to or produced by an agent
is strictly connected to a real, immutable evidence record.

Traces the complete process from evidence ingestion to FIR finding creation
and downstream to Agents 1–7.

Defect Types Tested & Enforced:
  1. MISSING_RECORD         — Record does not exist in PostgreSQL or the evidence store.
  2. DELETED_REFERENCE      — Reference points to an evidence record that was deleted or tombstoned.
  3. CROSS_CASE_VIOLATION   — Reference belongs to a different case (case boundary violation).
  4. CROSS_TENANT_VIOLATION — Reference belongs to a different tenant (tenant isolation violation).
  5. INVALID_ARTIFACT_ID    — Artifact ID is corrupted, malformed, or references an invalid intake artifact.
  6. MISMATCHED_PROVENANCE  — Finding does not have unbroken, valid provenance connecting to real evidence.
  7. EMPTY_REFERENCE        — Reference is empty, whitespace, or null.

Rules:
  - A non-empty evidence ID must NEVER automatically be considered a valid citation.
  - Invalid references must be rejected or flagged, NEVER silently replaced with other IDs.
  - Original evidence and historical findings must remain untouched (immutable).
"""

from __future__ import annotations

import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from fir.repository import FIRRepository
from fir.schemas import FIRFinding
from infrastructure.schemas import Evidence, EvidenceStatus
from infrastructure.repository.evidence_store import (
    REPOSITORY_DIR,
    DELETED_EVIDENCE_IDS,
    _should_attempt_postgres,
)

logger = logging.getLogger(__name__)

ARTIFACT_PATTERN = re.compile(
    r"^(ART|EVID|ARTIFACT|EVIDENCE|FILE|HASH|OBJ|LOG|PCAP|MEM|REG)-|"
    r"\.(evtx|pcap|pcapng|raw|dmp|mem|vmtemp|vmtmp|dd|e01|mft|log|reg|bin|exe|dll)$",
    re.IGNORECASE,
)


class ReferenceDefectType(str, Enum):
    MISSING_RECORD = "MISSING_RECORD"
    DELETED_REFERENCE = "DELETED_REFERENCE"
    CROSS_CASE_VIOLATION = "CROSS_CASE_VIOLATION"
    CROSS_TENANT_VIOLATION = "CROSS_TENANT_VIOLATION"
    INVALID_ARTIFACT_ID = "INVALID_ARTIFACT_ID"
    MISMATCHED_PROVENANCE = "MISMATCHED_PROVENANCE"
    EMPTY_REFERENCE = "EMPTY_REFERENCE"


class ReferenceValidationResult(BaseModel):
    citation_id: str
    is_valid: bool
    defect_type: Optional[ReferenceDefectType] = None
    defect_message: Optional[str] = None
    record_type: Optional[str] = None  # "evidence" | "fir_finding"
    provenance_chain: List[str] = Field(default_factory=list)
    case_id: Optional[str] = None
    tenant_id: Optional[str] = None
    record_details: Dict[str, Any] = Field(default_factory=dict)


class EvidenceReferenceValidator:
    """
    Authoritative reference validator. Validates that any evidence ID or finding ID
    cited by an agent connects to an existing, non-deleted record belonging to the
    same case and tenant, with unbroken evidentiary provenance.
    """

    _in_memory_evidence: Dict[str, Evidence] = {}
    _in_memory_tombstones: Set[str] = set()

    def __init__(
        self,
        fir_repo: Optional[Any] = None,
        evidence_store: Optional[Any] = None,
    ):
        self.fir_repo = fir_repo or FIRRepository()
        self.evidence_store = evidence_store

    @classmethod
    def register_evidence(cls, ev: Evidence) -> None:
        """Register evidence in memory for testing or local pipeline sessions."""
        cls._in_memory_evidence[str(ev.evidence_id).strip()] = ev

    @classmethod
    def mark_evidence_deleted(cls, evidence_id: str) -> None:
        """Tombstone an evidence ID across in-memory tracking."""
        clean = str(evidence_id).strip()
        cls._in_memory_tombstones.add(clean)
        DELETED_EVIDENCE_IDS.add(clean)
        if clean in cls._in_memory_evidence:
            ev = cls._in_memory_evidence[clean]
            ev.status = EvidenceStatus.DELETED

    @classmethod
    def clear_cache(cls) -> None:
        """Clear test in-memory registrations."""
        cls._in_memory_evidence.clear()
        cls._in_memory_tombstones.clear()

    def _lookup_evidence(self, ev_id: str) -> Optional[Dict[str, Any]]:
        """Look up evidence record across in-memory, PostgreSQL, and filesystem store."""
        clean_id = str(ev_id).strip()

        # 1. Check in-memory registrations
        if clean_id in self._in_memory_evidence:
            ev = self._in_memory_evidence[clean_id]
            return {
                "evidence_id": clean_id,
                "case_id": ev.case_id,
                "tenant_id": ev.tenant_id or "default",
                "status": getattr(ev.status, "value", str(ev.status)),
                "filename": ev.filename,
                "source": "in_memory",
            }

        # 2. Check PostgreSQL
        if _should_attempt_postgres():
            try:
                import psycopg2
                from config.settings import settings

                conn = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=1,
                )
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT e.evidence_id, e.case_id, c.tenant_id, e.status, e.filename
                    FROM evidence e
                    LEFT JOIN cases c ON e.case_id = c.case_id
                    WHERE e.evidence_id = %s;
                    """,
                    (clean_id,),
                )
                row = cur.fetchone()
                conn.close()
                if row:
                    return {
                        "evidence_id": row[0],
                        "case_id": row[1],
                        "tenant_id": row[2] or "default",
                        "status": str(row[3]),
                        "filename": row[4],
                        "source": "postgres",
                    }
            except Exception as pg_err:
                logger.debug(f"PostgreSQL evidence query note: {pg_err}")

        # 3. Check filesystem repository
        repo_path = Path(REPOSITORY_DIR)
        if repo_path.exists():
            for case_dir in repo_path.iterdir():
                if case_dir.is_dir():
                    ev_dir = case_dir / clean_id
                    if ev_dir.exists() and ev_dir.is_dir():
                        meta_file = ev_dir / "metadata.json"
                        stored_tenant = "default"
                        status_val = "stored"
                        filename_val = clean_id
                        if meta_file.exists():
                            try:
                                with open(meta_file, "r", encoding="utf-8") as f:
                                    data = json.load(f)
                                stored_tenant = data.get("tenant_id") or "default"
                                status_val = str(data.get("status", "stored"))
                                filename_val = data.get("filename", clean_id)
                            except Exception:
                                pass
                        return {
                            "evidence_id": clean_id,
                            "case_id": case_dir.name,
                            "tenant_id": stored_tenant,
                            "status": status_val,
                            "filename": filename_val,
                            "source": "filesystem",
                        }
        return None

    def _lookup_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Look up FIR finding across repository shared dict and PostgreSQL."""
        clean_id = str(finding_id).strip()

        # 1. In-memory FIR repository
        shared = getattr(self.fir_repo, "findings", FIRRepository._shared_findings)
        if clean_id in shared:
            f = shared[clean_id]
            ev_refs = getattr(f, "evidence_reference", [])
            if isinstance(ev_refs, str):
                ev_refs = [x.strip() for x in ev_refs.split(",") if x.strip()]
            return {
                "finding_id": clean_id,
                "case_id": getattr(f, "case_id", ""),
                "tenant_id": getattr(f, "tenant_id", "default"),
                "source_artifact_id": getattr(f, "source_artifact_id", None),
                "evidence_reference": ev_refs,
                "review_status": getattr(f, "review_status", "pending_review"),
                "fact": getattr(f, "fact", ""),
                "source": "fir_in_memory",
            }

        # 2. PostgreSQL fir_findings
        if _should_attempt_postgres():
            try:
                import psycopg2
                from config.settings import settings

                conn = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=1,
                )
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT finding_id, case_id, tenant_id, source_artifact_id,
                           evidence_reference, review_status, fact
                    FROM fir_findings
                    WHERE finding_id = %s;
                    """,
                    (clean_id,),
                )
                row = cur.fetchone()
                conn.close()
                if row:
                    raw_refs = row[4]
                    if isinstance(raw_refs, (list, tuple)):
                        parsed_refs = [str(x) for x in raw_refs]
                    elif isinstance(raw_refs, str):
                        parsed_refs = [x.strip() for x in raw_refs.split(",") if x.strip()]
                    else:
                        parsed_refs = []
                    return {
                        "finding_id": row[0],
                        "case_id": row[1],
                        "tenant_id": row[2] or "default",
                        "source_artifact_id": row[3],
                        "evidence_reference": parsed_refs,
                        "review_status": str(row[5]),
                        "fact": row[6],
                        "source": "postgres",
                    }
            except Exception as pg_err:
                logger.debug(f"PostgreSQL finding lookup note: {pg_err}")

        return None

    def _is_tombstoned(self, identifier: str) -> bool:
        """Check if an ID has been tombstoned or logged as deleted."""
        clean = str(identifier).strip()
        if clean in self._in_memory_tombstones or clean in DELETED_EVIDENCE_IDS:
            return True

        if _should_attempt_postgres():
            try:
                import psycopg2
                from config.settings import settings

                conn = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=1,
                )
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT 1 FROM audit_log
                    WHERE (evidence_id = %s OR detail::text LIKE %s)
                      AND event IN ('evidence_deleted', 'finding_deleted')
                    LIMIT 1;
                    """,
                    (clean, f"%{clean}%"),
                )
                row = cur.fetchone()
                conn.close()
                if row:
                    return True
            except Exception:
                pass

        return False

    def verify_reference(
        self,
        ref_id: Any,
        case_id: str,
        tenant_id: str = "default",
    ) -> ReferenceValidationResult:
        """
        Verify that an evidence reference is connected to a real, immutable evidence record.
        Enforces tenant and case isolation, non-deletion, and unbroken provenance.
        """
        active_case = str(case_id).strip() if case_id else ""
        active_tenant = str(tenant_id).strip() if tenant_id else "default"

        # 1. Null / Empty Check
        if ref_id is None or not str(ref_id).strip():
            return ReferenceValidationResult(
                citation_id=str(ref_id or ""),
                is_valid=False,
                defect_type=ReferenceDefectType.EMPTY_REFERENCE,
                defect_message="Evidence reference cannot be empty or null.",
            )

        cid = str(ref_id).strip()

        # 2. Tombstone / Deletion Fast-Path Check
        if self._is_tombstoned(cid):
            return ReferenceValidationResult(
                citation_id=cid,
                is_valid=False,
                defect_type=ReferenceDefectType.DELETED_REFERENCE,
                defect_message=f"Evidence reference [{cid}] has been deleted from evidence custody.",
            )

        # 3. Direct Evidence Record Lookup
        ev_record = self._lookup_evidence(cid)
        if ev_record:
            rec_status = str(ev_record.get("status", "")).lower()
            if rec_status in ("deleted", "failed", "validation_failed"):
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.DELETED_REFERENCE,
                    defect_message=f"Evidence record [{cid}] has status '{rec_status}' and cannot serve as valid citation.",
                    record_type="evidence",
                    case_id=ev_record.get("case_id"),
                    tenant_id=ev_record.get("tenant_id"),
                    record_details=ev_record,
                )

            rec_tenant = ev_record.get("tenant_id") or "default"
            if active_tenant != "default" and rec_tenant != "default" and rec_tenant != active_tenant:
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.CROSS_TENANT_VIOLATION,
                    defect_message=(
                        f"Cross-tenant reference violation: Evidence [{cid}] belongs to tenant "
                        f"'{rec_tenant}', not active tenant '{active_tenant}'."
                    ),
                    record_type="evidence",
                    case_id=ev_record.get("case_id"),
                    tenant_id=rec_tenant,
                    record_details=ev_record,
                )

            rec_case = ev_record.get("case_id")
            if active_case and rec_case and str(rec_case) != active_case:
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.CROSS_CASE_VIOLATION,
                    defect_message=(
                        f"Cross-case reference violation: Evidence [{cid}] belongs to case "
                        f"'{rec_case}', not active case '{active_case}'."
                    ),
                    record_type="evidence",
                    case_id=rec_case,
                    tenant_id=rec_tenant,
                    record_details=ev_record,
                )

            # Valid evidence record citation!
            return ReferenceValidationResult(
                citation_id=cid,
                is_valid=True,
                record_type="evidence",
                provenance_chain=[cid],
                case_id=rec_case,
                tenant_id=rec_tenant,
                record_details=ev_record,
            )

        # 4. FIR Finding Lookup
        finding_record = self._lookup_finding(cid)
        if finding_record:
            f_tenant = finding_record.get("tenant_id") or "default"
            if active_tenant != "default" and f_tenant != "default" and f_tenant != active_tenant:
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.CROSS_TENANT_VIOLATION,
                    defect_message=(
                        f"Cross-tenant reference violation: Finding [{cid}] belongs to tenant "
                        f"'{f_tenant}', not active tenant '{active_tenant}'."
                    ),
                    record_type="fir_finding",
                    case_id=finding_record.get("case_id"),
                    tenant_id=f_tenant,
                    record_details=finding_record,
                )

            f_case = finding_record.get("case_id")
            if active_case and f_case and str(f_case) != active_case:
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.CROSS_CASE_VIOLATION,
                    defect_message=(
                        f"Cross-case reference violation: Finding [{cid}] belongs to case "
                        f"'{f_case}', not active case '{active_case}'."
                    ),
                    record_type="fir_finding",
                    case_id=f_case,
                    tenant_id=f_tenant,
                    record_details=finding_record,
                )

            # ── Verify Provenance Linking to Original Ingested Evidence ──
            candidate_lineage: List[str] = []
            src_art = finding_record.get("source_artifact_id")
            if src_art and str(src_art).strip():
                candidate_lineage.append(str(src_art).strip())

            ev_refs = finding_record.get("evidence_reference") or []
            for r in ev_refs:
                clean_r = str(r).strip()
                if clean_r and clean_r not in candidate_lineage:
                    candidate_lineage.append(clean_r)

            if not candidate_lineage:
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.MISMATCHED_PROVENANCE,
                    defect_message=(
                        f"Mismatched provenance: Finding [{cid}] contains no underlying evidence "
                        "lineage or source artifact references."
                    ),
                    record_type="fir_finding",
                    case_id=f_case,
                    tenant_id=f_tenant,
                    record_details=finding_record,
                )

            # Verify that at least one candidate links to an active, valid original evidence record
            valid_ancestor: Optional[str] = None
            provenance_defects: List[str] = []

            for anc in candidate_lineage:
                if self._is_tombstoned(anc):
                    provenance_defects.append(f"Ancestor [{anc}] is deleted/tombstoned")
                    continue

                anc_ev = self._lookup_evidence(anc)
                if not anc_ev:
                    provenance_defects.append(f"Ancestor [{anc}] not found in evidence store")
                    continue

                anc_status = str(anc_ev.get("status", "")).lower()
                if anc_status in ("deleted", "failed", "validation_failed"):
                    provenance_defects.append(f"Ancestor [{anc}] has status '{anc_status}'")
                    continue

                anc_tenant = anc_ev.get("tenant_id") or "default"
                if active_tenant != "default" and anc_tenant != "default" and anc_tenant != active_tenant:
                    provenance_defects.append(f"Ancestor [{anc}] tenant mismatch ({anc_tenant} != {active_tenant})")
                    continue

                anc_case = anc_ev.get("case_id")
                if active_case and anc_case and str(anc_case) != active_case:
                    provenance_defects.append(f"Ancestor [{anc}] cross-case mismatch ({anc_case} != {active_case})")
                    continue

                # Found valid ancestor!
                valid_ancestor = anc
                break

            if not valid_ancestor:
                return ReferenceValidationResult(
                    citation_id=cid,
                    is_valid=False,
                    defect_type=ReferenceDefectType.MISMATCHED_PROVENANCE,
                    defect_message=(
                        f"Mismatched provenance: Finding [{cid}] does not connect to any active, "
                        f"valid evidence record in case '{active_case}' ({'; '.join(provenance_defects)})."
                    ),
                    record_type="fir_finding",
                    case_id=f_case,
                    tenant_id=f_tenant,
                    record_details=finding_record,
                )

            # Valid finding citation with proven lineage
            return ReferenceValidationResult(
                citation_id=cid,
                is_valid=True,
                record_type="fir_finding",
                provenance_chain=[valid_ancestor, cid],
                case_id=f_case,
                tenant_id=f_tenant,
                record_details=finding_record,
            )

        # 5. Record Not Found in Evidence or Findings
        if ARTIFACT_PATTERN.search(cid):
            return ReferenceValidationResult(
                citation_id=cid,
                is_valid=False,
                defect_type=ReferenceDefectType.INVALID_ARTIFACT_ID,
                defect_message=(
                    f"Invalid artifact ID [{cid}]: Formatted as an artifact/telemetry identifier "
                    "but does not exist in the evidence repository."
                ),
            )

        return ReferenceValidationResult(
            citation_id=cid,
            is_valid=False,
            defect_type=ReferenceDefectType.MISSING_RECORD,
            defect_message=f"Missing record: Evidence reference [{cid}] does not exist in repository.",
        )

    def validate_citations(
        self,
        cited_ids: List[Any],
        case_id: str,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Validate a batch of citations produced or consumed by an agent.
        Never replaces invalid citations; flags and categorizes defects.
        """
        valid_citations: List[str] = []
        invalid_citations: List[str] = []
        defects: Dict[str, str] = {}
        provenance_map: Dict[str, List[str]] = {}
        results: List[ReferenceValidationResult] = []

        for cid in cited_ids:
            res = self.verify_reference(cid, case_id=case_id, tenant_id=tenant_id)
            results.append(res)
            clean_id = str(cid).strip() if cid is not None else ""
            if res.is_valid:
                valid_citations.append(clean_id)
                provenance_map[clean_id] = res.provenance_chain
            else:
                invalid_citations.append(clean_id)
                defects[clean_id] = res.defect_type.value if res.defect_type else "UNKNOWN_DEFECT"

        return {
            "all_valid": bool(valid_citations and not invalid_citations),
            "valid_citations": valid_citations,
            "invalid_citations": invalid_citations,
            "defects": defects,
            "provenance_map": provenance_map,
            "results": [r.model_dump() for r in results],
        }

    def extract_valid_universe(
        self,
        case_id: str,
        tenant_id: str = "default",
        findings: Optional[List[Any]] = None,
    ) -> Tuple[Set[str], Set[str], Dict[str, ReferenceValidationResult]]:
        """
        Builds the universe of valid finding IDs and valid evidence IDs
        guaranteed to have verified provenance within this case and tenant.
        """
        valid_findings: Set[str] = set()
        valid_evidence: Set[str] = set()
        cache: Dict[str, ReferenceValidationResult] = {}

        candidate_findings = findings or []
        if not candidate_findings:
            if hasattr(self.fir_repo, "get_by_case"):
                try:
                    candidate_findings = self.fir_repo.get_by_case(tenant_id=tenant_id, case_id=case_id)
                except Exception:
                    candidate_findings = []
            elif hasattr(self.fir_repo, "findings"):
                candidate_findings = list(self.fir_repo.findings.values())

        for f in candidate_findings:
            fid = getattr(f, "finding_id", None) or (f.get("finding_id") if isinstance(f, dict) else None)
            if fid:
                res = self.verify_reference(fid, case_id=case_id, tenant_id=tenant_id)
                cache[str(fid).strip()] = res
                if res.is_valid:
                    valid_findings.add(str(fid).strip())
                    for p in res.provenance_chain:
                        if p != str(fid).strip():
                            valid_evidence.add(p)

            # Check direct evidence references as candidates
            ev_refs = getattr(f, "evidence_reference", None) or (f.get("evidence_reference") if isinstance(f, dict) else None)
            if isinstance(ev_refs, str):
                ev_refs = [x.strip() for x in ev_refs.split(",") if x.strip()]
            if isinstance(ev_refs, list):
                for ev_id in ev_refs:
                    clean_ev = str(ev_id).strip()
                    if clean_ev and clean_ev not in cache:
                        ev_res = self.verify_reference(clean_ev, case_id=case_id, tenant_id=tenant_id)
                        cache[clean_ev] = ev_res
                        if ev_res.is_valid:
                            valid_evidence.add(clean_ev)

        return valid_findings, valid_evidence, cache

