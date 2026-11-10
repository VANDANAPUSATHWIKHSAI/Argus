"""
Append-Only Finding Revision Repository
========================================
Manages formal, traceable correction history for FIR findings without mutating
or deleting original raw findings in PostgreSQL.

Guarantees:
  1. Append-Only: No UPDATE or DELETE operations on findings or revisions.
  2. Provenance Preservation: Original wording and evidence IDs remain linked.
  3. Idempotency: Retries do not create duplicate correction records.
  4. Tenant Isolation: All queries enforce case_id and tenant_id filtering.
  5. Audit Dual-Storage: Automatically writes to `audit_log` (reusing existing audit architecture)
     and `fir_finding_revisions` (if migration applied).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fir.revision_schemas import CorrectionStatus, FindingCorrectionRecord

logger = logging.getLogger(__name__)


class FindingRevisionRepository:
    """Repository for recording and querying append-only finding corrections."""

    def __init__(self):
        # In-memory registry for resilience when database connection pool is unavailable
        self._memory_revisions: Dict[str, FindingCorrectionRecord] = {}

    def record_correction(self, record: FindingCorrectionRecord) -> Tuple[FindingCorrectionRecord, bool]:
        """
        Appends a new correction record.
        Returns (record, is_new: bool). If an identical correction already exists,
        returns the existing record with is_new=False to prevent duplication.
        """
        # Alias for consistency
        return self._record_correction_impl(record)

    record_finding_revision = record_correction

    def _record_correction_impl(self, record: FindingCorrectionRecord) -> Tuple[FindingCorrectionRecord, bool]:
        # 1. Check in-memory store for duplicate
        for existing in self._memory_revisions.values():
            if (
                existing.original_finding_id == record.original_finding_id
                and existing.case_id == record.case_id
                and existing.tenant_id == record.tenant_id
                and existing.parser_analyzer_name == record.parser_analyzer_name
                and existing.parser_version == record.parser_version
                and existing.corrected_interpretation == record.corrected_interpretation
            ):
                return existing, False

        # 2. Check Database for duplicate and validate finding existence if PostgreSQL is available
        try:
            from api.routes.auth import get_db_connection

            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    # 2.0 Concurrency-safe advisory transaction lock on compound key hash
                    lock_key = f"{record.case_id}:{record.tenant_id}:{record.original_finding_id}:{record.parser_analyzer_name}:{record.parser_version}"
                    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s));", (lock_key,))

                    # 2.1 Validate original finding existence in fir_findings with strict tenant and case isolation
                    cur.execute(
                        """
                        SELECT 1 FROM fir_findings 
                        WHERE finding_id = %s AND case_id = %s AND tenant_id = %s
                        LIMIT 1;
                        """,
                        (record.original_finding_id, record.case_id, record.tenant_id),
                    )
                    if not cur.fetchone():
                        raise ValueError(
                            f"Cannot record correction: original finding '{record.original_finding_id}' "
                            f"does not exist for case '{record.case_id}' and tenant '{record.tenant_id}'."
                        )

                    # 2.2 Check dedicated table if it exists
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public' AND table_name = 'fir_finding_revisions'
                        );
                    """)
                    table_exists = cur.fetchone()[0]

                    if table_exists:
                        cur.execute(
                            """
                            SELECT revision_id, original_finding_id, case_id, tenant_id, original_wording,
                                   corrected_interpretation, correction_reason, parser_analyzer_name,
                                   parser_version, evidence_references, correction_status, reviewer_identity,
                                   reviewed_at, previous_revision_id, created_at
                            FROM fir_finding_revisions
                            WHERE original_finding_id = %s AND case_id = %s AND tenant_id = %s
                              AND parser_analyzer_name = %s AND parser_version = %s
                            ORDER BY created_at DESC LIMIT 1;
                            """,
                            (
                                record.original_finding_id,
                                record.case_id,
                                record.tenant_id,
                                record.parser_analyzer_name,
                                record.parser_version,
                            ),
                        )
                        row = cur.fetchone()
                        if row:
                            existing_rec = FindingCorrectionRecord(
                                revision_id=str(row[0]),
                                original_finding_id=str(row[1]),
                                case_id=str(row[2]),
                                tenant_id=str(row[3]),
                                original_wording=str(row[4]),
                                corrected_interpretation=str(row[5]),
                                correction_reason=str(row[6]),
                                parser_analyzer_name=str(row[7]),
                                parser_version=str(row[8]),
                                evidence_references=list(row[9] or []),
                                correction_status=CorrectionStatus(row[10]),
                                reviewer_identity=str(row[11]) if row[11] else None,
                                reviewed_at=row[12],
                                previous_revision_id=str(row[13]) if row[13] else None,
                                created_at=row[14],
                            )
                            self._memory_revisions[existing_rec.revision_id] = existing_rec
                            return existing_rec, False

                    # Check audit_log table without arbitrary case-level limit
                    cur.execute(
                        """
                        SELECT id, detail FROM audit_log
                        WHERE case_id = %s AND tenant_id = %s AND event = 'finding_correction_recorded'
                          AND detail->>'original_finding_id' = %s
                        ORDER BY id DESC;
                        """,
                        (record.case_id, record.tenant_id, record.original_finding_id),
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        detail = r[1] or {}
                        if (
                            detail.get("original_finding_id") == record.original_finding_id
                            and detail.get("parser_analyzer_name") == record.parser_analyzer_name
                            and detail.get("parser_version") == record.parser_version
                            and detail.get("corrected_interpretation") == record.corrected_interpretation
                        ):
                            existing_rec = FindingCorrectionRecord(
                                revision_id=detail.get("revision_id", str(uuid.uuid4())),
                                original_finding_id=detail["original_finding_id"],
                                case_id=record.case_id,
                                tenant_id=record.tenant_id,
                                original_wording=detail.get("original_wording", ""),
                                corrected_interpretation=detail.get("corrected_interpretation", ""),
                                correction_reason=detail.get("correction_reason", ""),
                                parser_analyzer_name=detail.get("parser_analyzer_name", ""),
                                parser_version=detail.get("parser_version", "1.0"),
                                evidence_references=detail.get("evidence_references", []),
                                correction_status=CorrectionStatus(detail.get("correction_status", "proposed")),
                                reviewer_identity=detail.get("reviewer_identity"),
                                reviewed_at=datetime.fromisoformat(detail["reviewed_at"]) if detail.get("reviewed_at") else None,
                                previous_revision_id=detail.get("previous_revision_id"),
                                created_at=datetime.fromisoformat(detail["created_at"]) if detail.get("created_at") else datetime.now(timezone.utc),
                            )
                            self._memory_revisions[existing_rec.revision_id] = existing_rec
                            return existing_rec, False

                    # Append to dedicated table if present
                    if table_exists:
                        cur.execute(
                            """
                            INSERT INTO fir_finding_revisions (
                                revision_id, original_finding_id, case_id, tenant_id, original_wording,
                                corrected_interpretation, correction_reason, parser_analyzer_name,
                                parser_version, evidence_references, correction_status, reviewer_identity,
                                reviewed_at, previous_revision_id, created_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                            """,
                            (
                                record.revision_id,
                                record.original_finding_id,
                                record.case_id,
                                record.tenant_id,
                                record.original_wording,
                                record.corrected_interpretation,
                                record.correction_reason,
                                record.parser_analyzer_name,
                                record.parser_version,
                                record.evidence_references,
                                record.correction_status.value if hasattr(record.correction_status, "value") else str(record.correction_status),
                                record.reviewer_identity,
                                record.reviewed_at,
                                record.previous_revision_id,
                                record.created_at,
                            ),
                        )

                    # Always append to audit_log for immutable system audit trail
                    cur.execute(
                        """
                        INSERT INTO audit_log (case_id, tenant_id, event, actor, timestamp, detail)
                        VALUES (%s, %s, %s, %s, %s, %s);
                        """,
                        (
                            record.case_id,
                            record.tenant_id,
                            "finding_correction_recorded",
                            record.parser_analyzer_name,
                            record.created_at,
                            json.dumps(record.model_dump(mode="json")),
                        ),
                    )
                conn.commit()
        except ValueError:
            raise
        except Exception as e:
            logger.info("Database connection unavailable for finding revision recording (%s). Retaining in memory.", e)

        # Store in memory registry
        self._memory_revisions[record.revision_id] = record
        return record, True

    def get_corrections_by_finding(
        self, finding_id: str, case_id: str, tenant_id: str
    ) -> List[FindingCorrectionRecord]:
        """Returns all corrections associated with a finding, sorted chronologically."""
        results = [
            r
            for r in self._memory_revisions.values()
            if r.original_finding_id == finding_id and r.case_id == case_id and r.tenant_id == tenant_id
        ]

        try:
            from api.routes.auth import get_db_connection

            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, detail FROM audit_log
                        WHERE case_id = %s AND tenant_id = %s AND event = 'finding_correction_recorded'
                        ORDER BY id ASC;
                        """,
                        (case_id, tenant_id),
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        detail = r[1] or {}
                        if detail.get("original_finding_id") == finding_id:
                            rev_id = detail.get("revision_id")
                            if rev_id and not any(res.revision_id == rev_id for res in results):
                                results.append(
                                    FindingCorrectionRecord(
                                        revision_id=rev_id,
                                        original_finding_id=detail["original_finding_id"],
                                        case_id=case_id,
                                        tenant_id=tenant_id,
                                        original_wording=detail.get("original_wording", ""),
                                        corrected_interpretation=detail.get("corrected_interpretation", ""),
                                        correction_reason=detail.get("correction_reason", ""),
                                        parser_analyzer_name=detail.get("parser_analyzer_name", ""),
                                        parser_version=detail.get("parser_version", "1.0"),
                                        evidence_references=detail.get("evidence_references", []),
                                        correction_status=CorrectionStatus(detail.get("correction_status", "proposed")),
                                        reviewer_identity=detail.get("reviewer_identity"),
                                        reviewed_at=datetime.fromisoformat(detail["reviewed_at"]) if detail.get("reviewed_at") else None,
                                        previous_revision_id=detail.get("previous_revision_id"),
                                        created_at=datetime.fromisoformat(detail["created_at"]) if detail.get("created_at") else datetime.now(timezone.utc),
                                    )
                                )
        except Exception:
            pass

        return sorted(results, key=lambda x: x.created_at)

    def get_corrections_by_case(self, case_id: str, tenant_id: str) -> List[FindingCorrectionRecord]:
        """Returns all corrections for a given case, enforcing tenant isolation and persistent retrieval."""
        results: Dict[str, FindingCorrectionRecord] = {
            r.revision_id: r
            for r in self._memory_revisions.values()
            if r.case_id == case_id and r.tenant_id == tenant_id
        }

        try:
            from api.routes.auth import get_db_connection

            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, detail FROM audit_log
                        WHERE case_id = %s AND tenant_id = %s AND event = 'finding_correction_recorded'
                        ORDER BY id ASC;
                        """,
                        (case_id, tenant_id),
                    )
                    rows = cur.fetchall()
                    for r in rows:
                        detail = r[1] or {}
                        rev_id = detail.get("revision_id")
                        if rev_id and rev_id not in results:
                            rec = FindingCorrectionRecord(
                                revision_id=rev_id,
                                original_finding_id=detail["original_finding_id"],
                                case_id=case_id,
                                tenant_id=tenant_id,
                                original_wording=detail.get("original_wording", ""),
                                corrected_interpretation=detail.get("corrected_interpretation", ""),
                                correction_reason=detail.get("correction_reason", ""),
                                parser_analyzer_name=detail.get("parser_analyzer_name", ""),
                                parser_version=detail.get("parser_version", "1.0"),
                                evidence_references=detail.get("evidence_references", []),
                                correction_status=CorrectionStatus(detail.get("correction_status", "proposed")),
                                reviewer_identity=detail.get("reviewer_identity"),
                                reviewed_at=datetime.fromisoformat(detail["reviewed_at"]) if detail.get("reviewed_at") else None,
                                previous_revision_id=detail.get("previous_revision_id"),
                                created_at=datetime.fromisoformat(detail["created_at"]) if detail.get("created_at") else datetime.now(timezone.utc),
                            )
                            results[rev_id] = rec
                            self._memory_revisions[rev_id] = rec
        except Exception as e:
            logger.info("Database note in get_corrections_by_case (%s). Returning cached records.", e)

        return sorted(results.values(), key=lambda x: x.created_at)

