# Forensic Intelligence Repository (FIR)
# Single source of truth — every deterministic finding lands here.
# Every AI agent must cite this repository for any claim.

import logging
import threading
import uuid
from typing import Dict, List, Optional
from datetime import datetime, timezone
from fir.schemas import FIRFinding, ReviewStatus, UnreviewedFindingError
from sanitization.pii_redactor import PIIRedactor
from sanitization.injection_gate import InjectionGate

logger = logging.getLogger(__name__)

def _ensure_fir_table_initialized(conn):
    if FIRRepository._table_initialized:
        return
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS fir_findings (
            finding_id          TEXT PRIMARY KEY,
            case_id             TEXT NOT NULL,
            tenant_id           TEXT NOT NULL DEFAULT 'default',
            fact                TEXT NOT NULL,
            sanitized_fact      TEXT,
            confidence          FLOAT NOT NULL DEFAULT 1.0,
            severity            TEXT NOT NULL DEFAULT 'medium',
            mitre_mapping       TEXT,
            evidence_reference  TEXT[] NOT NULL DEFAULT '{}',
            source_artifact_id  TEXT,
            finding_fingerprint TEXT,
            review_status       TEXT NOT NULL DEFAULT 'pending_review',
            reviewed_by         TEXT,
            injection_flagged   BOOLEAN DEFAULT FALSE,
            injection_score     FLOAT DEFAULT 0.0,
            layer               TEXT NOT NULL DEFAULT 'unknown',
            timestamp           TIMESTAMPTZ DEFAULT NOW(),
            raw_data            JSONB DEFAULT '{}'
        );
        ALTER TABLE fir_findings DROP CONSTRAINT IF EXISTS fir_findings_case_id_fkey;
        ALTER TABLE fir_findings ALTER COLUMN case_id TYPE TEXT USING case_id::text;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS source_engine TEXT;
        ALTER TABLE fir_findings ALTER COLUMN source_engine DROP NOT NULL;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS sanitized_fact TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS source_artifact_id TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS finding_fingerprint TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending_review';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_flagged BOOLEAN DEFAULT FALSE;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS injection_score FLOAT DEFAULT 0.0;
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS layer TEXT DEFAULT 'unknown';
        ALTER TABLE fir_findings ADD COLUMN IF NOT EXISTS timestamp TIMESTAMPTZ DEFAULT NOW();
        """
    )
    conn.commit()
    FIRRepository._table_initialized = True


class FIRRepository:
    """
    FIRRepository stores and retrieves FIRFinding records.
    Automatically applies write-time PII redaction and injection checks.
    Uses class-level shared in-memory state as single source of truth across service instances.
    """
    _shared_findings: Dict[str, FIRFinding] = {}
    _shared_fingerprints: Dict[str, Dict[str, str]] = {}
    _db_unreachable: bool = False
    _table_initialized: bool = False
    _lock: threading.RLock = threading.RLock()

    def __init__(self):
        self.findings = FIRRepository._shared_findings
        self._fingerprints = FIRRepository._shared_fingerprints
        self.pii_redactor = PIIRedactor()
        self.injection_gate = InjectionGate()

    def clear(self) -> None:
        """Clears in-memory repository store (primarily for unit test isolation)."""
        self.findings.clear()
        self._fingerprints.clear()

    def insert(self, finding: FIRFinding) -> FIRFinding:
        """
        Inserts a finding, performing write-time PII redaction and prompt injection validation with fingerprint deduplication.
        """
        case_id = finding.case_id
        fp = finding.finding_fingerprint

        if case_id not in self._fingerprints:
            self._fingerprints[case_id] = {}

        if fp and fp in self._fingerprints[case_id]:
            existing_id = self._fingerprints[case_id][fp]
            finding.finding_id = existing_id

        # 1. Write-time PII Redaction (Unaltered fact stays untouched)
        redacted_text, redactor_ver = self.pii_redactor.redact(finding.fact)
        finding.sanitized_fact = redacted_text
        finding.redactor_version = redactor_ver

        # 2. Dynamic Injection Gate checks on finding fact
        gate_res = self.injection_gate.check(finding.fact, field_name="unstructured")
        finding.injection_flagged = gate_res.injection_flagged
        finding.injection_score = gate_res.injection_score

        # 3. Store in repository
        self.findings[finding.finding_id] = finding
        if fp:
            self._fingerprints[case_id][fp] = finding.finding_id
        logger.info(
            "Inserted FIRFinding %s (Sanitized: %s, Injection Flagged: %s)",
            finding.finding_id, bool(finding.sanitized_fact), finding.injection_flagged
        )

        # 4. Attempt Postgres write to authoritative 'fir_findings' table
        from infrastructure.repository.evidence_store import _should_attempt_postgres
        if FIRRepository._db_unreachable:
            if _should_attempt_postgres():
                FIRRepository._db_unreachable = False
            else:
                return finding

        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=1
            )
            _ensure_fir_table_initialized(conn)
            cur = conn.cursor()
            review_st_str = finding.review_status.value if hasattr(finding.review_status, "value") else str(finding.review_status)
            cur.execute(
                """
                INSERT INTO fir_findings 
                    (finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                     evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                     injection_flagged, injection_score, layer, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (finding_id) DO UPDATE SET
                    fact = EXCLUDED.fact,
                    sanitized_fact = EXCLUDED.sanitized_fact,
                    confidence = EXCLUDED.confidence,
                    severity = EXCLUDED.severity,
                    mitre_mapping = EXCLUDED.mitre_mapping,
                    evidence_reference = EXCLUDED.evidence_reference,
                    source_artifact_id = EXCLUDED.source_artifact_id,
                    finding_fingerprint = EXCLUDED.finding_fingerprint,
                    review_status = EXCLUDED.review_status,
                    reviewed_by = EXCLUDED.reviewed_by,
                    injection_flagged = EXCLUDED.injection_flagged,
                    injection_score = EXCLUDED.injection_score,
                    layer = EXCLUDED.layer,
                    timestamp = EXCLUDED.timestamp;
                """,
                (
                    finding.finding_id,
                    finding.case_id,
                    finding.tenant_id,
                    finding.fact,
                    finding.sanitized_fact or finding.fact,
                    finding.confidence,
                    finding.severity,
                    finding.mitre_mapping,
                    finding.evidence_reference,
                    finding.source_artifact_id,
                    finding.finding_fingerprint,
                    review_st_str,
                    finding.reviewed_by,
                    finding.injection_flagged,
                    finding.injection_score,
                    finding.layer,
                    finding.timestamp,
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            FIRRepository._db_unreachable = True
            logger.error("Postgres insert error in FIRRepository.insert: %s. Switching to in-memory repository fallback.", e)

        return finding

    @classmethod
    def reset_db_unreachable(cls) -> None:
        """Reset DB unreachable status for testing or health check."""
        cls._db_unreachable = False

    def _hydrate_single_from_postgres(self, finding_id: str, tenant_id: str) -> Optional[FIRFinding]:
        """Hydrates a single finding from PostgreSQL 'fir_findings' table enforcing tenant scope."""
        if FIRRepository._db_unreachable:
            return None
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=1
            )
            cur = conn.cursor()
            cur.execute(
                """
                SELECT finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                       evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                       injection_flagged, injection_score, layer, timestamp
                FROM fir_findings
                WHERE finding_id = %s AND tenant_id = %s
                """,
                (finding_id, tenant_id)
            )
            row = cur.fetchone()
            if row:
                f_id, c_id, t_id, fact, s_fact, conf, sev, mitre, evid_ref, src_art, fp, st_val, rev_by, inj_flg, inj_sc, lyr, ts = row
                fnd = FIRFinding(
                    finding_id=f_id,
                    case_id=c_id,
                    tenant_id=t_id,
                    fact=fact or "",
                    sanitized_fact=s_fact or fact or "",
                    confidence=float(conf) if conf is not None else 1.0,
                    severity=str(sev) if sev else "medium",
                    mitre_mapping=str(mitre) if mitre else None,
                    evidence_reference=[str(x) for x in evid_ref] if isinstance(evid_ref, (list, tuple)) and evid_ref else [f"ref:{f_id}"],
                    source_artifact_id=str(src_art) if src_art else f_id,
                    finding_fingerprint=str(fp) if fp else "",
                    review_status=ReviewStatus(st_val) if st_val in ReviewStatus.__members__.values() or any(st_val == member.value for member in ReviewStatus) else ReviewStatus.PENDING_REVIEW,
                    reviewed_by=str(rev_by) if rev_by else None,
                    injection_flagged=bool(inj_flg) if inj_flg is not None else False,
                    injection_score=float(inj_sc or 0.0),
                    layer=str(lyr) if lyr else "unknown",
                    timestamp=ts or datetime.now(timezone.utc)
                )
                self.findings[f_id] = fnd
                conn.close()
                return fnd
            conn.close()
        except Exception as e:
            FIRRepository._db_unreachable = True
            logger.debug("Postgres single finding hydration skipped: %s", e)
        return None

    def get_by_id(
        self,
        tenant_id_or_finding_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
    ) -> Optional[FIRFinding]:
        """
        Gets a finding by its ID, enforcing tenant isolation.
        Requires both tenant_id and finding_id.
        Fails closed (returns None) if tenant_id is missing, empty, '*', or unscoped.
        """
        tid = tenant_id
        fid = finding_id

        if tenant_id_or_finding_id is not None:
            if fid is None:
                if tid is not None:
                    fid = tenant_id_or_finding_id
                else:
                    # Legacy unscoped call get_by_id(finding_id) -> fail closed!
                    return None
            else:
                tid = tenant_id_or_finding_id

        if not tid or tid in ("*", "") or not fid:
            return None

        finding = self.findings.get(fid)
        if finding:
            # Enforce strict tenant boundary without blanket wildcard/default bypass
            if finding.tenant_id == tid:
                return finding
            if not finding.tenant_id and tid == "default":
                return finding
            return None

        # Fallback to PostgreSQL if not present in memory
        return self._hydrate_single_from_postgres(fid, tid)

    def _hydrate_from_postgres(self, case_id: str, tenant_id: str) -> None:
        """Hydrates findings from PostgreSQL 'fir_findings' table."""
        if FIRRepository._db_unreachable:
            return
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=1
            )
            cur = conn.cursor()
            cur.execute(
                """
                SELECT finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                       evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                       injection_flagged, injection_score, layer, timestamp
                FROM fir_findings
                WHERE case_id = %s AND tenant_id = %s
                """,
                (case_id, tenant_id)
            )
            rows = cur.fetchall()
            for r in rows:
                f_id, c_id, t_id, fact, s_fact, conf, sev, mitre, evid_ref, src_art, fp, st_val, rev_by, inj_flg, inj_sc, lyr, ts = r
                if f_id not in self.findings:
                    fnd = FIRFinding(
                        finding_id=f_id,
                        case_id=c_id,
                        tenant_id=t_id,
                        fact=fact or "",
                        sanitized_fact=s_fact or fact or "",
                        confidence=float(conf) if conf is not None else 1.0,
                        severity=str(sev) if sev else "medium",
                        mitre_mapping=str(mitre) if mitre else None,
                        evidence_reference=[str(x) for x in evid_ref] if isinstance(evid_ref, (list, tuple)) and evid_ref else [f"ref:{f_id}"],
                        source_artifact_id=str(src_art) if src_art else f_id,
                        finding_fingerprint=str(fp) if fp else "",
                        review_status=ReviewStatus(st_val) if st_val in ReviewStatus.__members__.values() or any(st_val == member.value for member in ReviewStatus) else ReviewStatus.PENDING_REVIEW,
                        reviewed_by=str(rev_by) if rev_by else None,
                        injection_flagged=bool(inj_flg) if inj_flg is not None else False,
                        injection_score=float(inj_sc or 0.0),
                        layer=str(lyr) if lyr else "unknown",
                        timestamp=ts or datetime.now(timezone.utc)
                    )
                    self.findings[f_id] = fnd
            conn.close()
        except Exception as e:
            FIRRepository._db_unreachable = True
            logger.debug("Postgres hydration skipped: %s", e)

    def get_by_case(self, *args, **kwargs) -> List[FIRFinding]:
        """
        Gets all findings for a given case, enforcing tenant isolation.
        Requires both tenant_id and case_id.
        Supports:
        - get_by_case(tenant_id, case_id)
        - get_by_case(case_id, tenant_id=t)
        - get_by_case(case_id=c, tenant_id=t)
        - get_by_case(tenant_id=t, case_id=c)

        Fails closed (returns []) if tenant_id is missing, empty, '*', or unscoped.
        """
        tid = kwargs.get("tenant_id")
        cid = kwargs.get("case_id")

        if args:
            if len(args) == 1:
                if cid and not tid:
                    tid = args[0]
                elif tid and not cid:
                    cid = args[0]
                elif not cid and not tid:
                    cid = args[0]
            elif len(args) >= 2:
                tid, cid = args[0], args[1]

        if not cid or not tid or tid in ("*", ""):
            # Cannot establish tenant safely or unscoped query -> fail closed!
            return []

        self._hydrate_from_postgres(cid, tid)
        return [
            f for f in self.findings.values()
            if f.case_id == cid and (f.tenant_id == tid or (not f.tenant_id and tid == "default"))
        ]

    def mark_reviewed(
        self,
        tenant_id: str,
        finding_id: str,
        status: ReviewStatus,
        reviewer_id: str,
        *,
        force: bool = False,
        case_id: Optional[str] = None,
    ) -> FIRFinding:
        """
        The ONLY mechanism that may change review_status on a FIRFinding.

        Concurrency & Consistency Architecture:
        - Multi-process concurrency: When PostgreSQL is reachable, row-level locking
          (SELECT ... FOR UPDATE) inside an explicit database transaction guarantees that
          two worker processes cannot race or double-approve conflicting decisions.
        - The review-state precondition is validated and updated atomically inside PostgreSQL.
        - Multi-threading concurrency: An in-process threading.RLock (_lock) guards the
          in-memory repository dictionary mirror (self.findings) and provides concurrency
          control when operating in-memory or running unit tests without PostgreSQL.
        - Tenant and case isolation is strictly enforced in all database operations.

        Args:
            tenant_id:   Caller's tenant — enforces isolation; raises ValueError
                         if the finding belongs to a different tenant.
            finding_id:  ID of the finding to review.
            status:      New ReviewStatus (ANALYST_CONFIRMED or ANALYST_REJECTED).
                         Passing PENDING_REVIEW is rejected — use that only as
                         the initial default, never as a review decision.
            reviewer_id: Identity of the analyst making the decision (username /
                         employee ID / service account). Must be non-empty.
            force:       If True, allows overwriting an existing non-pending
                         review decision (e.g. to correct a mistake). Defaults
                         to False so accidental double-reviews are caught.
            case_id:     Optional case identifier to enforce strict case scoping.

        Returns:
            The updated FIRFinding.

        Raises:
            ValueError:  tenant_id/reviewer_id empty, finding not found,
                         wrong tenant, or invalid target status.
            RuntimeError: Attempting to overwrite an already-reviewed finding
                          without force=True.
        """
        # Protect in-process thread concurrency while delegating multi-process concurrency to PostgreSQL
        with FIRRepository._lock:
            if not tenant_id:
                raise ValueError("tenant_id is required to mark a finding as reviewed.")
            if not reviewer_id or not reviewer_id.strip():
                raise ValueError("reviewer_id must be a non-empty string.")
            if status == ReviewStatus.PENDING_REVIEW:
                raise ValueError(
                    "Cannot set review_status back to PENDING_REVIEW. "
                    "Valid review decisions are ANALYST_CONFIRMED or ANALYST_REJECTED."
                )

            # In-process pre-check: if present in memory, enforce status/tenant/case preconditions
            mem_finding = self.findings.get(finding_id)
            if mem_finding is not None:
                if mem_finding.tenant_id != tenant_id and (mem_finding.tenant_id or tenant_id != "default"):
                    raise ValueError(f"Finding {finding_id!r} belongs to a different tenant. Access denied.")
                if case_id and mem_finding.case_id != case_id:
                    raise ValueError(f"Finding {finding_id!r} belongs to case {mem_finding.case_id!r}, not {case_id!r}.")
                if not mem_finding.is_unreviewed and not force:
                    raise RuntimeError(
                        f"Finding {finding_id!r} already has review_status="
                        f"{mem_finding.review_status.value!r} (reviewed by {mem_finding.reviewed_by!r}). "
                        "Pass force=True to overwrite an existing review decision."
                    )

            now_utc = datetime.now(timezone.utc)
            review_st_str = status.value if hasattr(status, "value") else str(status)

            # 1. Authoritative PostgreSQL Row-Lock Transaction (when DB is reachable)
            from infrastructure.repository.evidence_store import _should_attempt_postgres
            if not FIRRepository._db_unreachable and _should_attempt_postgres():
                conn = None
                try:
                    import psycopg2
                    import json
                    from config.settings import settings
                    conn = psycopg2.connect(
                        host=settings.postgres_host,
                        port=settings.postgres_port,
                        database=settings.postgres_db,
                        user=settings.postgres_user,
                        password=settings.postgres_password,
                        connect_timeout=2
                    )
                    conn.autocommit = False
                    cur = conn.cursor()

                    # Authoritative row-level lock across multiple worker processes
                    # SELECT ... FOR UPDATE serializes concurrent review attempts
                    cur.execute(
                        """
                        SELECT review_status, reviewed_by, case_id, tenant_id
                        FROM fir_findings
                        WHERE finding_id = %s
                        FOR UPDATE;
                        """,
                        (finding_id,)
                    )
                    row = cur.fetchone()
                    if row is not None:
                        db_review_status, db_reviewed_by, db_case_id, db_tenant_id = row

                        if db_tenant_id != tenant_id and (db_tenant_id or tenant_id != "default"):
                            conn.rollback()
                            conn.close()
                            raise ValueError(f"Finding {finding_id!r} belongs to a different tenant. Access denied.")

                        if case_id and db_case_id != case_id:
                            conn.rollback()
                            conn.close()
                            raise ValueError(f"Finding {finding_id!r} belongs to case {db_case_id!r}, not {case_id!r}.")

                        # Atomically verify review-state precondition under the row lock
                        is_unrev = db_review_status in ("pending_review", ReviewStatus.PENDING_REVIEW.value, None, "")
                        if not is_unrev and not force:
                            conn.rollback()
                            conn.close()
                            raise RuntimeError(
                                f"Finding {finding_id!r} already has review_status={db_review_status!r} "
                                f"(reviewed by {db_reviewed_by!r}). Pass force=True to overwrite an existing review decision."
                            )

                        # Execute atomic update within PostgreSQL transaction
                        cur.execute(
                            """
                            UPDATE fir_findings
                            SET review_status = %s, reviewed_by = %s
                            WHERE finding_id = %s;
                            """,
                            (review_st_str, reviewer_id.strip(), finding_id)
                        )
                        target_cid = db_case_id
                    else:
                        # Row not yet in PostgreSQL DB: check in-memory repository
                        if mem_finding is None:
                            conn.rollback()
                            conn.close()
                            raise ValueError(f"Finding {finding_id!r} not found in repository.")

                        target_cid = case_id or mem_finding.case_id
                        cur.execute(
                            """
                            INSERT INTO fir_findings (finding_id, case_id, tenant_id, fact, sanitized_fact, review_status, reviewed_by, timestamp)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (finding_id) DO UPDATE SET review_status = EXCLUDED.review_status, reviewed_by = EXCLUDED.reviewed_by;
                            """,
                            (finding_id, target_cid, tenant_id, mem_finding.fact, mem_finding.sanitized_fact or mem_finding.fact, review_st_str, reviewer_id.strip(), now_utc)
                        )

                    # Record durable review event in DB audit_log (Authoritative Transactional Outbox)
                    outbox_event_id = f"outbox-{uuid.uuid4().hex}"
                    audit_detail = {
                        "action": "mark_reviewed",
                        "finding_id": finding_id,
                        "status": review_st_str,
                        "reviewer_id": reviewer_id.strip(),
                        "force": force,
                        "outbox_event_id": outbox_event_id,
                        "outbox_status": "pending"
                    }
                    cur.execute(
                        """
                        INSERT INTO audit_log (case_id, evidence_id, tenant_id, event, actor, timestamp, detail)
                        VALUES (%s, NULL, %s, %s, %s, %s, %s);
                        """,
                        (target_cid, tenant_id, "finding_reviewed" if not force else "finding_review_overridden", reviewer_id.strip(), now_utc, json.dumps(audit_detail))
                    )

                    conn.commit()
                    conn.close()

                    # Synchronize in-memory mirror
                    finding = self.findings.get(finding_id)
                    if finding:
                        finding.review_status = status
                        finding.reviewed_by = reviewer_id.strip()
                        finding.reviewed_at = now_utc
                        finding.outbox_event_id = outbox_event_id
                    else:
                        finding = self._hydrate_single_from_postgres(finding_id, tenant_id)

                    if not finding:
                        finding = FIRFinding(
                            finding_id=finding_id,
                            case_id=target_cid,
                            tenant_id=tenant_id,
                            fact=mem_finding.fact if mem_finding else "Forensic finding",
                            review_status=status,
                            reviewed_by=reviewer_id.strip(),
                            reviewed_at=now_utc,
                            confidence=1.0,
                            severity="medium",
                            evidence_reference=[f"ref:{finding_id}"],
                            layer="unknown",
                            outbox_event_id=outbox_event_id
                        )
                        self.findings[finding_id] = finding
                    else:
                        finding.outbox_event_id = outbox_event_id

                    logger.info(
                        "FIRFinding %s marked %s by %s in PostgreSQL (tenant=%s, case=%s, force=%s)",
                        finding_id, status.value, reviewer_id, tenant_id, case_id, force,
                    )
                    return finding

                except (ValueError, RuntimeError):
                    # Propagate domain validation and conflict exceptions directly
                    raise
                except Exception as e:
                    if conn is not None:
                        try:
                            conn.rollback()
                            conn.close()
                        except Exception:
                            pass
                    logger.error("Postgres mark_reviewed error: %s. Falling back to in-memory check.", e)

            # 2. In-Memory Store Path (Protected by _lock for fallback / unit tests when DB offline)
            finding = self.findings.get(finding_id)
            if finding is None:
                raise ValueError(f"Finding {finding_id!r} not found in repository.")
            if finding.tenant_id != tenant_id and (finding.tenant_id or tenant_id != "default"):
                raise ValueError(
                    f"Finding {finding_id!r} belongs to a different tenant. "
                    "Access denied."
                )
            if case_id and finding.case_id != case_id:
                raise ValueError(
                    f"Finding {finding_id!r} belongs to case {finding.case_id!r}, not {case_id!r}."
                )

            if not finding.is_unreviewed and not force:
                raise RuntimeError(
                    f"Finding {finding_id!r} already has review_status="
                    f"{finding.review_status.value!r} (reviewed by {finding.reviewed_by!r}). "
                    "Pass force=True to overwrite an existing review decision."
                )

            finding.review_status = status
            finding.reviewed_by   = reviewer_id.strip()
            finding.reviewed_at   = now_utc

            logger.info(
                "FIRFinding %s marked %s by %s (in-memory) (tenant=%s, force=%s)",
                finding_id, status.value, reviewer_id, tenant_id, force,
            )
            return finding

    def rollback_review(
        self,
        tenant_id: str,
        finding_id: str,
        prev_status: ReviewStatus,
        prev_reviewer: Optional[str],
        prev_reviewed_at: Optional[datetime],
        *,
        case_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Atomically rolls back an in-memory and PostgreSQL finding review state
        if downstream audit logging or persistence fails.

        Returns True if rollback succeeded, or False if rollback failed.
        """
        success = True
        from infrastructure.repository.evidence_store import _should_attempt_postgres
        if not FIRRepository._db_unreachable and _should_attempt_postgres():
            conn = None
            try:
                import psycopg2
                import json
                from config.settings import settings
                conn = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=2
                )
                conn.autocommit = False
                cur = conn.cursor()
                st_val = prev_status.value if hasattr(prev_status, "value") else str(prev_status)
                cur.execute(
                    """
                    SELECT case_id FROM fir_findings
                    WHERE finding_id = %s AND tenant_id = %s AND (%s IS NULL OR case_id = %s)
                    FOR UPDATE;
                    """,
                    (finding_id, tenant_id, case_id, case_id)
                )
                row = cur.fetchone()
                db_cid = row[0] if row else case_id

                cur.execute(
                    """
                    UPDATE fir_findings
                    SET review_status = %s, reviewed_by = %s
                    WHERE finding_id = %s AND tenant_id = %s AND (%s IS NULL OR case_id = %s);
                    """,
                    (st_val, prev_reviewer, finding_id, tenant_id, case_id, case_id)
                )
                rollback_detail = {
                    "action": "rollback_review",
                    "finding_id": finding_id,
                    "restored_status": st_val,
                    "previous_reviewer": prev_reviewer,
                    "reason": reason or "audit_write_failed"
                }
                try:
                    cur.execute(
                        """
                        INSERT INTO audit_log (case_id, evidence_id, tenant_id, event, actor, timestamp, detail)
                        VALUES (%s, NULL, %s, 'finding_review_rolled_back', %s, NOW(), %s);
                        """,
                        (db_cid, tenant_id, prev_reviewer or "system", json.dumps(rollback_detail))
                    )
                except Exception as db_audit_err:
                    logger.warning("Failed to insert rollback audit entry into DB audit_log: %s", db_audit_err)

                conn.commit()
                conn.close()
            except Exception as e:
                if conn is not None:
                    try:
                        conn.rollback()
                        conn.close()
                    except Exception:
                        pass
                logger.critical("Postgres rollback_review failed for %s: %s", finding_id, e, exc_info=True)
                success = False

        with FIRRepository._lock:
            finding = self.findings.get(finding_id)
            if finding and (finding.tenant_id == tenant_id or (not finding.tenant_id and tenant_id == "default")):
                finding.review_status = prev_status
                finding.reviewed_by = prev_reviewer
                finding.reviewed_at = prev_reviewed_at

        return success

    def reconcile_finding_audit_state(
        self,
        tenant_id: str,
        case_id: str,
        finding_id: str,
        *,
        repair: bool = False
    ) -> dict:
        """
        Identifies discrepancies between PostgreSQL fir_findings, database audit_log,
        and the file-based audit log for a finding without silently erasing audit history.
        Detects missing, duplicated, conflicting, and out-of-order audit events.

        If repair=True and a crash window occurred where PostgreSQL committed a review
        (which was written to DB audit_log) but failed to reach the file-based audit chain,
        this method idempotently appends the pending audit record to the cryptographic log
        (Transactional Outbox pattern).
        """
        result = {
            "finding_id": finding_id,
            "tenant_id": tenant_id,
            "case_id": case_id,
            "is_consistent": True,
            "db_status": None,
            "db_reviewed_by": None,
            "db_audit_count": 0,
            "db_audit_records": [],
            "file_audit_count": 0,
            "file_audit_records": [],
            "repaired": False,
            "unreconciled_issues": []
        }
        # 1. Check PostgreSQL fir_findings & audit_log
        from infrastructure.repository.evidence_store import _should_attempt_postgres
        if not FIRRepository._db_unreachable and _should_attempt_postgres():
            try:
                import psycopg2
                import json
                from config.settings import settings
                conn = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                    connect_timeout=2
                )
                cur = conn.cursor()
                cur.execute(
                    "SELECT review_status, reviewed_by FROM fir_findings WHERE finding_id = %s AND tenant_id = %s;",
                    (finding_id, tenant_id)
                )
                r = cur.fetchone()
                if r:
                    result["db_status"] = r[0]
                    result["db_reviewed_by"] = r[1]

                cur.execute(
                    "SELECT id, event, actor, timestamp, detail FROM audit_log WHERE tenant_id = %s AND detail->>'finding_id' = %s ORDER BY id ASC;",
                    (tenant_id, finding_id)
                )
                db_rows = cur.fetchall()
                result["db_audit_count"] = len(db_rows)
                for row in db_rows:
                    result["db_audit_records"].append({
                        "id": row[0],
                        "event": row[1],
                        "actor": row[2],
                        "timestamp": row[3].isoformat() if row[3] else None,
                        "detail": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {}
                    })
                conn.close()
            except Exception as e:
                result["unreconciled_issues"].append(f"DB check failed: {e}")

        # 2. Check File audit log
        import os
        from pathlib import Path
        import json
        base_logs_dir = os.getenv("ARGUS_LOGS_DIR", "logs")
        log_file = Path(base_logs_dir) / "audit" / f"{tenant_id}.jsonl"
        file_entries = []
        if log_file.exists():
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entry = json.loads(line)
                            if entry.get("finding_id") == finding_id:
                                file_entries.append(entry)
                result["file_audit_count"] = len(file_entries)
                result["file_audit_records"] = file_entries
            except Exception as e:
                result["unreconciled_issues"].append(f"File log read error: {e}")

        # 3. Detection Rules
        # A. Missing audit events (Crash window: DB reviewed but file has 0 entries)
        if result["db_status"] not in (None, "pending_review") and result["file_audit_count"] == 0:
            result["is_consistent"] = False
            is_in_progress = False
            if result["db_audit_records"]:
                latest_ts_str = result["db_audit_records"][-1].get("timestamp")
                if latest_ts_str:
                    try:
                        from datetime import datetime
                        db_ts = datetime.fromisoformat(latest_ts_str.replace("Z", "+00:00"))
                        age_sec = (datetime.now(timezone.utc) - db_ts).total_seconds()
                        if age_sec < 2.0 and not repair:
                            is_in_progress = True
                            result["in_progress"] = True
                            result["unreconciled_issues"].append(
                                f"In-progress review: finding was reviewed {age_sec:.2f}s ago and file audit delivery is in flight."
                            )
                    except Exception:
                        pass

            if not is_in_progress:
                result["unreconciled_issues"].append(
                    f"Missing audit record: finding has review_status '{result['db_status']}' in database but 0 entries in file audit log."
                )

        # B. DB status is pending_review but file has review events without rollback
        if result["db_status"] in (None, "pending_review") and result["file_audit_count"] > 0:
            has_rollback = any(
                e.get("event") in ("finding_review_rolled_back", "review_rolled_back") or
                e.get("action") == "rollback_review"
                for e in file_entries
            )
            if not has_rollback:
                result["is_consistent"] = False
                result["unreconciled_issues"].append(
                    f"Orphan audit record: finding is '{result['db_status']}' in database but has {result['file_audit_count']} un-rolled-back review entries in file audit log."
                )

        # C. Duplicated review events without override
        normal_reviews = [e for e in file_entries if e.get("event") == "finding_reviewed" and not e.get("is_override")]
        if len(normal_reviews) > 1:
            result["is_consistent"] = False
            result["unreconciled_issues"].append(
                f"Duplicated review entries: found {len(normal_reviews)} non-override 'finding_reviewed' events in file audit log."
            )

        # D. Conflicting state between latest file audit entry and database
        if file_entries and result["db_status"] is not None:
            latest_file = file_entries[-1]
            latest_status = latest_file.get("decision") or latest_file.get("new_status") or latest_file.get("status")
            if latest_status and latest_status != result["db_status"] and latest_file.get("event") != "finding_review_rolled_back":
                result["is_consistent"] = False
                result["unreconciled_issues"].append(
                    f"Conflicting status: database has '{result['db_status']}' but latest file audit record has '{latest_status}'."
                )
            latest_actor = latest_file.get("actor") or latest_file.get("reviewer") or latest_file.get("reviewer_id")
            if latest_actor and result["db_reviewed_by"] and latest_actor != result["db_reviewed_by"]:
                result["is_consistent"] = False
                result["unreconciled_issues"].append(
                    f"Conflicting reviewer: database has '{result['db_reviewed_by']}' but latest file audit record has '{latest_actor}'."
                )

        # E. Out-of-order audit event timestamps
        if len(file_entries) > 1:
            prev_ts = None
            for idx, entry in enumerate(file_entries):
                raw_ts = entry.get("timestamp")
                if raw_ts:
                    try:
                        from datetime import datetime
                        ts_val = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        if prev_ts and ts_val < prev_ts:
                            result["is_consistent"] = False
                            result["unreconciled_issues"].append(
                                f"Out-of-order audit events: entry #{idx} timestamp '{raw_ts}' is earlier than preceding entry."
                            )
                        prev_ts = ts_val
                    except Exception:
                        pass

        # 4. Idempotent Transactional Outbox Repair
        if repair and not result["is_consistent"]:
            if result["db_status"] not in (None, "pending_review") and result["file_audit_count"] == 0:
                from infrastructure.audit_logger import get_audit_logger
                audit_logger = get_audit_logger(tenant_id)
                outbox_entry = {
                    "event": "finding_reviewed",
                    "finding_id": finding_id,
                    "case_id": case_id,
                    "tenant_id": tenant_id,
                    "actor": result["db_reviewed_by"] or "system",
                    "decision": result["db_status"],
                    "status": result["db_status"],
                    "reconciled": True,
                    "reconciled_from": "postgres_audit_log"
                }
                latest_rec_id = None
                if result["db_audit_records"]:
                    latest_db_rec = result["db_audit_records"][-1]
                    outbox_entry["actor"] = latest_db_rec.get("actor", outbox_entry["actor"])
                    outbox_entry["event"] = latest_db_rec.get("event", outbox_entry["event"])
                    outbox_entry["outbox_event_id"] = latest_db_rec.get("detail", {}).get("outbox_event_id")
                    latest_rec_id = latest_db_rec.get("id")

                audit_logger.info(outbox_entry)

                if latest_rec_id and not FIRRepository._db_unreachable and _should_attempt_postgres():
                    try:
                        import psycopg2
                        from config.settings import settings
                        conn_upd = psycopg2.connect(
                            host=settings.postgres_host,
                            port=settings.postgres_port,
                            database=settings.postgres_db,
                            user=settings.postgres_user,
                            password=settings.postgres_password,
                            connect_timeout=2
                        )
                        cur_upd = conn_upd.cursor()
                        cur_upd.execute(
                            "UPDATE audit_log SET detail = detail || '{\"outbox_status\": \"delivered\"}'::jsonb WHERE id = %s;",
                            (latest_rec_id,)
                        )
                        conn_upd.commit()
                        conn_upd.close()
                    except Exception as upd_err:
                        logger.debug("Failed updating outbox status on repair: %s", upd_err)

                result["repaired"] = True
                result["is_consistent"] = True
                result["unreconciled_issues"].append("Reconciled missing file audit event from PostgreSQL outbox.")

        return result
