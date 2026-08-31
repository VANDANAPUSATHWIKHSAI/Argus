# Forensic Intelligence Repository (FIR)
# Single source of truth — every deterministic finding lands here.
# Every AI agent must cite this repository for any claim.

import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone
from fir.schemas import FIRFinding, ReviewStatus, UnreviewedFindingError
from sanitization.pii_redactor import PIIRedactor
from sanitization.injection_gate import InjectionGate

logger = logging.getLogger(__name__)

class FIRRepository:
    """
    FIRRepository stores and retrieves FIRFinding records.
    Automatically applies write-time PII redaction and injection checks.
    Uses class-level shared in-memory state as single source of truth across service instances.
    """
    _shared_findings: Dict[str, FIRFinding] = {}
    _shared_fingerprints: Dict[str, Dict[str, str]] = {}

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
        try:
            import psycopg2
            from config.settings import settings
            conn = psycopg2.connect(
                host=settings.postgres_host,
                port=settings.postgres_port,
                database=settings.postgres_db,
                user=settings.postgres_user,
                password=settings.postgres_password,
                connect_timeout=3
            )
            cur = conn.cursor()
            # Idempotent migration DDL updating schema safely without dropping existing rows
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
            logger.debug("Postgres persistence skipped for FIRRepository.insert: %s", e)

        return finding

    def get_by_id(self, tenant_id: str, finding_id: str) -> Optional[FIRFinding]:
        """
        Gets a finding by its ID, enforcing tenant isolation.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required to fetch findings.")
        finding = self.findings.get(finding_id)
        if finding and finding.tenant_id == tenant_id:
            return finding
        return None

    def _hydrate_from_postgres(self, case_id: str, tenant_id: str) -> None:
        """Hydrates findings from PostgreSQL 'fir_findings' table if not present in memory."""
        if any(f.case_id == case_id and f.tenant_id == tenant_id for f in self.findings.values()):
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
                connect_timeout=3
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
                        fact=fact,
                        sanitized_fact=s_fact or fact,
                        confidence=float(conf),
                        severity=sev,
                        mitre_mapping=mitre,
                        evidence_reference=list(evid_ref) if isinstance(evid_ref, (list, tuple)) else [],
                        source_artifact_id=src_art or f_id,
                        finding_fingerprint=fp or "",
                        review_status=ReviewStatus(st_val) if st_val in ReviewStatus.__members__.values() or any(st_val == member.value for member in ReviewStatus) else ReviewStatus.PENDING_REVIEW,
                        reviewed_by=rev_by,
                        injection_flagged=bool(inj_flg),
                        injection_score=float(inj_sc or 0.0),
                        layer=lyr or "unknown",
                        timestamp=ts
                    )
                    self.findings[f_id] = fnd
            conn.close()
        except Exception as e:
            logger.debug("Postgres hydration skipped: %s", e)

    def get_by_case(self, tenant_id: str, case_id: str) -> List[FIRFinding]:
        """
        Gets all findings for a given case, enforcing tenant isolation.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required to query findings.")
        self._hydrate_from_postgres(case_id, tenant_id)
        return [f for f in self.findings.values() if f.case_id == case_id and f.tenant_id == tenant_id]

    def mark_reviewed(
        self,
        tenant_id: str,
        finding_id: str,
        status: ReviewStatus,
        reviewer_id: str,
        *,
        force: bool = False,
    ) -> FIRFinding:
        """
        The ONLY mechanism that may change review_status on a FIRFinding.

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

        Returns:
            The updated FIRFinding.

        Raises:
            ValueError:  tenant_id/reviewer_id empty, finding not found,
                         wrong tenant, or invalid target status.
            RuntimeError: Attempting to overwrite an already-reviewed finding
                          without force=True.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required to mark a finding as reviewed.")
        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("reviewer_id must be a non-empty string.")
        if status == ReviewStatus.PENDING_REVIEW:
            raise ValueError(
                "Cannot set review_status back to PENDING_REVIEW. "
                "Valid review decisions are ANALYST_CONFIRMED or ANALYST_REJECTED."
            )

        finding = self.findings.get(finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id!r} not found in repository.")
        if finding.tenant_id != tenant_id:
            raise ValueError(
                f"Finding {finding_id!r} belongs to a different tenant. "
                "Access denied."
            )

        if not finding.is_unreviewed and not force:
            raise RuntimeError(
                f"Finding {finding_id!r} already has review_status="
                f"{finding.review_status.value!r} (reviewed by {finding.reviewed_by!r}). "
                "Pass force=True to overwrite an existing review decision."
            )

        finding.review_status = status
        finding.reviewed_by   = reviewer_id.strip()
        finding.reviewed_at   = datetime.now(timezone.utc)

        logger.info(
            "FIRFinding %s marked %s by %s (tenant=%s, force=%s)",
            finding_id, status.value, reviewer_id, tenant_id, force,
        )
        return finding
