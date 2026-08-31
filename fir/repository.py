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
    """
    def __init__(self):
        self.findings: Dict[str, FIRFinding] = {}
        self.pii_redactor = PIIRedactor()
        self.injection_gate = InjectionGate()

    def insert(self, finding: FIRFinding) -> FIRFinding:
        """
        Inserts a finding, performing write-time PII redaction and prompt injection validation.
        """
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
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS fir_findings (
                    finding_id          TEXT PRIMARY KEY,
                    case_id             TEXT NOT NULL,
                    tenant_id           TEXT NOT NULL,
                    fact                TEXT NOT NULL,
                    confidence          FLOAT NOT NULL,
                    severity            TEXT NOT NULL,
                    mitre_mapping       TEXT,
                    evidence_reference  TEXT[] NOT NULL DEFAULT '{}',
                    layer               TEXT NOT NULL,
                    timestamp           TIMESTAMPTZ DEFAULT NOW(),
                    raw_data            JSONB DEFAULT '{}'
                );
                """
            )
            cur.execute(
                """
                INSERT INTO fir_findings 
                    (finding_id, case_id, tenant_id, fact, confidence, severity, mitre_mapping, evidence_reference, layer, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (finding_id) DO UPDATE SET
                    fact = EXCLUDED.fact,
                    confidence = EXCLUDED.confidence,
                    severity = EXCLUDED.severity,
                    mitre_mapping = EXCLUDED.mitre_mapping,
                    evidence_reference = EXCLUDED.evidence_reference,
                    timestamp = EXCLUDED.timestamp;
                """,
                (
                    finding.finding_id,
                    finding.case_id,
                    finding.tenant_id,
                    finding.fact,
                    finding.confidence,
                    finding.severity,
                    finding.mitre_mapping,
                    finding.evidence_reference,
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

    def get_by_case(self, tenant_id: str, case_id: str) -> List[FIRFinding]:
        """
        Gets all findings for a given case, enforcing tenant isolation.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required to query findings.")
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
