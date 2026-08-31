import logging
from enum import Enum
from pydantic import BaseModel, field_validator
from typing import Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class ReviewStatus(str, Enum):
    """
    Lifecycle state of an analyst review decision on a FIRFinding.

    PENDING_REVIEW     — default on creation; finding has not been reviewed yet.
    ANALYST_CONFIRMED  — a human analyst has confirmed the finding is valid.
    ANALYST_REJECTED   — a human analyst has determined the finding is invalid/noise.

    The review_status field on FIRFinding may ONLY be changed through
    FIRRepository.mark_reviewed(). Direct field assignment is intentionally
    blocked by the repository gate.
    """
    PENDING_REVIEW    = "pending_review"
    ANALYST_CONFIRMED = "analyst_confirmed"
    ANALYST_REJECTED  = "analyst_rejected"


class FIRFinding(BaseModel):
    finding_id: str
    case_id: str
    tenant_id: str
    fact: str
    sanitized_fact: Optional[str] = None
    redactor_version: Optional[str] = None
    injection_flagged: bool = False
    injection_score: float = 0.0
    confidence: float
    severity: str
    mitre_mapping: Optional[str] = None
    timestamp: datetime
    evidence_reference: list[str]  # links back to FCR / raw artifact(s)
    layer: str               # which analysis engine produced this
    source_artifact_id: Optional[str] = None
    finding_fingerprint: Optional[str] = None

    @field_validator("evidence_reference", mode="before")
    @classmethod
    def _coerce_evidence_reference(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            logger.warning("FIRFinding.evidence_reference received legacy scalar string; coercing to list[str].")
            if "," in v:
                return [x.strip() for x in v.split(",") if x.strip()]
            return [v.strip()] if v.strip() else []
        elif isinstance(v, list):
            res = [str(x).strip() for x in v if str(x).strip()]
            if not res:
                raise ValueError("evidence_reference list cannot be empty.")
            return res
        elif v is None:
            raise ValueError("evidence_reference cannot be None.")
        return v

    # ── Review gate ────────────────────────────────────────────────────────────
    # review_status defaults to PENDING_REVIEW on creation and may only be
    # advanced to ANALYST_CONFIRMED or ANALYST_REJECTED via
    # FIRRepository.mark_reviewed(). Nothing should treat a PENDING_REVIEW
    # finding as finalized output.
    review_status: ReviewStatus = ReviewStatus.PENDING_REVIEW
    reviewed_by:   Optional[str]      = None   # analyst id / username
    reviewed_at:   Optional[datetime] = None   # UTC timestamp of review decision

    @property
    def is_unreviewed(self) -> bool:
        """True when the finding has not yet received an analyst review decision."""
        return self.review_status == ReviewStatus.PENDING_REVIEW

    def for_export(self, *, allow_unreviewed: bool = False) -> dict:
        """
        Return a dict representation suitable for downstream consumers
        (report generation, API responses, agent context, etc.).

        If the finding is still PENDING_REVIEW and allow_unreviewed=False
        (the default), raises UnreviewedFindingError rather than silently
        emitting an unreviewed finding as if it were confirmed.

        Pass allow_unreviewed=True only when the caller explicitly acknowledges
        it is operating on unreviewed data (e.g. a live analyst dashboard that
        labels each row with its review status).
        """
        if self.is_unreviewed and not allow_unreviewed:
            raise UnreviewedFindingError(
                f"Finding {self.finding_id!r} has review_status=pending_review. "
                "Call for_export(allow_unreviewed=True) to export it explicitly, "
                "or wait until an analyst confirms/rejects it via "
                "FIRRepository.mark_reviewed()."
            )

        data = self.model_dump()
        # Annotate the export so any consumer can see the review state clearly
        data["_review_gate"] = {
            "review_status": self.review_status.value,
            "reviewed_by":   self.reviewed_by,
            "reviewed_at":   self.reviewed_at.isoformat() if self.reviewed_at else None,
            "unreviewed":    self.is_unreviewed,
        }
        return data


class UnreviewedFindingError(RuntimeError):
    """
    Raised when code attempts to export or finalize a FIRFinding that still
    has review_status == PENDING_REVIEW without explicitly opting in to
    operating on unreviewed data.
    """

