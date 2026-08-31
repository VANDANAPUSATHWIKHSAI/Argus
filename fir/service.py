"""
FIR Analyst Finding Service — Stage 4 Analyst Query & Export API Layer
======================================================================
Unified query, review-gate workflow, and export service for human analyst dashboards and reports.
Integrates FIRRepository, UnifiedEvidenceStore, and UnifiedTimelineBuilder with strict case/tenant isolation.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Optional, Sequence, Any

from fir.schemas import FIRFinding, ReviewStatus, UnreviewedFindingError
from fir.repository import FIRRepository
from forensic_analysis.unified_store import UnifiedEvidenceStore
from preprocessing.fcr_engine.timeline import UnifiedTimelineBuilder, TimelineEvent
from preprocessing.schemas import Artifact
from preprocessing.fcr_engine.schemas import CorrelationRecord

logger = logging.getLogger(__name__)


class AnalystFindingService:
    """
    Analyst-facing query, review lifecycle management, and export service.
    """

    def __init__(
        self,
        fir_repo: Optional[FIRRepository] = None,
        unified_store: Optional[UnifiedEvidenceStore] = None,
        timeline_builder: Optional[UnifiedTimelineBuilder] = None
    ):
        self.fir_repo = fir_repo or FIRRepository()
        self.unified_store = unified_store or UnifiedEvidenceStore()
        self.timeline_builder = timeline_builder or UnifiedTimelineBuilder()

    def get_finding(self, finding_id: str, case_id: str, tenant_id: str = "default") -> Optional[FIRFinding]:
        """
        Retrieve a single FIRFinding by finding_id, enforcing case and tenant isolation.
        """
        finding = self.fir_repo.findings.get(finding_id)
        if finding and finding.case_id == case_id and finding.tenant_id == tenant_id:
            return finding
        return None

    def list_findings(
        self,
        case_id: str,
        tenant_id: str = "default",
        status: Optional[ReviewStatus] = None
    ) -> List[FIRFinding]:
        """
        Retrieve all FIRFindings for a case and tenant, optionally filtered by review status.
        """
        if not case_id or not case_id.strip():
            raise ValueError("case_id is required to query analyst findings.")

        case_findings = [
            f for f in self.fir_repo.findings.values()
            if f.case_id == case_id and f.tenant_id == tenant_id
        ]

        if status is not None:
            case_findings = [f for f in case_findings if f.review_status == status]

        return sorted(case_findings, key=lambda f: f.timestamp)

    def mark_review(
        self,
        finding_id: str,
        case_id: str,
        status: ReviewStatus,
        reviewed_by: str,
        tenant_id: str = "default"
    ) -> FIRFinding:
        """
        Advance the review lifecycle status of a finding (ANALYST_CONFIRMED or ANALYST_REJECTED).
        """
        finding = self.get_finding(finding_id, case_id=case_id, tenant_id=tenant_id)
        if not finding:
            raise KeyError(f"Finding '{finding_id}' not found for case '{case_id}' and tenant '{tenant_id}'.")

        return self.fir_repo.mark_reviewed(
            tenant_id=tenant_id,
            finding_id=finding_id,
            status=status,
            reviewer_id=reviewed_by
        )

    def export_report(
        self,
        case_id: str,
        tenant_id: str = "default",
        allow_unreviewed: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Export sanitized findings dicts for downstream consumers or reports.
        Enforces review gate unless allow_unreviewed=True.
        """
        findings = self.list_findings(case_id, tenant_id=tenant_id)
        exported = []

        for f in findings:
            try:
                exported.append(f.for_export(allow_unreviewed=allow_unreviewed))
            except UnreviewedFindingError:
                logger.debug("Skipped unreviewed finding %s during export", f.finding_id)
                continue

        return exported

    def build_case_timeline(
        self,
        case_id: str,
        artifacts: Sequence[Artifact],
        correlation_records: Sequence[CorrelationRecord],
        tenant_id: str = "default"
    ) -> List[TimelineEvent]:
        """
        Build an integrated timeline incorporating artifacts, correlation records, and findings.
        """
        case_findings = self.list_findings(case_id, tenant_id=tenant_id)
        return self.timeline_builder.build_timeline(
            artifacts=artifacts,
            correlation_records=correlation_records,
            findings=case_findings
        )
