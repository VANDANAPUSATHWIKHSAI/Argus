"""
API Route — Case Summary Endpoint
=================================
GET /cases/{case_id}

Queries case statistics, severity breakdowns, review status metrics, and evidence source counts.
Enforces strict case and tenant isolation.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from fir.repository import FIRRepository
from fir.service import AnalystFindingService

logger = logging.getLogger(__name__)

router = APIRouter()

_fir_repo = FIRRepository()
_analyst_service = AnalystFindingService(fir_repo=_fir_repo)


class CaseSummaryResponse(BaseModel):
    case_id: str
    tenant_id: str
    total_findings: int
    severity_breakdown: Dict[str, int]
    review_status_breakdown: Dict[str, int]
    layer_breakdown: Dict[str, int]
    source_artifact_count: int
    latest_timestamp: Optional[str] = None


@router.get("/{case_id}", response_model=CaseSummaryResponse)
async def get_case(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Retrieve structured case summary, severity metrics, and review status breakdown.
    Enforces strict tenant isolation.
    """
    if not case_id or not case_id.strip():
        raise HTTPException(status_code=400, detail="case_id path parameter cannot be empty.")

    findings = _analyst_service.list_findings(case_id=case_id, tenant_id=x_tenant_id)
    if not findings:
        raise HTTPException(
            status_code=404,
            detail=f"Case '{case_id}' not found for tenant '{x_tenant_id}'."
        )

    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts: Dict[str, int] = {"pending_review": 0, "analyst_confirmed": 0, "analyst_rejected": 0}
    layer_counts: Dict[str, int] = {}
    source_artifacts = set()
    latest_ts = None

    for f in findings:
        sev = (f.severity or "medium").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        st = f.review_status.value if hasattr(f.review_status, "value") else str(f.review_status)
        status_counts[st] = status_counts.get(st, 0) + 1

        lyr = f.layer or "unknown"
        layer_counts[lyr] = layer_counts.get(lyr, 0) + 1

        if f.source_artifact_id:
            source_artifacts.add(f.source_artifact_id)

        if f.timestamp:
            ts_str = f.timestamp.isoformat()
            if latest_ts is None or ts_str > latest_ts:
                latest_ts = ts_str

    return CaseSummaryResponse(
        case_id=case_id,
        tenant_id=x_tenant_id,
        total_findings=len(findings),
        severity_breakdown=severity_counts,
        review_status_breakdown=status_counts,
        layer_breakdown=layer_counts,
        source_artifact_count=len(source_artifacts),
        latest_timestamp=latest_ts
    )
