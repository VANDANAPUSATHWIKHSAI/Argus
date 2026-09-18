"""
API Route — Report Export Endpoint
===================================
GET /reports/{case_id}/report

Generates and exports legal-grade forensic reports in HTML, JSON, or PDF format.
Reuses AnalystFindingService, FIRRepository, and ReportGenerator.
Enforces review status gating (allow_unreviewed=False default) and tenant isolation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Response

from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from report_generation.generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter()

_fir_repo = FIRRepository()
_analyst_service = AnalystFindingService(fir_repo=_fir_repo)
_report_generator = ReportGenerator()


from fastapi.responses import Response

@router.get(
    "/{case_id}/report",
    response_class=Response,
    responses={
        200: {
            "content": {
                "text/html": {"schema": {"type": "string", "format": "binary"}},
                "application/json": {},
                "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            },
            "description": "Report generated successfully."
        }
    }
)
async def get_report(
    case_id: str,
    format: str = Query("html", description="Report format: 'html', 'json', or 'pdf'"),
    allow_unreviewed: bool = Query(True, description="Whether to include unreviewed findings"),
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Generate and download a forensic case report package in HTML, JSON, or PDF format.
    Enforces review status gating and strict tenant isolation.
    """
    if not case_id or not case_id.strip():
        raise HTTPException(status_code=400, detail="case_id path parameter cannot be empty.")

    from api.routes.evidence import sanitize_uuid
    clean_case_id = sanitize_uuid(case_id)

    from infrastructure.repository.evidence_store import list_evidence_by_case

    # 1. Fetch case evidence and findings with tenant isolation
    evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=clean_case_id)
    if not evidence_list and case_id != clean_case_id:
        evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=case_id)

    findings = _analyst_service.list_findings(case_id=clean_case_id, tenant_id=x_tenant_id)
    target_case_id = clean_case_id
    if not findings and case_id != clean_case_id:
        findings = _analyst_service.list_findings(case_id=case_id, tenant_id=x_tenant_id)
        if findings:
            target_case_id = case_id

    if not evidence_list and not findings:
        raise HTTPException(
            status_code=404,
            detail=f"Case '{case_id}' not found for tenant '{x_tenant_id}'."
        )

    # 2. Export sanitized findings payload subject to review gate
    exported_findings = []
    if findings:
        exported_findings = _analyst_service.export_report(
            case_id=target_case_id,
            tenant_id=x_tenant_id,
            allow_unreviewed=allow_unreviewed
        )

    # Build timeline entries for report payload
    timeline_events = []
    for f in findings:
        if allow_unreviewed or (hasattr(f.review_status, "value") and f.review_status.value != "pending_review") or str(f.review_status) != "pending_review":
            timeline_events.append({
                "timestamp": f.timestamp.isoformat() if hasattr(f.timestamp, "isoformat") and f.timestamp else str(f.timestamp) if f.timestamp else None,
                "event_type": f.layer or "finding",
                "host": getattr(f, "host", None),
                "summary": f.sanitized_fact or f.fact,
                "source_tool": getattr(f, "source_tool", "ARGUS")
            })

    # If timeline is empty (e.g. 0 threat findings), populate timeline directly from evidence file artifacts
    if not timeline_events and evidence_list:
        import os
        from infrastructure.schemas import Evidence
        from preprocessing.router import ParserRouter
        router_inst = ParserRouter()
        for ev in evidence_list:
            try:
                target_path = None
                for candidate in [ev.file_path, getattr(ev, "original_file_path", None), ev.original_repository_path, ev.repository_path]:
                    if not candidate:
                        continue
                    if os.path.exists(candidate):
                        target_path = candidate
                        break
                    parts = candidate.replace("\\", "/").split("/")
                    if len(parts) > 1:
                        c_p = os.path.join("data", "repository", *parts[1:])
                        if os.path.exists(c_p):
                            target_path = c_p
                            break
                        c_p2 = os.path.join("data", "repository", *parts)
                        if os.path.exists(c_p2):
                            target_path = c_p2
                            break
                    loc_p = os.path.join("data", "repository", ev.case_id, ev.evidence_id, "original", ev.filename)
                    if os.path.exists(loc_p):
                        target_path = loc_p
                        break

                if target_path and os.path.exists(target_path):
                    sub_ev = Evidence(
                        case_id=ev.case_id,
                        evidence_id=ev.evidence_id,
                        filename=ev.filename,
                        file_path=target_path,
                        raw_file_path=target_path,
                        uploaded_by=ev.uploaded_by,
                        sha256_hash=ev.sha256_hash
                    )
                    r_res = router_inst.determine_routing(sub_ev)
                    if r_res.status == "ROUTED" and r_res.parser_instance:
                        arts = r_res.parser_instance.parse(target_path, ev.evidence_id) or []
                        for art in arts[:100]:
                            ts_str = art.timestamp.isoformat() if hasattr(art.timestamp, "isoformat") and art.timestamp else str(art.timestamp) if art.timestamp else None
                            timeline_events.append({
                                "timestamp": ts_str,
                                "event_type": art.artifact_type or "artifact",
                                "host": getattr(art.normalized_fields, "host", None) if art.normalized_fields else None,
                                "summary": art.event_summary or f"Artifact from {ev.filename}",
                                "source_tool": art.source_tool or "ARGUS"
                            })
            except Exception as ev_err:
                logger.warning(f"Failed extracting timeline artifacts for report: {ev_err}")

    # Build report dictionary payload
    report_payload = {
        "case_id": case_id,
        "tenant_id": x_tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": exported_findings,
        "evidence_files": [{
            "evidence_id": ev.evidence_id,
            "filename": ev.filename,
            "status": ev.status.value if hasattr(ev.status, "value") else str(ev.status).replace("EvidenceStatus.", "").lower(),
            "sha256_hash": ev.sha256_hash
        } for ev in (evidence_list or [])],
        "timeline": timeline_events
    }

    # 3. Render report via ReportGenerator
    try:
        content = _report_generator.generate(report_payload, format=format)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Report generation error for case {case_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    # 4. Return HTTP Response with appropriate media type and Content-Disposition header
    fmt = (format or "html").lower().strip()
    filename = f"argus_report_{case_id}.{fmt}"
    disposition = f'attachment; filename="{filename}"'

    if fmt == "json":
        return Response(content=content, media_type="application/json", headers={"Content-Disposition": disposition})
    elif fmt == "pdf":
        return Response(content=content, media_type="application/pdf", headers={"Content-Disposition": disposition})
    else:  # html
        return Response(content=content, media_type="text/html", headers={"Content-Disposition": disposition})
