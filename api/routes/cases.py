"""
API Route — Case Summary Endpoint
=================================
GET /cases/{case_id}

Queries case statistics, severity breakdowns, review status metrics, and evidence source counts.
Enforces strict case and tenant isolation.
"""

from __future__ import annotations

import logging
import uuid
import hashlib
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Header, HTTPException, Query, Depends, BackgroundTasks
from pydantic import BaseModel, Field
from enum import Enum
from infrastructure.repository.evidence_store import create_case_session, list_cases, list_evidence_by_case, close_case
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from sanitization.gateway import SanitizationGateway
from api.routes.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

_fir_repo = FIRRepository()
_analyst_service = AnalystFindingService(fir_repo=_fir_repo)


class InvestigationStageStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"

class InvestigationProgress(BaseModel):
    evidence_collection: InvestigationStageStatus
    analysis: InvestigationStageStatus
    correlation: InvestigationStageStatus
    findings: InvestigationStageStatus
    report: InvestigationStageStatus


class CaseSummaryResponse(BaseModel):
    case_id: str
    tenant_id: str
    name: Optional[str] = "Unnamed Case"
    description: Optional[str] = "No description provided."
    total_evidence_files: int = 0
    total_artifacts: int = 0
    total_findings: int = 0
    severity_breakdown: Dict[str, int]
    review_status_breakdown: Dict[str, int]
    layer_breakdown: Dict[str, int]
    source_artifact_count: int
    investigation_progress: InvestigationProgress
    latest_timestamp: Optional[str] = None
    evidence_files: list[Dict[str, Any]] = Field(default_factory=list)

class CreateCaseRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    analyst: str = "Analyst"
    case_id: Optional[str] = None
    analyst_id: Optional[str] = None
    senior_analyst_id: Optional[str] = None

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from api.routes.auth import get_user_by_id

def send_assignment_email(target_email: str, case_id: str, case_name: str, role_title: str):
    SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "argus1267saaas@gmail.com")
    smtp_pass = os.environ.get("SMTP_PASSWORD") or os.environ.get("GMAIL_APP_PASSWORD")
    if not smtp_pass:
        print(f"[AUTH EMAIL] Email password not set. Simulated email to {target_email}: Assigned to {case_id}")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"ARGUS Forensics — Case Assignment: {case_name}"
        msg["From"] = SENDER_EMAIL
        msg["To"] = target_email

        text = f"You have been assigned to Case {case_id} ({case_name}) as {role_title}."
        html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; background: #090d16; color: #f8fafc; border-radius: 8px;">
            <h2 style="color: #3b82f6;">ARGUS Digital Forensics Platform</h2>
            <p>You have been assigned to a new case as <strong>{role_title}</strong>.</p>
            <div style="background: rgba(59,130,246,0.15); border: 1px solid #3b82f6; padding: 15px; text-align: center; border-radius: 6px; font-size: 18px; color: #60a5fa;">
                Case ID: {case_id} <br/> {case_name}
            </div>
            <p style="font-size: 12px; color: #94a3b8; margin-top: 15px;">Please log in to the dashboard to begin your investigation.</p>
        </div>
        """
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, smtp_pass)
            server.sendmail(SENDER_EMAIL, target_email, msg.as_string())
        print(f"[AUTH EMAIL] Successfully sent assignment email to {target_email}")
        return True
    except Exception as e:
        print(f"[AUTH EMAIL ERROR] {e}")
        return False

@router.post("/", response_model=Dict[str, Any])
async def create_case(
    req: CreateCaseRequest,
    background_tasks: BackgroundTasks,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create cases")

    existing_cases = list_cases(tenant_id=x_tenant_id)
    
    if req.case_id:
        case_id = req.case_id.strip()
    else:
        existing_seqs = []
        for c in existing_cases:
            if c.case_id.startswith('ARGUS_'):
                try:
                    existing_seqs.append(int(c.case_id.split('_')[1]))
                except ValueError:
                    pass
        next_seq = max(existing_seqs) + 1 if existing_seqs else 1
        case_id = f"ARGUS_{next_seq:02d}"
        
    if any(c.case_id == case_id for c in existing_cases):
        raise HTTPException(status_code=409, detail=f"Case ID '{case_id}' already exists.")
        
    session = create_case_session(
        tenant_id=x_tenant_id, 
        created_by=current_user.get("name", req.analyst), 
        case_id=case_id,
        analyst_id=req.analyst_id,
        senior_analyst_id=req.senior_analyst_id
    )
    
    # Store the case name in DB
    try:
        from config.settings import settings
        import psycopg2
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS name VARCHAR(255)")
        cur.execute(
            "UPDATE cases SET name = %s, analyst_id = %s, senior_analyst_id = %s WHERE case_id = %s", 
            (req.name, req.analyst_id, req.senior_analyst_id, session.case_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB WARNING] Could not store case name: {e}")
    
    # Send emails in background
    if req.analyst_id:
        analyst = get_user_by_id(req.analyst_id)
        if analyst and analyst.get("email"):
            background_tasks.add_task(send_assignment_email, analyst["email"], session.case_id, req.name, "Analyst")
            
    if req.senior_analyst_id:
        senior = get_user_by_id(req.senior_analyst_id)
        if senior and senior.get("email"):
            background_tasks.add_task(send_assignment_email, senior["email"], session.case_id, req.name, "Senior Analyst")
    
    return {
        "status": "SUCCESS",
        "case_id": session.case_id,
        "name": req.name,
        "description": req.description
    }

@router.get("/", response_model=Dict[str, Any])
async def get_all_cases(
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    cases = list_cases(tenant_id=x_tenant_id)
    
    # Fetch case names from DB
    case_names = {}
    try:
        from config.settings import settings
        import psycopg2
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute("SELECT case_id, name, analyst_id, senior_analyst_id FROM cases WHERE tenant_id = %s", (x_tenant_id,))
        for row in cur.fetchall():
            case_names[row[0]] = {"name": row[1], "analyst_id": row[2], "senior_analyst_id": row[3]}
        conn.close()
    except Exception as e:
        print(f"[DB WARNING] Could not fetch case names: {e}")
    
    return {
        "status": "SUCCESS",
        "data": [
            {
                "case_id": c.case_id,
                "created_by": c.created_by,
                "created_at": c.created_at,
                "status": c.status,
                "name": case_names.get(c.case_id, {}).get("name", ""),
                "analyst_id": case_names.get(c.case_id, {}).get("analyst_id"),
                "senior_analyst_id": case_names.get(c.case_id, {}).get("senior_analyst_id")
            }
            for c in cases
        ]
    }

@router.get("/activity", response_model=Dict[str, Any])
async def get_recent_activity(
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    activity = []
    
    user_map = {"Admin": "Admin User", "analyst_api": "Analyst", "Analyst_api": "Analyst"}
    try:
        from config.settings import settings
        import psycopg2
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM users")
        for row in cur.fetchall():
            user_map[str(row[0])] = row[1]
    except Exception as e:
        print(f"[DB WARNING] Could not fetch users: {e}")
        conn = None
    
    # 1. Get Cases (Excluding closed cases)
    cases = list_cases(tenant_id=x_tenant_id)
    active_case_ids = set()
    for c in cases:
        active_case_ids.add(c.case_id)
        c_by = c.created_by if c.created_by else ""
        mapped_name = user_map.get(c_by, c_by)
        
        activity.append({
            "action": "Created Case",
            "case_id": c.case_id,
            "created_by": mapped_name,
            "created_at": c.created_at.isoformat() if hasattr(c.created_at, "isoformat") else str(c.created_at),
            "details": c.case_id
        })
            
    # 2. Get Evidence from DB (Only for active cases)
    try:
        if conn and not conn.closed:
            cur.execute(
                """
                SELECT e.evidence_id, e.case_id, e.filename, e.uploaded_by, e.upload_timestamp
                FROM evidence e
                INNER JOIN cases c ON e.case_id = c.case_id
                WHERE c.tenant_id = %s
                """, 
                (x_tenant_id,)
            )
            for row in cur.fetchall():
                u_by = row[3] if row[3] else ""
                activity.append({
                    "action": "Uploaded Evidence",
                    "case_id": row[1],
                    "created_by": user_map.get(u_by, u_by),
                    "created_at": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
                    "details": row[2]
                })
            conn.close()
    except Exception as e:
        print(f"[DB WARNING] Could not fetch evidence activity: {e}")
        
    # Sort by created_at descending
    activity.sort(key=lambda x: x["created_at"], reverse=True)
    
    return {
        "status": "SUCCESS",
        "data": activity[:20]
    }



@router.put("/{case_id}/close")
async def close_case_endpoint(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Close an active case globally.
    """
    from api.routes.evidence import sanitize_uuid
    clean_case_id = sanitize_uuid(case_id)
    success = close_case(tenant_id=x_tenant_id, case_id=clean_case_id)
    if not success and clean_case_id != case_id:
        success = close_case(tenant_id=x_tenant_id, case_id=case_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Case not found or could not be closed.")
        
    return {"status": "SUCCESS", "message": f"Case {case_id} closed."}


@router.get("/{case_id}", response_model=CaseSummaryResponse)
async def get_case(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Retrieve structured case summary, severity metrics, and review status breakdown.
    Enforces strict tenant isolation.
    """
    from api.routes.evidence import sanitize_uuid
    from infrastructure.repository.evidence_store import get_case_session, list_evidence_by_case

    clean_case_id = sanitize_uuid(case_id)
    session = get_case_session(tenant_id=x_tenant_id, case_id=clean_case_id) or get_case_session(tenant_id=x_tenant_id, case_id=case_id)
    evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=clean_case_id)
    if not evidence_list and case_id != clean_case_id:
        evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=case_id)

    findings = _analyst_service.list_findings(case_id=clean_case_id, tenant_id=x_tenant_id)
    if not findings and case_id != clean_case_id:
        findings = _analyst_service.list_findings(case_id=case_id, tenant_id=x_tenant_id)

    if not session and not evidence_list and not findings:
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

    total_artifacts = 0
    formatted_evidence = []
    for ev in (evidence_list or []):
        meta = ev.metadata or {}
        arts = meta.get("parsed_artifact_count", 0) + meta.get("derived_observable_count", 0)
        total_artifacts += arts
        formatted_evidence.append({
            "evidence_id": ev.evidence_id,
            "filename": ev.filename,
            "status": ev.status,
            "sha256_hash": ev.sha256_hash,
            "parsed_artifact_count": meta.get("parsed_artifact_count", 0),
            "derived_observable_count": meta.get("derived_observable_count", 0),
            "timeline_event_count": meta.get("timeline_event_count", 0)
        })

    # Compute Dynamic Investigation Progress
    
    
    # 1. Evidence Collection
    if not evidence_list:
        ev_status = InvestigationStageStatus.NOT_STARTED
    else:
        # If any evidence is NOT in a final state, it's still in progress
        final_states = {"stored", "failed"}
        all_done = all(e.status.value in final_states if hasattr(e.status, 'value') else str(e.status) in final_states for e in evidence_list)
        ev_status = InvestigationStageStatus.COMPLETED if all_done else InvestigationStageStatus.IN_PROGRESS

    # 2. Analysis & 3. Correlation
    # In ARGUS, Stage 1-4 is synchronous, so if findings exist, analysis/correlation are complete.
    if ev_status != InvestigationStageStatus.COMPLETED:
        an_status = InvestigationStageStatus.NOT_STARTED
        cor_status = InvestigationStageStatus.NOT_STARTED
    elif len(findings) == 0:
        an_status = InvestigationStageStatus.IN_PROGRESS
        cor_status = InvestigationStageStatus.IN_PROGRESS
    else:
        an_status = InvestigationStageStatus.COMPLETED
        cor_status = InvestigationStageStatus.COMPLETED
        
    # 4. Findings
    if cor_status != InvestigationStageStatus.COMPLETED:
        find_status = InvestigationStageStatus.NOT_STARTED
    else:
        has_reviewed = status_counts.get("analyst_confirmed", 0) > 0 or status_counts.get("analyst_rejected", 0) > 0
        find_status = InvestigationStageStatus.COMPLETED if has_reviewed else InvestigationStageStatus.IN_PROGRESS
        
    # 5. Report
    if find_status != InvestigationStageStatus.COMPLETED:
        rep_status = InvestigationStageStatus.NOT_STARTED
    else:
        # Check case status for closure
        cases = list_cases(tenant_id=x_tenant_id)
        current_case = next((c for c in cases if c.case_id == case_id), None)
        is_closed = current_case and current_case.status == "closed"
        rep_status = InvestigationStageStatus.COMPLETED if is_closed else InvestigationStageStatus.IN_PROGRESS

    progress = InvestigationProgress(
        evidence_collection=ev_status,
        analysis=an_status,
        correlation=cor_status,
        findings=find_status,
        report=rep_status
    )

    # Fetch name and description from DB
    case_name = "Unnamed Case"
    case_desc = "No description provided."
    try:
        from config.settings import settings
        import psycopg2
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute("SELECT name FROM cases WHERE case_id = %s AND tenant_id = %s", (case_id, x_tenant_id))
        row = cur.fetchone()
        if row and row[0]:
            case_name = row[0]
        conn.close()
    except Exception as e:
        logger.warning(f"Could not fetch case name for summary: {e}")

    return CaseSummaryResponse(
        case_id=case_id,
        tenant_id=x_tenant_id,
        name=case_name,
        description=case_desc,
        total_evidence_files=len(evidence_list or []),
        total_artifacts=total_artifacts,
        total_findings=len(findings),
        severity_breakdown=severity_counts,
        review_status_breakdown=status_counts,
        layer_breakdown=layer_counts,
        source_artifact_count=len(source_artifacts),
        investigation_progress=progress,
        latest_timestamp=latest_ts,
        evidence_files=formatted_evidence

    )

@router.get("/{case_id}/findings")
async def get_case_findings(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Retrieve all parsed output findings for a specific case.
    """
    if not case_id or not case_id.strip():
        raise HTTPException(status_code=400, detail="case_id path parameter cannot be empty.")
    
    findings = _analyst_service.list_findings(case_id=case_id, tenant_id=x_tenant_id)
    
    # Inject demonstration findings if empty
    # Demonstration findings injection has been removed so it only shows present case ones
    gateway = SanitizationGateway()
    sanitized_results = []
    for f in findings:
        f_dict = f.model_dump(mode='json') if hasattr(f, 'model_dump') else dict(f)
        try:
            sanitized_ctx = gateway.sanitize_finding(f)
            # Serialize the full SanitizedAgentContext as a structured JSON object,
            # not just plain text fields. This preserves all sanitization metadata
            # (sanitization_actions, redaction_metadata, xml_evidence_block, confidence, etc.)
            f_dict["sanitized_context"] = sanitized_ctx.model_dump(mode='json')
            # Keep top-level convenience aliases for backwards compatibility
            f_dict["sanitized_fact"] = sanitized_ctx.sanitized_fact
            f_dict["injection_flagged"] = sanitized_ctx.injection_flagged
        except Exception as e:
            logger.error(f"Failed to sanitize finding: {e}")
        sanitized_results.append(f_dict)
        
    return sanitized_results
