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
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

import copy
from fastapi import APIRouter, Header, HTTPException, Query, Depends, BackgroundTasks, Response, Body
from pydantic import BaseModel, Field
from enum import Enum
from infrastructure.repository.evidence_store import create_case_session, list_cases, list_evidence_by_case, close_case
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from fir.schemas import ReviewStatus
from sanitization.gateway import SanitizationGateway
from api.routes.auth import get_current_user
from api.case_lock import case_lock_manager

logger = logging.getLogger(__name__)

router = APIRouter()

_fir_repo = FIRRepository()
_analyst_service = AnalystFindingService(fir_repo=_fir_repo)

import concurrent.futures
import threading

_agent_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="argus_agents")
_agent_jobs: Dict[str, Dict[str, Any]] = {}
_agent_jobs_lock = threading.Lock()
_agent_cancellations: Dict[str, threading.Event] = {}


class InvestigationStageStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"

class InvestigationProgress(BaseModel):
    evidence_collection: InvestigationStageStatus
    analysis: InvestigationStageStatus
    correlation: Optional[InvestigationStageStatus] = InvestigationStageStatus.NOT_STARTED
    findings: Optional[InvestigationStageStatus] = InvestigationStageStatus.NOT_STARTED
    agent_analysis: Optional[InvestigationStageStatus] = InvestigationStageStatus.NOT_STARTED
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
    lock: Optional[Dict[str, Any]] = None
    has_report: bool = False
    submitted_to_senior: bool = False
    submitted_to_auditor: bool = False
    submitted_to_senior_data: Optional[Dict[str, Any]] = None
    submitted_to_auditor_data: Optional[Dict[str, Any]] = None

class ReportSubmissionRequest(BaseModel):
    stage: str = "submitted_to_senior"
    note: Optional[str] = None
    findings_count: Optional[int] = None
    evidence_count: Optional[int] = None

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

def get_case_assigned_users(case_id: str, x_tenant_id: str = "default") -> Tuple[str, str]:
    """
    Returns (analyst_id, senior_analyst_id) for the given case.
    """
    try:
        from api.routes.auth import get_db_connection
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT analyst_id, senior_analyst_id FROM cases WHERE case_id = %s",
                    (case_id,)
                )
                row = cur.fetchone()
                if row:
                    return str(row[0] or ""), str(row[1] or "")
    except Exception:
        pass

    try:
        from infrastructure.repository.evidence_store import get_case_session
        session = get_case_session(tenant_id=x_tenant_id, case_id=case_id)
        if session:
            return str(getattr(session, "analyst_id", None) or ""), str(getattr(session, "senior_analyst_id", None) or "")
    except Exception:
        pass

    return "", ""


def is_user_authorized_for_case_modification(
    case_id: str,
    current_user: dict,
    x_tenant_id: str = "default"
) -> bool:
    """
    Returns True if current_user is:
    - An Admin ('admin' role)
    - The assigned Analyst for this case (matching analyst_id by id, name, or email)
    - The assigned Senior Analyst for this case (matching senior_analyst_id by id, name, or email)
    """
    role = (current_user.get("role") or "").lower()
    if role == "admin":
        return True
    
    if role == "auditor":
        return False

    uid = str(current_user.get("id") or "").strip().lower()
    uname = str(current_user.get("name") or "").strip().lower()
    uemail = str(current_user.get("email") or "").strip().lower()
    user_identifiers = {i for i in [uid, uname, uemail] if i}

    a_id, s_id = get_case_assigned_users(case_id, x_tenant_id)
    a_id = str(a_id or "").strip().lower()
    s_id = str(s_id or "").strip().lower()

    if a_id and a_id in user_identifiers:
        return True
    if s_id and s_id in user_identifiers:
        return True

    try:
        from api.routes.auth import get_db_connection
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name, email FROM users WHERE id IN (%s, %s) OR email IN (%s, %s)",
                    (a_id, s_id, a_id, s_id)
                )
                for row in cur.fetchall():
                    row_ids = {str(col or "").strip().lower() for col in row if col}
                    if user_identifiers.intersection(row_ids):
                        return True
    except Exception:
        pass

    return False


def verify_case_access(case_id: str, current_user: dict, x_tenant_id: str = "default") -> None:
    """
    Enforces strict tenant isolation and case access control.
    1. Tenant Isolation: Verifies that the case exists under x_tenant_id. If not, raises 404 immediately.
    2. Role-based / Individual Access:
       - Admins and Auditors can access any case within their authorized tenant.
       - Assigned Analyst / Senior Analyst can access cases explicitly assigned to them by id, username, or email.
       - Generic role assignments ('analyst' or 'senior_analyst') allow shared access to users holding that role.
       - Individual assignments (e.g. '5' or 'sathwik') restrict access strictly to that individual user.
       - Non-assigned users get HTTP 404 (preventing oracle probing).
    """
    if not case_id or not case_id.strip():
        raise HTTPException(status_code=400, detail="case_id cannot be empty.")

    clean_case_id = str(case_id).strip()
    user_tenant = current_user.get("tenant_id") or "default"
    is_valid_tenant = (
        x_tenant_id == user_tenant or
        (x_tenant_id in ("default", "dev-team") and user_tenant in ("default", "dev-team"))
    )
    if not is_valid_tenant and (current_user.get("role") or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Tenant access denied: user not authorized for requested tenant.")

    # 1. Authoritative check: case MUST exist under x_tenant_id
    case_row = None
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT analyst_id, senior_analyst_id, tenant_id 
                    FROM cases 
                    WHERE (case_id = %s OR case_id = %s) 
                      AND (tenant_id = %s OR (%s IN ('default', 'dev-team') AND tenant_id IN ('default', 'dev-team')))
                    LIMIT 1;
                    """,
                    (clean_case_id, clean_case_id.replace('-', '_'), x_tenant_id, x_tenant_id)
                )
                case_row = cur.fetchone()
    except Exception as e:
        logger.debug(f"verify_case_access DB note: {e}")

    if not case_row:
        from infrastructure.repository.evidence_store import get_case_session
        session = get_case_session(tenant_id=x_tenant_id, case_id=clean_case_id)
        if not session and '-' in clean_case_id:
            session = get_case_session(tenant_id=x_tenant_id, case_id=clean_case_id.replace('-', '_'))
        
        # Also check if case has registered findings under this tenant in fir_repo
        if not session:
            try:
                has_findings = bool(_analyst_service.list_findings(case_id=clean_case_id, tenant_id=x_tenant_id))
                if has_findings:
                    a_id = "analyst"
                    s_id = ""
                    session = True
            except Exception:
                pass

        if not session:
            raise HTTPException(
                status_code=404,
                detail=f"Case '{case_id}' not found for tenant '{x_tenant_id}'."
            )
        if session is not True:
            a_id = str(getattr(session, "analyst_id", None) or "").strip().lower()
            s_id = str(getattr(session, "senior_analyst_id", None) or "").strip().lower()
    else:
        a_id = str(case_row[0] or "").strip().lower()
        s_id = str(case_row[1] or "").strip().lower()

    # 2. Once tenant isolation is confirmed, Admin and Auditor have access to any case in their tenant
    role = (current_user.get("role") or "").lower()
    if role in ("admin", "auditor"):
        return

    # 3. Individual user identifiers
    uid = str(current_user.get("id", "")).strip().lower()
    uname = str(current_user.get("name", "")).strip().lower()
    u_email = str(current_user.get("email", "")).strip().lower()
    individual_identifiers = {i for i in (uid, uname, u_email) if i}

    # 4. Check Individual Assignment
    if a_id and a_id in individual_identifiers:
        return
    if s_id and s_id in individual_identifiers:
        return

    # 5. Check Shared Generic Role Assignment (only if explicitly assigned to generic pool handle)
    SHARED_ANALYST_HANDLES = {"analyst", "junior_analyst", "junior analyst", "unassigned"}
    SHARED_SENIOR_HANDLES = {"senior_analyst", "senior", "senior analyst"}

    if role in ("analyst", "junior_analyst") and a_id in SHARED_ANALYST_HANDLES:
        return
    if role in ("senior_analyst", "senior") and (s_id in SHARED_SENIOR_HANDLES or a_id in SHARED_ANALYST_HANDLES):
        return

    # 6. Not assigned to this individual or role
    raise HTTPException(
        status_code=404,
        detail=f"Case '{case_id}' not found for tenant '{x_tenant_id}'."
    )

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
        senior_analyst_id=req.senior_analyst_id,
        name=req.name,
        description=req.description
    )
    
    # Store the case name in DB
    try:
        from api.routes.auth import get_db_connection
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("ALTER TABLE cases ALTER COLUMN case_id TYPE VARCHAR(255) USING case_id::text;")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS name VARCHAR(255)")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS analyst_id VARCHAR(255)")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS senior_analyst_id VARCHAR(255)")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS description TEXT")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS closed_by TEXT")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS has_report BOOLEAN DEFAULT FALSE")
                cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS closed_reason TEXT")
                cur.execute(
                    "UPDATE cases SET name = %s, analyst_id = %s, senior_analyst_id = %s WHERE case_id = %s", 
                    (req.name, req.analyst_id, req.senior_analyst_id, session.case_id)
                )
            conn.commit()
    except Exception as e:
        logger.warning(f"[DB WARNING] Could not update case details in DB: {e}")
    
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

def _read_case_submission_meta(case_id: str, session: Optional[Any] = None) -> Dict[str, Any]:
    """Read authoritative report submission state from local case_session.json and CaseSession."""
    meta: Dict[str, Any] = {
        "submitted_to_senior": bool(getattr(session, "submitted_to_senior", False)) if session else False,
        "submitted_to_auditor": bool(getattr(session, "submitted_to_auditor", False)) if session else False,
        "has_report": bool(getattr(session, "has_report", False)) if session else False,
        "submitted_to_senior_data": None,
        "submitted_to_auditor_data": None,
    }
    try:
        from infrastructure.repository.evidence_store import REPOSITORY_DIR
        s_file = Path(REPOSITORY_DIR) / case_id / "case_session.json"
        if s_file.is_file():
            with open(s_file, "r", encoding="utf-8") as f:
                s_data = json.load(f)
            if s_data.get("submitted_to_senior"):
                meta["submitted_to_senior"] = True
            if s_data.get("submitted_to_auditor"):
                meta["submitted_to_auditor"] = True
                meta["submitted_to_senior"] = True
            if s_data.get("has_report") or meta["submitted_to_senior"] or meta["submitted_to_auditor"]:
                meta["has_report"] = True
            if isinstance(s_data.get("submitted_to_senior_data"), dict):
                meta["submitted_to_senior_data"] = s_data.get("submitted_to_senior_data")
            if isinstance(s_data.get("submitted_to_auditor_data"), dict):
                meta["submitted_to_auditor_data"] = s_data.get("submitted_to_auditor_data")
    except Exception:
        pass
    return meta


def _persist_case_report_stage(
    case_id: str,
    x_tenant_id: str,
    stage: str,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Persist report submission/escalation stage to case_session.json and PostgreSQL cases table."""
    from datetime import datetime, timezone
    from infrastructure.repository.evidence_store import REPOSITORY_DIR

    now_iso = datetime.now(timezone.utc).isoformat()
    record = {"case_id": case_id, "submitted": True, "submitted_at": now_iso, **(meta or {})}
    is_auditor_stage = stage == "submitted_to_auditor"

    try:
        case_dir = Path(REPOSITORY_DIR) / case_id
        if case_dir.exists() and case_dir.is_dir():
            s_file = case_dir / "case_session.json"
            s_data: Dict[str, Any] = {}
            if s_file.exists():
                try:
                    with open(s_file, "r", encoding="utf-8") as f:
                        s_data = json.load(f)
                except Exception:
                    s_data = {}
            s_data["has_report"] = True
            s_data["submitted_to_senior"] = True
            if is_auditor_stage:
                s_data["submitted_to_auditor"] = True
                s_data["submitted_to_auditor_data"] = record
            else:
                s_data["submitted_to_senior_data"] = record
            with open(s_file, "w", encoding="utf-8") as f:
                json.dump(s_data, f, indent=2)
    except Exception as f_err:
        logger.warning(f"Could not persist local report submission stage for {case_id}: {f_err}")

    try:
        from infrastructure.repository.evidence_store import _should_attempt_postgres
        if _should_attempt_postgres():
            from api.routes.auth import get_db_connection
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS has_report BOOLEAN DEFAULT FALSE;")
                    cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS submitted_to_senior BOOLEAN DEFAULT FALSE;")
                    cur.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS submitted_to_auditor BOOLEAN DEFAULT FALSE;")
                    if is_auditor_stage:
                        cur.execute(
                            "UPDATE cases SET has_report = TRUE, submitted_to_senior = TRUE, submitted_to_auditor = TRUE WHERE case_id = %s AND (tenant_id = %s OR tenant_id IN ('default', 'dev-team'));",
                            (case_id, x_tenant_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE cases SET has_report = TRUE, submitted_to_senior = TRUE WHERE case_id = %s AND (tenant_id = %s OR tenant_id IN ('default', 'dev-team'));",
                            (case_id, x_tenant_id),
                        )
                conn.commit()
    except Exception as db_err:
        logger.warning(f"Could not persist DB report submission stage for {case_id}: {db_err}")

    return record


_REQUIRED_SWARM_STAGES = ("agent1", "agent2", "agent3", "agent4", "agent5a", "agent5b", "agent6", "agent7")
_FINISHED_STAGE_STATUSES = {
    "COMPLETED",
    "SUCCESS",
    "NEEDS_REVIEW",
    "PARTIAL_SUCCESS",
    "COMPLETED_WITH_FINDINGS",
    "COMPLETED_WITH_NO_FINDINGS",
    "NO_CLAIMS",
}
_FINISHED_AGENT7_STATUSES = {"COMPLETED", "SUCCESS", "NEEDS_REVIEW", "NO_CLAIMS", "PARTIAL_SUCCESS"}


def _extract_stage_statuses(
    job_source: Optional[Dict[str, Any]] = None,
    stored_pipeline_results: Optional[Dict[str, Any]] = None,
    results_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Collect non-empty stage status entries across pipeline job and stored result structures."""
    merged: Dict[str, str] = {}
    for src in (
        (stored_pipeline_results or {}).get("stage_statuses"),
        ((job_source or {}).get("results") or {}).get("stage_statuses"),
        (job_source or {}).get("stage_statuses"),
        (results_data or {}).get("stage_statuses"),
    ):
        if isinstance(src, dict):
            for k, v in src.items():
                if v:
                    merged[k] = str(v)

    for container in (results_data, stored_pipeline_results, (job_source or {}).get("results")):
        if not isinstance(container, dict):
            continue
        for key in _REQUIRED_SWARM_STAGES:
            if not merged.get(key) and isinstance(container.get(key), dict):
                st = container[key].get("execution_status") or container[key].get("status")
                if st:
                    merged[key] = str(st)
    return merged


def _has_completed_agent_stages(stage_statuses: Optional[Dict[str, Any]]) -> bool:
    """Return True only when every stage in the 8-agent swarm reached a finished terminal state."""
    if not isinstance(stage_statuses, dict) or not stage_statuses:
        return False
    for key in _REQUIRED_SWARM_STAGES:
        if str(stage_statuses.get(key) or "").strip().upper() not in _FINISHED_STAGE_STATUSES:
            return False
    ag7_status = str(stage_statuses.get("agent7") or "").strip().upper()
    return ag7_status in _FINISHED_AGENT7_STATUSES


def _count_agent_claims_in_dict(source: Optional[Dict[str, Any]]) -> int:
    """Count verified claims/synthesis items present inside an in-memory or persisted agent payload."""
    if not isinstance(source, dict):
        return 0
    if isinstance(source.get("claims"), list) and source["claims"]:
        return len(source["claims"])
    total = 0
    for key in _REQUIRED_SWARM_STAGES:
        ag_obj = source.get(key)
        if not isinstance(ag_obj, dict):
            continue
        if isinstance(ag_obj.get("claims"), list):
            total += len(ag_obj["claims"])
        if key == "agent7":
            if isinstance(ag_obj.get("verification"), list):
                total += len(ag_obj["verification"])
            if isinstance(ag_obj.get("synthesis"), dict) and ag_obj["synthesis"]:
                total += 1
    return total


def _resolve_pipeline_sources(
    case_id: str,
    x_tenant_id: str,
    evidence_list: Optional[list] = None,
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, str]]:
    """Gather live job, durable ISM checkpoints, and evidence-stored pipeline results for a case."""
    from api.routes.evidence import sanitize_uuid
    from ism.checkpointer import Checkpointer

    clean_case_id = sanitize_uuid(case_id)
    with _agent_jobs_lock:
        mem_job = _agent_jobs.get(clean_case_id) or _agent_jobs.get(case_id)
        live_job = mem_job if (mem_job and mem_job.get("tenant_id") == x_tenant_id) else None

    checkpointer = Checkpointer()
    persisted_job = None
    case_stages = checkpointer.get_case_state(clean_case_id, tenant_id=x_tenant_id)
    if not case_stages and case_id != clean_case_id:
        case_stages = checkpointer.get_case_state(case_id, tenant_id=x_tenant_id)

    if not live_job:
        stg_pj = case_stages.get("pipeline_job")
        if stg_pj:
            persisted_job = stg_pj.get("checkpoint") if isinstance(stg_pj.get("checkpoint"), dict) else stg_pj

    stored_pipeline_results = None
    for ev in (evidence_list or []):
        meta = ev.metadata or {}
        if meta.get("agent_results"):
            stored_pipeline_results = meta.get("agent_results")
            break

    job_source = live_job or persisted_job
    stage_statuses = _extract_stage_statuses(job_source, stored_pipeline_results)

    # Fallback: reconstruct stage statuses from individual ISM stage checkpoints if pipeline_job wasn't captured
    if not _has_completed_agent_stages(stage_statuses):
        for key in _REQUIRED_SWARM_STAGES:
            if stage_statuses.get(key):
                continue
            stg_cp = case_stages.get(key)
            if isinstance(stg_cp, dict):
                st = stg_cp.get("status")
                if not st and isinstance(stg_cp.get("checkpoint"), dict):
                    st = stg_cp["checkpoint"].get("execution_status") or stg_cp["checkpoint"].get("status")
                if st:
                    stage_statuses[key] = str(st)

    return job_source, stored_pipeline_results, stage_statuses


def _has_verified_swarm_outputs(
    case_id: str,
    x_tenant_id: str,
    evidence_list: list,
    findings: list,
    job_source: Optional[Dict[str, Any]],
    stored_pipeline_results: Optional[Dict[str, Any]],
    stage_statuses: Dict[str, str],
) -> bool:
    """Return True if completed swarm produced FIR findings, agent claims/synthesis, or clean no-findings completion."""
    if findings:
        return True

    if _count_agent_claims_in_dict(job_source) > 0:
        return True
    if _count_agent_claims_in_dict((job_source or {}).get("results")) > 0:
        return True
    if _count_agent_claims_in_dict(stored_pipeline_results) > 0:
        return True

    # Clean benign evidence run: all 8 agents finished and reported no IOCs/claims
    if evidence_list and _has_completed_agent_stages(stage_statuses):
        ag7_st = str(stage_statuses.get("agent7") or "").upper()
        ag3_st = str(stage_statuses.get("agent3") or "").upper()
        if ag7_st == "NO_CLAIMS" or ag3_st == "COMPLETED_WITH_NO_FINDINGS":
            return True

    try:
        from infrastructure.repository.evidence_store import _should_attempt_postgres
        if _should_attempt_postgres():
            from api.routes.evidence import sanitize_uuid
            from api.routes.auth import get_db_connection
            clean_case_id = sanitize_uuid(case_id)
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM agent_outputs WHERE case_id IN (%s, %s) AND tenant_id = %s LIMIT 1;",
                        (clean_case_id, case_id, x_tenant_id),
                    )
                    if cur.fetchone():
                        return True
    except Exception:
        pass

    return False


def _get_agent_pipeline_status(
    case_id: str,
    x_tenant_id: str,
    evidence_list: Optional[list] = None,
) -> InvestigationStageStatus:
    """Resolve authoritative multi-agent swarm completion status for a case."""
    job_source, stored_pipeline_results, stage_statuses = _resolve_pipeline_sources(
        case_id, x_tenant_id, evidence_list
    )

    job_status = str((job_source.get("status") if job_source else "") or "").upper()
    stored_status = str((stored_pipeline_results.get("execution_status") if stored_pipeline_results else "") or "").upper()

    if job_status in ("RUNNING", "PROCESSING") or stored_status in ("RUNNING", "PROCESSING"):
        return InvestigationStageStatus.IN_PROGRESS

    terminal_blocked = {"FAILED", "ERROR", "STOPPED", "CANCELLED", "MODEL_UNAVAILABLE"}
    if job_status in ("COMPLETED", "SUCCESS") or stored_status in ("COMPLETED", "SUCCESS"):
        return InvestigationStageStatus.COMPLETED

    if (
        _has_completed_agent_stages(stage_statuses)
        and job_status not in terminal_blocked
        and stored_status not in terminal_blocked
    ):
        return InvestigationStageStatus.COMPLETED

    return InvestigationStageStatus.NOT_STARTED


@router.post("/{case_id}/report-submission", response_model=Dict[str, Any])
async def submit_case_report_stage(
    case_id: str,
    req: ReportSubmissionRequest,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user),
):
    """
    Persist explicit case report submission ('submitted_to_senior' or 'submitted_to_auditor').
    Enforces that investigation and multi-agent analysis have completed before a report can be submitted.
    """
    verify_case_access(case_id, current_user, x_tenant_id)
    from api.routes.evidence import sanitize_uuid
    from infrastructure.repository.evidence_store import get_case_session, list_evidence_by_case

    clean_case_id = sanitize_uuid(case_id)
    stage = (req.stage or "submitted_to_senior").strip().lower()
    if stage not in ("submitted_to_senior", "submitted_to_auditor"):
        raise HTTPException(status_code=400, detail="Unsupported report submission stage.")

    user_role = (current_user.get("role") or "").lower()
    session = get_case_session(tenant_id=x_tenant_id, case_id=clean_case_id) or get_case_session(tenant_id=x_tenant_id, case_id=case_id)
    target_case_id = session.case_id if session else clean_case_id
    evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=target_case_id)
    findings = _analyst_service.list_findings(case_id=target_case_id, tenant_id=x_tenant_id)

    if stage == "submitted_to_senior":
        user_id = str(current_user.get("id", ""))
        is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
            case_id=target_case_id,
            user_id=user_id,
            is_admin=user_role == "admin",
        )
        if not is_allowed and lock:
            raise HTTPException(
                status_code=423,
                detail=f"Cannot submit report: Case is locked by analyst '{lock.locked_by_user_name}'.",
            )

        job_source, stored_pipeline_results, stage_statuses = _resolve_pipeline_sources(
            target_case_id, x_tenant_id, evidence_list
        )
        agent_status = _get_agent_pipeline_status(target_case_id, x_tenant_id, evidence_list)
        has_outputs = _has_verified_swarm_outputs(
            target_case_id,
            x_tenant_id,
            evidence_list,
            findings,
            job_source,
            stored_pipeline_results,
            stage_statuses,
        )
        if not evidence_list or agent_status != InvestigationStageStatus.COMPLETED or not has_outputs:
            raise HTTPException(
                status_code=400,
                detail="Investigation, evidence processing, and Multi-Agent Swarm analysis must complete with verified findings before submitting the case report.",
            )

        record = _persist_case_report_stage(
            target_case_id,
            x_tenant_id,
            "submitted_to_senior",
            {
                "analyst_id": current_user.get("id") or "analyst",
                "analyst_name": current_user.get("name") or "Analyst",
                "note": req.note or "",
                "findings_count": req.findings_count if req.findings_count is not None else len(findings),
                "evidence_count": req.evidence_count if req.evidence_count is not None else len(evidence_list),
            },
        )
        return {"status": "SUCCESS", "stage": "submitted_to_senior", "record": record}

    # Senior escalation to Auditor
    if user_role not in ("senior_analyst", "senior", "admin"):
        raise HTTPException(status_code=403, detail="Only Senior Analysts or Admins can escalate reports to the Auditor.")

    sub_meta = _read_case_submission_meta(target_case_id, session)
    if not (sub_meta["submitted_to_senior"] or sub_meta["has_report"] or (session and getattr(session, "status", "") == "closed")):
        raise HTTPException(
            status_code=400,
            detail="The assigned Analyst must complete investigation and submit the report to Senior Analyst before escalating to Auditor.",
        )

    record = _persist_case_report_stage(
        target_case_id,
        x_tenant_id,
        "submitted_to_auditor",
        {
            "senior_analyst_id": current_user.get("id") or "senior_analyst",
            "senior_analyst_name": current_user.get("name") or "Senior Analyst",
            "memo": req.note or "",
            "findings_count": req.findings_count if req.findings_count is not None else len(findings),
            "evidence_count": req.evidence_count if req.evidence_count is not None else len(evidence_list),
        },
    )
    return {"status": "SUCCESS", "stage": "submitted_to_auditor", "record": record}


@router.get("/", response_model=Dict[str, Any])
async def get_all_cases(
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    cases = list_cases(tenant_id=x_tenant_id)
    
    user_map = {}
    senior_note_cases = set()
    auditor_note_cases = set()
    try:
        from api.routes.auth import get_db_connection
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, name FROM users")
                for row in cur.fetchall():
                    user_map[str(row[0])] = row[1]
                cur.execute(
                    "SELECT case_id, title FROM case_notes WHERE title ILIKE %s OR title ILIKE %s",
                    ("%Report Submitted%", "%Escalation to Auditor%")
                )
                for n_row in cur.fetchall():
                    n_cid = str(n_row[0] or "")
                    n_title = str(n_row[1] or "").lower()
                    if "escalation to auditor" in n_title:
                        auditor_note_cases.add(n_cid)
                        senior_note_cases.add(n_cid)
                    elif "report submitted" in n_title:
                        senior_note_cases.add(n_cid)
    except Exception as e:
        print(f"[DB WARNING] Could not fetch user names: {e}")

    # Fallback user_map when Postgres is offline
    if not user_map:
        from api.routes.auth import _BASE_FALLBACK_USERS
        for u in _BASE_FALLBACK_USERS:
            user_map[str(u["id"])] = u["name"]

    user_id = str(current_user.get("id", ""))
    user_email = str(current_user.get("email", "")).lower()
    user_role = (current_user.get("role") or "").lower()
    is_admin = user_role == "admin"
    is_auditor = user_role == "auditor"

    result = []
    from infrastructure.repository.evidence_store import REPOSITORY_DIR
    repo_dir_path = Path(REPOSITORY_DIR)

    for c in cases:
        c_name = getattr(c, "name", None)
        c_desc = getattr(c, "description", None)
        c_analyst_id = getattr(c, "analyst_id", None)
        c_senior_id = getattr(c, "senior_analyst_id", None)
        
        analyst_id_str = str(c_analyst_id or "").strip().lower()
        senior_id_str = str(c_senior_id or "").strip().lower()
        user_id_clean = user_id.strip().lower()
        user_name_clean = str(current_user.get("name", "")).strip().lower()
        user_email_clean = user_email.strip().lower()
        user_role_clean = user_role.strip().lower()
        individual_identifiers = {i for i in (user_id_clean, user_name_clean, user_email_clean) if i}

        is_individual_match = (
            (analyst_id_str and analyst_id_str in individual_identifiers) or
            (senior_id_str and senior_id_str in individual_identifiers)
        )
        SHARED_ANALYST_HANDLES = {"analyst", "junior_analyst", "junior analyst", "unassigned"}
        SHARED_SENIOR_HANDLES = {"senior_analyst", "senior", "senior analyst"}

        is_shared_match = (
            (user_role_clean in ("analyst", "junior_analyst") and analyst_id_str in SHARED_ANALYST_HANDLES) or
            (user_role_clean in ("senior_analyst", "senior") and (senior_id_str in SHARED_SENIOR_HANDLES or analyst_id_str in SHARED_ANALYST_HANDLES))
        )

        assigned = is_admin or is_auditor or is_individual_match or is_shared_match

        # Non-assigned cases are completely invisible to regular users
        if not is_admin and not is_auditor and not assigned:
            continue
        
        analyst_name = user_map.get(str(c_analyst_id or ""), str(c_analyst_id or ""))
        senior_name = user_map.get(str(c_senior_id or ""), str(c_senior_id or ""))
        
        is_open_case = str(getattr(c, "status", "open") or "open").lower() in ("open", "in_progress")
        lock = case_lock_manager.get_lock(c.case_id) if is_open_case else None
        if not is_open_case and case_lock_manager.get_lock(c.case_id):
            case_lock_manager.release(c.case_id, user_id, is_admin=True)
        is_team_member = (
            is_admin or
            is_individual_match or
            is_shared_match
        )
        lock_info = lock.to_dict(user_id, is_assigned=is_team_member) if lock else None

        submitted_to_senior = bool(
            c.case_id in senior_note_cases or
            getattr(c, "submitted_to_senior", False)
        )
        submitted_to_auditor = bool(
            c.case_id in auditor_note_cases or
            getattr(c, "submitted_to_auditor", False)
        )
        if submitted_to_auditor:
            submitted_to_senior = True

        has_report = bool(
            submitted_to_senior or
            submitted_to_auditor or
            getattr(c, "has_report", False)
        )

        closed_reason = getattr(c, "closed_reason", None)
        if not closed_reason and getattr(c, "status", "") == "closed":
            closed_reason = c_desc

        result.append({
            "case_id": c.case_id,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat() if hasattr(c.created_at, "isoformat") else (str(c.created_at) if c.created_at else None),
            "status": c.status,
            "name": c_name,
            "description": c_desc,
            "analyst_id": c_analyst_id,
            "analyst_name": analyst_name,
            "senior_analyst_id": c_senior_id,
            "senior_analyst_name": senior_name,
            "assigned_to_you": assigned,
            "lock": lock_info,
            "has_report": has_report,
            "submitted_to_senior": submitted_to_senior,
            "submitted_to_auditor": submitted_to_auditor,
            "submitted_to_senior_data": None,
            "submitted_to_auditor_data": None,
            "closed_reason": closed_reason,
        })

    return {"status": "SUCCESS", "data": result}

@router.get("/activity", response_model=Dict[str, Any])
async def get_recent_activity(
    case_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    activity = []
    target_case_id = str(case_id).strip() if case_id else None
    
    user_map = {"Admin": "Admin User", "analyst_api": "Analyst", "Analyst_api": "Analyst"}
    try:
        from api.routes.auth import get_db_connection
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, name FROM users")
                for row in cur.fetchall():
                    user_map[str(row[0])] = row[1]
                    
                # 1. Case Creation
                cur.execute("SELECT case_id, created_by, created_at, closed_at, closed_by FROM cases WHERE tenant_id = %s OR (%s IN ('default', 'dev-team') AND tenant_id IN ('default', 'dev-team'))", (x_tenant_id, x_tenant_id))
                for row in cur.fetchall():
                    c_id, c_by, created_at, closed_at, closed_by = row
                    mapped_name = user_map.get(c_by, c_by)
                    activity.append({
                        "action": "Created Case",
                        "case_id": c_id,
                        "created_by": mapped_name,
                        "created_by_id": c_by,
                        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                        "details": c_id
                    })
                    if closed_at:
                        c_by_name = user_map.get(closed_by, closed_by) if closed_by else "Admin User"
                        activity.append({
                            "action": "Closed Case",
                            "case_id": c_id,
                            "created_by": c_by_name,
                            "created_by_id": closed_by if closed_by else c_by,
                            "created_at": closed_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                            "details": f"Case {c_id} was closed"
                        })

                # 2. Uploaded Evidence
                cur.execute(
                    """
                    SELECT e.evidence_id, e.case_id, e.filename, e.uploaded_by, e.upload_timestamp
                    FROM evidence e
                    INNER JOIN cases c ON e.case_id = c.case_id
                    WHERE c.tenant_id = %s OR (%s IN ('default', 'dev-team') AND c.tenant_id IN ('default', 'dev-team'))
                    """, 
                    (x_tenant_id, x_tenant_id)
                )
                for row in cur.fetchall():
                    u_by = row[3] if row[3] else ""
                    activity.append({
                        "action": "Uploaded Evidence",
                        "case_id": row[1],
                        "created_by": user_map.get(u_by, u_by),
                        "created_by_id": u_by,
                        "created_at": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
                        "details": row[2]
                    })

                # 3. Analyst Findings
                cur.execute(
                    """
                    SELECT f.case_id, COALESCE(f.timestamp, c.created_at) AS created_at, f.fact, f.source_engine, f.reviewed_by, f.review_status, f.timestamp
                    FROM fir_findings f
                    INNER JOIN cases c ON f.case_id = c.case_id
                    WHERE c.tenant_id = %s OR (%s IN ('default', 'dev-team') AND c.tenant_id IN ('default', 'dev-team'))
                    ORDER BY f.timestamp DESC
                    """,
                    (x_tenant_id, x_tenant_id)
                )
                
                # Deduplicate findings by action, case, user, and approximate minute
                finding_events = {}
                for row in cur.fetchall():
                    f_cid, created_at, fact, source_engine, reviewed_by, review_status, review_time = row
                    
                    action_name = None
                    evt_time = None
                    if review_status in ('analyst_confirmed', 'analyst_rejected') and review_time:
                        action_name = "Confirmed Finding" if review_status == 'analyst_confirmed' else "Rejected Finding"
                        evt_time = review_time
                    elif source_engine == 'manual' or review_status == 'manual_entry':
                        action_name = "Created Finding"
                        evt_time = created_at
                        
                    if action_name and evt_time:
                        # Group by minute
                        minute_key = evt_time.replace(second=0, microsecond=0)
                        user_name = user_map.get(reviewed_by, reviewed_by) if reviewed_by else "Analyst"
                        group_key = (action_name, f_cid, user_name, minute_key)
                        
                        if group_key not in finding_events:
                            finding_events[group_key] = {
                                "action": action_name,
                                "case_id": f_cid,
                                "created_by": user_name,
                                "created_by_id": reviewed_by if reviewed_by else "system",
                                "created_at": evt_time,
                                "details": fact[:50] + "..." if fact and len(fact) > 50 else fact,
                                "count": 1
                            }
                        else:
                            finding_events[group_key]["count"] += 1

                for grp, evt in finding_events.items():
                    if evt["count"] > 1:
                        evt["action"] = f"{evt['action']} ({evt['count']})"
                        evt["details"] = f"Multiple findings ({evt['count']}) updated"
                    evt["created_at"] = evt["created_at"].isoformat() if hasattr(evt["created_at"], "isoformat") else str(evt["created_at"])
                    activity.append(evt)
                    
                # 4. Case Notes
                cur.execute(
                    """
                    SELECT note_id, case_id, created_by, created_at, title, type
                    FROM case_notes
                    WHERE tenant_id = %s OR (%s IN ('default', 'dev-team') AND tenant_id IN ('default', 'dev-team'))
                    """,
                    (x_tenant_id, x_tenant_id)
                )
                for row in cur.fetchall():
                    note_id, n_cid, created_by, created_at, title, note_type = row
                    activity.append({
                        "action": "Created Note",
                        "case_id": n_cid,
                        "created_by": user_map.get(created_by, created_by),
                        "created_by_id": created_by,
                        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                        "details": f"{title} ({note_type})"
                    })

                # 5. Audit Log table events
                try:
                    cur.execute(
                        """
                        SELECT id, case_id, event, actor, timestamp, detail
                        FROM audit_log
                        WHERE (tenant_id = %s OR tenant_id IN ('default', 'dev-team'))
                        ORDER BY timestamp DESC
                        LIMIT 200;
                        """,
                        (x_tenant_id,)
                    )
                    existing_evidence_timestamps = {a.get("created_at") for a in activity if a.get("action") == "Uploaded Evidence"}
                    existing_evidence_names = {f"{a.get('case_id')}:{a.get('details')}" for a in activity if a.get("action") == "Uploaded Evidence"}
                    
                    for row in cur.fetchall():
                        log_id, log_case_id, log_event, log_actor, log_ts, log_details = row
                        
                        # Humanize event names
                        action_name = log_event or "Audit Event"
                        if log_event == "evidence_stored":
                            action_name = "Uploaded Evidence"
                        elif log_event == "evidence_deleted":
                            action_name = "Deleted Evidence"
                        elif log_event == "finding_reviewed":
                            action_name = "Reviewed Finding"
                        elif log_event == "finding_review_rolled_back":
                            action_name = "Review Rolled Back"
                        elif log_event == "Triggered Multi-Agent Analysis":
                            action_name = "Triggered Multi-Agent Analysis"
                        elif log_event == "Restarted Multi-Agent Analysis":
                            action_name = "Restarted Multi-Agent Analysis"

                        # Extract clean readable details
                        details_str = ""
                        actor_resolved = log_actor
                        if isinstance(log_details, dict):
                            actor_resolved = actor_resolved or log_details.get("deleted_by") or log_details.get("uploaded_by") or log_details.get("actor")
                            if log_details.get("filename"):
                                details_str = log_details["filename"]
                            elif log_details.get("repository_path"):
                                details_str = os.path.basename(log_details["repository_path"])
                            elif log_details.get("description"):
                                details_str = log_details["description"]
                            elif log_details.get("reason"):
                                details_str = log_details["reason"]
                            elif log_details.get("event"):
                                details_str = log_details["event"]
                            elif log_details.get("sha256"):
                                details_str = f"SHA-256: {log_details['sha256'][:16]}..."
                            else:
                                details_str = json.dumps(log_details)
                        elif log_details:
                            details_str = str(log_details)

                        ts_iso = log_ts.isoformat() if hasattr(log_ts, "isoformat") and log_ts else str(log_ts)
                        
                        # Avoid duplicates for Uploaded Evidence
                        if action_name == "Uploaded Evidence":
                            if ts_iso in existing_evidence_timestamps or f"{log_case_id}:{details_str}" in existing_evidence_names:
                                continue

                        actor_name = user_map.get(str(actor_resolved), str(actor_resolved)) if actor_resolved else "System"

                        activity.append({
                            "action": action_name,
                            "case_id": log_case_id,
                            "created_by": actor_name,
                            "created_by_id": actor_resolved or "system",
                            "created_at": ts_iso,
                            "details": details_str
                        })
                except Exception as al_err:
                    logger.warning(f"Audit log fetch note: {al_err}")
    except Exception as e:
        print(f"[DB WARNING] Could not fetch comprehensive activity: {e}")

    # 6. Read cryptographically chained local audit logs from logs/audit/{tenant}.jsonl as fallback/augmentation
    try:
        base_logs_dir = os.getenv("ARGUS_LOGS_DIR", "logs")
        audit_file = Path(base_logs_dir) / "audit" / f"{x_tenant_id}.jsonl"
        audit_files = [audit_file]
        if x_tenant_id in ("default", "dev-team"):
            alt_file = Path(base_logs_dir) / "audit" / "default.jsonl"
            if alt_file not in audit_files:
                audit_files.append(alt_file)

        existing_entries = {
            (str(a.get("case_id") or "").strip().lower(), str(a.get("created_at") or "")[:19].strip(), str(a.get("action") or "").strip())
            for a in activity
        }

        for af in audit_files:
            if not af.exists():
                continue
            with af.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        record = json.loads(line_str)
                    except Exception:
                        continue

                    rec_cid = str(record.get("case_id") or "")
                    rec_event = record.get("event") or "audit_event"
                    rec_ts = record.get("timestamp") or ""
                    rec_actor = record.get("created_by") or record.get("actor") or "System"
                    rec_detail = record.get("detail") or {}

                    action_name = rec_event
                    details_str = rec_cid
                    if rec_event == "case_created":
                        action_name = "Created Case"
                        details_str = rec_cid
                    elif rec_event in ("evidence_stored", "evidence_uploaded"):
                        action_name = "Uploaded Evidence"
                        if isinstance(rec_detail, dict):
                            details_str = (
                                rec_detail.get("filename")
                                or (os.path.basename(rec_detail.get("repository_path", "")) if rec_detail.get("repository_path") else "")
                                or (os.path.basename(rec_detail.get("original_repository_path", "")) if rec_detail.get("original_repository_path") else "")
                                or rec_cid
                            )
                    elif rec_event in ("evidence_deleted",):
                        action_name = "Deleted Evidence"
                    elif rec_event in ("finding_reviewed",):
                        action_name = "Reviewed Finding"
                    elif rec_event in ("case_closed",):
                        action_name = "Closed Case"

                    key = (rec_cid.strip().lower(), str(rec_ts)[:19].strip(), action_name.strip())
                    if key in existing_entries:
                        continue
                    existing_entries.add(key)

                    activity.append({
                        "action": action_name,
                        "case_id": rec_cid,
                        "created_by": user_map.get(str(rec_actor), str(rec_actor)),
                        "created_by_id": str(rec_actor),
                        "created_at": rec_ts,
                        "details": details_str
                    })
    except Exception as local_al_err:
        logger.warning(f"Could not read local audit jsonl files: {local_al_err}")

    activity.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)

    if target_case_id:
        clean_cid = target_case_id.lower()
        activity = [a for a in activity if str(a.get("case_id") or "").strip().lower() == clean_cid]

    return {
        "status": "SUCCESS",
        "data": activity[:limit]
    }


@router.get("/auditor-stats", response_model=Dict[str, Any])
async def get_auditor_stats(
    limit: int = Query(50, ge=1, le=100),
    x_tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Get dynamic auditor statistics and data-driven previous case severity & confidence for top completed cases.
    """
    import datetime
    from config.settings import settings
    import psycopg2

    total_findings = 0
    high_severity = 0
    medium_severity = 0
    low_severity = 0

    previous_cases = []

    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            
            cur.execute(
                """
                SELECT f.severity
                FROM fir_findings f
                INNER JOIN cases c ON f.case_id = c.case_id
                WHERE c.tenant_id = %s
                """,
                (x_tenant_id,)
            )
            rows = cur.fetchall()
            for row in rows:
                sev_str = (row[0] or "medium").lower()
                total_findings += 1
                if sev_str in ("critical", "high"):
                    high_severity += 1
                elif sev_str == "medium":
                    medium_severity += 1
                else:
                    low_severity += 1

            cur.execute(
                """
                SELECT c.case_id, c.name, c.closed_at, c.created_at,
                       COUNT(f.finding_id) as finding_count,
                       AVG(f.confidence) as avg_conf,
                       MAX(CASE 
                           WHEN LOWER(f.severity) = 'critical' THEN 4 
                           WHEN LOWER(f.severity) = 'high' THEN 3 
                           WHEN LOWER(f.severity) = 'medium' THEN 2 
                           WHEN LOWER(f.severity) = 'low' THEN 1 
                           ELSE 0 END) as max_sev_rank
                FROM cases c
                LEFT JOIN fir_findings f ON c.case_id = f.case_id
                WHERE (c.tenant_id = %s OR (%s IN ('default', 'dev-team') AND c.tenant_id IN ('default', 'dev-team')))
                GROUP BY c.case_id, c.name, c.closed_at, c.created_at, c.has_report, c.submitted_to_senior, c.submitted_to_auditor
                HAVING COUNT(f.finding_id) > 0
                    OR COALESCE(c.has_report, FALSE) = TRUE
                    OR COALESCE(c.submitted_to_senior, FALSE) = TRUE
                    OR COALESCE(c.submitted_to_auditor, FALSE) = TRUE
                ORDER BY COALESCE(c.closed_at, c.created_at) DESC
                LIMIT %s
                """,
                (x_tenant_id, x_tenant_id, limit)
            )
            case_rows = list(reversed(cur.fetchall()))

            sev_rank_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Low"}

            for r in case_rows:
                cid, name, closed_at, created_at, f_count, avg_conf, max_sev_rank = r
                dt = closed_at or created_at
                conf_pct = round(float(avg_conf) * 100, 1) if avg_conf is not None else 0.0
                sev_label = sev_rank_map.get(max_sev_rank or 0, "Low")
                
                previous_cases.append({
                    "case_id": cid,
                    "name": name or cid,
                    "closed_at": dt.isoformat() if dt else None,
                    "month": dt.strftime("%b") if dt else "",
                    "date_formatted": dt.strftime("%b %d") if dt else "",
                    "full_date_formatted": dt.strftime("%b %d, %Y") if dt else "",
                    "severity": sev_label,
                    "confidence": conf_pct,
                    "total_findings": f_count
                })
    except Exception as e:
        logger.warning(f"Could not fetch auditor stats from DB: {e}")

    return {
        "status": "SUCCESS",
        "total_findings": total_findings,
        "high_severity": high_severity,
        "medium_severity": medium_severity,
        "low_severity": low_severity,
        "previous_cases": previous_cases[:limit]
    }





@router.put("/{case_id}/close")
@router.post("/{case_id}/close")
async def close_case_endpoint(
    case_id: str,
    payload: Optional[Dict[str, Any]] = Body(None),
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Close an active case globally.
    """
    user_role = (current_user.get("role") or "").lower()
    if user_role == "analyst":
        raise HTTPException(
            status_code=403,
            detail="Analysts are not authorized to close cases. Only administrators and supervisors may close cases."
        )

    reason = None
    if isinstance(payload, dict):
        reason = payload.get("reason")

    from api.routes.evidence import sanitize_uuid
    clean_case_id = sanitize_uuid(case_id)

    # Gating: Closing a case before report generation requires an explicit reason
    has_report = False
    try:
        from pathlib import Path
        import json
        from infrastructure.repository.evidence_store import REPOSITORY_DIR
        for cid in (clean_case_id, case_id):
            case_dir = Path(REPOSITORY_DIR) / cid
            if case_dir.exists() and case_dir.is_dir():
                s_file = case_dir / "case_session.json"
                if s_file.exists():
                    try:
                        with open(s_file, "r", encoding="utf-8") as f:
                            s_data = json.load(f)
                        if (
                            s_data.get("has_report")
                            or s_data.get("submitted_to_senior")
                            or s_data.get("submitted_to_auditor")
                            or (case_dir / "report.json").exists()
                            or (case_dir / "report.html").exists()
                        ):
                            has_report = True
                            break
                    except Exception:
                        pass
    except Exception:
        pass

    if not has_report:
        try:
            from api.routes.auth import get_db_connection
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT has_report FROM cases WHERE case_id = %s OR case_id = %s LIMIT 1;",
                        (clean_case_id, case_id)
                    )
                    r = cur.fetchone()
                    if r and r[0]:
                        has_report = True
                    else:
                        cur.execute(
                            "SELECT 1 FROM case_notes WHERE (case_id = %s OR case_id = %s) AND (title ILIKE %s OR title ILIKE %s) LIMIT 1;",
                            (clean_case_id, case_id, "%Report Submitted%", "%Escalation to Auditor%")
                        )
                        if cur.fetchone():
                            has_report = True
        except Exception:
            pass

    reason_str = str(reason).strip() if reason else ""
    if not has_report and not reason_str:
        raise HTTPException(
            status_code=400,
            detail="A reason is required to close a case before report generation."
        )

    # Enforce case lock
    user_id = str(current_user.get("id", ""))
    is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
        case_id=clean_case_id,
        user_id=user_id,
        is_admin=user_role == "admin"
    )
    if not is_allowed and lock:
        raise HTTPException(
            status_code=423,
            detail=f"Cannot close case: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
        )
    
    # Custom db update to add closed_by and resolve effective tenant
    from config.settings import settings
    import psycopg2
    effective_tenant = x_tenant_id
    db_updated = False
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            # Resolve real tenant from DB
            cur.execute("SELECT tenant_id FROM cases WHERE case_id = %s", (clean_case_id,))
            row = cur.fetchone()
            if not row and clean_case_id != case_id:
                cur.execute("SELECT tenant_id FROM cases WHERE case_id = %s", (case_id,))
                row = cur.fetchone()
                if row:
                    clean_case_id = case_id
            if row and row[0]:
                effective_tenant = row[0]

            if reason:
                cur.execute(
                    "UPDATE cases SET status = 'closed', closed_at = NOW(), closed_by = %s, closed_reason = %s, description = COALESCE(%s, description) WHERE case_id = %s;",
                    (str(current_user.get("id", current_user.get("name", "admin"))), reason, reason, clean_case_id)
                )
            else:
                cur.execute(
                    "UPDATE cases SET status = 'closed', closed_at = NOW(), closed_by = %s WHERE case_id = %s;",
                    (str(current_user.get("id", current_user.get("name", "admin"))), clean_case_id)
                )
            if cur.rowcount > 0:
                db_updated = True
            conn.commit()
    except Exception as e:
        print(f"[DB] Error closing case directly: {e}")
        
    success = close_case(tenant_id=effective_tenant, case_id=clean_case_id, reason=reason)
    if not success and clean_case_id != case_id:
        success = close_case(tenant_id=effective_tenant, case_id=case_id, reason=reason)
    if not success and effective_tenant != x_tenant_id:
        success = close_case(tenant_id=x_tenant_id, case_id=clean_case_id, reason=reason)
    
    if not success and not db_updated:
        raise HTTPException(status_code=404, detail="Case not found or could not be closed.")

    case_lock_manager.release(clean_case_id, user_id, is_admin=True)
    if case_id != clean_case_id:
        case_lock_manager.release(case_id, user_id, is_admin=True)

    return {"status": "SUCCESS", "message": f"Case {case_id} closed."}






class AssignSeniorRequest(BaseModel):
    senior_analyst_id: Union[int, str]


AssignSeniorRequest.model_rebuild()


class AssignAnalystRequest(BaseModel):
    analyst_id: Union[int, str]


AssignAnalystRequest.model_rebuild()


@router.put("/{case_id}/assign-senior")
@router.post("/{case_id}/assign-senior")
async def assign_senior_analyst(
    case_id: str,
    req: AssignSeniorRequest,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Assign a senior analyst to an existing case. Admin only.
    Supports both PostgreSQL and local repository fallback.
    """
    if current_user.get("role") not in ("admin", "analyst", "senior_analyst"):
        raise HTTPException(status_code=403, detail="Unauthorized to assign senior analyst.")

    updated_local = False
    try:
        from infrastructure.repository.evidence_store import REPOSITORY_DIR
        case_file = Path(REPOSITORY_DIR) / case_id / "case_session.json"
        if case_file.exists():
            with open(case_file, "r", encoding="utf-8") as f:
                cdata = json.load(f)
            cdata["senior_analyst_id"] = str(req.senior_analyst_id)
            with open(case_file, "w", encoding="utf-8") as f:
                json.dump(cdata, f, indent=2)
            updated_local = True
    except Exception as f_err:
        logger.warning(f"Could not persist local senior_analyst_id to case_session.json: {f_err}")

    updated_db = False
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE cases SET senior_analyst_id = %s WHERE case_id = %s AND (tenant_id = %s OR tenant_id IN ('default', 'dev-team'))",
                (str(req.senior_analyst_id), case_id, x_tenant_id)
            )
            if cur.rowcount > 0:
                updated_db = True
            conn.commit()

            # Send assignment email in background if configured
            senior = get_user_by_id(req.senior_analyst_id)
            if senior and senior.get("email"):
                case_name = case_id
                try:
                    cur.execute("SELECT name FROM cases WHERE case_id = %s", (case_id,))
                    row = cur.fetchone()
                    if row and row[0]:
                        case_name = row[0]
                except Exception:
                    pass
                try:
                    send_assignment_email(senior["email"], case_id, case_name, "Senior Analyst")
                except Exception as email_err:
                    logger.warning(f"Could not send assignment email: {email_err}")
    except Exception as db_err:
        logger.warning(f"Database update for senior analyst assignment: {db_err}")

    if not updated_db and not updated_local:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {"status": "SUCCESS", "message": f"Senior Analyst {req.senior_analyst_id} assigned to {case_id}."}


@router.put("/{case_id}/assign-analyst")
async def assign_analyst(
    case_id: str,
    req: AssignAnalystRequest,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Assign an analyst to an existing case. Admin only.
    Supports both PostgreSQL and local repository fallback.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can assign an analyst.")

    updated_local = False
    try:
        from infrastructure.repository.evidence_store import REPOSITORY_DIR
        case_file = Path(REPOSITORY_DIR) / case_id / "case_session.json"
        if case_file.exists():
            with open(case_file, "r", encoding="utf-8") as f:
                cdata = json.load(f)
            cdata["analyst_id"] = str(req.analyst_id)
            with open(case_file, "w", encoding="utf-8") as f:
                json.dump(cdata, f, indent=2)
            updated_local = True
    except Exception as f_err:
        logger.warning(f"Could not persist local analyst_id to case_session.json: {f_err}")

    updated_db = False
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE cases SET analyst_id = %s WHERE case_id = %s AND (tenant_id = %s OR tenant_id IN ('default', 'dev-team'))",
                (str(req.analyst_id), case_id, x_tenant_id)
            )
            if cur.rowcount > 0:
                updated_db = True
            conn.commit()

            analyst = get_user_by_id(req.analyst_id)
            if analyst and analyst.get("email"):
                case_name = case_id
                try:
                    cur.execute("SELECT name FROM cases WHERE case_id = %s", (case_id,))
                    row = cur.fetchone()
                    if row and row[0]:
                        case_name = row[0]
                except Exception:
                    pass
                try:
                    send_assignment_email(analyst["email"], case_id, case_name, "Analyst")
                except Exception as email_err:
                    logger.warning(f"Could not send assignment email: {email_err}")
    except Exception as db_err:
        logger.warning(f"Database update for analyst assignment: {db_err}")

    if not updated_db and not updated_local:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {"status": "SUCCESS", "message": f"Analyst {req.analyst_id} assigned to {case_id}."}


@router.get("/locks/active", response_model=Dict[str, Any])
async def get_all_active_case_locks(
    current_user: Dict = Depends(get_current_user)
):
    """
    Retrieve all currently active case locks in the workspace.
    """
    return {
        "status": "SUCCESS",
        "locks": case_lock_manager.get_all_active_locks()
    }


def _is_case_closed(case_id: str, x_tenant_id: str) -> bool:
    """Return True if the case session has been closed/completed/archived."""
    try:
        from api.routes.evidence import sanitize_uuid
        from infrastructure.repository.evidence_store import get_case_session
        clean_cid = sanitize_uuid(case_id)
        session = get_case_session(tenant_id=x_tenant_id, case_id=clean_cid) or get_case_session(tenant_id=x_tenant_id, case_id=case_id)
        if session and str(getattr(session, "status", "open") or "").lower() in ("closed", "completed", "archived"):
            return True
    except Exception:
        pass
    return False


@router.post("/{case_id}/lock", response_model=Dict[str, Any])
async def acquire_or_refresh_case_lock(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    verify_case_access(case_id, current_user, x_tenant_id)
    user_id = str(current_user.get("id", ""))
    user_name = current_user.get("name") or current_user.get("userid") or "Analyst"
    user_email = current_user.get("email")

    if _is_case_closed(case_id, x_tenant_id):
        case_lock_manager.release(case_id, user_id, is_admin=True)
        return {
            "status": "CASE_CLOSED",
            "lock_status": "CASE_CLOSED",
            "is_locked": False,
            "is_owner": False,
            "read_only": True,
            "message": f"Case '{case_id}' is closed.",
            "lock": None,
        }

    is_authorized = is_user_authorized_for_case_modification(case_id, current_user, x_tenant_id)

    granted, lock, status_code = case_lock_manager.acquire_or_refresh(
        case_id=case_id,
        user_id=user_id,
        user_name=user_name,
        user_email=user_email,
        is_assigned_team=is_authorized
    )

    is_owner = granted or is_authorized
    read_only = False if is_authorized else (not granted)
    lock_dict = lock.to_dict(user_id, is_assigned=is_authorized)

    if is_owner:
        message = f"Case lock active for assigned investigator '{user_name}'."
    else:
        message = (
            f"Case '{case_id}' is currently being investigated by analyst '{lock.locked_by_user_name}'. "
            f"You have been granted Read-Only access."
        )

    return {
        "status": "SUCCESS" if is_owner else "LOCKED_BY_OTHER",
        "lock_status": status_code,
        "is_locked": True,
        "is_owner": is_owner,
        "read_only": read_only,
        "message": message,
        "lock": lock_dict
    }


@router.get("/{case_id}/lock", response_model=Dict[str, Any])
async def get_case_lock_status(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Check current lock status for a specific case.
    """
    user_id = str(current_user.get("id", ""))
    if _is_case_closed(case_id, x_tenant_id):
        case_lock_manager.release(case_id, user_id, is_admin=True)
        return {
            "status": "UNLOCKED",
            "is_locked": False,
            "is_owner": False,
            "read_only": True,
            "message": "Case is closed and unlocked.",
            "lock": None
        }
    is_authorized = is_user_authorized_for_case_modification(case_id, current_user, x_tenant_id)
    lock = case_lock_manager.get_lock(case_id)
    if not lock:
        return {
            "status": "UNLOCKED",
            "is_locked": False,
            "is_owner": is_authorized,
            "read_only": not is_authorized,
            "message": "Case is currently not locked by any analyst.",
            "lock": None
        }

    is_owner = is_authorized or (lock.locked_by_user_id == user_id)
    read_only = False if is_authorized else (not is_owner)
    return {
        "status": "OWNED" if is_owner else "LOCKED",
        "is_locked": True,
        "is_owner": is_owner,
        "read_only": read_only,
        "message": (
            "You have active investigation rights on this case."
            if is_owner
            else f"Case is currently locked by analyst '{lock.locked_by_user_name}'."
        ),
        "lock": lock.to_dict(user_id, is_assigned=is_authorized)
    }


@router.post("/{case_id}/heartbeat", response_model=Dict[str, Any])
async def case_lock_heartbeat(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Heartbeat to extend TTL of an active case lock.
    """
    user_id = str(current_user.get("id", ""))
    if _is_case_closed(case_id, x_tenant_id):
        case_lock_manager.release(case_id, user_id, is_admin=True)
        return {
            "status": "CASE_CLOSED",
            "lock_status": "CASE_CLOSED",
            "is_locked": False,
            "is_owner": False,
            "read_only": True,
            "lock": None,
        }
    is_authorized = is_user_authorized_for_case_modification(case_id, current_user, x_tenant_id)
    success, lock, code = case_lock_manager.heartbeat(case_id=case_id, user_id=user_id, is_assigned=is_authorized)
    if not success:
        if code == "NOT_OWNER":
            raise HTTPException(
                status_code=403,
                detail=f"Cannot heartbeat case lock: active lock is held by '{lock.locked_by_user_name if lock else 'another user'}'."
            )
        else:
            # Lock might have expired; try to re-acquire
            user_name = current_user.get("name") or current_user.get("userid") or "Analyst"
            granted, new_lock, acquire_code = case_lock_manager.acquire_or_refresh(
                case_id=case_id,
                user_id=user_id,
                user_name=user_name,
                user_email=current_user.get("email")
            )
            return {
                "status": "SUCCESS" if granted else "LOCKED_BY_OTHER",
                "lock_status": acquire_code,
                "is_locked": True,
                "is_owner": granted,
                "read_only": not granted,
                "lock": new_lock.to_dict(user_id)
            }

    return {
        "status": "SUCCESS",
        "lock_status": "HEARTBEAT_ACK",
        "is_locked": True,
        "is_owner": True,
        "read_only": False,
        "lock": lock.to_dict(user_id) if lock else None
    }


@router.post("/{case_id}/unlock", response_model=Dict[str, Any])
@router.delete("/{case_id}/lock", response_model=Dict[str, Any])
async def release_case_lock(
    case_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """
    Release case lock when an analyst finishes investigating, switches cases, or logs out.
    """
    user_id = str(current_user.get("id", ""))
    is_admin = current_user.get("role") == "admin"
    released, reason = case_lock_manager.release(case_id=case_id, user_id=user_id, is_admin=is_admin)

    if not released:
        raise HTTPException(
            status_code=403,
            detail="Cannot unlock case: You are not the owner of this lock."
        )

    return {
        "status": "SUCCESS",
        "message": f"Lock for case '{case_id}' released successfully ({reason})."
    }


@router.get("/{case_id}", response_model=CaseSummaryResponse)
async def get_case(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieve structured case summary, severity metrics, and review status breakdown.
    Enforces strict tenant isolation.
    """
    verify_case_access(case_id, current_user, x_tenant_id)
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
        # Evidence has been uploaded to the case -> Evidence Collection stage is complete.
        ev_status = InvestigationStageStatus.COMPLETED

    # 2. Analysis & 3. Correlation
    # In ARGUS, once evidence is collected, analysis & entity correlation complete.
    if ev_status != InvestigationStageStatus.COMPLETED:
        an_status = InvestigationStageStatus.NOT_STARTED
        cor_status = InvestigationStageStatus.NOT_STARTED
    else:
        an_status = InvestigationStageStatus.COMPLETED
        cor_status = InvestigationStageStatus.COMPLETED
        
    # 4. Findings & Agent Analysis verification
    if cor_status != InvestigationStageStatus.COMPLETED:
        find_status = InvestigationStageStatus.NOT_STARTED
        agent_status = InvestigationStageStatus.NOT_STARTED
    else:
        find_status = InvestigationStageStatus.COMPLETED
        agent_status = _get_agent_pipeline_status(case_id, x_tenant_id, evidence_list)

    sub_meta = _read_case_submission_meta(case_id, session)
    is_closed = getattr(session, "status", "") == "closed"
    submitted_to_senior = sub_meta["submitted_to_senior"]
    submitted_to_auditor = sub_meta["submitted_to_auditor"]

    if not (submitted_to_senior and submitted_to_auditor):
        try:
            from infrastructure.repository.evidence_store import _should_attempt_postgres
            if _should_attempt_postgres():
                from api.routes.auth import get_db_connection
                with get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT title FROM case_notes WHERE case_id = %s AND (title ILIKE %s OR title ILIKE %s)",
                            (case_id, "%Report Submitted%", "%Escalation to Auditor%")
                        )
                        for n_row in cur.fetchall():
                            n_title = str(n_row[0] or "").lower()
                            if "escalation to auditor" in n_title:
                                submitted_to_auditor = True
                                submitted_to_senior = True
                            elif "report submitted" in n_title:
                                submitted_to_senior = True
        except Exception:
            pass

    if submitted_to_auditor:
        submitted_to_senior = True

    has_report_flag = bool(submitted_to_senior or submitted_to_auditor or sub_meta["has_report"])

    # 5. Report (Must NOT be ready or in-progress if Agent Analysis has not completed!)
    if agent_status != InvestigationStageStatus.COMPLETED:
        rep_status = InvestigationStageStatus.NOT_STARTED
    elif is_closed or submitted_to_senior or submitted_to_auditor:
        rep_status = InvestigationStageStatus.COMPLETED
    else:
        rep_status = InvestigationStageStatus.IN_PROGRESS

    progress = InvestigationProgress(
        evidence_collection=ev_status,
        analysis=an_status,
        correlation=cor_status,
        findings=find_status,
        agent_analysis=agent_status,
        report=rep_status
    )

    # Fetch name and description from session or DB
    case_name = getattr(session, "name", None) or "Unnamed Case"
    case_desc = getattr(session, "description", None) or "No description provided."
    if case_name == "Unnamed Case":
        try:
            from databases.postgres_pool import PostgresConnectionPool
            with PostgresConnectionPool.get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT name, description FROM cases WHERE case_id = %s AND tenant_id = %s", (case_id, x_tenant_id))
                row = cur.fetchone()
                if row:
                    if row[0]:
                        case_name = row[0]
                    if len(row) > 1 and row[1]:
                        case_desc = row[1]
        except Exception as e:
            logger.warning(f"Could not fetch case name for summary: {e}")

    user_id = str(current_user.get("id", ""))
    is_authorized = is_user_authorized_for_case_modification(case_id, current_user, x_tenant_id)
    case_lock = case_lock_manager.get_lock(case_id)
    lock_dict = case_lock.to_dict(user_id, is_assigned=is_authorized) if case_lock else None

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
        evidence_files=formatted_evidence,
        lock=lock_dict,
        has_report=has_report_flag,
        submitted_to_senior=submitted_to_senior,
        submitted_to_auditor=submitted_to_auditor,
        submitted_to_senior_data=sub_meta["submitted_to_senior_data"],
        submitted_to_auditor_data=sub_meta["submitted_to_auditor_data"],
    )

from collections import OrderedDict

# In-memory thread-safe LRU cache for sanitized findings to avoid expensive repeated regex/NFKC/XML passes
_FINDINGS_SANITIZATION_CACHE: OrderedDict[str, Dict[str, Any]] = OrderedDict()
_FINDINGS_CACHE_LOCK = threading.Lock()
_MAX_FINDINGS_CACHE_SIZE = 5000

def invalidate_findings_cache(tenant_id: str, case_id: Optional[str] = None, finding_id: Optional[str] = None):
    """Evict cached sanitization contexts when findings are updated or reviewed."""
    with _FINDINGS_CACHE_LOCK:
        if not case_id and not finding_id:
            keys_to_del = [k for k in _FINDINGS_SANITIZATION_CACHE if k.startswith(f"{tenant_id}:")]
        elif case_id and not finding_id:
            prefix = f"{tenant_id}:{case_id}:"
            keys_to_del = [k for k in _FINDINGS_SANITIZATION_CACHE if k.startswith(prefix)]
        else:
            prefix = f"{tenant_id}:{case_id}:{finding_id}:"
            keys_to_del = [k for k in _FINDINGS_SANITIZATION_CACHE if k.startswith(prefix)]
        for k in keys_to_del:
            _FINDINGS_SANITIZATION_CACHE.pop(k, None)

@router.get("/{case_id}/findings")
async def get_case_findings(
    case_id: str,
    response: Response,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user),
    limit: Optional[int] = Query(None, ge=1, le=10000, description="Maximum number of findings to return"),
    skip: int = Query(0, ge=0, description="Number of findings to skip for pagination"),
    ids: Optional[str] = Query(None, description="Comma-separated finding IDs to filter (e.g. for graph nodes)")
):
    """
    Retrieve parsed output findings for a specific case.
    Access restricted: only assigned analyst, senior analyst, or admin.
    Supports optional pagination/limits, ID filtering for correlated graphs,
    and high-performance in-memory sanitization caching with fail-closed semantics.
    """
    if not case_id or not case_id.strip():
        raise HTTPException(status_code=400, detail="case_id path parameter cannot be empty.")

    verify_case_access(case_id, current_user, x_tenant_id)
    
    findings = _analyst_service.list_findings(case_id=case_id, tenant_id=x_tenant_id)

    # Optional ID-based filtering (for graph correlation without unbounded payload retrieval)
    if ids and ids.strip():
        target_ids = {item.strip() for item in ids.split(",") if item.strip()}
        findings = [
            f for f in findings
            if str(getattr(f, 'finding_id', None) or (f.get('finding_id') if isinstance(f, dict) else '') or '') in target_ids
        ]
    
    total_count = len(findings)

    # Apply pagination slice before heavy sanitization if limit/skip is specified
    if skip > 0 or limit is not None:
        if limit is not None:
            paginated_findings = findings[skip:skip + limit]
        else:
            paginated_findings = findings[skip:]
    else:
        paginated_findings = findings

    # Populate explicit RFC-compatible pagination headers to preserve flat JSON array schema
    response.headers["X-Total-Count"] = str(total_count)
    response.headers["X-Page-Limit"] = str(limit if limit is not None else total_count)
    response.headers["X-Page-Skip"] = str(skip)
    response.headers["X-Has-More"] = "true" if (skip + len(paginated_findings) < total_count) else "false"

    gateway = SanitizationGateway()
    sanitized_results = []
    for f in paginated_findings:
        f_dict = f.model_dump(mode='json') if hasattr(f, 'model_dump') else dict(f)
        f_id = str(getattr(f, 'finding_id', None) or f_dict.get('finding_id') or f_dict.get('id', ''))
        fact_val = str(getattr(f, 'fact', None) or f_dict.get('fact', ''))
        s_fact_val = str(getattr(f, 'sanitized_fact', None) or f_dict.get('sanitized_fact', ''))
        sev_val = str(getattr(f, 'severity', None) or f_dict.get('severity', ''))
        layer_val = str(getattr(f, 'layer', None) or f_dict.get('layer', ''))
        mitre_val = str(getattr(f, 'mitre_mapping', None) or f_dict.get('mitre_mapping', ''))
        status_val = str(getattr(f, 'review_status', None) or f_dict.get('review_status', ''))
        conf_val = str(getattr(f, 'confidence', None) or f_dict.get('confidence', ''))
        src_art = str(getattr(f, 'source_artifact_id', None) or f_dict.get('source_artifact_id', ''))
        ev_ref = str(getattr(f, 'evidence_reference', None) or f_dict.get('evidence_reference', ''))
        ts_val = str(getattr(f, 'timestamp', None) or f_dict.get('timestamp', ''))
        inj_flg = str(getattr(f, 'injection_flagged', None) or f_dict.get('injection_flagged', ''))

        sig = f"{fact_val}|{s_fact_val}|{sev_val}|{layer_val}|{mitre_val}|{status_val}|{conf_val}|{src_art}|{ev_ref}|{ts_val}|{inj_flg}"
        cache_key = f"{x_tenant_id}:{case_id}:{f_id}:{hashlib.sha256(sig.encode('utf-8', errors='ignore')).hexdigest()}"

        cached = None
        with _FINDINGS_CACHE_LOCK:
            if cache_key in _FINDINGS_SANITIZATION_CACHE:
                cached = _FINDINGS_SANITIZATION_CACHE[cache_key]
                _FINDINGS_SANITIZATION_CACHE.move_to_end(cache_key)

        if cached is not None:
            # Defensive copy prevents callers and downstream mutators from altering cache state
            f_dict["sanitized_context"] = copy.deepcopy(cached["sanitized_context"])
            f_dict["sanitized_fact"] = cached["sanitized_fact"]
            f_dict["injection_flagged"] = cached["injection_flagged"]
        else:
            try:
                sanitized_ctx = gateway.sanitize_finding(f)
                ctx_dict = sanitized_ctx.model_dump(mode='json')
                f_dict["sanitized_context"] = ctx_dict
                f_dict["sanitized_fact"] = sanitized_ctx.sanitized_fact
                f_dict["injection_flagged"] = sanitized_ctx.injection_flagged

                with _FINDINGS_CACHE_LOCK:
                    if len(_FINDINGS_SANITIZATION_CACHE) >= _MAX_FINDINGS_CACHE_SIZE:
                        _FINDINGS_SANITIZATION_CACHE.popitem(last=False)
                    _FINDINGS_SANITIZATION_CACHE[cache_key] = {
                        "sanitized_context": copy.deepcopy(ctx_dict),
                        "sanitized_fact": sanitized_ctx.sanitized_fact,
                        "injection_flagged": sanitized_ctx.injection_flagged
                    }
            except Exception as e:
                # FAIL-CLOSED: Never return raw untrusted text or flag as safe when sanitization fails
                logger.error(f"Failed to sanitize finding '{f_id}' in case '{case_id}': {type(e).__name__}: {e}")
                safe_fallback_placeholder = "[SANITISED: Content blocked due to processing failure]"
                f_dict["sanitized_fact"] = safe_fallback_placeholder
                f_dict["injection_flagged"] = True
                f_dict["sanitization_error"] = True
                f_dict["sanitized_context"] = {
                    "finding_id": f_id,
                    "case_id": case_id,
                    "tenant_id": x_tenant_id,
                    "sanitized_fact": safe_fallback_placeholder,
                    "injection_flagged": True,
                    "injection_score": 1.0,
                    "sanitization_actions": ["sanitization_exception_fail_closed"],
                    "error_type": type(e).__name__
                }
        sanitized_results.append(f_dict)
        
    return sanitized_results



class CaseNoteModel(BaseModel):
    title: str
    content: str
    type: str
    priority: str = "Normal"
    status: str = "Open"
    related_evidence_id: Optional[str] = None
    related_finding_id: Optional[str] = None


class ReviewNoteModel(BaseModel):
    title: str
    content: str
    type: str
    status: str = "Open"
    related_type: Optional[str] = None
    related_id: Optional[str] = None
@router.get("/{case_id}/notes")
async def get_case_notes(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    verify_case_access(case_id, current_user, x_tenant_id)
    from databases.postgres_pool import PostgresConnectionPool
    import psycopg2
    try:
        with PostgresConnectionPool.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT note_id, title, content, type, priority, created_by, created_at, updated_at, related_evidence_id, related_finding_id
                    FROM case_notes
                    WHERE case_id = %s AND tenant_id = %s
                    ORDER BY updated_at DESC
                    """,
                    (case_id, x_tenant_id)
                )
                notes = []
                for row in cur.fetchall():
                    notes.append({
                        "noteId": row[0],
                        "caseId": case_id,
                        "title": row[1],
                        "content": row[2],
                        "type": row[3],
                        "priority": row[4],
                        "createdBy": row[5],
                        "createdAt": row[6].isoformat() if hasattr(row[6], "isoformat") else str(row[6]),
                        "updatedAt": row[7].isoformat() if hasattr(row[7], "isoformat") else str(row[7]),
                        "relatedEvidenceId": row[8],
                        "relatedFindingId": row[9]
                    })
                return {"status": "SUCCESS", "data": notes}
    except (psycopg2.OperationalError, psycopg2.DatabaseError) as db_err:
        logger.error(f"PostgreSQL database error fetching notes for case {case_id}: {db_err}")
        raise HTTPException(status_code=503, detail="PostgreSQL service temporarily unavailable")
    except Exception as e:
        logger.error(f"Unexpected error fetching notes for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{case_id}/notes")
async def create_case_note(
    case_id: str,
    note: CaseNoteModel,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    verify_case_access(case_id, current_user, x_tenant_id)
    user_id = str(current_user.get("id", ""))
    user_role = (current_user.get("role") or "").lower()
    note_title_lower = (note.title or "").lower()
    is_senior_escalation_note = user_role in ("senior_analyst", "senior") and "escalation to auditor" in note_title_lower

    if not is_senior_escalation_note:
        is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
            case_id=case_id,
            user_id=user_id,
            is_admin=user_role == "admin"
        )
        if not is_allowed and lock:
            raise HTTPException(
                status_code=423,
                detail=f"Cannot add case note: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
            )

    from databases.postgres_pool import PostgresConnectionPool
    import psycopg2
    import uuid
    try:
        note_id = f"NOTE-{str(uuid.uuid4())[:8].upper()}"
        with PostgresConnectionPool.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO case_notes (note_id, case_id, tenant_id, title, content, type, priority, created_by, related_evidence_id, related_finding_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (note_id, case_id, x_tenant_id, note.title, note.content, note.type, note.priority, current_user.get("name", "Analyst"), note.related_evidence_id, note.related_finding_id)
                )
                conn.commit()

        if "escalation to auditor" in note_title_lower:
            _persist_case_report_stage(
                case_id,
                x_tenant_id,
                "submitted_to_auditor",
                {"senior_analyst_name": current_user.get("name") or "Senior Analyst", "memo": note.content},
            )
        elif "report submitted" in note_title_lower:
            _persist_case_report_stage(
                case_id,
                x_tenant_id,
                "submitted_to_senior",
                {"analyst_name": current_user.get("name") or "Analyst", "note": note.content},
            )

        return {"status": "SUCCESS", "noteId": note_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{case_id}/notes/{note_id}")
async def update_case_note(
    case_id: str,
    note_id: str,
    note: CaseNoteModel,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    user_id = str(current_user.get("id", ""))
    is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
        case_id=case_id,
        user_id=user_id,
        is_admin=current_user.get("role") == "admin"
    )
    if not is_allowed and lock:
        raise HTTPException(
            status_code=423,
            detail=f"Cannot update case note: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
        )

    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE case_notes 
                SET title = %s, content = %s, type = %s, priority = %s, updated_at = now(), related_evidence_id = %s, related_finding_id = %s
                WHERE note_id = %s AND case_id = %s AND tenant_id = %s
                """,
                (note.title, note.content, note.type, note.priority, note.related_evidence_id, note.related_finding_id, note_id, case_id, x_tenant_id)
            )
            conn.commit()
            return {"status": "SUCCESS"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{case_id}/notes/{note_id}")
async def delete_case_note(
    case_id: str,
    note_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    user_id = str(current_user.get("id", ""))
    is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
        case_id=case_id,
        user_id=user_id,
        is_admin=current_user.get("role") == "admin"
    )
    if not is_allowed and lock:
        raise HTTPException(
            status_code=423,
            detail=f"Cannot delete case note: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
        )
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM case_notes WHERE note_id = %s AND case_id = %s AND tenant_id = %s", (note_id, case_id, x_tenant_id))
            conn.commit()
            return {"status": "SUCCESS"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{case_id}/review-notes")
async def get_review_notes(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    verify_case_access(case_id, current_user, x_tenant_id)
    from databases.postgres_pool import PostgresConnectionPool
    import psycopg2
    try:
        with PostgresConnectionPool.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT note_id, title, content, type, status, related_type, related_id, created_by, created_at, updated_at
                    FROM review_notes
                    WHERE case_id = %s AND tenant_id = %s
                    ORDER BY created_at DESC
                    """,
                    (case_id, x_tenant_id)
                )
                notes = []
                for row in cur.fetchall():
                    notes.append({
                        "noteId": row[0],
                        "caseId": case_id,
                        "title": row[1],
                        "content": row[2],
                        "type": row[3],
                        "status": row[4],
                        "relatedType": row[5],
                        "relatedId": row[6],
                        "createdBy": row[7],
                        "createdAt": row[8].isoformat() if hasattr(row[8], "isoformat") else str(row[8]),
                        "updatedAt": row[9].isoformat() if hasattr(row[9], "isoformat") else str(row[9])
                    })
                return {"status": "SUCCESS", "data": notes}
    except (psycopg2.OperationalError, psycopg2.DatabaseError) as db_err:
        logger.error(f"PostgreSQL database error fetching review notes for case {case_id}: {db_err}")
        raise HTTPException(status_code=503, detail="PostgreSQL service temporarily unavailable")
    except Exception as e:
        logger.error(f"Unexpected error fetching review notes for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{case_id}/review-notes")
async def create_review_note(
    case_id: str,
    note: ReviewNoteModel,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    verify_case_access(case_id, current_user, x_tenant_id)
    from databases.postgres_pool import PostgresConnectionPool
    import uuid
    try:
        note_id = f"RN-{str(uuid.uuid4())[:8].upper()}"
        with PostgresConnectionPool.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO review_notes (note_id, case_id, tenant_id, title, content, type, status, related_type, related_id, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (note_id, case_id, x_tenant_id, note.title, note.content, note.type, note.status, note.related_type, note.related_id, current_user.get("name", "Senior Analyst"))
                )
                
                # Log to audit log
                cur.execute(
                    """
                    INSERT INTO audit_log (tenant_id, case_id, event, actor, detail, timestamp)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    """,
                    (x_tenant_id, case_id, "Created Review Note", current_user.get("name", "analyst"), json.dumps({"user_id": current_user.get("user_id", "admin"), "note_id": note_id, "title": note.title}))
                )
                conn.commit()
        return {"status": "SUCCESS", "noteId": note_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{case_id}/review-notes/{note_id}")
async def update_review_note(
    case_id: str,
    note_id: str,
    note: ReviewNoteModel,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE review_notes 
                SET title = %s, content = %s, type = %s, status = %s, related_type = %s, related_id = %s, updated_at = CURRENT_TIMESTAMP
                WHERE note_id = %s AND case_id = %s AND tenant_id = %s
                """,
                (note.title, note.content, note.type, note.status, note.related_type, note.related_id, note_id, case_id, x_tenant_id)
            )
            
            # Log to audit log
            action_name = "Resolved Review Note" if note.status == "Resolved" else "Updated Review Note"
            cur.execute(
                """
                INSERT INTO audit_log (tenant_id, case_id, event, actor, detail, timestamp)
                VALUES (%s, %s, %s, %s, %s, NOW())
                """,
                (x_tenant_id, case_id, action_name, current_user.get("name", "analyst"), json.dumps({"user_id": current_user.get("user_id", "admin"), "note_id": note_id, "title": note.title}))
            )
            conn.commit()
            return {"status": "SUCCESS"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{case_id}/agents")
async def get_case_agent_results(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Retrieve comprehensive multi-agent forensic intelligence (Agents 1-7),
    persisted claims, attack graph reconstruction, threat intelligence, and supervisor verdict.
    Strictly enforces case ownership and tenant isolation.
    """
    verify_case_access(case_id, current_user, x_tenant_id)
    from api.routes.evidence import sanitize_uuid
    from infrastructure.repository.evidence_store import list_evidence_by_case, get_case_session
    from ism.checkpointer import Checkpointer
    from config.settings import settings
    from pathlib import Path

    clean_case_id = sanitize_uuid(case_id)

    # 1. Enforce Case Evidence and Findings with Tenant Isolation
    evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=clean_case_id)
    if not evidence_list and case_id != clean_case_id:
        evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=case_id)

    findings = _analyst_service.list_findings(case_id=clean_case_id, tenant_id=x_tenant_id)
    if not findings and case_id != clean_case_id:
        findings = _analyst_service.list_findings(case_id=case_id, tenant_id=x_tenant_id)

    # 2. Check in-memory live job (tenant-checked)
    with _agent_jobs_lock:
        mem_job = _agent_jobs.get(clean_case_id) or _agent_jobs.get(case_id)
        live_job = mem_job if (mem_job and mem_job.get("tenant_id") == x_tenant_id) else None

    # 3. Durable Checkpoint Recovery (survives server restarts)
    checkpointer = Checkpointer()
    persisted_job = None
    if not live_job:
        cp = checkpointer.get_stage_checkpoint(case_id=clean_case_id, stage="pipeline_job", tenant_id=x_tenant_id)
        if not cp and case_id != clean_case_id:
            cp = checkpointer.get_stage_checkpoint(case_id=case_id, stage="pipeline_job", tenant_id=x_tenant_id)
        if cp:
            persisted_job = cp.get("checkpoint") if isinstance(cp.get("checkpoint"), dict) else cp

    # 4. Query evidence metadata for agent_results
    stored_pipeline_results = None
    for ev in (evidence_list or []):
        meta = ev.metadata or {}
        if meta.get("agent_results"):
            stored_pipeline_results = meta.get("agent_results")
            break

    # 5. Query PostgreSQL agent_outputs table with strict tenant filter
    db_claims = []
    try:
        from databases.postgres_pool import PostgresConnectionPool
        from agents.agent1_evidence_intelligence.agent import _ensure_agent_outputs_table_initialized
        with PostgresConnectionPool.get_connection() as conn:
            _ensure_agent_outputs_table_initialized(conn)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, agent_id, claim, evidence_ids, confidence, verified, execution_status, flags, created_at, model_used
                FROM agent_outputs
                WHERE case_id IN (%s, %s) AND tenant_id = %s
                ORDER BY id ASC;
                """,
                (clean_case_id, case_id, x_tenant_id)
            )
            rows = cur.fetchall()
            for r in rows:
                db_claims.append({
                    "id": r[0],
                    "agent_id": r[1],
                    "claim": r[2],
                    "evidence_ids": r[3] or [],
                    "confidence": r[4] or 0.0,
                    "verified": bool(r[5]),
                    "execution_status": r[6] or "COMPLETED",
                    "flags": r[7] if isinstance(r[7], list) else [],
                    "created_at": r[8].isoformat() if hasattr(r[8], "isoformat") and r[8] else str(r[8]),
                    "model_used": r[9] or "Qwen3-8B"
                })
    except Exception as dbe:
        logger.warning(f"Could not query agent_outputs table: {dbe}")

    # Determine overall status and assemble payload
    job_source = live_job or persisted_job
    if job_source and job_source.get("status") == "RUNNING":
        status_val = "RUNNING"
        stage_statuses = _extract_stage_statuses(job_source, stored_pipeline_results)
        results_data = job_source.get("results") or stored_pipeline_results or {}
    elif job_source and str(job_source.get("status") or "").upper() in ("COMPLETED", "SUCCESS", "PARTIAL_SUCCESS", "NEEDS_REVIEW", "FAILED", "ERROR"):
        status_val = job_source["status"]
        results_data = job_source.get("results") or stored_pipeline_results or {}
        stage_statuses = _extract_stage_statuses(job_source, stored_pipeline_results, results_data)
        if not stage_statuses and str(status_val or "").upper() in ("COMPLETED", "SUCCESS"):
            stage_statuses = {k: str(status_val).upper() for k in _REQUIRED_SWARM_STAGES}
    elif job_source and str(job_source.get("status") or "").upper() in ("STOPPED", "CANCELLED"):
        status_val = "STOPPED"
        results_data = job_source.get("results") or stored_pipeline_results or {}
        stage_statuses = _extract_stage_statuses(job_source, stored_pipeline_results, results_data)
    elif stored_pipeline_results:
        status_val = stored_pipeline_results.get("execution_status", "COMPLETED")
        results_data = stored_pipeline_results
        stage_statuses = _extract_stage_statuses(None, stored_pipeline_results, results_data)
        if not stage_statuses and str(status_val or "").upper() in ("COMPLETED", "SUCCESS"):
            stage_statuses = {k: str(status_val).upper() for k in _REQUIRED_SWARM_STAGES}
    elif db_claims:
        claim_agents = {c.get("agent_id") for c in db_claims}
        stage_statuses = {
            "agent1": "COMPLETED" if ("agent1" in claim_agents or "agent1_evidence_intelligence" in claim_agents) else "PENDING",
            "agent2": "COMPLETED" if "agent2" in claim_agents else "PENDING",
            "agent3": "COMPLETED" if "agent3" in claim_agents else "PENDING",
            "agent4": "COMPLETED" if "agent4" in claim_agents else "PENDING",
            "agent5a": "COMPLETED" if "agent5a" in claim_agents else "PENDING",
            "agent5b": "COMPLETED" if "agent5b" in claim_agents else "PENDING",
            "agent6": "COMPLETED" if ("agent6" in claim_agents or "agent_6" in claim_agents) else "PENDING",
            "agent7": "COMPLETED" if "agent7" in claim_agents else "PENDING",
        }
        all_done = all(v == "COMPLETED" for v in stage_statuses.values())
        status_val = "COMPLETED" if all_done else "PARTIAL"
        results_data = {}
    else:
        status_val = "READY"
        results_data = {}
        stage_statuses = {k: "PENDING" for k in _REQUIRED_SWARM_STAGES}
        # Fallback: recover stage statuses from per-agent ISM checkpoints if pipeline_job wasn't written
        recovered_any = False
        for key in _REQUIRED_SWARM_STAGES:
            stg_cp = checkpointer.get_stage_checkpoint(case_id=clean_case_id, stage=key, tenant_id=x_tenant_id)
            if not stg_cp and case_id != clean_case_id:
                stg_cp = checkpointer.get_stage_checkpoint(case_id=case_id, stage=key, tenant_id=x_tenant_id)
            if isinstance(stg_cp, dict):
                cp_body = stg_cp.get("checkpoint") if isinstance(stg_cp.get("checkpoint"), dict) else {}
                st = stg_cp.get("status") or cp_body.get("execution_status") or cp_body.get("status")
                if st:
                    stage_statuses[key] = str(st)
                    recovered_any = True
                if cp_body:
                    results_data[key] = cp_body
        if recovered_any:
            if _has_completed_agent_stages(stage_statuses):
                status_val = "COMPLETED"
            else:
                status_val = "PARTIAL"

    # Extract per-agent intelligence from real results (never fabricated)
    a1_data = results_data.get("agent1") or {}
    a2_data = results_data.get("agent2") or {}
    a3_data = results_data.get("agent3") or {}
    a4_data = results_data.get("agent4") or {}
    a5a_data = results_data.get("agent5a") or {}
    a5b_data = results_data.get("agent5b") or {}
    a6_data = results_data.get("agent6") or {}
    a7_data = results_data.get("agent7") or {}

    # Extract claims (from pipeline results or persisted database records)
    all_claims = list(db_claims)
    if not all_claims and results_data:
        for a_key in ["agent1", "agent2", "agent3", "agent4", "agent5a", "agent5b", "agent6", "agent7"]:
            ag_obj = results_data.get(a_key)
            if isinstance(ag_obj, dict) and "claims" in ag_obj and isinstance(ag_obj["claims"], list):
                for c in ag_obj["claims"]:
                    c_dict = c if isinstance(c, dict) else (c.model_dump(mode='json') if hasattr(c, 'model_dump') else {})
                    c_dict["agent_id"] = a_key
                    all_claims.append(c_dict)

    return {
        "status": status_val,
        "case_id": clean_case_id,
        "tenant_id": x_tenant_id,
        "findings_count": len(findings),
        "evidence_count": len(evidence_list or []),
        "stage_statuses": stage_statuses,
        "agent1": a1_data,
        "agent2": a2_data,
        "agent3": a3_data,
        "agent4": a4_data,
        "agent5a": a5a_data,
        "agent5b": a5b_data,
        "agent6": a6_data,
        "agent7": a7_data,
        "claims": all_claims,
        "supervisor_synthesis": a7_data.get("synthesis", {}),
        "confidence_gate": a7_data.get("confidence_gate", {}),
        "review_level": a7_data.get("review_level", None),
        "verification_results": a7_data.get("verification", []),
        "agent_errors": results_data.get("agent_errors", job_source.get("error", None) if job_source else None),
        "stopped_at": job_source.get("stopped_at") if job_source else None,
        "message": job_source.get("message") if job_source else None
    }


def _dispatch_pipeline_job(
    clean_case_id: str,
    case_id_raw: str,
    x_tenant_id: str,
    current_user: Dict[str, Any],
    is_restart: bool = False
) -> Dict[str, Any]:
    from api.routes.evidence import sanitize_uuid, _resolve_authoritative_artifact_path
    from infrastructure.repository.evidence_store import get_case_session
    from ism.checkpointer import Checkpointer
    from config.settings import settings
    import psycopg2
    from pathlib import Path
    from datetime import datetime, timezone

    # 1. Enforce Case Existence for this Tenant
    evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=clean_case_id)
    if not evidence_list and case_id_raw != clean_case_id:
        evidence_list = list_evidence_by_case(tenant_id=x_tenant_id, case_id=case_id_raw)

    findings = _analyst_service.list_findings(case_id=clean_case_id, tenant_id=x_tenant_id)
    if not findings and case_id_raw != clean_case_id:
        findings = _analyst_service.list_findings(case_id=case_id_raw, tenant_id=x_tenant_id)

    case_exists = bool(evidence_list or findings)
    if not case_exists:
        try:
            session = get_case_session(tenant_id=x_tenant_id, case_id=clean_case_id) or get_case_session(tenant_id=x_tenant_id, case_id=case_id_raw)
            if session:
                case_exists = True
        except Exception:
            pass

    if not case_exists:
        try:
            from databases.postgres_pool import PostgresConnectionPool
            with PostgresConnectionPool.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT case_id FROM cases WHERE (case_id = %s OR case_id = %s) AND tenant_id = %s;",
                    (clean_case_id, case_id_raw, x_tenant_id)
                )
                if cur.fetchone():
                    case_exists = True
        except Exception as ce:
            logger.debug(f"Cases table query note: {ce}")

    if not case_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Case '{case_id_raw}' not found for tenant '{x_tenant_id}'."
        )

    # 2. Check for evidence/findings requirement
    if not findings and not evidence_list:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot run agents: Case '{case_id_raw}' has no ingested evidence or findings."
        )

    # 3. Collect ALL evidence candidate paths and ids so no evidence is missed
    evidence_paths = []
    evidence_ids = []
    for ev in (evidence_list or []):
        p = _resolve_authoritative_artifact_path(ev)
        if p and p.exists():
            evidence_paths.append(str(p))
            evidence_ids.append(ev.evidence_id)
        elif ev.file_path and Path(ev.file_path).exists():
            evidence_paths.append(str(Path(ev.file_path)))
            evidence_ids.append(ev.evidence_id)
        elif ev.raw_file_path and Path(ev.raw_file_path).exists():
            evidence_paths.append(str(Path(ev.raw_file_path)))
            evidence_ids.append(ev.evidence_id)

    # 4. Setup cancellation token
    cancel_evt = threading.Event()
    with _agent_jobs_lock:
        prev_cancel = _agent_cancellations.get(clean_case_id)
        if prev_cancel:
            prev_cancel.set()
        _agent_cancellations[clean_case_id] = cancel_evt

    initial_stage_statuses = {
        "agent1": "RUNNING", "agent2": "PENDING", "agent3": "PENDING",
        "agent4": "PENDING", "agent5a": "PENDING", "agent5b": "PENDING",
        "agent6": "PENDING", "agent7": "PENDING"
    }

    # 5. Initialize job in memory and durable ISM checkpoint
    with _agent_jobs_lock:
        _agent_jobs[clean_case_id] = {
            "status": "RUNNING",
            "case_id": clean_case_id,
            "tenant_id": x_tenant_id,
            "stage_statuses": initial_stage_statuses,
            "evidence_count": len(evidence_list or []),
            "findings_count": len(findings or []),
            "is_restart": is_restart,
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    checkpointer = Checkpointer()
    try:
        checkpointer.save_stage_checkpoint(
            case_id=clean_case_id,
            stage="pipeline_job",
            state=_agent_jobs[clean_case_id],
            status="RUNNING",
            tenant_id=x_tenant_id
        )
    except Exception as cp_err:
        logger.warning(f"Could not write initial pipeline_job checkpoint: {cp_err}")

    # 6. Log to audit log
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO audit_log (tenant_id, case_id, event, actor, detail, timestamp)
                VALUES (%s, %s, %s, %s, %s, NOW())
                """,
                (
                    x_tenant_id, clean_case_id,
                    "Restarted Multi-Agent Analysis" if is_restart else "Triggered Multi-Agent Analysis",
                    current_user.get("name") or "analyst",
                    json.dumps({
                        "user_id": current_user.get("id") or current_user.get("user_id", "analyst"),
                        "description": f"Multi-agent reasoning swarm {'restarted' if is_restart else 'launched'} capturing {len(evidence_list or [])} evidence files and {len(findings or [])} findings.",
                        "evidence_count": len(evidence_list or []),
                        "evidence_paths": evidence_paths
                    })
                )
            )
            conn.commit()
    except Exception as al_e:
        logger.warning(f"Could not write audit log for agent execution: {al_e}")

    def _execute_agent_pipeline():
        try:
            from argus_pipeline import run_pipeline

            results = run_pipeline(
                evidence_paths=evidence_paths if evidence_paths else None,
                evidence_ids=evidence_ids if evidence_ids else None,
                evidence_path=evidence_paths[0] if evidence_paths else None,
                case_id=clean_case_id,
                tenant_id=x_tenant_id,
                fir_findings=findings,
                stop_on_error=False,
                resume=(not is_restart),
                cancel_event=cancel_evt
            )

            final_status = results.get("execution_status", "COMPLETED")
            if cancel_evt.is_set():
                final_status = "STOPPED"
                results["execution_status"] = "STOPPED"

            with _agent_jobs_lock:
                _agent_jobs[clean_case_id] = {
                    "status": final_status,
                    "case_id": clean_case_id,
                    "tenant_id": x_tenant_id,
                    "results": results,
                    "stage_statuses": results.get("stage_statuses", {}),
                    "evidence_count": len(evidence_list or []),
                    "findings_count": len(findings or []),
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }

            # Save durable final checkpoint to ISM
            try:
                checkpointer.save_stage_checkpoint(
                    case_id=clean_case_id,
                    stage="pipeline_job",
                    state=_agent_jobs[clean_case_id],
                    status=final_status,
                    tenant_id=x_tenant_id
                )
            except Exception as cp_err:
                logger.warning(f"Could not persist final pipeline_job checkpoint: {cp_err}")

            # Update evidence metadata for ALL evidence items in this case to ensure full retention
            if evidence_list:
                try:
                    from databases.postgres_pool import PostgresConnectionPool
                    with PostgresConnectionPool.get_connection() as conn:
                        cur = conn.cursor()
                        for ev_item in evidence_list:
                            ev_item.metadata = ev_item.metadata or {}
                            ev_item.metadata["agent_results"] = results
                            ev_item.metadata["workload_status"] = final_status
                            cur.execute(
                                "UPDATE evidence SET metadata = %s WHERE evidence_id = %s AND case_id = %s;",
                                (json.dumps(ev_item.metadata, default=str), ev_item.evidence_id, clean_case_id)
                            )
                        conn.commit()
                except Exception as meta_e:
                    logger.warning(f"Could not persist agent_results to evidence table: {meta_e}")

            logger.info(f"[+] Multi-agent analysis finished ({final_status}) for Case {clean_case_id}")
        except Exception as exc:
            logger.error(f"[-] Multi-agent execution error for Case {clean_case_id}: {exc}", exc_info=True)
            with _agent_jobs_lock:
                _agent_jobs[clean_case_id] = {
                    "status": "FAILED",
                    "case_id": clean_case_id,
                    "tenant_id": x_tenant_id,
                    "error": str(exc),
                    "stage_statuses": {}
                }
            try:
                checkpointer.save_stage_checkpoint(
                    case_id=clean_case_id,
                    stage="pipeline_job",
                    state={
                        "status": "FAILED",
                        "case_id": clean_case_id,
                        "tenant_id": x_tenant_id,
                        "error": str(exc)
                    },
                    status="FAILED",
                    tenant_id=x_tenant_id
                )
            except Exception as cp_err:
                logger.warning(f"Could not persist failed pipeline_job checkpoint: {cp_err}")

    _agent_executor.submit(_execute_agent_pipeline)

    action_word = "restarted" if is_restart else "initiated"
    return {
        "status": "RUNNING" if is_restart else "STARTED",
        "case_id": clean_case_id,
        "evidence_count": len(evidence_list or []),
        "message": f"Multi-agent forensic workload (Agents 1-7) successfully {action_word} for Case '{clean_case_id}' across {len(evidence_list or [])} evidence files."
    }


@router.post("/{case_id}/run-agents")
async def run_case_agents(
    case_id: str,
    restart: bool = Query(False, description="Whether to restart the workload from scratch with all evidence"),
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Launch asynchronous multi-agent reasoning execution (Agents 1-7)
    for an existing case and its ingested evidence/findings.
    Enforces case authorization, tenant isolation, and durable state tracking.
    """
    from api.routes.evidence import sanitize_uuid

    clean_case_id = sanitize_uuid(case_id)
    verify_case_access(clean_case_id, current_user, x_tenant_id)

    # Enforce case lock: another analyst cannot run agents if case is locked by someone else
    user_id = str(current_user.get("id", ""))
    is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
        case_id=clean_case_id,
        user_id=user_id,
        is_admin=current_user.get("role") == "admin"
    )
    if not is_allowed and lock:
        raise HTTPException(
            status_code=423,
            detail=f"Cannot run multi-agent analysis: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
        )

    if restart:
        return _dispatch_pipeline_job(
            clean_case_id=clean_case_id,
            case_id_raw=case_id,
            x_tenant_id=x_tenant_id,
            current_user=current_user,
            is_restart=True
        )

    # Check for actively running job
    with _agent_jobs_lock:
        current_job = _agent_jobs.get(clean_case_id)
        if current_job and current_job.get("status") == "RUNNING" and current_job.get("tenant_id") == x_tenant_id:
            return {
                "status": "RUNNING",
                "case_id": clean_case_id,
                "message": "Multi-agent analysis is already running for this case."
            }

    return _dispatch_pipeline_job(
        clean_case_id=clean_case_id,
        case_id_raw=case_id,
        x_tenant_id=x_tenant_id,
        current_user=current_user,
        is_restart=False
    )


@router.post("/{case_id}/stop-workload")
@router.post("/{case_id}/stop-agents")
async def stop_case_workload(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Stops/aborts the active multi-agent reasoning workload for the case.
    Ensures all captured evidence and findings are safely retained in repository.
    Allows analysts to upload missing evidence and resume or restart cleanly.
    """
    from api.routes.evidence import sanitize_uuid
    from ism.checkpointer import Checkpointer
    from config.settings import settings
    import psycopg2
    from datetime import datetime, timezone

    clean_case_id = sanitize_uuid(case_id)
    verify_case_access(clean_case_id, current_user, x_tenant_id)

    user_id = str(current_user.get("id", ""))
    is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
        case_id=clean_case_id,
        user_id=user_id,
        is_admin=current_user.get("role") == "admin"
    )
    if not is_allowed and lock:
        raise HTTPException(
            status_code=423,
            detail=f"Cannot stop workload: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
        )

    with _agent_jobs_lock:
        cancel_evt = _agent_cancellations.get(clean_case_id)
        if cancel_evt:
            cancel_evt.set()

        current_job = _agent_jobs.get(clean_case_id)
        stage_statuses = dict(current_job.get("stage_statuses", {})) if current_job else {}
        for k, v in stage_statuses.items():
            if v == "RUNNING":
                stage_statuses[k] = "STOPPED"

        stopped_payload = {
            "status": "STOPPED",
            "case_id": clean_case_id,
            "tenant_id": x_tenant_id,
            "message": "Workload stopped by analyst. All captured evidence is safely retained.",
            "stage_statuses": stage_statuses,
            "results": current_job.get("results") if current_job else None,
            "stopped_at": datetime.now(timezone.utc).isoformat()
        }
        _agent_jobs[clean_case_id] = stopped_payload

    # Persist durable STOPPED checkpoint in ISM
    checkpointer = Checkpointer()
    try:
        checkpointer.save_stage_checkpoint(
            case_id=clean_case_id,
            stage="pipeline_job",
            state=stopped_payload,
            status="STOPPED",
            tenant_id=x_tenant_id
        )
    except Exception as cp_err:
        logger.warning(f"Could not persist STOPPED checkpoint: {cp_err}")

    # Write audit log
    try:
        from databases.postgres_pool import PostgresConnectionPool
        with PostgresConnectionPool.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO audit_log (tenant_id, case_id, event, actor, detail, timestamp)
                VALUES (%s, %s, %s, %s, %s, NOW())
                """,
                (
                    x_tenant_id, clean_case_id,
                    "Stopped Multi-Agent Analysis",
                    current_user.get("name") or "analyst",
                    json.dumps({
                        "user_id": current_user.get("id") or current_user.get("user_id", "analyst"),
                        "description": "Workload stopped by analyst to review or capture additional evidence."
                    })
                )
            )
            conn.commit()
    except Exception as al_e:
        logger.warning(f"Could not write audit log for stop workload: {al_e}")

    return {
        "status": "STOPPED",
        "case_id": clean_case_id,
        "message": f"Workload for Case '{clean_case_id}' successfully stopped. All evidence has been retained properly.",
        "tenant_id": x_tenant_id
    }


@router.post("/{case_id}/restart-workload")
@router.post("/{case_id}/restart-agents")
async def restart_case_workload(
    case_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Restarts the multi-agent workload from scratch for this case.
    Re-aggregates all uploaded evidence files and findings, clearing stale stage checkpoints
    so that no newly uploaded or previously missed evidence is omitted.
    """
    from api.routes.evidence import sanitize_uuid

    clean_case_id = sanitize_uuid(case_id)
    verify_case_access(clean_case_id, current_user, x_tenant_id)

    user_id = str(current_user.get("id", ""))
    is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
        case_id=clean_case_id,
        user_id=user_id,
        is_admin=current_user.get("role") == "admin"
    )
    if not is_allowed and lock:
        raise HTTPException(
            status_code=423,
            detail=f"Cannot restart workload: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
        )

    return _dispatch_pipeline_job(
        clean_case_id=clean_case_id,
        case_id_raw=case_id,
        x_tenant_id=x_tenant_id,
        current_user=current_user,
        is_restart=True
    )


# ── TASK A: Analyst Finding Review Endpoint ──────────────────────────────────
REVIEW_AUTHORIZED_ROLES = {"senior_analyst", "admin", "supervisor"}
OVERRIDE_AUTHORIZED_ROLES = {"senior_analyst", "admin", "supervisor"}

class ReviewFindingRequest(BaseModel):
    status: ReviewStatus
    notes: Optional[str] = None
    force: bool = False

class ReviewFindingResponse(BaseModel):
    status: str = "SUCCESS"
    finding_id: str
    case_id: str
    tenant_id: str
    review_status: ReviewStatus
    reviewed_by: str
    reviewed_at: str
    finding: Dict[str, Any]
    notes: Optional[str] = None

@router.put("/{case_id}/findings/{finding_id}/review", response_model=ReviewFindingResponse)
@router.post("/{case_id}/findings/{finding_id}/review", response_model=ReviewFindingResponse)
async def review_finding_endpoint(
    case_id: str,
    finding_id: str,
    req: ReviewFindingRequest,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    PUT /cases/{case_id}/findings/{finding_id}/review

    Enforces:
    1. Authenticated JWT caller via get_current_user.
    2. Role authorization: restricted to senior_analyst, admin, and supervisor roles.
    3. Strict tenant isolation: tenant derived from user claims / validated X-Tenant-ID header.
    4. Reviewer identity derived from trusted authentication context (never client-supplied).
    5. Case-finding consistency: finding must belong to both the target case and tenant.
    6. Double-review prevention: cannot overwrite without force=True.
    7. Override safety: force=True requires authorized override role and non-empty justification notes.
       Hierarchical protection: senior_analyst cannot override decisions made by admin or supervisor.
    8. Status validation: pending_review cannot be used as a review decision.
    9. Durable audit persistence: rollback on audit write failure (never claim review without audit record).
    """
    # 1. Server-side role authorization check
    user_role = current_user.get("role", "")
    if user_role not in REVIEW_AUTHORIZED_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{user_role}' is not authorized to review findings. Only senior_analyst and admin roles are permitted."
        )

    # 2. Derive trusted tenant context
    from api.routes.evidence import authorize_tenant_access, sanitize_uuid
    clean_tenant = authorize_tenant_access(current_user, x_tenant_id)
    clean_case_id = sanitize_uuid(case_id)

    # 3. Derive reviewer identity from trusted context
    reviewer_id = current_user.get("id") or current_user.get("email") or current_user.get("username")
    if not reviewer_id or not str(reviewer_id).strip():
        raise HTTPException(status_code=401, detail="Authenticated context lacks a valid reviewer identity.")

    # 4. Enforce valid review status transition
    if req.status == ReviewStatus.PENDING_REVIEW:
        raise HTTPException(
            status_code=400,
            detail="Cannot set review_status to 'pending_review'. Valid decisions are 'analyst_confirmed' or 'analyst_rejected'."
        )

    # 5. Resolve finding with strict case and tenant boundary
    finding = _analyst_service.get_finding(finding_id, case_id=clean_case_id, tenant_id=clean_tenant)
    target_case_id = clean_case_id
    if not finding and case_id != clean_case_id:
        finding = _analyst_service.get_finding(finding_id, case_id=case_id, tenant_id=clean_tenant)
        if finding:
            target_case_id = case_id

    if not finding:
        # Cross-case / cross-tenant / non-existent defense:
        raw_finding = _fir_repo.findings.get(finding_id)
        if raw_finding and raw_finding.case_id != target_case_id and (raw_finding.tenant_id == clean_tenant or (not raw_finding.tenant_id and clean_tenant == "default")):
            raise HTTPException(
                status_code=404,
                detail=f"Finding '{finding_id}' does not belong to case '{case_id}'."
            )
        # For non-existent or other-tenant findings, fail closed with standard 404
        raise HTTPException(
            status_code=404,
            detail=f"Finding '{finding_id}' not found for case '{case_id}' and tenant '{clean_tenant}'."
        )

    # 6. Override authorization and policy checks
    if req.force:
        if user_role not in OVERRIDE_AUTHORIZED_ROLES:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user_role}' is not authorized to override existing review decisions."
            )
        if not req.notes or not str(req.notes).strip():
            raise HTTPException(
                status_code=400,
                detail="Review override (force=true) requires an explicit non-empty justification in notes."
            )
        if not finding.is_unreviewed and finding.reviewed_by in ("admin", "admin_root", "supervisor") and user_role == "senior_analyst":
            raise HTTPException(
                status_code=403,
                detail="A senior analyst cannot override a review decision established by an administrator or supervisor."
            )

    # 7. Check double-review conflict without force
    if not finding.is_unreviewed and not req.force:
        raise HTTPException(
            status_code=409,
            detail=f"Finding '{finding_id}' has already been reviewed ({finding.review_status.value} by {finding.reviewed_by}). Pass force=true to overwrite."
        )

    # Capture previous state before applying update for audit and rollback
    prev_status = finding.review_status
    prev_reviewer = finding.reviewed_by
    prev_reviewed_at = finding.reviewed_at

    # 8. Apply review via AnalystFindingService
    try:
        updated_finding = _analyst_service.mark_review(
            finding_id=finding_id,
            case_id=target_case_id,
            status=req.status,
            reviewed_by=str(reviewer_id),
            tenant_id=clean_tenant,
            force=req.force
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in mark_review for {finding_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during finding review.")

    # 9. Record append-only audit event (Mandatory Security Rule: Roll back if audit persistence fails)
    from datetime import datetime, timezone
    reviewed_at_iso = updated_finding.reviewed_at.isoformat() if updated_finding.reviewed_at else datetime.now(timezone.utc).isoformat()
    try:
        from infrastructure.audit_logger import get_audit_logger
        audit_logger = get_audit_logger(clean_tenant)
        outbox_id = getattr(updated_finding, "outbox_event_id", None)
        audit_entry = {
            "event": "finding_review_overridden" if req.force else "finding_reviewed",
            "finding_id": finding_id,
            "case_id": target_case_id,
            "tenant_id": clean_tenant,
            "actor": str(reviewer_id),
            "actor_role": user_role,
            "previous_status": prev_status.value if hasattr(prev_status, "value") else str(prev_status),
            "previous_reviewer": prev_reviewer,
            "previous_reviewed_at": prev_reviewed_at.isoformat() if prev_reviewed_at else None,
            "new_status": req.status.value,
            "decision": req.status.value,
            "is_override": req.force,
            "override_reason": req.notes if req.force else None,
            "notes": req.notes,
            "timestamp": reviewed_at_iso,
            "outbox_event_id": outbox_id
        }
        audit_logger.info(audit_entry)

        # Mark outbox record delivered in PostgreSQL
        if outbox_id:
            try:
                from databases.postgres_pool import PostgresConnectionPool
                with PostgresConnectionPool.get_connection() as conn_ob:
                    cur_ob = conn_ob.cursor()
                    cur_ob.execute(
                        "UPDATE audit_log SET detail = detail || '{\"outbox_status\": \"delivered\"}'::jsonb WHERE detail->>'outbox_event_id' = %s;",
                        (outbox_id,)
                    )
                    conn_ob.commit()
            except Exception as e_ob:
                logger.debug("Failed marking outbox delivered in DB: %s", e_ob)
    except Exception as audit_err:
        logger.critical(f"Audit log write failed for finding {finding_id}: {audit_err}. Rolling back review.", exc_info=True)
        rollback_ok = _fir_repo.rollback_review(
            tenant_id=clean_tenant,
            finding_id=finding_id,
            prev_status=prev_status,
            prev_reviewer=prev_reviewer,
            prev_reviewed_at=prev_reviewed_at,
            case_id=target_case_id,
            reason=f"audit_write_failed: {audit_err}"
        )
        if not rollback_ok:
            logger.critical(
                "UNRECONCILED_AUDIT_INCONSISTENCY: Finding %s in case %s (tenant %s) was committed to DB "
                "but audit log write failed (%s) AND database rollback failed. State is inconsistent.",
                finding_id, target_case_id, clean_tenant, audit_err
            )
            raise HTTPException(
                status_code=500,
                detail=f"CRITICAL: Durable audit persistence failed ({audit_err}) and automated rollback failed. Inconsistent state flagged for administrative reconciliation."
            )
        raise HTTPException(
            status_code=500,
            detail=f"Durable audit persistence failure: review decision rolled back because audit record could not be written ({audit_err})."
        )

    invalidate_findings_cache(clean_tenant, target_case_id, finding_id)

    return ReviewFindingResponse(
        status="SUCCESS",
        finding_id=updated_finding.finding_id,
        case_id=updated_finding.case_id,
        tenant_id=updated_finding.tenant_id,
        review_status=updated_finding.review_status,
        reviewed_by=updated_finding.reviewed_by or str(reviewer_id),
        reviewed_at=reviewed_at_iso,
        finding=updated_finding.model_dump(mode="json"),
        notes=req.notes
    )

