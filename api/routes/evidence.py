"""
API Route — Evidence Ingestion Endpoint
========================================
POST /evidence/upload

In-depth REST API endpoint for uploading raw digital evidence, running cryptographic hash verification,
executing the 4-stage ARGUS forensic pipeline, persisting findings to FIR, and returning full status telemetry.

NOTE: Heavy pipeline stages (FCR, Stage-4 analysis) are run in a background thread pool so the
event loop is never blocked, keeping login / all other endpoints responsive.
"""

from __future__ import annotations

import os
import hashlib
import tempfile
import logging
import asyncio
import threading
import concurrent.futures
import hmac
from enum import Enum
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import APIRouter, File, UploadFile, Form, Header, HTTPException, Query, Depends, BackgroundTasks
from api.routes.auth import get_current_user
from pydantic import BaseModel, Field

from infrastructure.schemas import Evidence, CaseSession, CustodyLogEntry
from infrastructure.repository.evidence_store import create_case_session, store_evidence, list_evidence_by_case, get_evidence, delete_evidence, REPOSITORY_DIR
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from fir.service import AnalystFindingService

logger = logging.getLogger(__name__)

router = APIRouter()

# Shared repository and service instances
_fir_repo = FIRRepository()
_analyst_service = AnalystFindingService(fir_repo=_fir_repo)
_parser_router = ParserRouter()
_extractor = ArtifactExtractor()
_fcr_engine = FCREngine()

# Thread pool for CPU-bound forensic pipeline work
_pipeline_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="argus_pipeline")

# In-memory registry for evidence job status tracking
_evidence_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


class EvidenceUploadResponse(BaseModel):
    status: str = "PROCESSING"
    case_id: str
    tenant_id: str
    evidence_id: str
    filename: str
    sha256_hash: str
    parsed_artifact_count: int
    derived_observable_count: int
    fcr_count: int
    finding_count: int
    timeline_event_count: int
    stage_statuses: Dict[str, str] = Field(default_factory=dict)
    agent_results: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)
    task_id: Optional[str] = None
    engine: str = "thread_pool"


import urllib.parse
import uuid

def sanitize_uuid(val: Optional[str]) -> str:
    """Ensure case_id is present and clean of URL encoding or surrounding quotes."""
    if not val:
        return str(uuid.uuid4())
    cleaned = str(val).strip()
    # Decode URL-encoded quotes or parameters (e.g. %22CASE-02%22 -> "CASE-02")
    if "%" in cleaned:
        try:
            cleaned = urllib.parse.unquote(cleaned).strip()
        except Exception:
            pass
    # Strip literal %22 prefixes/suffixes if unquote didn't catch them
    while cleaned.startswith("%22"):
        cleaned = cleaned[3:].strip()
    while cleaned.endswith("%22"):
        cleaned = cleaned[:-3].strip()
    # Strip surrounding quotes
    while (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        if len(cleaned) < 2:
            break
        cleaned = cleaned[1:-1].strip()
    if cleaned.lower() in ("", "string", "none", "null"):
        return str(uuid.uuid4())
    return cleaned


def authorize_tenant_access(current_user: dict, requested_tenant: Optional[str]) -> str:
    """
    Validates tenant access against the authenticated user context.
    - Prohibits empty string or wildcard '*' tenant values in ordinary application paths.
    - Verifies user membership if user has explicit tenant restrictions.
    - Privileged cross-tenant access requires explicit admin role.
    """
    clean_tenant = (requested_tenant or "").strip()
    if clean_tenant in ("*", ""):
        raise HTTPException(status_code=400, detail="Invalid tenant identifier. Wildcards and empty tenants are prohibited.")

    user_role = current_user.get("role", "")
    user_tenant = current_user.get("tenant_id")
    user_tenants = current_user.get("tenants")

    if user_role == "admin":
        return clean_tenant or "default"

    if user_tenants and isinstance(user_tenants, list):
        if clean_tenant not in user_tenants:
            raise HTTPException(status_code=403, detail="Tenant access denied: user not authorized for requested tenant.")
        return clean_tenant

    if user_tenant:
        if clean_tenant != user_tenant:
            raise HTTPException(status_code=403, detail="Tenant access denied: user not authorized for requested tenant.")
        return user_tenant

    return clean_tenant or "default"


def _run_forensic_pipeline(
    evidence: Evidence,
    session: CaseSession,
    file_path: Path,
    file_bytes: bytes,
    target_case_id: str,
    tenant_id: str,
    host_id: str,
    uploaded_by: str,
    filename_original: str,
):
    """
    Run the full 4-stage forensic pipeline synchronously (called in a thread pool).
    Parse happens BEFORE store_evidence so the temp file is still present.
    store_evidence is called after parsing to move file to MinIO.
    Returns a dict with counts and errors.
    """
    parsed_artifacts = []
    derived_observables = []
    fcr_records = []
    findings = []
    errors = []

    try:
        import urllib.parse
        temp_dir = file_path.parent

        # Stage 1/2 — Parsing
        if filename_original.lower().endswith(".zip"):
            import zipfile
            extract_dir = temp_dir / f"extracted_{hashlib.sha256(filename_original.encode()).hexdigest()[:8]}"
            extract_dir.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(str(file_path), 'r') as zf:
                    resolved_extract_dir = extract_dir.resolve()
                    for member in zf.infolist():
                        member_target = (extract_dir / member.filename).resolve()
                        try:
                            member_target.relative_to(resolved_extract_dir)
                        except ValueError:
                            logger.warning(f"Skipping unsafe zip entry: {member.filename}")
                            continue
                        zf.extract(member, extract_dir)

                extracted_files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.name.startswith(".") and not p.name.startswith("__MACOSX")]
                logger.info(f"Extracted {len(extracted_files)} files from '{filename_original}'")

                for ext_file in extracted_files:
                    sub_bytes = ext_file.read_bytes()
                    sub_ev = Evidence(
                        case_id=target_case_id,
                        filename=ext_file.name,
                        file_path=str(ext_file),
                        raw_file_path=str(ext_file),
                        uploaded_by=uploaded_by,
                        sha256_hash=hashlib.sha256(sub_bytes).hexdigest(),
                        metadata={"size_bytes": len(sub_bytes), "tenant_id": tenant_id}
                    )
                    r_res = _parser_router.determine_routing(sub_ev)
                    if r_res.status == "ROUTED" and r_res.parser_instance:
                        try:
                            sub_arts = r_res.parser_instance.parse(str(ext_file), sub_ev.evidence_id) or []
                            for art in sub_arts:
                                art.case_id = target_case_id
                                art.host_id = host_id
                                art.tenant_id = tenant_id
                                if getattr(art, "normalized_fields", None):
                                    art.normalized_fields.host = host_id
                            parsed_artifacts.extend(sub_arts)
                        except Exception as pe:
                            logger.error(f"Failed parsing '{ext_file.name}': {pe}")
            except Exception as zip_e:
                err_msg = f"Zip extraction error: {zip_e}"
                logger.error(err_msg)
                errors.append(err_msg)
        else:
            routing_res = _parser_router.determine_routing(evidence)
            if routing_res.status == "ROUTED" and routing_res.parser_instance:
                try:
                    arts = routing_res.parser_instance.parse(str(file_path), evidence.evidence_id)
                    if arts:
                        for art in arts:
                            art.case_id = target_case_id
                            art.host_id = host_id
                            art.tenant_id = tenant_id
                            if getattr(art, "normalized_fields", None):
                                art.normalized_fields.host = host_id
                        parsed_artifacts.extend(arts)
                except Exception as parse_e:
                    err_msg = f"Parser execution failed: {parse_e}"
                    logger.error(err_msg)
                    errors.append(err_msg)
            else:
                logger.info(f"Parser routing: raw file intake stored without specialized parser for '{filename_original}' (status: {routing_res.status}).")

        # Store evidence into durable storage (MinIO/local) AFTER parsing
        # so the temp file is still available during parse.
        # store_evidence deletes the temp file after upload, which is correct.
        try:
            store_evidence(evidence, session)
        except Exception as se:
            logger.warning(f"Store evidence warning: {se}")

        # Stage 2.5 — Extractor
        if parsed_artifacts:
            try:
                obs_list = _extractor.extract(parsed_artifacts, evidence_id=evidence.evidence_id)
                for obs in (obs_list or []):
                    obs.case_id = target_case_id
                    obs.host_id = host_id
                    obs.tenant_id = tenant_id
                    if obs.normalized_fields:
                        obs.normalized_fields.host = host_id
                    derived_observables.append(obs)
            except Exception as ext_e:
                logger.error(f"Extractor failed: {ext_e}")

        all_artifacts = parsed_artifacts + list(derived_observables)
        artifacts_map = {art.artifact_id: art for art in parsed_artifacts}

        # Stage 3 — FCR Correlation
        if all_artifacts:
            try:
                fcr_records = _fcr_engine.correlate(
                    artifacts=parsed_artifacts,
                    extracted_entities=derived_observables,
                    allow_single_artifact=True
                )
            except Exception as fcr_e:
                logger.error(f"FCR Engine failed: {fcr_e}")

        # Stage 4 — Analysis & FIR Storage
        if fcr_records:
            try:
                findings = process_fcr_batch(
                    case_id=target_case_id,
                    fcr_objects=fcr_records,
                    artifacts_by_id=artifacts_map,
                    fir_repo=_fir_repo,
                    tenant_id=tenant_id
                )
            except Exception as batch_e:
                logger.error(f"Stage 4 analysis failed: {batch_e}")

        # Timeline
        all_artifacts = parsed_artifacts + list(derived_observables)
        timeline = []
        try:
            timeline = _analyst_service.build_case_timeline(
                case_id=target_case_id,
                artifacts=all_artifacts,
                correlation_records=fcr_records,
                tenant_id=tenant_id
            )
        except Exception as tl_e:
            logger.error(f"Timeline building failed: {tl_e}")

        # Stage 5+ — Multi-Agent Ingestion & Reasoning (Agents 1-7 via unified orchestrator)
        stage_statuses = {
            "intake": "COMPLETED",
            "preprocessing": "COMPLETED" if parsed_artifacts else ("FAILED" if errors else "SKIPPED"),
            "extractor": "COMPLETED" if derived_observables else "SKIPPED",
            "fcr_engine": "COMPLETED" if fcr_records else "SKIPPED",
            "analysis_fir": "COMPLETED" if findings else "SKIPPED",
            "timeline": "COMPLETED" if timeline else "SKIPPED",
            "agent_reasoning": "PENDING",
            "agent7_supervisor": "PENDING",
        }
        agent_pipeline_results = None
        current_case_findings = findings or _fir_repo.get_by_case(tenant_id, target_case_id)
        if current_case_findings:
            try:
                from argus_pipeline import run_pipeline
                agent_pipeline_results = run_pipeline(
                    case_id=target_case_id,
                    tenant_id=tenant_id,
                    fir_findings=current_case_findings,
                    stop_on_error=False
                )
                if agent_pipeline_results:
                    if "stage_statuses" in agent_pipeline_results:
                        stage_statuses.update(agent_pipeline_results["stage_statuses"])
                    agent_status = agent_pipeline_results.get("execution_status", "COMPLETED")
                    stage_statuses["agent_reasoning"] = agent_status
                    ag7_out = agent_pipeline_results.get("agent7", {})
                    stage_statuses["agent7_supervisor"] = ag7_out.get("status") or ag7_out.get("execution_status", "COMPLETED")
            except Exception as agent_e:
                err_text = f"Agent pipeline execution error: {agent_e}"
                logger.error(err_text)
                errors.append(err_text)
                stage_statuses["agent_reasoning"] = "FAILED"
                stage_statuses["agent7_supervisor"] = "FAILED"
        else:
            stage_statuses["agent_reasoning"] = "SKIPPED"
            stage_statuses["agent7_supervisor"] = "SKIPPED"

        # The upload path must not report full investigation success when only preprocessing completed.
        # It must accurately reflect downstream agent completion.
        if errors:
            pipeline_status = "PARTIAL_SUCCESS"
        elif not current_case_findings:
            pipeline_status = "PARTIAL_SUCCESS"
        elif agent_pipeline_results and agent_pipeline_results.get("execution_status") == "SUCCESS":
            ag7_status = (agent_pipeline_results.get("agent7") or {}).get("status")
            if ag7_status == "COMPLETED":
                pipeline_status = "SUCCESS"
            elif ag7_status == "NEEDS_REVIEW":
                pipeline_status = "NEEDS_REVIEW"
            else:
                pipeline_status = "PARTIAL_SUCCESS"
        else:
            pipeline_status = "PARTIAL_SUCCESS"

        try:
            evidence.metadata.update({
                "parsed_artifact_count": len(parsed_artifacts),
                "derived_observable_count": len(derived_observables),
                "fcr_count": len(fcr_records),
                "finding_count": len(findings),
                "timeline_event_count": len(timeline),
                "stage_statuses": stage_statuses,
                "agent_results": agent_pipeline_results,
                "status": pipeline_status,
                "errors": errors
            })
            from infrastructure.repository.evidence_store import _should_attempt_postgres, REPOSITORY_DIR
            if _should_attempt_postgres():
                import json
                import psycopg2
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
                    "UPDATE evidence SET metadata = %s WHERE evidence_id = %s;",
                    (json.dumps(evidence.metadata, default=str), evidence.evidence_id)
                )
                conn.commit()
                conn.close()
            else:
                repo_base = Path(REPOSITORY_DIR) / target_case_id / evidence.evidence_id
                if repo_base.exists():
                    meta_file = repo_base / "metadata.json"
                    meta_data = {}
                    if meta_file.exists():
                        try:
                            import json
                            with open(meta_file, "r", encoding="utf-8") as mf:
                                meta_data = json.load(mf)
                        except Exception:
                            pass
                    meta_data.update(evidence.metadata)
                    meta_data["tenant_id"] = tenant_id
                    meta_data["case_id"] = target_case_id
                    import json
                    with open(meta_file, "w", encoding="utf-8") as mf:
                        json.dump(meta_data, mf, indent=2, default=str)
        except Exception as db_meta_e:
            logger.warning(f"Failed to update evidence metadata: {db_meta_e}")

        result_payload = {
            "status": pipeline_status,
            "case_id": target_case_id,
            "tenant_id": tenant_id,
            "evidence_id": evidence.evidence_id,
            "filename": filename_original,
            "sha256_hash": evidence.sha256_hash,
            "parsed_artifact_count": len(parsed_artifacts),
            "derived_observable_count": len(derived_observables),
            "fcr_count": len(fcr_records),
            "finding_count": len(findings),
            "timeline_event_count": len(timeline),
            "stage_statuses": stage_statuses,
            "agent_results": agent_pipeline_results,
            "errors": errors,
        }
        with _jobs_lock:
            if evidence.evidence_id in _evidence_jobs:
                _evidence_jobs[evidence.evidence_id].update(result_payload)
        return result_payload
    except Exception as e:
        logger.error(f"Forensic pipeline unhandled error: {e}")
        err_payload = {
            "status": "FAILED",
            "parsed_artifact_count": 0,
            "derived_observable_count": 0,
            "fcr_count": 0,
            "finding_count": 0,
            "timeline_event_count": 0,
            "errors": [str(e)],
        }
        with _jobs_lock:
            if evidence.evidence_id in _evidence_jobs:
                _evidence_jobs[evidence.evidence_id].update(err_payload)
        return err_payload


@router.post("/upload", response_model=EvidenceUploadResponse)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: Optional[str] = Query(None),
    form_case_id: Optional[str] = Form(None, alias="case_id"),
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    uploaded_by: str = Form("analyst_api"),
    host_id: str = Form("NTFS1-HOST"),
    relative_path: Optional[str] = Form(None),
    async_mode: bool = Query(False, description="Whether to run ingestion asynchronously in the background"),
    form_async_mode: Optional[bool] = Form(None, alias="async_mode"),
    current_user: dict = Depends(get_current_user)
):
    """
    Ingest a raw evidence file. By default, executes the pipeline in a background
    thread pool while yielding the asyncio event loop, returning the completed status.
    If async_mode=True, returns PROCESSING immediately and allows polling via GET /evidence/status/{evidence_id}.
    """
    raw_case_id = case_id or form_case_id
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided in evidence upload request.")

    target_case_id = sanitize_uuid(raw_case_id)
    tenant_id = authorize_tenant_access(current_user, tenant_id)
    if target_case_id:
        from api.routes.cases import verify_case_access
        verify_case_access(target_case_id, current_user, tenant_id)

    # Check if case exists to resolve actual tenant
    try:
        from infrastructure.repository.evidence_store import get_case_session
        existing_session = get_case_session(tenant_id, target_case_id)
        if not existing_session:
            existing_session = get_case_session("default", target_case_id)
        if existing_session and existing_session.tenant_id:
            tenant_id = existing_session.tenant_id
    except Exception:
        pass

    # Enforce case lock
    if target_case_id:
        from api.case_lock import case_lock_manager
        from api.routes.cases import is_user_authorized_for_case_modification
        user_id = str(current_user.get("id", ""))
        is_assigned = is_user_authorized_for_case_modification(
            case_id=target_case_id,
            current_user=current_user,
            x_tenant_id=tenant_id
        )
        is_allowed, lock, _msg = case_lock_manager.check_modification_allowed(
            case_id=target_case_id,
            user_id=user_id,
            is_admin=current_user.get("role") == "admin",
            is_assigned=is_assigned
        )
        if not is_allowed and lock:
            raise HTTPException(
                status_code=423,
                detail=f"Cannot upload evidence: Case is currently locked by analyst '{lock.locked_by_user_name}'. You have Read-Only access."
            )

    # Create or fetch case session
    uploader_name = current_user.get("name", uploaded_by)
    if existing_session:
        session = existing_session
    else:
        try:
            session = create_case_session(
                tenant_id=tenant_id,
                created_by=uploader_name,
                case_id=target_case_id,
                analyst_id=str(current_user.get("id")) if current_user.get("id") else None
            )
        except Exception as e:
            logger.warning(f"Case session setup warning: {e}")
            session = CaseSession(
                case_id=target_case_id,
                tenant_id=tenant_id,
                created_by=uploader_name,
                analyst_id=str(current_user.get("id")) if current_user.get("id") else None
            )

    # Save temp upload file
    temp_dir = Path(tempfile.gettempdir()) / "argus_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)

    import urllib.parse
    raw_name = relative_path if relative_path else file.filename
    unquoted = urllib.parse.unquote(raw_name)
    safe_name = os.path.basename(unquoted.replace("\\", "/"))
    if not safe_name or safe_name in (".", ".."):
        safe_name = "evidence_upload.bin"

    resolved_temp_dir = temp_dir.resolve()
    file_path = (temp_dir / safe_name).resolve()
    try:
        file_path.relative_to(resolved_temp_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal attempt detected.")
    file_path.parent.mkdir(parents=True, exist_ok=True)

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")

    with open(file_path, "wb") as fh:
        fh.write(file_bytes)

    sha256_digest = hashlib.sha256(file_bytes).hexdigest()

    # Idempotency / duplicate-work prevention: if identical file is already processing or completed for this tenant & case, return existing job
    with _jobs_lock:
        for j_id, j_rec in _evidence_jobs.items():
            if (j_rec.get("tenant_id") == tenant_id and
                j_rec.get("case_id") == target_case_id and
                j_rec.get("sha256_hash") == sha256_digest and
                j_rec.get("status") in ("PROCESSING", "SUCCESS", "COMPLETED_PREPROCESSING_ONLY", "NEEDS_REVIEW", "PARTIAL_SUCCESS")):
                logger.info(f"Duplicate upload detected: evidence '{j_id}' with hash '{sha256_digest}' already exists in registry.")
                return EvidenceUploadResponse(**j_rec)

    # Create evidence object
    evidence = Evidence(
        case_id=target_case_id,
        filename=safe_name,
        file_path=str(file_path),
        raw_file_path=str(file_path),
        uploaded_by=uploader_name,
        sha256_hash=sha256_digest,
        metadata={"size_bytes": len(file_bytes)}
    )

    # Register initial job status
    task_id = None
    engine_used = "thread_pool"

    job_record = {
        "status": "PROCESSING",
        "case_id": target_case_id,
        "tenant_id": tenant_id,
        "evidence_id": evidence.evidence_id,
        "filename": file.filename,
        "sha256_hash": sha256_digest,
        "parsed_artifact_count": 0,
        "derived_observable_count": 0,
        "fcr_count": 0,
        "finding_count": 0,
        "timeline_event_count": 0,
        "stage_statuses": {
            "intake": "COMPLETED",
            "preprocessing": "PROCESSING",
            "fcr_engine": "PENDING",
            "analysis_fir": "PENDING",
            "timeline": "PENDING",
            "agent_reasoning": "PENDING",
            "agent7_supervisor": "PENDING",
        },
        "agent_results": None,
        "errors": [],
        "task_id": None,
        "engine": "thread_pool"
    }

    # Background forensic pipeline execution:
    # 1. Prefer Celery distributed task queue if Redis broker is available.
    # 2. Fall back to local ThreadPoolExecutor if Redis/Celery is offline.
    try:
        from tasks.celery_app import is_celery_broker_available
        from tasks.forensic_tasks import process_forensic_pipeline_task

        if is_celery_broker_available():
            celery_task = process_forensic_pipeline_task.delay(
                evidence_dict=evidence.model_dump(mode="json"),
                session_dict=session.model_dump(mode="json"),
                file_path_str=str(file_path),
                target_case_id=target_case_id,
                tenant_id=tenant_id,
                host_id=host_id,
                uploaded_by=uploader_name,
                filename_original=file.filename,
            )
            task_id = celery_task.id
            engine_used = "celery"
            job_record["task_id"] = task_id
            job_record["engine"] = engine_used
            logger.info(f"Dispatched Celery task {task_id} for evidence {evidence.evidence_id}")
    except Exception as cel_e:
        logger.warning(f"Celery dispatch check failed ({cel_e}), falling back to thread pool.")
        task_id = None

    with _jobs_lock:
        _evidence_jobs[evidence.evidence_id] = job_record

    if task_id:
        return EvidenceUploadResponse(**job_record)

    loop = asyncio.get_running_loop()
    should_run_async = async_mode or bool(form_async_mode)

    if should_run_async:
        # Asynchronous contract: dispatch pipeline to background thread pool and return PROCESSING immediately
        def _bg_worker():
            res = _run_forensic_pipeline(
                evidence,
                session,
                file_path,
                file_bytes,
                target_case_id,
                tenant_id,
                host_id,
                uploader_name,
                file.filename,
            )
            job_record.update(res)

        loop.run_in_executor(_pipeline_executor, _bg_worker)
        return EvidenceUploadResponse(**job_record)
    else:
        # Synchronous contract (default): await pipeline completion without blocking the event loop
        pipeline_res = await loop.run_in_executor(
            _pipeline_executor,
            _run_forensic_pipeline,
            evidence,
            session,
            file_path,
            file_bytes,
            target_case_id,
            tenant_id,
            host_id,
            uploader_name,
            file.filename,
        )
        job_record.update(pipeline_res)
        return EvidenceUploadResponse(**job_record)


@router.get("/status/{evidence_id}", response_model=EvidenceUploadResponse)
@router.get("/{evidence_id}/status", response_model=EvidenceUploadResponse)
async def get_evidence_status(
    evidence_id: str,
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieve the current ingestion status and telemetry for an uploaded evidence job.
    Enforces tenant isolation.
    """
    from infrastructure.repository.evidence_store import get_evidence
    from infrastructure.schemas import EvidenceStatus

    tenant_id = authorize_tenant_access(current_user, tenant_id)

    # Check in-memory job registry first
    with _jobs_lock:
        job = dict(_evidence_jobs[evidence_id]) if evidence_id in _evidence_jobs else None
    if job:
        if job["tenant_id"] != tenant_id:
            raise HTTPException(status_code=403, detail="Tenant access denied.")
        return EvidenceUploadResponse(**job)

    # Check persistent repository
    ev = get_evidence(tenant_id=tenant_id, evidence_id=evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence '{evidence_id}' not found.")

    meta = ev.metadata or {}
    raw_st = meta.get("status") or (ev.status.value if hasattr(ev.status, "value") else str(ev.status).lower())
    if raw_st in ("stored", "completed"):
        status_val = "SUCCESS"
    elif raw_st in ("failed", "validation_failed"):
        status_val = "FAILED"
    else:
        status_val = raw_st.upper()

    return EvidenceUploadResponse(
        status=status_val,
        case_id=ev.case_id,
        tenant_id=tenant_id,
        evidence_id=ev.evidence_id,
        filename=ev.filename,
        sha256_hash=ev.sha256_hash or "",
        parsed_artifact_count=meta.get("parsed_artifact_count", 0),
        derived_observable_count=meta.get("derived_observable_count", 0),
        fcr_count=meta.get("fcr_count", 0),
        finding_count=meta.get("finding_count", 0),
        timeline_event_count=meta.get("timeline_event_count", 0),
        stage_statuses=meta.get("stage_statuses", {}),
        agent_results=meta.get("agent_results"),
        errors=meta.get("errors", []),
        task_id=meta.get("task_id"),
        engine=meta.get("engine", "thread_pool")
    )


@router.get("/task/{task_id}")
async def get_task_status(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Check real-time status of a background Celery forensic pipeline task.
    Returns: PENDING | STARTED | PROGRESS | SUCCESS | FAILURE along with progress metadata.
    """
    try:
        from tasks.celery_app import celery_app
        from celery.result import AsyncResult

        res = AsyncResult(task_id, app=celery_app)
        task_info = {
            "task_id": task_id,
            "status": res.status,
            "ready": res.ready(),
            "successful": res.successful() if res.ready() else False,
        }

        if res.info and isinstance(res.info, dict):
            task_info["metadata"] = res.info
        elif res.failed():
            task_info["error"] = str(res.result)

        return task_info
    except Exception as e:
        logger.error(f"Error querying task {task_id}: {e}")
        return {"task_id": task_id, "status": "UNKNOWN", "error": str(e)}

@router.get("/case/{case_id}")
async def get_evidence_by_case(
    case_id: str,
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieve all evidence records for a given case ID.
    """
    try:
        tenant_id = authorize_tenant_access(current_user, tenant_id)
        from api.routes.cases import verify_case_access
        verify_case_access(case_id, current_user, tenant_id)
        evidence_list = list_evidence_by_case(tenant_id=tenant_id, case_id=case_id)
        return {"status": "SUCCESS", "data": [e.model_dump(mode='json') for e in evidence_list]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching evidence for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{evidence_id}")
async def remove_evidence(
    evidence_id: str,
    case_id: Optional[str] = Query(None),
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    Remove an evidence artifact from a case and storage repository.
    Enforces tenant boundaries and cleans up associated custody logs and findings.
    """
    try:
        tenant_id = authorize_tenant_access(current_user, tenant_id)
        uploader_name = current_user.get("name") or current_user.get("email") or "analyst"

        with _jobs_lock:
            _evidence_jobs.pop(evidence_id, None)

        success = delete_evidence(
            tenant_id=tenant_id,
            evidence_id=evidence_id,
            case_id=case_id,
            actor=uploader_name
        )

        if not success:
            raise HTTPException(status_code=404, detail=f"Evidence artifact '{evidence_id}' not found or could not be removed.")

        return {
            "status": "SUCCESS",
            "message": f"Evidence artifact '{evidence_id}' removed successfully.",
            "evidence_id": evidence_id,
            "case_id": case_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing evidence {evidence_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove evidence: {str(e)}")


# ── TASK B: Server-side SHA-256 Evidence Integrity Verification ─────────────

_verification_lock = threading.Lock()

class EvidenceVerificationStatus(str, Enum):
    """
    Defensible, explicit verification states:
    VERIFIED: The stored artifact bytes match the authoritative recorded SHA-256 acquisition digest.
    CORRUPTED: The artifact bytes were successfully read, but the computed SHA-256 digest differs from the recorded seal.
    UNVERIFIABLE: Verification could not establish a cryptographic verdict (e.g. missing metadata, missing file, inaccessible storage).
    ERROR: Verification could not complete due to an operational or system failure during execution.
    """
    VERIFIED     = "VERIFIED"
    CORRUPTED    = "CORRUPTED"
    UNVERIFIABLE = "UNVERIFIABLE"
    ERROR        = "ERROR"


class EvidenceVerificationResponse(BaseModel):
    evidence_id: str
    case_id: str
    tenant_id: str
    status: EvidenceVerificationStatus
    digest_match: bool
    expected_sha256: Optional[str] = None
    calculated_sha256: Optional[str] = None
    timestamp_status: Optional[str] = None
    timestamp_details: Optional[Dict[str, Any]] = None
    audit_chain_status: Optional[str] = "NOT_CHECKED"
    verified_at: str
    verified_by: str
    failure_reason: Optional[str] = None


EVIDENCE_VERIFY_ROLES = {"senior_analyst", "admin", "auditor", "analyst"}


def _resolve_authoritative_artifact_path(ev: Evidence) -> Optional[Path]:
    """
    Locates the authoritative stored immutable evidence artifact on storage.
    Preserves read-only evidence semantics. Never returns temporary intake or encrypted files.
    """
    candidates: List[Path] = []
    if ev.original_repository_path:
        candidates.append(Path(ev.original_repository_path))
    if ev.original_file_path:
        candidates.append(Path(ev.original_file_path))
    if ev.repository_path and not ev.repository_path.endswith(".enc"):
        candidates.append(Path(ev.repository_path))

    # Standard repository layout: data/repository/{case_id}/{evidence_id}/original/{filename}
    repo_base = Path(REPOSITORY_DIR) / ev.case_id / ev.evidence_id
    orig_dir = repo_base / "original"
    if ev.filename:
        candidates.append(orig_dir / ev.filename)
    if orig_dir.exists() and orig_dir.is_dir():
        for f in orig_dir.iterdir():
            if f.is_file() and not f.name.endswith(".enc"):
                candidates.append(f)

    if ev.file_path and not ev.file_path.endswith(".enc"):
        candidates.append(Path(ev.file_path))

    for path in candidates:
        if path.exists() and path.is_file():
            return path
    return None


@router.post("/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
@router.post("/status/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
async def verify_evidence_endpoint(
    evidence_id: str,
    x_tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    POST /evidence/{evidence_id}/verify

    Server-side cryptographic evidence re-verification workflow:
    1. Authenticate caller and enforce appropriate verification permissions.
    2. Resolve evidence record using evidence_id and authenticated tenant context.
    3. Determine authoritative storage backend (Production MinIO/S3 vs Local Repository).
    4. Stream artifact through SHA-256 computation in 64KB chunks (never load entire file to memory).
    5. Compare calculated digest against recorded digest using constant-time comparison (hmac.compare_digest).
    6. Validate associated RFC 3161 timestamp token if available (kept distinct from byte integrity).
    7. Record an append-only hash-chained audit event via get_audit_logger().
    8. Persist verification result and custody log with atomic concurrency protection.
    9. Prevent cross-tenant access and never expose physical paths or secrets.
    """
    # 1. Role verification
    user_role = current_user.get("role", "")
    if user_role not in EVIDENCE_VERIFY_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{user_role}' is not authorized to verify evidence integrity."
        )

    # 2. Derive trusted tenant context
    clean_tenant = authorize_tenant_access(current_user, x_tenant_id)

    # 3. Derive verifier identity
    verifier_id = current_user.get("id") or current_user.get("email") or current_user.get("username")
    if not verifier_id or not str(verifier_id).strip():
        raise HTTPException(status_code=401, detail="Authenticated context lacks a valid verifier identity.")

    # 4. Resolve evidence record strictly within tenant context
    ev = get_evidence(tenant_id=clean_tenant, evidence_id=evidence_id)
    if not ev:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence '{evidence_id}' not found for tenant '{clean_tenant}'."
        )

    from datetime import datetime, timezone
    verified_at = datetime.now(timezone.utc).isoformat()

    expected_sha256 = (
        ev.sha256_hash or 
        (ev.metadata.get("sha256") if ev.metadata else None) or
        (ev.metadata.get("sha256_hash") if ev.metadata else None)
    )
    if expected_sha256:
        expected_sha256 = str(expected_sha256).strip().lower()

    # Validate recorded expected digest
    calculated_sha256: Optional[str] = None
    digest_match: bool = False
    status: EvidenceVerificationStatus
    failure_reason: Optional[str] = None

    if not expected_sha256 or len(expected_sha256) != 64:
        status = EvidenceVerificationStatus.UNVERIFIABLE
        failure_reason = "Authoritative acquisition metadata lacks a valid 64-character SHA-256 digest."
    else:
        # 5. Authoritative Storage Selection & Streaming SHA-256 Computation
        from infrastructure.repository.evidence_store import _should_attempt_minio
        from databases.minio_client import minio_store, S3Error
        from config.settings import settings

        local_path = _resolve_authoritative_artifact_path(ev)
        
        is_minio = False
        if ev.original_repository_path and not os.path.isabs(ev.original_repository_path) and not Path(ev.original_repository_path).is_file():
            is_minio = True
        elif ev.repository_path and not os.path.isabs(ev.repository_path) and not Path(ev.repository_path).is_file():
            is_minio = True
        elif local_path is None and _should_attempt_minio():
            is_minio = True
        elif getattr(settings, "storage_backend", "").lower() == "minio":
            is_minio = True

        if is_minio:
            # MinIO Storage Verification Branch
            if not _should_attempt_minio():
                # If MinIO is configured but unavailable, return explicit operational failure
                # Never silently fall back to an alternate local artifact!
                status = EvidenceVerificationStatus.ERROR
                failure_reason = "Operational failure: configured production MinIO object storage is offline or unavailable."
            else:
                obj_key = ev.original_repository_path or ev.repository_path or f"{clean_tenant}/{ev.case_id}/{ev.evidence_id}/original/{ev.filename}"
                obj_key = str(obj_key).replace("\\", "/")

                # Enforce tenant, case, and evidence ID boundary on object key
                key_parts = obj_key.split("/")
                if not obj_key.startswith(f"{clean_tenant}/") or ev.case_id not in key_parts or ev.evidence_id not in key_parts:
                    status = EvidenceVerificationStatus.UNVERIFIABLE
                    failure_reason = (
                        f"Security boundary or metadata mismatch: MinIO object key '{obj_key}' "
                        f"does not match authenticated tenant '{clean_tenant}', case '{ev.case_id}', "
                        f"and evidence ID '{ev.evidence_id}'."
                    )
                else:
                    try:
                        raw_bucket = getattr(settings, "minio_bucket_raw_evidence", minio_store.RAW_BUCKET)
                        stat = minio_store.client.stat_object(raw_bucket, obj_key)

                        # Independent object metadata consistency checks
                        # Metadata disagreement is surfaced explicitly and cannot be silently resolved by trusting one source
                        meta_conflict = False
                        if hasattr(stat, "metadata") and stat.metadata:
                            meta_sha = stat.metadata.get("x-amz-meta-sha256") or stat.metadata.get("sha256")
                            if meta_sha and meta_sha.strip().lower() != expected_sha256.strip().lower():
                                meta_conflict = True
                                status = EvidenceVerificationStatus.CORRUPTED
                                failure_reason = (
                                    f"Metadata integrity conflict: MinIO object metadata sha256 ('{meta_sha.strip().lower()}') "
                                    f"conflicts with authoritative recorded acquisition digest ('{expected_sha256.strip().lower()}')."
                                )

                        ev_size = getattr(ev, "file_size", getattr(ev, "size_bytes", None))
                        if not meta_conflict and ev_size is not None and ev_size > 0 and stat.size != ev_size:
                            meta_conflict = True
                            status = EvidenceVerificationStatus.CORRUPTED
                            failure_reason = (
                                f"Storage size mismatch: MinIO object size ({stat.size} bytes) "
                                f"does not match authoritative acquisition size ({ev_size} bytes)."
                            )

                        if not meta_conflict:
                            # Stream object bytes in bounded 64KB chunks (never load entire file into RAM)
                            response = None
                            stream_succeeded = False
                            hasher = hashlib.sha256()
                            try:
                                response = minio_store.client.get_object(raw_bucket, obj_key)
                                while True:
                                    chunk = response.read(64 * 1024)
                                    if not chunk:
                                        break
                                    hasher.update(chunk)
                                stream_succeeded = True
                            finally:
                                if response is not None:
                                    try:
                                        response.close()
                                    except Exception as close_err:
                                        logger.warning("Error closing MinIO response stream: %s", close_err)
                                    try:
                                        response.release_conn()
                                    except Exception as release_err:
                                        logger.warning("Error releasing MinIO response connection: %s", release_err)

                            if stream_succeeded:
                                calculated_sha256 = hasher.hexdigest().lower()
                                digest_match = hmac.compare_digest(calculated_sha256, expected_sha256)
                                if digest_match:
                                    status = EvidenceVerificationStatus.VERIFIED
                                else:
                                    status = EvidenceVerificationStatus.CORRUPTED
                                    failure_reason = "Cryptographic integrity failure: computed SHA-256 digest differs from recorded acquisition seal."
                            else:
                                calculated_sha256 = None
                                digest_match = False
                                status = EvidenceVerificationStatus.ERROR
                                failure_reason = "Streaming read was interrupted or incomplete before reaching end of object."

                    except S3Error as s3_err:
                        calculated_sha256 = None
                        digest_match = False
                        if s3_err.code in ("NoSuchKey", "NotFound"):
                            status = EvidenceVerificationStatus.UNVERIFIABLE
                            failure_reason = f"Authoritative evidence object '{obj_key}' not found in MinIO storage."
                        elif s3_err.code in ("AccessDenied", "Forbidden"):
                            status = EvidenceVerificationStatus.ERROR
                            failure_reason = f"MinIO storage access permission denied for object '{obj_key}'."
                        else:
                            status = EvidenceVerificationStatus.ERROR
                            failure_reason = f"MinIO storage S3 error: {s3_err}"
                    except (OSError, IOError) as io_err:
                        calculated_sha256 = None
                        digest_match = False
                        status = EvidenceVerificationStatus.ERROR
                        failure_reason = f"Storage I/O read failure during MinIO streaming: {io_err}"
                    except Exception as exc:
                        calculated_sha256 = None
                        digest_match = False
                        status = EvidenceVerificationStatus.ERROR
                        failure_reason = f"Operational verification failure during MinIO streaming: {exc}"
        else:
            # Local Filesystem Storage Verification Branch
            if not local_path:
                status = EvidenceVerificationStatus.UNVERIFIABLE
                failure_reason = "Authoritative evidence artifact file not found on storage repository."
            else:
                # Stream file through SHA-256 computation in 64KB chunks
                try:
                    hasher = hashlib.sha256()
                    with open(local_path, "rb") as f:
                        while True:
                            chunk = f.read(64 * 1024)
                            if not chunk:
                                break
                            hasher.update(chunk)
                    calculated_sha256 = hasher.hexdigest().lower()

                    # Safe constant-time comparison
                    digest_match = hmac.compare_digest(calculated_sha256, expected_sha256)
                    if digest_match:
                        status = EvidenceVerificationStatus.VERIFIED
                    else:
                        status = EvidenceVerificationStatus.CORRUPTED
                        failure_reason = "Cryptographic integrity failure: computed SHA-256 digest differs from recorded acquisition seal."
                except (OSError, IOError) as io_err:
                    status = EvidenceVerificationStatus.ERROR
                    failure_reason = f"Storage I/O read failure while accessing evidence artifact: {io_err}"
                except Exception as exc:
                    status = EvidenceVerificationStatus.ERROR
                    failure_reason = f"Operational verification failure: {exc}"

    # 7. Independent RFC 3161 Timestamp Verification
    timestamp_status: Optional[str] = None
    ts_details: Optional[Dict[str, Any]] = None
    if not ev.timestamp_record and ev.metadata and isinstance(ev.metadata.get("timestamp_record"), dict):
        try:
            from infrastructure.schemas import TimestampRecord
            ev.timestamp_record = TimestampRecord(**ev.metadata["timestamp_record"])
        except Exception:
            pass

    if ev.timestamp_record or ev.rfc3161_timestamp:
        try:
            from infrastructure.integrity.timestamp_service import verify_rfc3161_timestamp
            is_ts_valid = verify_rfc3161_timestamp(ev, expected_sha256=expected_sha256 or calculated_sha256)
            if is_ts_valid:
                timestamp_status = (
                    ev.timestamp_record.timestamp_verification_status.upper()
                    if ev.timestamp_record and hasattr(ev.timestamp_record, "timestamp_verification_status")
                    else "VERIFIED"
                )
            else:
                timestamp_status = "FAILED"
            if ev.timestamp_record and hasattr(ev.timestamp_record, "verification_details"):
                ts_details = ev.timestamp_record.verification_details
        except Exception as ts_err:
            timestamp_status = "FAILED"
            logger.warning(f"RFC 3161 timestamp verification exception: {ts_err}")
    else:
        timestamp_status = "NOT_PRESENT"

    # 8. Append-only Hash-Chained Audit Record (Mandatory Security Rule)
    from infrastructure.audit_logger import get_audit_logger, verify_chain, AuditChainVerificationError
    try:
        audit_logger = get_audit_logger(clean_tenant)
        audit_entry = {
            "event": "evidence_integrity_verified",
            "evidence_id": evidence_id,
            "case_id": ev.case_id,
            "tenant_id": clean_tenant,
            "verifier": str(verifier_id),
            "verifier_role": user_role,
            "status": status.value,
            "digest_match": digest_match,
            "expected_sha256": expected_sha256,
            "calculated_sha256": calculated_sha256,
            "timestamp_status": timestamp_status,
            "failure_reason": failure_reason,
            "timestamp": verified_at
        }
        audit_logger.info(audit_entry)
    except Exception as audit_err:
        logger.error(f"CRITICAL: Failed to write durable audit log for evidence verification: {audit_err}", exc_info=True)
        # Security Policy: Never claim successful verification if audit persistence fails!
        raise HTTPException(
            status_code=500,
            detail="Critical audit integrity failure: verification audit record could not be written."
        )

    # 9. Cryptographic Audit Chain Verification
    # A successful write/append is NOT verification. We explicitly verify the entire hash chain.
    audit_chain_status = "NOT_CHECKED"
    try:
        chain_res = verify_chain(clean_tenant)
        if chain_res.get("entries_verified", 0) == 0:
            audit_chain_status = "NOT_PRESENT"
        else:
            audit_chain_status = "VERIFIED"
    except AuditChainVerificationError as chain_err:
        logger.error("Cryptographic audit chain verification FAILED for tenant %s: %s", clean_tenant, chain_err)
        audit_chain_status = "FAILED"
    except Exception as chain_exc:
        logger.warning("Audit chain verification encountered operational error for tenant %s: %s", clean_tenant, chain_exc)
        audit_chain_status = "ERROR"

    # 9. Update Custody Log & Metadata with Atomic Concurrency Protection
    with _verification_lock:
        try:
            ev.custody_log.append(CustodyLogEntry(
                actor=str(verifier_id),
                action="integrity_verified",
                notes=f"Evidence verification result: {status.value} (digest_match={digest_match}, timestamp={timestamp_status})"
            ))
            if not ev.metadata:
                ev.metadata = {}
            ev.metadata["last_verification"] = {
                "status": status.value,
                "digest_match": digest_match,
                "expected_sha256": expected_sha256,
                "calculated_sha256": calculated_sha256,
                "timestamp_status": timestamp_status,
                "audit_chain_status": audit_chain_status,
                "verified_by": str(verifier_id),
                "verified_at": verified_at,
                "failure_reason": failure_reason
            }

            # Persist to local metadata.json if directory exists
            repo_base = Path(REPOSITORY_DIR) / ev.case_id / ev.evidence_id
            meta_file = repo_base / "metadata.json"
            if repo_base.exists():
                with open(meta_file, "w", encoding="utf-8") as mf:
                    import json
                    json.dump(ev.model_dump(mode="json"), mf, indent=2)

            # Update Postgres metadata if reachable
            from infrastructure.repository.evidence_store import _should_attempt_postgres
            if _should_attempt_postgres():
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
                    import json
                    cur.execute(
                        "UPDATE evidence SET metadata = %s WHERE evidence_id = %s;",
                        (json.dumps(ev.metadata, default=str), ev.evidence_id)
                    )
                    conn.commit()
                    conn.close()
                except Exception as db_err:
                    logger.debug(f"Postgres verification metadata update skipped: {db_err}")
        except Exception as persist_err:
            logger.warning(f"Failed to persist verification metadata: {persist_err}")

    return EvidenceVerificationResponse(
        evidence_id=evidence_id,
        case_id=ev.case_id,
        tenant_id=clean_tenant,
        status=status,
        digest_match=digest_match,
        expected_sha256=expected_sha256,
        calculated_sha256=calculated_sha256,
        timestamp_status=timestamp_status,
        timestamp_details=ts_details,
        audit_chain_status=audit_chain_status,
        verified_at=verified_at,
        verified_by=str(verifier_id),
        failure_reason=failure_reason
    )

