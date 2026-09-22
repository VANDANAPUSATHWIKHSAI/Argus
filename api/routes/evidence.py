"""
API Route — Evidence Ingestion Endpoint
========================================
POST /evidence/upload

In-depth REST API endpoint for uploading raw digital evidence, running cryptographic hash verification,
executing the 4-stage ARGUS forensic pipeline, persisting findings to FIR, and returning full status telemetry.
"""

from __future__ import annotations

import os
import hashlib
import tempfile
import logging
from typing import Optional, List
from pathlib import Path

from fastapi import APIRouter, File, UploadFile, Form, Header, HTTPException, Query, Depends
from api.routes.auth import get_current_user
from pydantic import BaseModel, Field

from infrastructure.schemas import Evidence, CaseSession
from infrastructure.repository.evidence_store import create_case_session, store_evidence, list_evidence_by_case
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


class EvidenceUploadResponse(BaseModel):
    status: str = "SUCCESS"
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
    errors: List[str] = Field(default_factory=list)


import uuid

def sanitize_uuid(val: Optional[str]) -> str:
    """Ensure case_id is present."""
    if not val:
        return str(uuid.uuid4())
    cleaned = val.strip().strip('"').strip("'").strip("%22").strip()
    if cleaned.lower() in ("", "string", "none", "null"):
        return str(uuid.uuid4())
    return cleaned


@router.post("/upload", response_model=EvidenceUploadResponse)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: Optional[str] = Query(None),
    form_case_id: Optional[str] = Form(None, alias="case_id"),
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    uploaded_by: str = Form("analyst_api"),
    host_id: str = Form("NTFS1-HOST"),
    relative_path: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    """
    Ingest a raw evidence file, execute the Stage 1-4 pipeline, and store findings.
    """
    raw_case_id = case_id or form_case_id
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided in evidence upload request.")

    target_case_id = sanitize_uuid(raw_case_id)

    # Create or fetch case session
    uploader_name = current_user.get("name", uploaded_by)
    try:
        session = create_case_session(tenant_id=tenant_id, created_by=uploader_name, case_id=target_case_id)
    except Exception as e:
        logger.warning(f"Case session setup warning: {e}")
        session = CaseSession(case_id=target_case_id, tenant_id=tenant_id, created_by=uploader_name)

    # Save temp upload file
    temp_dir = Path(tempfile.gettempdir()) / "argus_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    safe_name = file.filename
    if relative_path:
        # avoid path traversal
        safe_name = relative_path.replace("..", "").lstrip("\\/")
        
    file_path = temp_dir / safe_name
    file_path.parent.mkdir(parents=True, exist_ok=True)

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")

    with open(file_path, "wb") as fh:
        fh.write(file_bytes)

    sha256_digest = hashlib.sha256(file_bytes).hexdigest()

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

    # Stage 1 / 2 Parsing (must run BEFORE store_evidence cleans up temp file)
    routing_res = _parser_router.determine_routing(evidence)
    parsed_artifacts = []
    derived_observables = []
    fcr_records = []
    findings = []
    errors = []

    # Automatic Folder Zip Archive Extraction & Recursive File Processing
    if file.filename.lower().endswith(".zip"):
        import zipfile
        extract_dir = temp_dir / f"extracted_{hashlib.sha256(file.filename.encode()).hexdigest()[:8]}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        zip_source_path = str(file_path)
        try:
            with zipfile.ZipFile(zip_source_path, 'r') as zf:
                resolved_extract_dir = extract_dir.resolve()
                for member in zf.infolist():
                    member_target = (extract_dir / member.filename).resolve()
                    try:
                        member_target.relative_to(resolved_extract_dir)
                    except ValueError:
                        logger.warning(f"Skipping unsafe zip entry (Path Traversal / Zip Slip attempt): {member.filename}")
                        continue
                    zf.extract(member, extract_dir)
            
            extracted_files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.name.startswith(".") and not p.name.startswith("__MACOSX")]
            logger.info(f"Extracted {len(extracted_files)} files from folder archive '{file.filename}'")
            
            for ext_file in extracted_files:
                sub_bytes = ext_file.read_bytes()
                sub_ev = Evidence(
                    case_id=target_case_id,
                    filename=ext_file.name,
                    file_path=str(ext_file),
                    raw_file_path=str(ext_file),
                    uploaded_by=uploaded_by,
                    sha256_hash=hashlib.sha256(sub_bytes).hexdigest(),
                    metadata={"size_bytes": len(sub_bytes)}
                )
                r_res = _parser_router.determine_routing(sub_ev)
                if r_res.status == "ROUTED" and r_res.parser_instance:
                    try:
                        sub_arts = r_res.parser_instance.parse(str(ext_file), sub_ev.evidence_id) or []
                        for art in sub_arts:
                            art.case_id = target_case_id
                            art.host_id = host_id
                            if getattr(art, "normalized_fields", None):
                                art.normalized_fields.host = host_id
                        parsed_artifacts.extend(sub_arts)
                    except Exception as pe:
                        logger.error(f"Failed parsing file '{ext_file.name}': {pe}")
        except Exception as zip_e:
            err_msg = f"Zip folder extraction error: {zip_e}"
            logger.error(err_msg)
            errors.append(err_msg)
    else:
        # Single File Processing
        routing_res = _parser_router.determine_routing(evidence)
        if routing_res.status == "ROUTED" and routing_res.parser_instance:
            try:
                target_path = str(file_path)
                arts = routing_res.parser_instance.parse(target_path, evidence.evidence_id)
                if arts:
                    for art in arts:
                        art.case_id = target_case_id
                        art.host_id = host_id
                        if getattr(art, "normalized_fields", None):
                            art.normalized_fields.host = host_id
                    parsed_artifacts.extend(arts)
            except Exception as parse_e:
                err_msg = f"Parser execution failed: {parse_e}"
                logger.error(err_msg)
                errors.append(err_msg)
        else:
            err_msg = f"Parser routing failed or blocked for file '{file.filename}' (status: {routing_res.status})."
            logger.warning(err_msg)
            errors.append(err_msg)

    # Store evidence into durable storage/MinIO (cleans up temp file)
    try:
        store_evidence(evidence, session)
    except Exception as e:
        logger.warning(f"Store evidence warning: {e}")

    # Stage 2.5 Extractor
    derived_observables = []
    if parsed_artifacts:
        try:
            obs_list = _extractor.extract(parsed_artifacts, evidence_id=evidence.evidence_id)
            for obs in (obs_list or []):
                obs.case_id = target_case_id
                obs.host_id = host_id
                if obs.normalized_fields:
                    obs.normalized_fields.host = host_id
                derived_observables.append(obs)
        except Exception as ext_e:
            logger.error(f"Extractor execution failed: {ext_e}")

    all_artifacts = parsed_artifacts + list(derived_observables)
    # Ensure artifacts_map contains the parsed Stage 2 Artifact objects (ExtractedEntity objects share parent artifact_id and must not overwrite parent Artifacts)
    artifacts_map = {art.artifact_id: art for art in parsed_artifacts}

    # Stage 3 FCR Correlation
    fcr_records = []
    if all_artifacts:
        try:
            fcr_records = _fcr_engine.correlate(
                artifacts=parsed_artifacts,
                extracted_entities=derived_observables,
                allow_single_artifact=True
            )
        except Exception as fcr_e:
            logger.error(f"FCR Engine correlation failed: {fcr_e}")

    # Stage 4 Analysis Engines & FIR Storage
    findings = []
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
            logger.error(f"Stage 4 analysis batch execution failed: {batch_e}")

    # Timeline calculation
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

    # Persist updated metadata counts to PostgreSQL evidence table
    try:
        evidence.metadata.update({
            "parsed_artifact_count": len(parsed_artifacts),
            "derived_observable_count": len(derived_observables),
            "fcr_count": len(fcr_records),
            "finding_count": len(findings),
            "timeline_event_count": len(timeline)
        })
        import json, psycopg2
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
            (json.dumps(evidence.metadata), evidence.evidence_id)
        )
        conn.commit()
        conn.close()
    except Exception as db_meta_e:
        logger.warning(f"Failed to update evidence metadata counts in PostgreSQL: {db_meta_e}")

    return EvidenceUploadResponse(
        status="SUCCESS" if not errors else "PARTIAL_SUCCESS",
        case_id=target_case_id,
        tenant_id=tenant_id,
        evidence_id=evidence.evidence_id,
        filename=file.filename,
        sha256_hash=sha256_digest,
        parsed_artifact_count=len(parsed_artifacts),
        derived_observable_count=len(derived_observables),
        fcr_count=len(fcr_records),
        finding_count=len(findings),
        timeline_event_count=len(timeline),
        errors=errors
    )

@router.get("/case/{case_id}")
async def get_evidence_by_case(
    case_id: str,
    tenant_id: str = Header("default", alias="X-Tenant-ID")
):
    """
    Retrieve all evidence records for a given case ID.
    """
    try:
        evidence_list = list_evidence_by_case(tenant_id=tenant_id, case_id=case_id)
        return {"status": "SUCCESS", "data": [e.model_dump(mode='json') for e in evidence_list]}
    except Exception as e:
        logger.error(f"Error fetching evidence for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
