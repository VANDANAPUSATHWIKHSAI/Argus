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

from fastapi import APIRouter, File, UploadFile, Form, Header, HTTPException
from pydantic import BaseModel, Field

from infrastructure.schemas import Evidence, CaseSession
from infrastructure.repository.evidence_store import create_case_session, store_evidence
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


@router.post("/upload", response_model=EvidenceUploadResponse)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    uploaded_by: str = Form("analyst_api"),
    host_id: str = Form("NTFS1-HOST"),
):
    """
    Ingest a raw evidence file, execute the Stage 1-4 pipeline, and store findings.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided in evidence upload request.")

    target_case_id = case_id or f"CASE-{hashlib.sha256(file.filename.encode()).hexdigest()[:8]}"
    
    # Create or fetch case session
    try:
        session = create_case_session(case_id=target_case_id, tenant_id=tenant_id, created_by=uploaded_by)
    except Exception as e:
        logger.warning(f"Case session setup warning: {e}")
        session = CaseSession(case_id=target_case_id, tenant_id=tenant_id, created_by=uploaded_by)

    # Save temp upload file
    temp_dir = Path(tempfile.gettempdir()) / "argus_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)
    file_path = temp_dir / file.filename

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")

    with open(file_path, "wb") as fh:
        fh.write(file_bytes)

    sha256_digest = hashlib.sha256(file_bytes).hexdigest()

    # Create evidence object
    evidence = Evidence(
        case_id=target_case_id,
        filename=file.filename,
        file_path=str(file_path),
        raw_file_path=str(file_path),
        uploaded_by=uploaded_by,
        sha256_hash=sha256_digest,
        metadata={"size_bytes": len(file_bytes)}
    )

    try:
        store_evidence(evidence, session)
    except Exception as e:
        logger.warning(f"Store evidence warning: {e}")

    # Stage 1 / 2 Parsing
    routing_res = _parser_router.determine_routing(evidence)
    parsed_artifacts = []
    errors = []

    if routing_res.status == "ROUTED" and routing_res.parser_instance:
        try:
            arts = routing_res.parser_instance.parse(str(file_path), evidence.evidence_id)
            if arts:
                for art in arts:
                    art.case_id = target_case_id
                    art.host_id = host_id
                    if art.normalized_fields:
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

    # Stage 2.5 Extractor
    derived_observables = []
    if parsed_artifacts:
        try:
            derived_observables = _extractor.extract(parsed_artifacts, evidence_id=evidence.evidence_id)
        except Exception as ext_e:
            logger.error(f"Extractor execution failed: {ext_e}")

    all_artifacts = parsed_artifacts + list(derived_observables)
    artifacts_map = {art.artifact_id: art for art in all_artifacts}

    # Stage 3 FCR Correlation
    fcr_records = []
    if all_artifacts:
        try:
            fcr_records = _fcr_engine.correlate(all_artifacts)
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
                fir_repo=_fir_repo
            )
        except Exception as batch_e:
            logger.error(f"Stage 4 analysis batch execution failed: {batch_e}")

    # Timeline calculation
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
