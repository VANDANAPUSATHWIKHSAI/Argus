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

from fastapi import APIRouter, File, UploadFile, Form, Header, HTTPException, Query, Depends, BackgroundTasks
from api.routes.auth import get_current_user
from pydantic import BaseModel, Field

from infrastructure.schemas import Evidence, CaseSession, EvidenceStatus
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

import re

def sanitize_uuid(uuid_str: str) -> str:
    """Sanitizes a case or evidence ID to prevent directory traversal or injection."""
    if not uuid_str:
        return ""
    return re.sub(r'[^a-zA-Z0-9_\-]', '', str(uuid_str))



def process_evidence_pipeline(evidence, file_path, target_case_id, host_id, tenant_id, uploaded_by, session, file_filename):
    evidence.status = EvidenceStatus.UPLOADED
    # Insert initial state into Postgres so frontend shows it as Processing
    try:
        import psycopg2, json
        from config.settings import settings
        conn = psycopg2.connect(
            host=settings.postgres_host, port=settings.postgres_port,
            database=settings.postgres_db, user=settings.postgres_user,
            password=settings.postgres_password, connect_timeout=2
        )
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO evidence 
              (evidence_id, case_id, filename, uploaded_by, status, sha256_hash, encrypted, metadata, repository_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (evidence_id) DO NOTHING;
            """,
            (evidence.evidence_id, evidence.case_id, evidence.filename, evidence.uploaded_by,
             "uploaded", evidence.sha256_hash, evidence.encrypted, json.dumps(evidence.metadata), "")
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to insert initial evidence record: {e}")

    try:
        from infrastructure.repository.evidence_store import REPOSITORY_DIR
        repo_base = Path(REPOSITORY_DIR) / target_case_id / evidence.evidence_id
        repo_base.mkdir(parents=True, exist_ok=True)
        with open(repo_base / "metadata.json", "w") as f:
            f.write(evidence.model_dump_json())
    except Exception as e:
        logger.warning(f"Failed to write metadata.json: {e}")

    if background_tasks:
        background_tasks.add_task(
            process_evidence_pipeline,
            evidence=evidence,
            file_path=file_path,
            target_case_id=target_case_id,
            host_id=host_id,
            tenant_id=tenant_id,
            uploaded_by=uploader_name,
            session=session,
            file_filename=file.filename
        )
    else:
        process_evidence_pipeline(evidence, file_path, target_case_id, host_id, tenant_id, uploader_name, session, file.filename)

    return EvidenceUploadResponse(
        status="PROCESSING",
        case_id=target_case_id,
        tenant_id=tenant_id,
        evidence_id=evidence.evidence_id,
        filename=file.filename,
        sha256_hash=sha256_digest,
        parsed_artifact_count=0,
        derived_observable_count=0,
        fcr_count=0,
        finding_count=0,
        timeline_event_count=0,
        errors=[]
    )

@router.get("/case/{case_id}")
async def get_evidence_by_case(
    case_id: str,
    tenant_id: str = Header("default", alias="X-Tenant-ID"),
    current_user: dict = Depends(get_current_user),
    background_tasks: BackgroundTasks = None
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
