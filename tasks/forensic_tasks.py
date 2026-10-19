"""
ARGUS Celery Forensic Pipeline Task
==================================
Runs background evidence parsing, observable extraction, FCR correlation,
and FIR findings generation as an asynchronous Celery task.
"""

import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

from tasks.celery_app import celery_app
from infrastructure.schemas import Evidence, CaseSession
from infrastructure.repository.evidence_store import store_evidence
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from fir.service import AnalystFindingService

logger = logging.getLogger(__name__)

# Shared engine instances
_fir_repo = FIRRepository()
_analyst_service = AnalystFindingService(fir_repo=_fir_repo)
_parser_router = ParserRouter()
_extractor = ArtifactExtractor()
_fcr_engine = FCREngine()


def run_pipeline_core(
    evidence_dict: Dict[str, Any],
    session_dict: Dict[str, Any],
    file_path_str: str,
    target_case_id: str,
    tenant_id: str,
    host_id: str,
    uploaded_by: str,
    filename_original: str,
    task_instance=None,
) -> Dict[str, Any]:
    """
    Core forensic execution logic executed either by Celery worker or thread pool.
    """
    evidence = Evidence.model_validate(evidence_dict)
    session = CaseSession.model_validate(session_dict)
    file_path = Path(file_path_str)

    parsed_artifacts = []
    derived_observables = []
    fcr_records = []
    findings = []
    errors = []

    try:
        temp_dir = file_path.parent

        # ── Stage 1: Parsing ───────────────────────────────────────
        if task_instance:
            task_instance.update_state(state="PROGRESS", meta={"stage": "parsing", "progress": 20})

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
                            if getattr(art, "normalized_fields", None):
                                art.normalized_fields.host = host_id
                        parsed_artifacts.extend(arts)
                except Exception as parse_e:
                    err_msg = f"Parser execution failed: {parse_e}"
                    logger.error(err_msg)
                    errors.append(err_msg)
            else:
                err_msg = f"Parser routing: no parser matched for '{filename_original}' (status: {routing_res.status})."
                logger.warning(err_msg)
                errors.append(err_msg)

        # ── Stage 2: Store evidence into durable storage (MinIO/local) ──
        try:
            store_evidence(evidence, session)
        except Exception as se:
            logger.warning(f"Store evidence warning: {se}")

        # ── Stage 2.5: Observable Extraction ───────────────────────
        if task_instance:
            task_instance.update_state(state="PROGRESS", meta={"stage": "extracting", "progress": 45})

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
                logger.error(f"Extractor failed: {ext_e}")

        all_artifacts = parsed_artifacts + list(derived_observables)
        artifacts_map = {art.artifact_id: art for art in parsed_artifacts}

        # ── Stage 3: FCR Correlation ───────────────────────────────
        if task_instance:
            task_instance.update_state(state="PROGRESS", meta={"stage": "correlating", "progress": 65})

        if all_artifacts:
            try:
                fcr_records = _fcr_engine.correlate(
                    artifacts=parsed_artifacts,
                    extracted_entities=derived_observables,
                    allow_single_artifact=True
                )
            except Exception as fcr_e:
                logger.error(f"FCR Engine failed: {fcr_e}")

        # ── Stage 4: Analysis & FIR Storage ────────────────────────
        if task_instance:
            task_instance.update_state(state="PROGRESS", meta={"stage": "findings_generation", "progress": 80})

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

        # ── Timeline Generation ────────────────────────────────────
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

        # ── Persist metadata counts to PostgreSQL ───────────────────
        try:
            evidence.metadata.update({
                "parsed_artifact_count": len(parsed_artifacts),
                "derived_observable_count": len(derived_observables),
                "fcr_count": len(fcr_records),
                "finding_count": len(findings),
                "timeline_event_count": len(timeline)
            })
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
                (json.dumps(evidence.metadata), evidence.evidence_id)
            )
            conn.commit()
            conn.close()
        except Exception as db_meta_e:
            logger.warning(f"Failed to update evidence metadata: {db_meta_e}")

        result_summary = {
            "status": "COMPLETED",
            "evidence_id": evidence.evidence_id,
            "case_id": target_case_id,
            "parsed_artifact_count": len(parsed_artifacts),
            "derived_observable_count": len(derived_observables),
            "fcr_count": len(fcr_records),
            "finding_count": len(findings),
            "timeline_event_count": len(timeline),
            "errors": errors,
        }

        if task_instance:
            task_instance.update_state(state="SUCCESS", meta=result_summary)

        return result_summary

    except Exception as e:
        logger.error(f"Forensic pipeline unhandled error: {e}")
        err_res = {
            "status": "FAILED",
            "evidence_id": evidence.evidence_id,
            "case_id": target_case_id,
            "parsed_artifact_count": 0,
            "derived_observable_count": 0,
            "fcr_count": 0,
            "finding_count": 0,
            "timeline_event_count": 0,
            "errors": [str(e)],
        }
        if task_instance:
            task_instance.update_state(state="FAILURE", meta=err_res)
        return err_res


@celery_app.task(bind=True, name="process_forensic_pipeline")
def process_forensic_pipeline_task(
    self,
    evidence_dict: Dict[str, Any],
    session_dict: Dict[str, Any],
    file_path_str: str,
    target_case_id: str,
    tenant_id: str,
    host_id: str,
    uploaded_by: str,
    filename_original: str,
):
    """
    Celery task wrapper for processing the forensic pipeline.
    """
    logger.info(f"Celery task started: parsing evidence {evidence_dict.get('evidence_id')}")
    return run_pipeline_core(
        evidence_dict=evidence_dict,
        session_dict=session_dict,
        file_path_str=file_path_str,
        target_case_id=target_case_id,
        tenant_id=tenant_id,
        host_id=host_id,
        uploaded_by=uploaded_by,
        filename_original=filename_original,
        task_instance=self,
    )
