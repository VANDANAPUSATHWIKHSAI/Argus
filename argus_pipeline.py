"""
ARGUS Production Forensic Pipeline CLI
=========================================
Unified single entrypoint for ALL evidence types (.E01 disk images, .eml, .pcap, .evtx, memory dumps).

Pipeline Architecture:
  Evidence Path (.E01 / other) or Raw FIR Findings
          ↓
  Stage 1: Ingestion Router & Forensic Parsers
          ↓
  Stage 2: Artifact & Observable Extraction
          ↓
  Stage 3: Forensic Correlation Record (FCR) Engine
          ↓
  Stage 4: Batch Orchestrator -> Sanitization Gateway -> FIR Repository (PostgreSQL)
          ↓
  Agent 1: Evidence Intelligence Agent (Qwen3-8B Reasoning & Lineage Verification)
          ↓
  Agent 2: Evidence Correlation Agent (Neo4j Graph, GDS WCC & Timeline)
          ↓
  Agent 3: Attack Reconstruction Agent (Infection Path, MITRE Kill-Chain & Neo4j Writer)
          ↓
  Agent 4: Malware Behaviour Agent (Deterministic Indicators, YARA & IOC Aggregator)
          ↓
  Agent 5a: Threat Intelligence Agent (STIX/TAXII, CVE/NVD & MITRE Mapping)
          ↓
  Agent 5b: Campaign Similarity Agent (Qdrant Vector Store RAG & Historical Cases)
          ↓
  Agent 6: Impact Assessment Agent (CVSS v3.1 Math, ISS Severity, Assets & Playbook)
          ↓
  Agent 7: Supervisor Agent (Synthesis Call 1 & Independent Verification Call 2)
          ↓
  PostgreSQL & Structured JSON Persistence

Usage:
  python argus_pipeline.py --evidence "path/to/evidence.E01" [--case-id "CASE-2026-001"] [--tenant-id "default"]
"""

import os
import sys
import argparse
import json
import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext
from models.llm import OllamaWrapper, LLMLoader
from config.settings import settings

# Agents 1-7
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from agents.agent4_malware_behaviour.agent import MalwareBehaviourAgent
from agents.agent5a_threat_intelligence.agent import ThreatIntelligenceAgent
from agents.agent5b_campaign_similarity.agent import CampaignSimilarityAgent
from agents.agent6_impact_assessment.agent import ImpactAssessmentAgent
from agents.agent7_supervisor.call1_synthesis import SupervisorSynthesis
from agents.agent7_supervisor.call2_verification import SupervisorVerification
from agents.agent7_supervisor.agent import SupervisorAgent

# Threat Intel & Vector Store Clients
from threat_intel.stix_taxii import StixTaxiiClient
from threat_intel.cve_nvd import CVEClient
from threat_intel.mitre_attack import MitreAttackClient
from vector_store.qdrant_client import VectorStore
from ism.checkpointer import Checkpointer, build_ism_idempotency_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ArgusPipeline")


def run_pipeline(
    evidence_path: Optional[str] = None,
    case_id: Optional[str] = None,
    tenant_id: str = "default",
    model_name: str = "Qwen3-8B",
    llm: Optional[Any] = None,
    neo4j_client: Optional[Any] = None,
    stix_client: Optional[Any] = None,
    cve_client: Optional[Any] = None,
    mitre_client: Optional[Any] = None,
    vector_store: Optional[Any] = None,
    fir_findings: Optional[List[Any]] = None,
    stop_on_error: bool = False,
    resume: bool = True,
    evidence_id: Optional[str] = None,
    evidence_paths: Optional[List[str]] = None,
    evidence_ids: Optional[List[str]] = None,
    cancel_event: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Executes the integrated ARGUS production pipeline covering Stages 1-4 and Agents 1, 2, 3, 4, 5a, 5b, 6, and 7.
    Supports durable cross-cutting ISM checkpointing, idempotency keys, stage resume, multi-evidence aggregation,
    and responsive workload cancellation/stop requests.
    """
    evidence_paths_list: List[str] = []
    if evidence_paths:
        evidence_paths_list.extend([p for p in evidence_paths if p])
    elif evidence_path:
        evidence_paths_list.append(evidence_path)

    if not evidence_paths_list and fir_findings is None:
        raise ValueError("Either evidence_path, evidence_paths, or fir_findings must be provided to run_pipeline.")

    for p in evidence_paths_list:
        if p and not os.path.exists(p):
            logger.warning(f"Evidence file candidate not found on disk: {p}")

    evidence_ids_list: List[str] = []
    if evidence_ids:
        evidence_ids_list.extend(evidence_ids)
    elif evidence_id:
        evidence_ids_list.append(evidence_id)

    first_path = evidence_paths_list[0] if evidence_paths_list else None
    filename = os.path.basename(first_path) if first_path else "synthetic_case"
    case_id = case_id or f"CASE-{Path(filename).stem.upper()}-{uuid.uuid4().hex[:6]}"
    if not evidence_id and fir_findings:
        first_ref = getattr(fir_findings[0], "evidence_reference", None) or (fir_findings[0].get("evidence_reference") if isinstance(fir_findings[0], dict) else None)
        if first_ref:
            evidence_id = first_ref[0] if isinstance(first_ref, list) and first_ref else str(first_ref)
    evidence_id = evidence_id or f"EVID-{Path(filename).stem.upper()}"
    if not evidence_ids_list:
        evidence_ids_list = [evidence_id]

    logger.info("=" * 80)
    logger.info("  ARGUS UNIFIED PRODUCTION PIPELINE INGESTION & MULTI-AGENT REASONING")
    logger.info("=" * 80)
    logger.info(f"Evidence Sources : {evidence_paths_list or 'Pre-loaded FIR findings'}")
    logger.info(f"Case ID          : {case_id}")
    logger.info(f"Tenant ID        : {tenant_id}")

    fir_repo = FIRRepository()
    gw = SanitizationGateway()
    artifacts: List[Any] = []

    # ── STAGE 1–4: Evidence Intake & Parsing (if evidence file(s) provided) ───
    if evidence_paths_list:
        logger.info(f"\n[STAGE 1] Ingesting & Routing {len(evidence_paths_list)} Evidence File(s)...")
        router = ParserRouter()
        all_parsed_artifacts = []
        for idx, ev_p in enumerate(evidence_paths_list):
            if not os.path.exists(ev_p):
                continue
            cur_eid = evidence_ids_list[idx] if idx < len(evidence_ids_list) else f"EVID-{Path(ev_p).stem.upper()}"
            cur_fname = os.path.basename(ev_p)
            evidence_obj = Evidence(
                evidence_id=cur_eid,
                case_id=case_id,
                tenant_id=tenant_id,
                filename=cur_fname,
                file_path=ev_p,
                raw_file_path=ev_p,
                uploaded_by="argus_cli"
            )
            routing_res = router.determine_routing(evidence_obj)
            if routing_res.status == "ROUTED" and routing_res.parser_instance:
                cur_arts = routing_res.parser_instance.parse(ev_p, cur_eid) or []
                for art in cur_arts:
                    art.case_id = case_id
                all_parsed_artifacts.extend(cur_arts)
        artifacts = all_parsed_artifacts
        logger.info(f"[+] Stage 1 Complete: Extracted {len(artifacts)} raw artifacts across all evidence files.")

        logger.info("\n[STAGE 2 & 3] Derived Observables & FCR Correlation across all evidence...")
        extractor = ArtifactExtractor()
        observables = extractor.extract(artifacts, evidence_id=evidence_ids_list[0] if evidence_ids_list else evidence_id) or []
        for obs in observables:
            obs.case_id = case_id

        fcr_engine = FCREngine()
        fcr_records = fcr_engine.correlate(
            artifacts=artifacts,
            extracted_entities=observables,
            allow_single_artifact=True
        )
        logger.info(f"[+] Stage 3 Complete: Generated {len(fcr_records)} FCR correlation records.")

        logger.info("\n[STAGE 4] Orchestration & PostgreSQL FIR Ingestion...")
        artifacts_by_id = {art.artifact_id: art for art in artifacts}
        process_fcr_batch(
            case_id=case_id,
            fcr_objects=fcr_records,
            artifacts_by_id=artifacts_by_id,
            fir_repo=fir_repo,
            tenant_id=tenant_id
        )

        all_findings = fir_repo.get_by_case(tenant_id=tenant_id, case_id=case_id) or []
        if fir_findings:
            existing_fps = {f.finding_fingerprint for f in all_findings if hasattr(f, 'finding_fingerprint')}
            for pf in fir_findings:
                fp = getattr(pf, 'finding_fingerprint', None) or (pf.get('finding_fingerprint') if isinstance(pf, dict) else None)
                if not fp or fp not in existing_fps:
                    all_findings.append(pf)
        fir_findings = all_findings
        logger.info(f"[+] Stage 4 Complete: Total of {len(fir_findings)} FIR findings retained in repository for Case '{case_id}'.")
    else:
        # Pre-loaded FIR findings: insert into repository for tenant & case isolation
        logger.info(f"\n[STAGE 4] Registering {len(fir_findings)} pre-loaded FIR findings into repository...")
        for f in fir_findings:
            if hasattr(f, "case_id"):
                f.case_id = case_id
            if hasattr(f, "tenant_id"):
                f.tenant_id = tenant_id
            try:
                fir_repo.insert(f)
            except Exception as e:
                logger.debug(f"FIR repository insertion note: {e}")

    # ── Initialize Shared Drivers (Neo4j & LLM) ─────────────────────────────
    neo4j_driver = neo4j_client
    if neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
            neo4j_driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
            neo4j_driver.verify_connectivity()
            logger.info("[+] Neo4j Driver connected successfully at bolt://localhost:7687")
        except Exception as exc:
            neo4j_driver = None
            logger.warning(f"Neo4j offline/unreachable fallback: {exc}")

    if llm is not None:
        active_llm = llm
    else:
        try:
            active_llm = LLMLoader().load_qwen3_8b()
        except Exception as exc:
            logger.warning(f"LLMLoader failed to load Qwen3-8B: {exc}. Falling back to OllamaWrapper.")
            active_llm = OllamaWrapper(model_name, "http://localhost:11434")

    model_metadata = {
        "llm_model": getattr(active_llm, "model_name", model_name),
        "embedding_model": settings.embedding_model,
        "is_mock_llm": (hasattr(active_llm, "allow_mock") and getattr(active_llm, "allow_mock", False)) or "Mock" in type(active_llm).__name__
    }

    stage_statuses = {
        "stage1_intake": "COMPLETED" if evidence_path else "SKIPPED",
        "stage2_extractor": "COMPLETED" if artifacts else ("SKIPPED" if not evidence_path else "NO_DATA"),
        "stage3_fcr": "COMPLETED" if artifacts else ("SKIPPED" if not evidence_path else "NO_DATA"),
        "stage4_fir_ingestion": "COMPLETED" if fir_findings else "FAILED",
        "agent1": "PENDING",
        "agent2": "PENDING",
        "agent3": "PENDING",
        "agent4": "PENDING",
        "agent5a": "PENDING",
        "agent5b": "PENDING",
        "agent6": "PENDING",
        "agent7": "PENDING",
    }

    pipeline_results: Dict[str, Any] = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "evidence_id": evidence_id,
        "fir_findings_count": len(fir_findings),
        "execution_status": "SUCCESS",
        "stage_statuses": stage_statuses,
        "model_metadata": model_metadata,
        "agent_errors": {}
    }

    # Cross-cutting Investigation State Management (ISM)
    checkpointer = Checkpointer()
    pipeline_version = getattr(settings, "pipeline_version", "1.0.0")
    idempotency_key = build_ism_idempotency_key(
        case_id=case_id,
        tenant_id=tenant_id,
        evidence_ids=evidence_ids_list if evidence_ids_list else ([evidence_id] if evidence_id else []),
        pipeline_version=pipeline_version
    )
    pipeline_results["idempotency_key"] = idempotency_key

    def _is_cancelled() -> bool:
        return bool(cancel_event and getattr(cancel_event, "is_set", lambda: False)())

    def _get_resumed_stage(stage_key: str) -> Optional[Any]:
        if not resume:
            return None
        cp = checkpointer.get_stage_checkpoint(
            case_id=case_id,
            stage=stage_key,
            tenant_id=tenant_id,
            expected_idempotency_key=idempotency_key,
            expected_version=pipeline_version
        )
        if cp and cp.get("status") == "COMPLETED" and "checkpoint" in cp:
            return cp["checkpoint"]
        return None

    def _save_stage(stage_key: str, state: Any, status: str = "COMPLETED", retry_count: int = 0):
        checkpointer.save_stage_checkpoint(
            case_id=case_id,
            stage=stage_key,
            state=state,
            status=status,
            retry_count=retry_count,
            tenant_id=tenant_id,
            idempotency_key=idempotency_key,
            pipeline_version=pipeline_version
        )

    # Check for early cancellation
    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 1 for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 1: Evidence Intelligence Agent ─────────────────────────────────
    logger.info("\n[AGENT 1] Evidence Intelligence Agent Execution...")
    resumed_a1 = _get_resumed_stage("agent1")
    if resumed_a1 is not None:
        agent1_output = resumed_a1
        pipeline_results["agent1"] = agent1_output
        stage_statuses["agent1"] = "RESUMED"
        logger.info(f"[+] Agent 1 Resumed from ISM checkpoint: {len(agent1_output.get('claims', []))} claims.")
    else:
        try:
            agent1 = EvidenceIntelligenceAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
            agent1_output = agent1.run(
                case_id=case_id,
                context={
                    "fir_findings": fir_findings,
                    "case_id": case_id,
                    "tenant_id": tenant_id,
                    "evidence_id": evidence_id,
                    "artifacts": [a.model_dump() if hasattr(a, "model_dump") else a for a in artifacts]
                }
            )
            pipeline_results["agent1"] = agent1_output
            stage_statuses["agent1"] = agent1_output.get("execution_status", "COMPLETED") if isinstance(agent1_output, dict) else "COMPLETED"
            _save_stage("agent1", state=agent1_output, status=stage_statuses["agent1"])
            logger.info(f"[+] Agent 1 Complete: {len(agent1_output.get('claims', []))} claims generated.")
        except Exception as exc:
            logger.error(f"[-] Agent 1 Execution failed: {exc}", exc_info=True)
            pipeline_results["agent1"] = {"execution_status": "FAILED", "error": str(exc), "claims": []}
            pipeline_results["agent_errors"]["agent1"] = str(exc)
            stage_statuses["agent1"] = "FAILED"
            _save_stage("agent1", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 2 for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 2: Evidence Correlation Agent ──────────────────────────────────
    logger.info("\n[AGENT 2] Evidence Correlation & Graph Engine Execution...")
    resumed_a2 = _get_resumed_stage("agent2")
    if resumed_a2 is not None:
        agent2_output = resumed_a2
        pipeline_results["agent2"] = agent2_output
        stage_statuses["agent2"] = "RESUMED"
        logger.info(f"[+] Agent 2 Resumed from ISM checkpoint: {len(agent2_output.get('claims', []))} claims.")
    else:
        try:
            agent2 = EvidenceCorrelationAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, neo4j_client=neo4j_driver, tenant_id=tenant_id)
            agent2_output = agent2.run(
                case_id=case_id,
                context={
                    "fir_findings": fir_findings,
                    "tenant_id": tenant_id,
                    "neo4j_client": neo4j_driver
                }
            )
            pipeline_results["agent2"] = agent2_output
            stage_statuses["agent2"] = agent2_output.get("execution_status", "COMPLETED") if isinstance(agent2_output, dict) else "COMPLETED"
            _save_stage("agent2", state=agent2_output, status=stage_statuses["agent2"])
            logger.info(f"[+] Agent 2 Complete: {len(agent2_output.get('claims', []))} correlated claims generated.")
        except Exception as exc:
            logger.error(f"[-] Agent 2 Execution failed: {exc}", exc_info=True)
            pipeline_results["agent2"] = {"execution_status": "FAILED", "error": str(exc), "claims": [], "graph_metrics": {}}
            pipeline_results["agent_errors"]["agent2"] = str(exc)
            stage_statuses["agent2"] = "FAILED"
            _save_stage("agent2", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 3 for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 3: Attack Reconstruction Agent ─────────────────────────────────
    logger.info("\n[AGENT 3] Attack Reconstruction Agent Execution...")
    resumed_a3 = _get_resumed_stage("agent3")
    if resumed_a3 is not None:
        agent3_output = resumed_a3
        pipeline_results["agent3"] = agent3_output
        stage_statuses["agent3"] = "RESUMED"
        logger.info(f"[+] Agent 3 Resumed from ISM checkpoint: {len(agent3_output.get('attack_path', []))} attack steps.")
    else:
        try:
            agent3 = AttackReconstructionAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
            agent3_output = agent3.run(
                case_id=case_id,
                context={
                    "fir_findings": fir_findings,
                    "tenant_id": tenant_id,
                    "neo4j_client": neo4j_driver,
                    "agent2_correlation": pipeline_results.get("agent2")
                }
            )
            pipeline_results["agent3"] = agent3_output
            stage_statuses["agent3"] = agent3_output.get("execution_status", "COMPLETED") if isinstance(agent3_output, dict) else "COMPLETED"
            _save_stage("agent3", state=agent3_output, status=stage_statuses["agent3"])
            logger.info(f"[+] Agent 3 Complete: Attack steps: {len(agent3_output.get('attack_path', []))}.")
        except Exception as exc:
            logger.error(f"[-] Agent 3 Execution failed: {exc}", exc_info=True)
            pipeline_results["agent3"] = {"execution_status": "FAILED", "error": str(exc), "attack_path": []}
            pipeline_results["agent_errors"]["agent3"] = str(exc)
            stage_statuses["agent3"] = "FAILED"
            _save_stage("agent3", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 4 for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 4: Malware Behaviour Agent ─────────────────────────────────────
    logger.info("\n[AGENT 4] Malware Behaviour Agent Execution...")
    resumed_a4 = _get_resumed_stage("agent4")
    if resumed_a4 is not None:
        agent4_output = resumed_a4
        pipeline_results["agent4"] = agent4_output
        stage_statuses["agent4"] = "RESUMED"
        logger.info(f"[+] Agent 4 Resumed from ISM checkpoint.")
    else:
        try:
            agent4 = MalwareBehaviourAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
            agent4_out_obj = agent4.run(case_id=case_id, context=pipeline_results.get("agent2"))
            agent4_output = agent4_out_obj.model_dump() if hasattr(agent4_out_obj, "model_dump") else agent4_out_obj
            pipeline_results["agent4"] = agent4_output
            stage_statuses["agent4"] = agent4_output.get("execution_status", "COMPLETED") if isinstance(agent4_output, dict) else "COMPLETED"
            _save_stage("agent4", state=agent4_output, status=stage_statuses["agent4"])
            logger.info(f"[+] Agent 4 Complete: Scan status: {agent4_output.get('execution_status')}, claims: {len(agent4_output.get('claims', []))}.")
        except Exception as exc:
            logger.error(f"[-] Agent 4 Execution failed: {exc}", exc_info=True)
            pipeline_results["agent4"] = {"execution_status": "FAILED", "error": str(exc), "claims": []}
            pipeline_results["agent_errors"]["agent4"] = str(exc)
            stage_statuses["agent4"] = "FAILED"
            _save_stage("agent4", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 5a for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 5a: Threat Intelligence Agent ──────────────────────────────────
    logger.info("\n[AGENT 5a] Threat Intelligence Agent Execution...")
    resumed_a5a = _get_resumed_stage("agent5a")
    if resumed_a5a is not None:
        agent5a_output = resumed_a5a
        pipeline_results["agent5a"] = agent5a_output
        stage_statuses["agent5a"] = "RESUMED"
        logger.info(f"[+] Agent 5a Resumed from ISM checkpoint.")
    else:
        try:
            agent5a = ThreatIntelligenceAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
            c_stix = stix_client or StixTaxiiClient()
            c_cve = cve_client or CVEClient()
            c_mitre = mitre_client or MitreAttackClient()
            agent5a_output = agent5a.run(
                case_id=case_id,
                context={
                    "stix_client": c_stix,
                    "cve_client": c_cve,
                    "mitre_client": c_mitre,
                    "tenant_id": tenant_id,
                    "fir_findings": fir_findings,
                    "agent2_output": pipeline_results.get("agent2")
                }
            )
            pipeline_results["agent5a"] = agent5a_output
            stage_statuses["agent5a"] = agent5a_output.get("execution_status", "COMPLETED") if isinstance(agent5a_output, dict) else "COMPLETED"
            _save_stage("agent5a", state=agent5a_output, status=stage_statuses["agent5a"])
            logger.info(f"[+] Agent 5a Complete: Threat intel claim generated.")
        except Exception as exc:
            logger.error(f"[-] Agent 5a Execution failed: {exc}", exc_info=True)
            pipeline_results["agent5a"] = {"execution_status": "FAILED", "error": str(exc), "claim": ""}
            pipeline_results["agent_errors"]["agent5a"] = str(exc)
            stage_statuses["agent5a"] = "FAILED"
            _save_stage("agent5a", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 5b for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 5b: Campaign Similarity Agent ──────────────────────────────────
    logger.info("\n[AGENT 5b] Campaign Similarity Agent Execution...")
    resumed_a5b = _get_resumed_stage("agent5b")
    if resumed_a5b is not None:
        agent5b_output = resumed_a5b
        pipeline_results["agent5b"] = agent5b_output
        stage_statuses["agent5b"] = "RESUMED"
        logger.info(f"[+] Agent 5b Resumed from ISM checkpoint.")
    else:
        try:
            agent5b = CampaignSimilarityAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
            c_vec = vector_store or (VectorStore(url=settings.qdrant_url) if hasattr(settings, "qdrant_url") else None)
            agent5b_output = agent5b.run(
                case_id=case_id,
                context={
                    "vector_store": c_vec,
                    "agent2_output": pipeline_results.get("agent2"),
                    "agent3_output": pipeline_results.get("agent3"),
                    "agent4_output": pipeline_results.get("agent4"),
                    "agent5a_output": pipeline_results.get("agent5a"),
                    "fir_findings": fir_findings,
                    "tenant_id": tenant_id
                }
            )
            pipeline_results["agent5b"] = agent5b_output
            stage_statuses["agent5b"] = agent5b_output.get("execution_status", "COMPLETED") if isinstance(agent5b_output, dict) else "COMPLETED"
            _save_stage("agent5b", state=agent5b_output, status=stage_statuses["agent5b"])
            logger.info(f"[+] Agent 5b Complete: Campaign similarity claim generated.")
        except Exception as exc:
            logger.error(f"[-] Agent 5b Execution failed: {exc}", exc_info=True)
            pipeline_results["agent5b"] = {"execution_status": "FAILED", "error": str(exc), "claim": ""}
            pipeline_results["agent_errors"]["agent5b"] = str(exc)
            stage_statuses["agent5b"] = "FAILED"
            _save_stage("agent5b", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 6 for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 6: Impact Assessment Agent ─────────────────────────────────────
    logger.info("\n[AGENT 6] Impact Assessment Agent Execution...")
    resumed_a6 = _get_resumed_stage("agent6")
    if resumed_a6 is not None:
        agent6_output = resumed_a6
        pipeline_results["agent6"] = agent6_output
        stage_statuses["agent6"] = "RESUMED"
        logger.info(f"[+] Agent 6 Resumed from ISM checkpoint.")
    else:
        try:
            agent6 = ImpactAssessmentAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
            agent6_output = agent6.run(
                case_id=case_id,
                context={
                    "case_id": case_id,
                    "tenant_id": tenant_id,
                    "fir_findings": fir_findings,
                    "agent2_output": pipeline_results.get("agent2"),
                    "agent3_output": pipeline_results.get("agent3"),
                    "agent4_output": pipeline_results.get("agent4"),
                    "agent5_output": {
                        "agent5a": pipeline_results.get("agent5a"),
                        "agent5b": pipeline_results.get("agent5b")
                    }
                }
            )
            pipeline_results["agent6"] = agent6_output
            stage_statuses["agent6"] = agent6_output.get("execution_status", "COMPLETED") if isinstance(agent6_output, dict) else "COMPLETED"
            cvss_score = agent6_output.get("cvss_assessment", {}).get("base_score")
            iss_score = agent6_output.get("iss_assessment", {}).get("iss_score")
            _save_stage("agent6", state=agent6_output, status=stage_statuses["agent6"])
            logger.info(f"[+] Agent 6 Complete: CVSS={cvss_score}, ISS={iss_score}, Assets={len(agent6_output.get('affected_assets', []))}.")
        except Exception as exc:
            logger.error(f"[-] Agent 6 Execution failed: {exc}", exc_info=True)
            pipeline_results["agent6"] = {"execution_status": "FAILED", "error": str(exc)}
            pipeline_results["agent_errors"]["agent6"] = str(exc)
            stage_statuses["agent6"] = "FAILED"
            _save_stage("agent6", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    if _is_cancelled():
        logger.info(f"[!] Pipeline cancelled before Agent 7 for Case {case_id}")
        pipeline_results["execution_status"] = "STOPPED"
        pipeline_results["error"] = "Workload stopped by user request."
        pipeline_results["stage_statuses"] = stage_statuses
        return pipeline_results

    # ── AGENT 7: Supervisor Agent (Synthesis, Verification, Reports) ─────────
    logger.info("\n[AGENT 7] Supervisor Synthesis, Independent Verification & Report Generation...")
    resumed_a7 = _get_resumed_stage("agent7")
    if resumed_a7 is not None:
        pipeline_results["agent7"] = resumed_a7
        stage_statuses["agent7"] = "RESUMED"
        logger.info(f"[+] Agent 7 Resumed from ISM checkpoint.")
    else:
        try:
            agent7 = SupervisorAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)

            # Collect cited evidence IDs from upstream
            cited_eids: List[str] = []
            for step in pipeline_results.get("agent3", {}).get("attack_path", []):
                if isinstance(step, dict):
                    cited_eids.extend(step.get("evidence_ids", []))
            for c in pipeline_results.get("agent2", {}).get("claims", []):
                if isinstance(c, dict):
                    cited_eids.extend(c.get("cited_evidence_ids", []))
            for c in pipeline_results.get("agent4", {}).get("claims", []):
                if isinstance(c, dict):
                    cited_eids.extend(c.get("cited_evidence_ids", []))
            for eid in pipeline_results.get("agent6", {}).get("cited_evidence_ids", []):
                cited_eids.append(eid)
            cited_eids = list(dict.fromkeys(cited_eids))

            agent7_output = agent7.run(
                case_id=case_id,
                context={
                    "agent_outputs": {
                        "agent1": pipeline_results.get("agent1"),
                        "agent2": pipeline_results.get("agent2"),
                        "agent3": pipeline_results.get("agent3"),
                        "agent4": pipeline_results.get("agent4"),
                        "agent5a": pipeline_results.get("agent5a"),
                        "agent5b": pipeline_results.get("agent5b"),
                        "agent6": pipeline_results.get("agent6")
                    },
                    "evidence_ids": cited_eids,
                    "tenant_id": tenant_id,
                    "fir_findings": fir_findings
                }
            )

            a7_res = {
                "synthesis": agent7_output.get("synthesis", {}),
                "verification": agent7_output.get("verification_results", []),
                "confidence_gate": agent7_output.get("confidence_gate", {}),
                "reports": agent7_output.get("reports", {}),
                "report_metadata": agent7_output.get("report_metadata", {}),
                "status": agent7_output.get("status", "COMPLETED"),
                "execution_status": agent7_output.get("execution_status", "SUCCESS"),
                "review_level": agent7_output.get("review_level", "ROUTINE_ANALYST_REVIEW"),
            }
            pipeline_results["agent7"] = a7_res
            stage_statuses["agent7"] = agent7_output.get("status", "COMPLETED")
            _save_stage("agent7", state=a7_res, status=stage_statuses["agent7"])
            logger.info(f"[+] Agent 7 Complete: Status={agent7_output.get('status')}, Review Level={agent7_output.get('review_level')}")
        except Exception as exc:
            logger.error(f"[-] Agent 7 Execution failed: {exc}", exc_info=True)
            pipeline_results["agent7"] = {"execution_status": "FAILED", "error": str(exc), "synthesis": {}, "verification": []}
            pipeline_results["agent_errors"]["agent7"] = str(exc)
            stage_statuses["agent7"] = "FAILED"
            _save_stage("agent7", state={"error": str(exc)}, status="FAILED", retry_count=1)
            if stop_on_error:
                raise

    pipeline_results["stage_statuses"] = stage_statuses
    pipeline_results["model_metadata"] = model_metadata

    # Sync internal agent failures with agent_errors dict
    for agent_key in ["agent1", "agent2", "agent3", "agent4", "agent5a", "agent5b", "agent6", "agent7"]:
        out = pipeline_results.get(agent_key)
        if isinstance(out, dict) and str(out.get("execution_status", "")).upper() == "FAILED":
            if agent_key not in pipeline_results["agent_errors"]:
                err = out.get("error_message") or out.get("error")
                if not err and out.get("error_details"):
                    err = "; ".join(map(str, out["error_details"]))
                pipeline_results["agent_errors"][agent_key] = str(err or f"{agent_key} execution failed")

    if pipeline_results["agent_errors"]:
        pipeline_results["execution_status"] = "PARTIAL_SUCCESS"
    elif any(s in ("FAILED", "BLOCKED") for s in stage_statuses.values()):
        pipeline_results["execution_status"] = "PARTIAL_SUCCESS"
    else:
        pipeline_results["execution_status"] = "SUCCESS"

    logger.info("\n" + "=" * 80)
    logger.info(f"  ARGUS PIPELINE COMPLETE (Status: {pipeline_results['execution_status']})")
    logger.info("=" * 80)
    return pipeline_results


def main():
    parser = argparse.ArgumentParser(description="ARGUS Unified Production Forensic Ingestion & Multi-Agent Pipeline")
    parser.add_argument("--evidence", "-e", required=True, help="Path to evidence file (.E01, .eml, .pcap, .evtx, etc.)")
    parser.add_argument("--case-id", "-c", default=None, help="Case ID (auto-generated if omitted)")
    parser.add_argument("--tenant-id", "-t", default="default", help="Tenant ID (default: 'default')")
    parser.add_argument("--model", "-m", default="Qwen3-8B", help="Ollama LLM model name (default: 'Qwen3-8B')")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop pipeline immediately if an agent fails")
    parser.add_argument("--no-resume", action="store_true", help="Disable stage resumption from checkpoints")

    args = parser.parse_args()

    try:
        results = run_pipeline(
            evidence_path=args.evidence,
            case_id=args.case_id,
            tenant_id=args.tenant_id,
            model_name=args.model,
            stop_on_error=args.stop_on_error,
            resume=not args.no_resume
        )
        print("\nPipeline Summary:")
        print(f"Case ID           : {results['case_id']}")
        print(f"FIR Findings Count: {results['fir_findings_count']}")
        print(f"Overall Status    : {results['execution_status']}")
        if results['agent_errors']:
            print(f"Agent Errors      : {results['agent_errors']}")
    except Exception as exc:
        logger.error(f"Pipeline execution failed: {exc}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
