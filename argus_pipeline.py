"""
ARGUS Production Forensic Pipeline CLI
=========================================
Unified single entrypoint for ALL evidence types (.E01 disk images, .eml, .pcap, .evtx, memory dumps).

Pipeline Architecture:
  Evidence Path (.E01 / other)
          ↓
  Stage 1: Ingestion Router & Forensic Parsers
          ↓
  Stage 2: Artifact & Observable Extraction
          ↓
  Stage 3: Forensic Correlation Record (FCR) Engine
          ↓
  Stage 4: Batch Orchestrator -> Sanitization Gateway -> FIR Repository (PostgreSQL)
          ↓
  Agent 2: Evidence Correlation Agent
          ├── GraphBuilder (NetworkX WCC & Neo4j Ingestion)
          ├── TimelineBuilder (Chronological Clustering)
          ├── ConflictDetector (Attitudinal & Hash Anomaly Detection)
          ├── LLM Reasoning & Context Sampling (Qwen3-8B)
          └── Validator (FIR Universe & Citation Verification Gate)
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
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent
from models.llm import OllamaWrapper, LLMLoader
from config.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ArgusPipeline")


def run_pipeline(evidence_path: str, case_id: Optional[str] = None, tenant_id: str = "default", model_name: str = "qwen2.5:latest") -> dict:
    """
    Executes the ARGUS production pipeline over any given evidence file path.
    """
    if not os.path.exists(evidence_path):
        raise FileNotFoundError(f"Evidence file not found: {evidence_path}")

    filename = os.path.basename(evidence_path)
    case_id = case_id or f"CASE-{Path(filename).stem.upper()}-{uuid.uuid4().hex[:6]}"
    evidence_id = f"EVID-{uuid.uuid4().hex[:8]}"

    logger.info("=" * 80)
    logger.info("  ARGUS UNIFIED PRODUCTION PIPELINE INGESTION")
    logger.info("=" * 80)
    logger.info(f"Evidence Path : {evidence_path}")
    logger.info(f"Case ID       : {case_id}")
    logger.info(f"Tenant ID     : {tenant_id}")

    fir_repo = FIRRepository()

    # ── STAGE 1: Evidence Routing & Parsing ─────────────────────────────────
    logger.info("\n[STAGE 1] Ingesting & Routing Evidence...")
    router = ParserRouter()
    evidence_obj = Evidence(
        evidence_id=evidence_id,
        case_id=case_id,
        tenant_id=tenant_id,
        filename=filename,
        file_path=evidence_path,
        raw_file_path=evidence_path,
        uploaded_by="argus_cli"
    )

    routing_res = router.determine_routing(evidence_obj)
    artifacts = []
    if routing_res.status == "ROUTED" and routing_res.parser_instance:
        artifacts = routing_res.parser_instance.parse(evidence_path, evidence_id) or []
        for art in artifacts:
            art.case_id = case_id
    logger.info(f"[+] Stage 1 Complete: Extracted {len(artifacts)} raw artifacts.")

    # ── STAGE 2: Observable Extraction & Stage 3 FCR Correlation ──────────
    logger.info("\n[STAGE 2 & 3] Derived Observables & FCR Correlation...")
    extractor = ArtifactExtractor()
    observables = extractor.extract(artifacts, evidence_id=evidence_id) or []
    for obs in observables:
        obs.case_id = case_id

    fcr_engine = FCREngine()
    fcr_records = fcr_engine.correlate(
        artifacts=artifacts,
        extracted_entities=observables,
        allow_single_artifact=True
    )
    logger.info(f"[+] Stage 3 Complete: Generated {len(fcr_records)} FCR correlation records.")

    # ── STAGE 4: Orchestration & FIR Database Ingestion ──────────────────────
    logger.info("\n[STAGE 4] Orchestration & PostgreSQL FIR Ingestion...")
    artifacts_by_id = {art.artifact_id: art for art in artifacts}
    process_fcr_batch(
        case_id=case_id,
        fcr_objects=fcr_records,
        artifacts_by_id=artifacts_by_id,
        fir_repo=fir_repo,
        tenant_id=tenant_id
    )

    # Fetch FIR findings for Agent 2 processing
    fir_findings = fir_repo.get_by_case(tenant_id=tenant_id, case_id=case_id)
    logger.info(f"[+] Stage 4 Complete: Ingested {len(fir_findings)} FIR findings into PostgreSQL ('{case_id}').")

    # ── AGENT 2: Evidence Correlation Agent ──────────────────────────────────
    logger.info("\n[AGENT 2] Evidence Correlation & Graph Engine Execution...")
    try:
        from neo4j import GraphDatabase
        neo4j_driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        neo4j_driver.verify_connectivity()
        logger.info("[+] Neo4j Driver connected successfully at bolt://localhost:7687")
    except Exception as exc:
        neo4j_driver = None
        logger.warning(f"Neo4j offline/unreachable fallback: {exc}")

    llm = OllamaWrapper(model_name, "http://localhost:11434")
    agent2 = EvidenceCorrelationAgent(model=llm, fir_repo=fir_repo, neo4j_client=neo4j_driver, tenant_id=tenant_id)

    agent2_output = agent2.run(
        case_id=case_id,
        context={
            "fir_findings": fir_findings,
            "tenant_id": tenant_id,
            "neo4j_client": neo4j_driver
        }
    )

    logger.info("\n" + "=" * 80)
    logger.info("  ARGUS AGENT 2 FORENSIC CORRELATION RESULTS")
    logger.info("=" * 80)
    logger.info(json.dumps(agent2_output, indent=2, default=str))

    # ── AGENT 3: Attack Reconstruction Agent ─────────────────────────────────
    logger.info("\n[AGENT 3] Attack Reconstruction Agent Execution...")
    from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
    agent3 = AttackReconstructionAgent(model=llm, fir_repo=fir_repo, tenant_id=tenant_id)

    agent3_output = agent3.run(
        case_id=case_id,
        context={
            "fir_findings": fir_findings,
            "tenant_id": tenant_id,
            "neo4j_client": neo4j_driver,
            "agent2_correlation": agent2_output
        }
    )

    logger.info("\n" + "=" * 80)
    logger.info("  ARGUS AGENT 3 ATTACK RECONSTRUCTION RESULTS")
    logger.info("=" * 80)
    logger.info(json.dumps(agent3_output, indent=2, default=str))

    return {
        "agent2": agent2_output,
        "agent3": agent3_output
    }


def main():
    parser = argparse.ArgumentParser(description="ARGUS Unified Production Forensic Ingestion & Correlation Pipeline")
    parser.add_argument("--evidence", "-e", required=True, help="Path to evidence file (.E01, .eml, .pcap, .evtx, etc.)")
    parser.add_argument("--case-id", "-c", default=None, help="Case ID (auto-generated if omitted)")
    parser.add_argument("--tenant-id", "-t", default="default", help="Tenant ID (default: 'default')")
    parser.add_argument("--model", "-m", default="qwen2.5:latest", help="Ollama LLM model name (default: 'qwen2.5:latest')")

    args = parser.parse_args()

    try:
        run_pipeline(
            evidence_path=args.evidence,
            case_id=args.case_id,
            tenant_id=args.tenant_id,
            model_name=args.model
        )
    except Exception as exc:
        logger.error(f"Pipeline execution failed: {exc}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
