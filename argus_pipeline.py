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

# Threat Intel & Vector Store Clients
from threat_intel.stix_taxii import StixTaxiiClient
from threat_intel.cve_nvd import CVEClient
from threat_intel.mitre_attack import MitreAttackClient
from vector_store.qdrant_client import VectorStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ArgusPipeline")


def run_pipeline(
    evidence_path: Optional[str] = None,
    case_id: Optional[str] = None,
    tenant_id: str = "default",
    model_name: str = "qwen2.5:latest",
    llm: Optional[Any] = None,
    neo4j_client: Optional[Any] = None,
    stix_client: Optional[Any] = None,
    cve_client: Optional[Any] = None,
    mitre_client: Optional[Any] = None,
    vector_store: Optional[Any] = None,
    fir_findings: Optional[List[Any]] = None,
    stop_on_error: bool = False
) -> Dict[str, Any]:
    """
    Executes the integrated ARGUS production pipeline covering Stages 1-4 and Agents 1, 2, 3, 4, 5a, 5b, 6, and 7.
    """
    if evidence_path is None and fir_findings is None:
        raise ValueError("Either evidence_path or fir_findings must be provided to run_pipeline.")

    if evidence_path and not os.path.exists(evidence_path):
        raise FileNotFoundError(f"Evidence file not found: {evidence_path}")

    filename = os.path.basename(evidence_path) if evidence_path else "synthetic_case"
    case_id = case_id or f"CASE-{Path(filename).stem.upper()}-{uuid.uuid4().hex[:6]}"
    evidence_id = f"EVID-{uuid.uuid4().hex[:8]}"

    logger.info("=" * 80)
    logger.info("  ARGUS UNIFIED PRODUCTION PIPELINE INGESTION & MULTI-AGENT REASONING")
    logger.info("=" * 80)
    logger.info(f"Evidence Source: {evidence_path or 'Pre-loaded FIR findings'}")
    logger.info(f"Case ID        : {case_id}")
    logger.info(f"Tenant ID      : {tenant_id}")

    fir_repo = FIRRepository()
    gw = SanitizationGateway()
    artifacts: List[Any] = []

    # ── STAGE 1–4: Evidence Intake & Parsing (if evidence file provided) ───
    if evidence_path:
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
        if routing_res.status == "ROUTED" and routing_res.parser_instance:
            artifacts = routing_res.parser_instance.parse(evidence_path, evidence_id) or []
            for art in artifacts:
                art.case_id = case_id
        logger.info(f"[+] Stage 1 Complete: Extracted {len(artifacts)} raw artifacts.")

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

        logger.info("\n[STAGE 4] Orchestration & PostgreSQL FIR Ingestion...")
        artifacts_by_id = {art.artifact_id: art for art in artifacts}
        process_fcr_batch(
            case_id=case_id,
            fcr_objects=fcr_records,
            artifacts_by_id=artifacts_by_id,
            fir_repo=fir_repo,
            tenant_id=tenant_id
        )

        fir_findings = fir_repo.get_by_case(tenant_id=tenant_id, case_id=case_id) or []
        logger.info(f"[+] Stage 4 Complete: Ingested {len(fir_findings)} FIR findings into repository ('{case_id}').")
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

    active_llm = llm or OllamaWrapper(model_name, "http://localhost:11434")

    pipeline_results: Dict[str, Any] = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "evidence_id": evidence_id,
        "fir_findings_count": len(fir_findings),
        "execution_status": "SUCCESS",
        "agent_errors": {}
    }

    # ── AGENT 1: Evidence Intelligence Agent ─────────────────────────────────
    logger.info("\n[AGENT 1] Evidence Intelligence Agent Execution...")
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
        logger.info(f"[+] Agent 1 Complete: {len(agent1_output.get('claims', []))} claims generated.")
    except Exception as exc:
        logger.error(f"[-] Agent 1 Execution failed: {exc}", exc_info=True)
        pipeline_results["agent1"] = {"execution_status": "FAILED", "error": str(exc), "claims": []}
        pipeline_results["agent_errors"]["agent1"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 2: Evidence Correlation Agent ──────────────────────────────────
    logger.info("\n[AGENT 2] Evidence Correlation & Graph Engine Execution...")
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
        logger.info(f"[+] Agent 2 Complete: {len(agent2_output.get('claims', []))} correlated claims generated.")
    except Exception as exc:
        logger.error(f"[-] Agent 2 Execution failed: {exc}", exc_info=True)
        pipeline_results["agent2"] = {"execution_status": "FAILED", "error": str(exc), "claims": [], "graph_metrics": {}}
        pipeline_results["agent_errors"]["agent2"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 3: Attack Reconstruction Agent ─────────────────────────────────
    logger.info("\n[AGENT 3] Attack Reconstruction Agent Execution...")
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
        logger.info(f"[+] Agent 3 Complete: Attack steps: {len(agent3_output.get('attack_path', []))}.")
    except Exception as exc:
        logger.error(f"[-] Agent 3 Execution failed: {exc}", exc_info=True)
        pipeline_results["agent3"] = {"execution_status": "FAILED", "error": str(exc), "attack_path": []}
        pipeline_results["agent_errors"]["agent3"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 4: Malware Behaviour Agent ─────────────────────────────────────
    logger.info("\n[AGENT 4] Malware Behaviour Agent Execution...")
    try:
        agent4 = MalwareBehaviourAgent(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
        agent4_out_obj = agent4.run(case_id=case_id, context=pipeline_results.get("agent2"))
        agent4_output = agent4_out_obj.model_dump() if hasattr(agent4_out_obj, "model_dump") else agent4_out_obj
        pipeline_results["agent4"] = agent4_output
        logger.info(f"[+] Agent 4 Complete: Scan status: {agent4_output.get('execution_status')}, claims: {len(agent4_output.get('claims', []))}.")
    except Exception as exc:
        logger.error(f"[-] Agent 4 Execution failed: {exc}", exc_info=True)
        pipeline_results["agent4"] = {"execution_status": "FAILED", "error": str(exc), "claims": []}
        pipeline_results["agent_errors"]["agent4"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 5a: Threat Intelligence Agent ──────────────────────────────────
    logger.info("\n[AGENT 5a] Threat Intelligence Agent Execution...")
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
        logger.info(f"[+] Agent 5a Complete: Threat intel claim generated.")
    except Exception as exc:
        logger.error(f"[-] Agent 5a Execution failed: {exc}", exc_info=True)
        pipeline_results["agent5a"] = {"execution_status": "FAILED", "error": str(exc), "claim": ""}
        pipeline_results["agent_errors"]["agent5a"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 5b: Campaign Similarity Agent ──────────────────────────────────
    logger.info("\n[AGENT 5b] Campaign Similarity Agent Execution...")
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
        logger.info(f"[+] Agent 5b Complete: Campaign similarity claim generated.")
    except Exception as exc:
        logger.error(f"[-] Agent 5b Execution failed: {exc}", exc_info=True)
        pipeline_results["agent5b"] = {"execution_status": "FAILED", "error": str(exc), "claim": ""}
        pipeline_results["agent_errors"]["agent5b"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 6: Impact Assessment Agent ─────────────────────────────────────
    logger.info("\n[AGENT 6] Impact Assessment Agent Execution...")
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
        cvss_score = agent6_output.get("cvss_assessment", {}).get("base_score")
        iss_score = agent6_output.get("iss_assessment", {}).get("iss_score")
        logger.info(f"[+] Agent 6 Complete: CVSS={cvss_score}, ISS={iss_score}, Assets={len(agent6_output.get('affected_assets', []))}.")
    except Exception as exc:
        logger.error(f"[-] Agent 6 Execution failed: {exc}", exc_info=True)
        pipeline_results["agent6"] = {"execution_status": "FAILED", "error": str(exc)}
        pipeline_results["agent_errors"]["agent6"] = str(exc)
        if stop_on_error:
            raise

    # ── AGENT 7: Supervisor Agent (Synthesis & Verification) ─────────────────
    logger.info("\n[AGENT 7] Supervisor Synthesis & Independent Verification...")
    try:
        agent7_synth = SupervisorSynthesis(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
        
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

        agent7_synth_output = agent7_synth.run(
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
                "evidence_ids": cited_eids
            }
        )

        agent7_verif = SupervisorVerification(model=active_llm, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
        verif_results = []
        for claim in agent7_synth_output.get("claims", []):
            v_res = agent7_verif.verify(claim, fir_records=fir_findings)
            verif_results.append(v_res)

        pipeline_results["agent7"] = {
            "synthesis": agent7_synth_output,
            "verification": verif_results
        }
        logger.info(f"[+] Agent 7 Complete: Supervisor claims synthesized & independently verified.")
    except Exception as exc:
        logger.error(f"[-] Agent 7 Execution failed: {exc}", exc_info=True)
        pipeline_results["agent7"] = {"execution_status": "FAILED", "error": str(exc), "synthesis": {}, "verification": []}
        pipeline_results["agent_errors"]["agent7"] = str(exc)
        if stop_on_error:
            raise

    if pipeline_results["agent_errors"]:
        pipeline_results["execution_status"] = "PARTIAL_SUCCESS"

    logger.info("\n" + "=" * 80)
    logger.info(f"  ARGUS PIPELINE COMPLETE (Status: {pipeline_results['execution_status']})")
    logger.info("=" * 80)
    return pipeline_results


def main():
    parser = argparse.ArgumentParser(description="ARGUS Unified Production Forensic Ingestion & Multi-Agent Pipeline")
    parser.add_argument("--evidence", "-e", required=True, help="Path to evidence file (.E01, .eml, .pcap, .evtx, etc.)")
    parser.add_argument("--case-id", "-c", default=None, help="Case ID (auto-generated if omitted)")
    parser.add_argument("--tenant-id", "-t", default="default", help="Tenant ID (default: 'default')")
    parser.add_argument("--model", "-m", default="qwen2.5:latest", help="Ollama LLM model name (default: 'qwen2.5:latest')")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop pipeline immediately if an agent fails")

    args = parser.parse_args()

    try:
        results = run_pipeline(
            evidence_path=args.evidence,
            case_id=args.case_id,
            tenant_id=args.tenant_id,
            model_name=args.model,
            stop_on_error=args.stop_on_error
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
