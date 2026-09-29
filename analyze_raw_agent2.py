"""
ARGUS — Raw Evidence File -> Agent 2 Correlation Analyzer
===========================================================
Usage:
    python analyze_raw_agent2.py <path_to_raw_evidence_file> [--case_id <case_id>]

Example:
    python analyze_raw_agent2.py sample/sample_phishing.eml
"""

import os
import sys
import argparse
import json

from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from models.llm import LLMLoader, OllamaWrapper
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent


def analyze_raw_evidence(file_path: str, case_id: str = "CASE-RAW-ANALYSIS-001", tenant_id: str = "default") -> dict:
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Evidence file not found: {abs_path}")

    filename = os.path.basename(abs_path)
    print(f"\n[1/5] Ingesting Raw Evidence File: {abs_path}")

    # Stage 1: Router & Dynamic Parser Execution
    router = ParserRouter()
    evidence = Evidence(
        case_id=case_id,
        filename=filename,
        file_path=abs_path,
        raw_file_path=abs_path,
        uploaded_by="analyst_cli",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    routing_res = router.determine_routing(evidence)
    print(f"[+] Router status: {routing_res.status}, Target Parser: {routing_res.target_parser}")

    if routing_res.status != "ROUTED" or not routing_res.parser_instance:
        raise RuntimeError(f"Routing failed for '{filename}': {routing_res.reason}")

    # Stage 2: Parsing
    parsed_artifacts = routing_res.parser_instance.parse(abs_path, evidence.evidence_id) or []
    print(f"[+] Stage 2 Parsed Artifacts: {len(parsed_artifacts)}")
    for art in parsed_artifacts:
        art.case_id = case_id

    # Stage 2.5: Extractor
    extractor = ArtifactExtractor()
    observables = extractor.extract(parsed_artifacts, evidence_id=evidence.evidence_id) or []
    print(f"[+] Stage 2.5 Derived Observables: {len(observables)}")
    for obs in observables:
        obs.case_id = case_id

    # Stage 3: FCR Engine
    fcr_engine = FCREngine()
    fcr_records = fcr_engine.correlate(
        artifacts=parsed_artifacts,
        extracted_entities=observables,
        allow_single_artifact=True
    )
    print(f"[+] Stage 3 Forensic Correlation Records (FCRs): {len(fcr_records)}")

    # Stage 4: Analysis Engines & FIR Storage
    fir_repo = FIRRepository()
    artifacts_map = {art.artifact_id: art for art in parsed_artifacts}

    findings = process_fcr_batch(
        case_id=case_id,
        fcr_objects=fcr_records,
        artifacts_by_id=artifacts_map,
        fir_repo=fir_repo,
        tenant_id=tenant_id
    )
    print(f"[+] Stage 4 Forensic Findings Generated: {len(findings)}")

    fir_findings = fir_repo.get_by_case(tenant_id, case_id)
    print(f"[+] Total FIR Findings in Repository for Agent 2: {len(fir_findings)}")

    # Stage 5: Agent 2 Correlation Reasoning
    print("\n[5/5] Executing Agent 2 (EvidenceCorrelationAgent)...")
    llm = LLMLoader().load_qwen3_8b()
    agent = EvidenceCorrelationAgent(model=llm, fir_repo=fir_repo, tenant_id=tenant_id)

    context = {"fir_findings": fir_findings, "tenant_id": tenant_id}
    agent_result = agent.run(case_id, context=context)

    return {
        "file_name": filename,
        "case_id": case_id,
        "router_status": routing_res.status,
        "parser": routing_res.target_parser,
        "artifacts_count": len(parsed_artifacts),
        "observables_count": len(observables),
        "fcr_count": len(fcr_records),
        "findings_count": len(findings),
        "agent2_result": agent_result
    }


def main():
    parser = argparse.ArgumentParser(description="Run Agent 2 correlation on a raw evidence file.")
    parser.add_argument("file_path", help="Path to raw evidence file (.eml, .evtx, .pcap, .msg, etc.)")
    parser.add_argument("--case_id", default="CASE-RAW-ANALYSIS-001", help="Custom case ID")
    args = parser.parse_args()

    res = analyze_raw_evidence(args.file_path, case_id=args.case_id)

    print("\n" + "=" * 75)
    print("                    AGENT 2 CORRELATION REPORT")
    print("=" * 75)
    print(f"Evidence File    : {res['file_name']}")
    print(f"Routed Parser    : {res['parser']}")
    print(f"Artifacts Count  : {res['artifacts_count']}")
    print(f"Observables      : {res['observables_count']}")
    print(f"FCR Count        : {res['fcr_count']}")
    print(f"FIR Findings     : {res['findings_count']}")

    ag2 = res["agent2_result"]
    print(f"Agent 2 Status   : {ag2.get('execution_status')}")
    print(f"Model Used       : {ag2.get('model_used')}")
    print(f"Graph Metrics    : {ag2.get('graph_metrics')}")

    claims = ag2.get("claims", [])
    print(f"\n[+] Agent 2 Correlation Claims ({len(claims)}):")
    if not claims:
        print("[-] No claims generated.")
    for idx, claim in enumerate(claims, 1):
        print(f"\n--- Claim {idx}: {claim.get('claim_id')} ---")
        print(f"Summary             : {claim.get('summary')}")
        print(f"Correlation Type    : {claim.get('correlation_type')}")
        print(f"Assessed Importance : {claim.get('assessed_importance')}")
        print(f"Confidence Score    : {claim.get('confidence_score')}")
        print(f"Cited Evidence IDs  : {claim.get('cited_evidence_ids')}")
        print(f"Findings Summary    : {claim.get('findings_summary')}")
        print(f"Reasoning Notes     : {claim.get('reasoning_notes')}")

    print("\n" + "=" * 75)
    print("[+] Analysis Complete!")
    print("=" * 75)


if __name__ == "__main__":
    main()
