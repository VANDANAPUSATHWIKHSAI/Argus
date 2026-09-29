"""
Live End-to-End Verification Script: Email (.eml) Input -> Agent 2 Correlation
================================================================================
Parses sample_phishing.eml through Stage 1-4 pipeline, feeds derived FIR findings
into EvidenceCorrelationAgent (Agent 2) with local Qwen3-8B, and prints the result.
"""

import os
import sys
from datetime import datetime, timezone

from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from models.llm import LLMLoader
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent


def main():
    print("=" * 75)
    print("      ARGUS — EML EVIDENCE INTAKE & AGENT 2 CORRELATION VERIFICATION")
    print("=" * 75)

    eml_file_path = os.path.abspath("sample/sample_phishing.eml")
    if not os.path.exists(eml_file_path):
        print(f"[-] Error: File not found at {eml_file_path}")
        sys.exit(1)

    print(f"\n[1] Ingesting .eml file: {eml_file_path}")

    # Stage 1: Router & EmailParser
    router = ParserRouter()
    evidence = Evidence(
        case_id="CASE-EML-2026-001",
        filename="sample_phishing.eml",
        file_path=eml_file_path,
        raw_file_path=eml_file_path,
        uploaded_by="analyst_verification",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    routing_res = router.determine_routing(evidence)
    print(f"[+] Router status: {routing_res.status}, parser: {routing_res.target_parser}")

    if routing_res.status != "ROUTED" or not routing_res.parser_instance:
        print(f"[-] Routing failed: {routing_res.reason}")
        return

    artifacts = routing_res.parser_instance.parse(eml_file_path, evidence.evidence_id)
    print(f"[+] Stage 2 Parsed Artifacts: {len(artifacts)}")
    for art in artifacts:
        art.case_id = "CASE-EML-2026-001"
        print(f"    - Type: {art.artifact_type:<15} | Summary: {art.event_summary}")

    # Stage 2.5: Artifact Extractor
    extractor = ArtifactExtractor()
    observables = extractor.extract(artifacts, evidence_id=evidence.evidence_id) or []
    print(f"[+] Stage 2.5 Derived Observables: {len(observables)}")
    for obs in observables:
        obs.case_id = "CASE-EML-2026-001"
        print(f"    - Entity Type: {obs.entity_type:<15} | Value: {obs.value}")

    # Stage 3: FCR Engine
    fcr_engine = FCREngine()
    fcr_records = fcr_engine.correlate(
        artifacts=artifacts,
        extracted_entities=observables,
        allow_single_artifact=True
    )
    print(f"[+] Stage 3 Forensic Correlation Records (FCRs): {len(fcr_records)}")

    # Stage 4: Analysis Engines & FIR Storage
    fir_repo = FIRRepository()
    all_artifacts = artifacts + list(observables)
    artifacts_map = {art.artifact_id: art for art in artifacts}

    findings = process_fcr_batch(
        case_id="CASE-EML-2026-001",
        fcr_objects=fcr_records,
        artifacts_by_id=artifacts_map,
        fir_repo=fir_repo,
        tenant_id="default"
    )
    print(f"[+] Stage 4 Forensic Findings Generated: {len(findings)}")

    # Query FIR findings for this case
    fir_findings = fir_repo.get_by_case("default", "CASE-EML-2026-001")
    print(f"[+] Retrieved {len(fir_findings)} FIR Findings from repository for Agent 2.")

    for ff in fir_findings:
        print(f"    - Finding [{ff.finding_id}] ({ff.layer}): {ff.fact}")

    # Stage 5: Agent 2 Evidence Correlation Agent
    print("\n" + "-" * 75)
    print("[+] Initializing Agent 2 (EvidenceCorrelationAgent) with Qwen3-8B...")
    print("-" * 75)

    llm = LLMLoader().load_qwen3_8b()
    agent = EvidenceCorrelationAgent(model=llm, tenant_id="default")

    context = {"fir_findings": fir_findings}
    result = agent.run("CASE-EML-2026-001", context=context)

    # Display Agent 2 Output
    print("\n" + "=" * 75)
    print("              AGENT 2 EXECUTION RESULTS (EML INPUT)")
    print("=" * 75)
    print(f"Execution Status : {result.get('execution_status')}")
    print(f"Case ID          : {result.get('case_id')}")
    print(f"Model Used       : {result.get('model_used')}")
    print(f"Processed        : {result.get('total_findings_processed')} FIR findings")
    print(f"Graph Metrics    : {result.get('graph_metrics')}")

    claims = result.get("claims", [])
    print(f"\n[+] Agent 2 Generated Claims: {len(claims)}")
    for idx, claim in enumerate(claims, 1):
        print(f"\n--- Claim {idx}: {claim.get('claim_id')} ---")
        print(f"Summary             : {claim.get('summary')}")
        print(f"Correlation Type    : {claim.get('correlation_type')}")
        print(f"Assessed Importance : {claim.get('assessed_importance')}")
        print(f"Confidence Score    : {claim.get('confidence_score')}")
        print(f"Cited Evidence IDs  : {claim.get('cited_evidence_ids')}")
        print(f"Reasoning Notes     : {claim.get('reasoning_notes')}")

    print("\n" + "=" * 75)
    print("[+] EML -> Agent 2 Correlation Test Completed Successfully!")
    print("=" * 75)


if __name__ == "__main__":
    main()
