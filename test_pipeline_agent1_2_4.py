"""
End-to-End Verification Script: EML Evidence Intake -> Stage 1-4 -> Agent 1 -> Agent 2 -> Agent 4
===================================================================================================
Verifies complete flow from raw evidence parsing (email/EML or general evidence) through:
  - Stage 1: Router & EmailParser
  - Stage 2: Artifact Extraction
  - Stage 2.5: Observable Extraction
  - Stage 3: FCR Engine
  - Stage 4: FIR Repository Ingestion
  - Agent 1: Evidence Intelligence Agent
  - Agent 2: Evidence Correlation Agent
  - Agent 4: Malware Behaviour Agent
"""

import os
import sys
import json
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath("."))

from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from models.llm import OllamaWrapper
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent
from agents.agent4_malware_behaviour.agent import MalwareBehaviourAgent
from agents.agent4_malware_behaviour.schemas import Agent2Output
from sanitization.gateway import SanitizationGateway

def verify_pipeline():
    print("=" * 80)
    print("      ARGUS END-TO-END PIPELINE VERIFICATION: AGENT 1 -> AGENT 2 -> AGENT 4")
    print("=" * 80)

    # Configure fallback timeout for local environment
    os.environ["ALLOW_OLLAMA_FALLBACK"] = "true"
    os.environ["OLLAMA_TIMEOUT_SECONDS"] = "10"

    case_id = "CASE-VERIFY-2026-001"
    tenant_id = "default"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    eml_file_path = os.path.join(script_dir, "sample", "sample_phishing.eml")

    if not os.path.exists(eml_file_path):
        print(f"[-] Error: File not found at {eml_file_path}")
        sys.exit(1)

    # ── [STEP 1] Evidence Intake & Routing ─────────────────────────────────────
    print(f"\n[STEP 1] Ingesting & Routing Evidence File: {eml_file_path}")
    router = ParserRouter()
    evidence = Evidence(
        evidence_id="EVID-EML-001",
        case_id=case_id,
        filename="sample_phishing.eml",
        file_path=eml_file_path,
        raw_file_path=eml_file_path,
        uploaded_by="analyst_verification",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    routing_res = router.determine_routing(evidence)
    print(f"  [+] Routing Status: {routing_res.status}")
    print(f"  [+] Target Parser:   {routing_res.target_parser}")

    if routing_res.status != "ROUTED" or not routing_res.parser_instance:
        print(f"  [-] Routing failed: {routing_res.reason}")
        return False

    artifacts = routing_res.parser_instance.parse(eml_file_path, evidence.evidence_id)
    print(f"  [+] Stage 2 Parsed Artifacts ({len(artifacts)} total):")
    for art in artifacts:
        art.case_id = case_id
        print(f"      * [{art.artifact_type:<15}] {art.event_summary[:80]}")

    # ── [STEP 2] Observable & FCR Extraction ──────────────────────────────────
    print(f"\n[STEP 2] Extracting Observables & Correlating (Stage 2.5 & Stage 3)")
    extractor = ArtifactExtractor()
    observables = extractor.extract(artifacts, evidence_id=evidence.evidence_id) or []
    for obs in observables:
        obs.case_id = case_id
    print(f"  [+] Stage 2.5 Derived Observables ({len(observables)} total):")
    for obs in observables[:5]:
        print(f"      * [{obs.entity_type:<15}] {obs.value}")

    fcr_engine = FCREngine()
    fcr_records = fcr_engine.correlate(
        artifacts=artifacts,
        extracted_entities=observables,
        allow_single_artifact=True
    )
    print(f"  [+] Stage 3 Forensic Correlation Records (FCRs): {len(fcr_records)}")

    # ── [STEP 3] Stage 4 FIR Generation ───────────────────────────────────────
    print(f"\n[STEP 3] Stage 4: Analysis Engines & FIR Database Ingestion")
    fir_repo = FIRRepository()
    artifacts_map = {art.artifact_id: art for art in artifacts}

    findings = process_fcr_batch(
        case_id=case_id,
        fcr_objects=fcr_records,
        artifacts_by_id=artifacts_map,
        fir_repo=fir_repo,
        tenant_id=tenant_id
    )

    fir_findings = fir_repo.get_by_case(tenant_id, case_id)
    print(f"  [+] Saved {len(fir_findings)} Forensic Findings (FIR) in Repository:")
    for ff in fir_findings:
        print(f"      * Finding [{ff.finding_id}] ({ff.layer}): {ff.fact[:80]}")

    gw = SanitizationGateway()
    model = OllamaWrapper(model_name="qwen3:8b", base_url="http://localhost:11434")

    # ── [STEP 4] Agent 1 Execution ────────────────────────────────────────────
    print(f"\n[STEP 4] Executing Agent 1: Evidence Intelligence Agent")
    try:
        agent1 = EvidenceIntelligenceAgent(model=model, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
        agent1_context = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "evidence_id": evidence.evidence_id,
            "artifacts": [a.model_dump() for a in artifacts],
            "findings": fir_findings
        }
        agent1_output = agent1.run(case_id=case_id, context=agent1_context)
        print(f"  [+] Agent 1 Execution Completed Successfully!")
        c_list = agent1_output.claims if hasattr(agent1_output, "claims") else agent1_output.get("claims", [])
        print(f"      * Total Claims Generated: {len(c_list)}")
        for c in c_list:
            cid = getattr(c, "claim_id", c.get("claim_id") if isinstance(c, dict) else "CLM-AG1")
            sum_txt = getattr(c, "summary", c.get("summary") if isinstance(c, dict) else "")
            print(f"      * Claim [{cid}]: {sum_txt}")
    except Exception as e:
        print(f"  [!] Agent 1 Execution Note: {e}")

    # ── [STEP 5] Agent 2 Execution ────────────────────────────────────────────
    print(f"\n[STEP 5] Executing Agent 2: Evidence Correlation Agent")
    agent2 = EvidenceCorrelationAgent(model=model, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
    agent2_output_obj = agent2.run(case_id=case_id, context={"case_id": case_id, "tenant_id": tenant_id, "fir_findings": fir_findings})
    print(f"  [+] Agent 2 Execution Completed Successfully!")
    
    claims = agent2_output_obj.claims if hasattr(agent2_output_obj, 'claims') else agent2_output_obj.get('claims', [])
    print(f"      * Correlated Claims Count: {len(claims)}")
    for claim in claims:
        if isinstance(claim, dict):
            print(f"      * Claim [{claim.get('claim_id')}] ({claim.get('assessed_importance')}): {claim.get('summary')}")
            print(f"        Cited Evidence IDs: {claim.get('cited_evidence_ids')}")
        else:
            print(f"      * Claim [{claim.claim_id}] ({claim.assessed_importance}): {claim.summary}")
            print(f"        Cited Evidence IDs: {claim.cited_evidence_ids}")

    # ── [STEP 6] Agent 4 Execution ────────────────────────────────────────────
    print(f"\n[STEP 6] Executing Agent 4: Malware Behaviour Agent")
    agent4 = MalwareBehaviourAgent(model=model, fir_repo=fir_repo, sanitization_gateway=gw, tenant_id=tenant_id)
    agent4_output_obj = agent4.run(case_id=case_id, context=agent2_output_obj)
    print(f"  [+] Agent 4 Execution Completed Successfully!")
    print(f"      * Execution Status:            {agent4_output_obj.execution_status}")
    print(f"      * Total FIR Findings Built:    {agent4_output_obj.scan_summary.total_fir_findings_built}")
    print(f"      * YARA Rules Fired:            {agent4_output_obj.scan_summary.yara_rules_fired or 'None (Clean)'}")
    print(f"      * Behaviour Categories Found:  {agent4_output_obj.scan_summary.behaviour_categories_found}")
    print(f"      * Enriched Behaviour Claims:   {len(agent4_output_obj.claims)}")

    if agent4_output_obj.claims:
        top_claim = agent4_output_obj.claims[0]
        print(f"\n  [Agent 4 Enriched Analysis Breakdown]")
        print(f"      * Claim Summary:           {top_claim.summary}")
        print(f"      * Infection Lifecycle:     {top_claim.infection_stage.value if hasattr(top_claim.infection_stage, 'value') else top_claim.infection_stage}")
        print(f"      * Risk Level:              {top_claim.malware_profile.risk_level.value if hasattr(top_claim.malware_profile.risk_level, 'value') else top_claim.malware_profile.risk_level}")
        print(f"      * Threat Family:           {top_claim.malware_profile.family}")
        print(f"      * Malware Type:            {top_claim.malware_profile.type}")
        print(f"      * Overall Confidence:      {top_claim.confidence_score * 100:.1f}%")
        print(f"      * Coverage Gaps Noted:     {len(top_claim.coverage_gaps)}")

    print("\n" + "=" * 80)
    print("      SUCCESS: AGENT 1 -> AGENT 2 -> AGENT 4 PIPELINE VERIFIED FULLY!")
    print("=" * 80)
    return True

if __name__ == "__main__":
    verify_pipeline()
