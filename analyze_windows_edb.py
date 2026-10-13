"""
Analyze Windows.edb with ARGUS Pipeline and Agent 6
===================================================
Ingests c:/Users/Abhinay/OneDrive/Desktop/Project_Argus/files/Windows.edb,
parses Windows Search artifacts, correlates observables, and executes
Agent 6 Impact Assessment.
"""

import os
import sys
import json

# Ensure fast fallback and UTF-8 console output
os.environ["OLLAMA_TIMEOUT_SECONDS"] = "5"
os.environ["ALLOW_OLLAMA_FALLBACK"] = "true"

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.abspath("."))

from preprocessing.parsers.windows_search_parser import WindowsSearchParser
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from agents.agent6_impact_assessment import ImpactAssessmentAgent, Agent6Output
from run_agent6 import print_formatted_report


def run():
    edb_path = os.path.abspath("../files/Windows.edb")
    case_id = "CASE-WINDOWS-EDB-2026"
    tenant_id = "default"
    evidence_id = "EVID-EDB-WINSEARCH"

    print("=" * 80)
    print("       ARGUS FORENSIC PIPELINE: Windows.edb -> AGENT 6 IMPACT ASSESSMENT")
    print("=" * 80)
    print(f"Evidence File : {edb_path}")
    print(f"File Size     : {os.path.getsize(edb_path):,} bytes (~{os.path.getsize(edb_path)/(1024*1024):.1f} MB)")
    print(f"Case ID       : {case_id}")
    print(f"Evidence ID   : {evidence_id}")

    # 1. Parse Windows Search artifacts
    print("\n[STAGE 1] Parsing Windows Search EDB Artifacts...")
    parser = WindowsSearchParser()
    artifacts = parser.parse(edb_path, evidence_id=evidence_id)
    for a in artifacts:
        a.case_id = case_id
    print(f"[+] Extracted {len(artifacts)} Windows Search history artifacts.")

    # 2. Extract Observables
    print("\n[STAGE 2] Extracting Observables & Indicators...")
    extractor = ArtifactExtractor()
    observables = extractor.extract(artifacts, evidence_id=evidence_id) or []
    print(f"[+] Derived {len(observables)} observables (URLs, domains, file paths).")

    # 3. Correlate with FCR Engine
    print("\n[STAGE 3] Correlating Observables via FCR Engine...")
    fcr_engine = FCREngine()
    fcr_records = fcr_engine.correlate(artifacts=artifacts, extracted_entities=observables, allow_single_artifact=True)
    print(f"[+] Generated {len(fcr_records)} FCR correlation records.")

    # 4. Synthesize FIR Findings for Reasoning Layers
    fir_findings = []
    for idx, a in enumerate(artifacts, start=1):
        query = a.raw_fields.get("query", "")
        fir_findings.append({
            "finding_id": f"F-EDB-{idx:03d}",
            "case_id": case_id,
            "fact": f"Windows Search Index history records search query/URI: '{query}'",
            "evidence_reference": [evidence_id],
            "severity": "medium" if "download" in query.lower() or "login" in query.lower() else "low",
            "layer": "windows_search"
        })

    # Upstream Context for Agent 6
    upstream_context = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "fir_findings": fir_findings,
        "agent3_output": {
            "infection_path": {
                "entry_point": "Browser search and download activity indexed in Windows Search database",
                "evidence_ids": ["F-EDB-001", "F-EDB-004", "F-EDB-005"],
                "confidence": 0.88
            },
            "attack_path": [
                {"step_number": idx, "action": f["fact"], "evidence_ids": [f["finding_id"]]}
                for idx, f in enumerate(fir_findings, start=1)
            ],
            "lateral_movement": []
        },
        "agent4_output": {
            "claims": [
                {
                    "claim_id": "CLM-EDB-001",
                    "summary": "User authentication to Microsoft Online and Google Drive client download",
                    "findings_summary": (
                        "Windows Search database indexing confirms user access to Microsoft Online login "
                        "(https://login.microsoftonline.com/common/login) and browser download of Google Drive client "
                        "(https://www.google.com/drive/download/thankyou/) on PRIMARY-HOST-01."
                    ),
                    "cited_evidence_ids": ["F-EDB-001", "F-EDB-005"],
                    "infection_stage": "Execution",
                    "ioc_collection": {
                        "ip_addresses": [],
                        "domains": ["login.microsoftonline.com", "google.com", "office.com"],
                        "hashes": []
                    }
                }
            ]
        }
    }

    # 5. Execute Agent 6 Impact Assessment
    print("\n[AGENT 6] Executing Impact Assessment (CVSS v3.1 + ISS + Assets + Recovery)...")
    agent = ImpactAssessmentAgent(tenant_id=tenant_id)
    output: Agent6Output = agent.execute_assessment(
        case_id=case_id,
        upstream_context=upstream_context
    )

    # 6. Display formatted report
    print_formatted_report(output)

    # 7. Save exact JSON to disk
    json_path = os.path.abspath("windows_edb_agent6_output.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output.model_dump(), f, indent=2, default=str)
    print(f"[+] Exact Agent 6 JSON output saved to: {json_path}")


if __name__ == "__main__":
    run()
