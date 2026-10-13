"""
ARGUS Agent 6 — Impact Assessment Standalone Runner & CLI
===========================================================
Allows you to pass forensic evidence, upstream agent outputs, or run a realistic
forensic incident simulation to test and inspect the output of Agent 6.

Usage:
  1. Run with built-in realistic forensic scenario:
     python run_agent6.py

  2. Run with an upstream Agent 2 / Agent 3 JSON output file:
     python run_agent6.py --case-file "../files/agent2_output_2020JimmyWilson.json"

  3. Run with custom case ID and tenant:
     python run_agent6.py --case-id "CASE-2026-DEMO" --tenant-id "default"
"""

import os
import sys
import json
import argparse
from typing import Dict, Any, List
from datetime import datetime, timezone

# Ensure fast fallback if Ollama is not locally running
os.environ.setdefault("OLLAMA_TIMEOUT_SECONDS", "5")
os.environ.setdefault("ALLOW_OLLAMA_FALLBACK", "true")

# Ensure project root in python path
sys.path.insert(0, os.path.abspath("."))

# Ensure UTF-8 output encoding on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from agents.agent6_impact_assessment import ImpactAssessmentAgent, Agent6Output
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway
from models.llm import LLMLoader


def create_sample_context(case_id: str, tenant_id: str) -> Dict[str, Any]:
    """Generates a realistic forensic evidence scenario."""
    return {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "agent3_output": {
            "infection_path": {
                "entry_point": "Remote inbound phishing email with macro attachment",
                "evidence_ids": ["F-101", "F-102"],
                "confidence": 0.94
            },
            "attack_path": [
                {
                    "step_number": 1,
                    "action": "User 'john.doe' opened malicious invoice attachment on WIN-WORKSTATION-01",
                    "evidence_ids": ["F-101"]
                },
                {
                    "step_number": 2,
                    "action": "WINword.exe spawned cmd.exe -> powershell.exe download cradle to 198.51.100.22:443",
                    "evidence_ids": ["F-102", "F-103"]
                },
                {
                    "step_number": 3,
                    "action": "User 'admin' scheduled task persistence 'update.exe' installed via schtasks",
                    "evidence_ids": ["F-104"]
                }
            ],
            "lateral_movement": [
                {
                    "source_host": "WIN-WORKSTATION-01",
                    "destination_host": "CORP-DC-01",
                    "evidence_ids": ["F-105"],
                    "protocol": "SMB"
                }
            ]
        },
        "agent4_output": {
            "claims": [
                {
                    "claim_id": "CLM-AG4-001",
                    "summary": "Network C2 beaconing to 198.51.100.22:443 transferring 850KB",
                    "findings_summary": "Finding F-103 details continuous encrypted TLS beaconing from WIN-WORKSTATION-01 to external IP 198.51.100.22 on port 443 with 850KB data transfer.",
                    "cited_evidence_ids": ["F-102", "F-103"],
                    "infection_stage": "Command_and_Control",
                    "ioc_collection": {
                        "ip_addresses": ["198.51.100.22"],
                        "hashes": ["7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"]
                    }
                },
                {
                    "claim_id": "CLM-AG4-002",
                    "summary": "Scheduled task persistence update.exe with matching payload hash",
                    "findings_summary": "Finding F-104 shows user 'admin' on WIN-WORKSTATION-01 creating scheduled task update.exe with SHA256 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069.",
                    "cited_evidence_ids": ["F-104"],
                    "infection_stage": "Persistence",
                    "ioc_collection": {
                        "ip_addresses": [],
                        "hashes": ["7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"]
                    }
                }
            ]
        },
        "fir_findings": [
            {
                "finding_id": "F-101",
                "fact": "Phishing email with attachment 'Invoice_2026.docm' delivered to user 'john.doe' at 08:30:00 UTC.",
                "evidence_reference": ["EVID-EML-001"]
            },
            {
                "finding_id": "F-102",
                "fact": "Process WINWORD.EXE spawned cmd.exe then powershell.exe -enc AAAA on host WIN-WORKSTATION-01.",
                "evidence_reference": ["EVID-EVTX-002"]
            },
            {
                "finding_id": "F-103",
                "fact": "Established socket connection from WIN-WORKSTATION-01 to external C2 IP 198.51.100.22:443 transferring 850KB.",
                "evidence_reference": ["EVID-PCAP-003"]
            },
            {
                "finding_id": "F-104",
                "fact": "User 'admin' created scheduled task persistence update.exe with SHA256 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069.",
                "evidence_reference": ["EVID-REG-004"]
            },
            {
                "finding_id": "F-105",
                "fact": "Lateral movement connection via SMB from WIN-WORKSTATION-01 targeting Domain Controller CORP-DC-01.",
                "evidence_reference": ["EVID-NET-005"]
            }
        ]
    }


def load_context_from_file(file_path: str, case_id: str, tenant_id: str) -> Dict[str, Any]:
    """Loads case findings from a JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Check if file is Agent 2 output
    if "claims" in data and ("agent_id" in data or "total_findings_processed" in data):
        return {
            "case_id": data.get("case_id", case_id),
            "tenant_id": data.get("tenant_id", tenant_id),
            "agent2_output": data,
            "fir_findings": [
                {
                    "finding_id": eid,
                    "fact": f"Evidence fact derived from Claim: {c.get('summary', '')}"
                }
                for c in data.get("claims", [])
                for eid in c.get("cited_evidence_ids", [])
            ]
        }
    return data


def print_formatted_report(output: Agent6Output):
    """Pretty prints the structured Agent 6 output."""
    print("\n" + "=" * 80)
    print("               ARGUS AGENT 6 — IMPACT ASSESSMENT REPORT")
    print("=" * 80)
    print(f"Case ID           : {output.case_id}")
    print(f"Tenant ID         : {output.tenant_id}")
    print(f"Execution Status  : {output.execution_status}")
    print(f"Timestamp         : {output.timestamp}")
    print(f"Model Used        : {output.model_used}")

    print("\n" + "-" * 80)
    print("1. TECHNICAL VULNERABILITY SEVERITY (CVSS v3.1)")
    print("-" * 80)
    cvss = output.cvss_assessment
    print(f"Assessment Status : {cvss.assessment_status.value}")
    if cvss.base_score is not None:
        print(f"CVSS Base Score   : {cvss.base_score}/10.0 [{cvss.severity.value}]")
        print(f"Vector String     : {cvss.vector_string}")
        print(f"Exploitability    : {cvss.exploitability_subscore} | Impact Subscore: {cvss.impact_subscore}")
    elif cvss.score_range_min is not None and cvss.score_range_max is not None:
        print(f"Confirmed Range   : [{cvss.score_range_min} - {cvss.score_range_max}] (Severity: UNDETERMINED)")
        print(f"Missing Metrics   : {', '.join(cvss.missing_metrics)}")
    else:
        print(f"CVSS Score        : None [UNDETERMINED]")
        print(f"Missing Metrics   : {', '.join(cvss.missing_metrics)}")
    print(f"Calculation Notes : {cvss.calculation_notes}")
    print(f"Supporting Evidence: {', '.join(cvss.evidence_ids) if cvss.evidence_ids else 'None'}")

    print("\n" + "-" * 80)
    print("2. ARGUS INVESTIGATION SEVERITY SCORE (ISS) -- BUSINESS RISK")
    print("-" * 80)
    iss = output.iss_assessment
    print(f"Overall ISS Score : {iss.iss_score}/10.0 [{iss.severity.value}]")
    print("Factor Breakdown  :")
    for key, f in iss.factor_breakdown.items():
        print(f"  * {f.factor_name:<46}: Raw={f.raw_score:>4.1f}/10  Weighted={f.weighted_score:>4.2f} pts (Weight: {f.weight})")
        print(f"    |- Details: {f.description}")
        if f.evidence_ids:
            print(f"    |- Evidence IDs: {', '.join(f.evidence_ids[:6])}")
    print(f"\nExecutive Summary : {iss.executive_summary}")

    print("\n" + "-" * 80)
    print(f"3. AFFECTED ASSETS & IDENTITIES INVENTORY ({output.total_assets_affected} Assets)")
    print("-" * 80)
    for a in output.affected_assets:
        print(f"  * [{a.asset_type.value:<16}] {a.asset_id:<22} | Criticality: {a.criticality.value:<8} | State: {a.compromise_state.value:<21} | Risk: {a.risk_score:>4.1f}/10")
        print(f"    |- Impact Details: {a.impact_details}")
        if a.evidence_ids:
            print(f"    |- Evidence: {', '.join(a.evidence_ids)}")

    print("\n" + "-" * 80)
    print(f"4. OPERATIONAL RECOVERY PLAYBOOK & CHECKLIST ({len(output.recovery_actions)} Actions)")
    print("-" * 80)
    checklist = output.recovery_checklist
    phases = [
        ("PHASE 1: CONTAINMENT (Immediate 1-2h)", checklist.containment_steps),
        ("PHASE 2: ERADICATION (6-12h)", checklist.eradication_steps),
        ("PHASE 3: RECOVERY (24-48h)", checklist.recovery_steps),
        ("PHASE 4: POST-INCIDENT HARDENING", checklist.hardening_steps)
    ]
    for phase_name, steps in phases:
        if steps:
            print(f"\n  [{phase_name}]")
            for s in steps:
                print(f"    [{s.priority.value}] {s.action_id}: {s.title} (Role: {s.responsible_role.value})")
                print(f"      • Task        : {s.description}")
                print(f"      • Verification: {s.verification_step}")
                if s.target_assets:
                    print(f"      • Targets     : {', '.join(s.target_assets)}")

    print("\n" + "-" * 80)
    print("5. QWEN3-8B NARRATIVE REPORT")
    print("-" * 80)
    print(output.explanation)

    print("\n" + "-" * 80)
    print("6. FORENSIC TRACEABILITY & CITATION INTEGRITY")
    print("-" * 80)
    val = output.citation_validation
    print(f"Citation Valid    : {val.get('citation_valid')}")
    print(f"Total Citations   : {val.get('total_citations')}")
    print(f"Valid Citations   : {val.get('valid_citations_count')}")
    if val.get("invalid_citations"):
        print(f"Invalid Citations : {val.get('invalid_citations')}")
    print(f"Validation Notes  : {val.get('validation_notes')}")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="ARGUS Agent 6 Impact Assessment Runner")
    parser.add_argument("--case-file", "-f", default=None, help="Path to input case JSON file")
    parser.add_argument("--case-id", "-c", default="CASE-AGENT6-DEMO", help="Case ID (default: CASE-AGENT6-DEMO)")
    parser.add_argument("--tenant-id", "-t", default="default", help="Tenant ID (default: default)")
    parser.add_argument("--export-json", "-o", default=None, help="Save structured Agent 6 JSON output to file")

    args = parser.parse_args()

    # Load context
    if args.case_file:
        print(f"Loading input evidence from: {args.case_file}")
        context = load_context_from_file(args.case_file, args.case_id, args.tenant_id)
    else:
        print("Running with comprehensive realistic digital forensic incident scenario...")
        context = create_sample_context(args.case_id, args.tenant_id)

    # Initialize Agent 6
    agent = ImpactAssessmentAgent(
        tenant_id=args.tenant_id
    )

    # Execute Assessment
    output: Agent6Output = agent.execute_assessment(
        case_id=args.case_id,
        upstream_context=context
    )

    # Print Formatted Report
    print_formatted_report(output)

    # Optional JSON export
    if args.export_json:
        with open(args.export_json, "w", encoding="utf-8") as f:
            json.dump(output.model_dump(), f, indent=2, default=str)
        print(f"[+] Full JSON output saved to: {args.export_json}")


if __name__ == "__main__":
    main()
