"""
Live Verification Script for Agent 2 — Evidence Correlation
============================================================
Executes EvidenceCorrelationAgent with live local Ollama Qwen3-8B model
and displays deterministic graph metrics, timeline clusters, and LLM claims.
"""

import sys
import json
from datetime import datetime, timezone

from fir.schemas import FIRFinding
from models.llm import LLMLoader
from agents.agent2_evidence_correlation.agent import EvidenceCorrelationAgent


def main():
    print("=" * 70)
    print("      ARGUS AGENT 2 — LIVE QWEN3-8B VERIFICATION SCRIPT")
    print("=" * 70)

    # 1. Initialize sample FIR findings representing a real incident scenario
    sample_findings = [
        FIRFinding(
            finding_id="F-1001",
            case_id="CASE-INCIDENT-2026-001",
            tenant_id="default",
            fact="Process cmd.exe spawned powershell.exe on host WIN-WORKSTATION-01 connecting to C2 IP 192.168.1.50. SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
            confidence=0.9,
            severity="high",
            timestamp=datetime(2026, 9, 23, 14, 0, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-EVTX-001"],
            layer="endpoint_analysis"
        ),
        FIRFinding(
            finding_id="F-1002",
            case_id="CASE-INCIDENT-2026-001",
            tenant_id="default",
            fact="Network connection established from WIN-WORKSTATION-01 to external C2 IP 192.168.1.50 transferring 450KB.",
            confidence=0.85,
            severity="high",
            timestamp=datetime(2026, 9, 23, 14, 12, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-PCAP-002"],
            layer="network_analysis"
        ),
        FIRFinding(
            finding_id="F-1003",
            case_id="CASE-INCIDENT-2026-001",
            tenant_id="default",
            fact="User admin created scheduled task persistence via update.exe with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
            confidence=0.95,
            severity="critical",
            timestamp=datetime(2026, 9, 23, 14, 30, 0, tzinfo=timezone.utc),
            evidence_reference=["EVD-REG-003"],
            layer="log_analysis"
        )
    ]

    print(f"\n[+] Loaded {len(sample_findings)} FIR findings for case CASE-INCIDENT-2026-001.")

    # 2. Instantiate LLMLoader and EvidenceCorrelationAgent
    print("[+] Initializing Ollama Qwen3-8B model wrapper...")
    llm = LLMLoader().load_qwen3_8b()

    agent = EvidenceCorrelationAgent(
        model=llm,
        tenant_id="default"
    )

    # 3. Execute Agent 2 reasoning
    print("\n[+] Running Agent 2 Evidence Correlation pipeline...")
    context = {"fir_findings": sample_findings}
    result = agent.run("CASE-INCIDENT-2026-001", context=context)

    # 4. Display Results
    print("\n" + "=" * 70)
    print("                       EXECUTION SUMMARY")
    print("=" * 70)
    print(f"Status           : {result.get('execution_status')}")
    print(f"Case ID          : {result.get('case_id')}")
    print(f"Model Used       : {result.get('model_used')}")
    print(f"Findings Count   : {result.get('total_findings_processed')}")
    print(f"Graph Metrics    : {result.get('graph_metrics')}")
    print(f"Sanitization     : {result.get('sanitization_summary')}")

    print("\n" + "=" * 70)
    print("             AGENT 2 FORENSIC CORRELATION CLAIMS")
    print("=" * 70)

    claims = result.get("claims", [])
    if not claims:
        print("[-] No claims generated.")
    else:
        for idx, claim in enumerate(claims, 1):
            print(f"\n--- Claim {idx}: {claim.get('claim_id')} ---")
            print(f"Summary             : {claim.get('summary')}")
            print(f"Correlation Type    : {claim.get('correlation_type')}")
            print(f"Assessed Importance : {claim.get('assessed_importance')}")
            print(f"Confidence Score    : {claim.get('confidence_score')}")
            print(f"Citation Verified   : {claim.get('citation_verified')}")
            print(f"Cited Evidence IDs  : {claim.get('cited_evidence_ids')}")
            print(f"Invalid Citations   : {claim.get('invalid_citations')}")
            print(f"Timeline Sequence   : {claim.get('timeline_sequence')}")
            print(f"Findings Summary    : {claim.get('findings_summary')}")
            print(f"Reasoning Notes     : {claim.get('reasoning_notes')}")
            print(f"Validation Notes    : {claim.get('validation_notes')}")

    print("\n" + "=" * 70)
    print("[+] Live Agent 2 Verification Complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
