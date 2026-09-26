import sys
from unittest.mock import MagicMock

# Mock heavy/missing modules so we can run the logic test without them
sys.modules['transformers'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()
sys.modules['pydantic_settings'] = MagicMock()
sys.modules['requests'] = MagicMock()

import json
from datetime import datetime, timezone
from fir.schemas import FIRFinding
from agents.agent3_attack_reconstruction.agent import AttackReconstructionAgent
from sanitization.gateway import SanitizationGateway
from models.llm import LLMLoader
import time

def run_bulk_test():
    print("Generating bulk FIR findings (150 records)...")
    bulk_findings = []
    for i in range(1, 151):
        bulk_findings.append(
            FIRFinding(
                finding_id=f"F-BULK-{i:04d}",
                case_id="CASE-BULK-001",
                tenant_id="default",
                fact=f"Bulk generated event number {i} involving synthetic malware trace.",
                confidence=0.85,
                severity="medium",
                timestamp=datetime(2026, 9, 23, 10, i % 60, i % 60, tzinfo=timezone.utc),
                evidence_reference=[f"EVD-BULK-{i:04d}"],
                layer="synthetic_bulk"
            )
        )

    class MockFIRRepo:
        def get_by_case(self, tenant_id, case_id):
            return bulk_findings

    mock_gateway = MagicMock()
    mock_gateway.sanitize_finding.side_effect = lambda f: MagicMock(
        xml_evidence_block=f"<finding id='{f.finding_id}'>{f.fact}</finding>",
        injection_flagged=False
    )

    print("Initializing Agent 3 Attack Reconstruction (Smart Mock LLM)...")
    agent = AttackReconstructionAgent(
        model=LLMLoader().load_qwen3_8b(),
        fir_repo=MockFIRRepo(),
        sanitization_gateway=mock_gateway,
        tenant_id="default"
    )

    print("Running Agent 3 over bulk data...")
    start_time = time.time()
    result = agent.run("CASE-BULK-001")
    duration = time.time() - start_time

    print(f"\n[+] Execution Status: {result['execution_status']}")
    print(f"[+] Total Findings Processed: {result['total_findings_processed']}")
    print(f"[+] Timeline Events: {len(result['attack_timeline'])}")
    print(f"[+] Attack Chain Stages: {len(result['attack_chain'])}")
    
    events = result['attack_timeline']
    if len(events) > 0:
        print(f"[+] Validation Passed: All valid citations? {all(c['citation_verified'] for c in events)}")
    print(f"[+] Processing Time: {duration:.2f} seconds")
    print("\nSample Timeline Event:")
    if events:
        print(json.dumps(events[0], indent=2))
    else:
        print("No timeline events generated.")

if __name__ == "__main__":
    run_bulk_test()
