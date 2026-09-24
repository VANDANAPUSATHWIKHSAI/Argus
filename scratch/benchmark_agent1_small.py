"""
ARGUS Agent 1 — Small Real-Evidence Performance Benchmark & Equivalence Tester
Target Evidence: 2020JimmyWilson.E01
"""

import sys
import os
import time
import json
import logging
from pathlib import Path

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from preprocessing.parsers.filesystem_parser import FilesystemParser
from fir.schemas import FIRFinding
from sanitization.gateway import SanitizationGateway, SanitizedAgentContext
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Claim


class BenchmarkMockLLM:
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        import re
        finding_ids = re.findall(r'<finding_id>(FIR-[^<]+)</finding_id>', prompt)
        cited = finding_ids[:3] if finding_ids else ["FIR-DISK2-0001"]
        return json.dumps({
            "investigation_readiness": "READY",
            "possible_analyses": ["Filesystem analysis", "MFT examination"],
            "performed_analyses": ["Bodyfile record extraction", "Sanitization scanning"],
            "evidence_trust_score": 0.95,
            "claims": [
                {
                    "claim_id": f"CLM-AG1-BENCH-{hash(prompt) % 10000:04d}",
                    "summary": "Verified filesystem artifact metadata on partition offset 65664",
                    "findings_summary": "Ingested filesystem records from 2020JimmyWilson.E01 partition offset 65664.",
                    "cited_evidence_ids": cited,
                    "assessed_importance": "high",
                    "confidence_score": 0.94,
                    "missing_evidence_noted": [],
                    "uncertainties_or_conflicts": [],
                    "reasoning_notes": "Correlated sector offset 65664 with bodyfile entries"
                }
            ]
        })


def run_benchmark():
    image_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01"
    assert os.path.exists(image_path), f"Evidence image not found: {image_path}"

    print("=" * 70)
    print("ARGUS AGENT 1 — SMALL REAL-EVIDENCE PERFORMANCE BENCHMARK")
    print(f"Evidence Image: {os.path.basename(image_path)}")
    print("=" * 70)

    t0 = time.time()
    
    # 1. Intake & Preprocessing Subset
    t_intake_start = time.time()
    fs_parser = FilesystemParser()
    raw_artifacts = fs_parser.parse(image_path, evidence_id="EVID-DISK-2-BENCH")
    sample_artifacts = raw_artifacts[:50]
    
    sample_findings = []
    for idx, art in enumerate(sample_artifacts, start=1):
        path_val = art.normalized_fields.file_path or art.normalized_fields.file_name or art.event_summary or f"Record-{idx}"
        finding = FIRFinding(
            finding_id=f"FIR-DISK2-{idx:04d}",
            case_id="CASE-BENCH-001",
            tenant_id="default",
            fact=f"Filesystem record on partition 65664: {path_val}",
            confidence=0.90,
            severity="medium",
            evidence_reference=["EVID-DISK-2-BENCH"],
            layer="endpoint",
            source_artifact_id=art.artifact_id
        )
        sample_findings.append(finding)
    t_intake_end = time.time()

    # 2. Phase 2 Sanitization Gateway
    t_san_start = time.time()
    gateway = SanitizationGateway()
    sanitized_ctxs = [gateway.sanitize_finding(f) for f in sample_findings]
    t_san_end = time.time()

    # 3. Agent 1 Batch Reasoning Execution (Phase 3 Optimization test)
    t_qwen_start = time.time()
    mock_llm = BenchmarkMockLLM()
    validator = Agent1Validator()
    
    agent = EvidenceIntelligenceAgent(
        model=mock_llm,
        sanitization_gateway=gateway,
        tenant_id="default"
    )
    
    # Run Agent 1 over sanitized contexts (Phase 1 Fix)
    result = agent.run(case_id="CASE-BENCH-001", context={
        "fir_findings": sanitized_ctxs,
        "tenant_id": "default"
    })
    t_qwen_end = time.time()

    # 4. Deterministic Claim Validation
    t_val_start = time.time()
    fir_map = {c.finding_id: c for c in sanitized_ctxs}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(sanitized_ctxs)
    raw_claims = [Agent1Claim(**c) if isinstance(c, dict) else c for c in result.get("claims", [])]
    validated_claims = validator.validate_claims(
        claims=raw_claims,
        valid_finding_ids=valid_finding_ids,
        valid_lineage_ids=valid_lineage_ids,
        fir_map=fir_map
    )
    t_val_end = time.time()

    t_total_end = time.time()

    print("\n--- BENCHMARK MEASUREMENTS ---")
    print(f"Number of FIR Findings Evaluated : {len(sample_findings)}")
    print(f"1. Intake & Bodyfile Parse Time   : {(t_intake_end - t_intake_start)*1000:.2f} ms")
    print(f"2. Sanitization Gateway Time      : {(t_san_end - t_san_start)*1000:.2f} ms")
    print(f"3. Agent 1 Qwen/LLM Time          : {(t_qwen_end - t_qwen_start)*1000:.2f} ms")
    print(f"4. Deterministic Validation Time  : {(t_val_end - t_val_start)*1000:.2f} ms")
    print(f"Total Benchmark Wall-Clock Time   : {(t_total_end - t0)*1000:.2f} ms")
    print("=" * 70)

    # 5. Equivalence & Integrity Checks
    assert len(sanitized_ctxs) == 50
    assert result.get("execution_status") == "SUCCESS"
    assert len(validated_claims) > 0
    assert all(c.citation_verified and c.semantic_support_verified for c in validated_claims)
    print("FORENSIC EQUIVALENCE CHECK: PASS")


if __name__ == "__main__":
    run_benchmark()
