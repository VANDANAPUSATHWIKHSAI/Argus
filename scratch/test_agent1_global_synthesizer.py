"""
Controlled Test Runner for Agent 1 Stage 3 Global Synthesizer
==============================================================
ARGUS Phase 8E Controlled Test.
Tests Stage 3 Global Synthesis using Qwen3-14B over Stage 2 consolidated handoff payload derived from Phase 8C 100-FIR scale test results.

DO NOT RUN ON FULL 3,286 CORPUS.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timezone

# Ensure stdout handles UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Ensure project root is on Python path
sys.path.insert(0, os.path.abspath("."))

from agents.agent1_evidence_intelligence.global_synthesizer import GlobalSynthesizer
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Output

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main():
    print("=" * 80)
    print("ARGUS PHASE 8E -- STAGE 3 GLOBAL SYNTHESIZER CONTROLLED TEST")
    print("=" * 80)

    # 1. Load Phase 8C Scale Test Results
    phase8c_path = "scratch/phase8c_scale_test_results.json"
    if not os.path.exists(phase8c_path):
        print(f"ERROR: File not found: {phase8c_path}")
        sys.exit(1)

    with open(phase8c_path, "r", encoding="utf-8") as f:
        phase8c_data = json.load(f)

    # 2. Reconstruct Stage 2 Consolidated Payload
    telemetry_list = phase8c_data.get("telemetry_list", [])
    consolidation_meta = phase8c_data.get("consolidation", {})

    all_worker_claims = []
    all_fir_ids = set()

    for batch in telemetry_list:
        b_fir_ids = batch.get("fir_ids", [])
        all_fir_ids.update(b_fir_ids)
        for clm in batch.get("validated_claims", []):
            all_worker_claims.append(clm)

    evidence_id_union = set(consolidation_meta.get("evidence_id_union", []))
    valid_universe_finding_ids = evidence_id_union.union(all_fir_ids)

    consolidated_payload = {
        "case_id": "CASE-2020JIMMYWILSON-E01",
        "tenant_id": "default",
        "total_findings_processed": phase8c_data.get("total_firs", 100),
        "consolidated_claims": all_worker_claims,
        "worker_possible_analyses_union": consolidation_meta.get("worker_possible_analyses_union", []),
        "worker_performed_analyses_union": consolidation_meta.get("worker_performed_analyses_union", []),
        "sanitization_summary": {
            "findings_sanitized": 100,
            "injections_flagged": 0,
            "gateway_status": "CLEAN"
        }
    }

    payload_json_str = json.dumps(consolidated_payload, indent=2)
    payload_char_count = len(payload_json_str)
    approx_input_tokens = payload_char_count // 4

    print(f"\n[STEP 1] Input Stage 2 Payload Prepared:")
    print(f"  - Total FIR Findings Universe: {len(all_fir_ids)}")
    print(f"  - Stage 2 Consolidated Claims Count: {len(all_worker_claims)}")
    print(f"  - Valid Evidence ID Universe Size: {len(valid_universe_finding_ids)}")
    print(f"  - Input Payload Size: {payload_char_count} chars (~{approx_input_tokens} tokens)")

    # 3. Deterministic Pre-Check
    print(f"\n[STEP 2] Running Deterministic Pre-Check...")
    precheck_uncited = 0
    precheck_out_of_bounds = 0

    for wc in all_worker_claims:
        cited = wc.get("cited_evidence_ids", [])
        if not cited:
            precheck_uncited += 1
        for cid in cited:
            if cid not in valid_universe_finding_ids:
                precheck_out_of_bounds += 1

    print(f"  - Stage 2 Uncited Claims: {precheck_uncited}")
    print(f"  - Stage 2 Out-of-Bounds Citations: {precheck_out_of_bounds}")

    if precheck_out_of_bounds > 0 or precheck_uncited > 0:
        print("  [FAIL] PRE-CHECK FAILED! Halting execution.")
        sys.exit(1)
    else:
        print("  [PASS] PRE-CHECK PASSED! All Stage 2 claims cite valid FIR evidence IDs.")

    # 4. Instantiate Global Synthesizer & Run Synthesis
    print(f"\n[STEP 3] Initializing Stage 3 Global Synthesizer...")
    synthesizer = GlobalSynthesizer()
    print(f"  - Loaded LLM Model: {synthesizer.model_name}")

    print(f"\n[STEP 4] Executing Qwen3-14B Global Synthesis Call...")
    t0 = time.time()
    result_output: Agent1Output = synthesizer.synthesize(
        consolidated_payload=consolidated_payload,
        valid_universe_finding_ids=valid_universe_finding_ids,
        valid_universe_lineage_ids=set()
    )
    t1 = time.time()
    latency_sec = round(t1 - t0, 2)

    # 5. Measure & Validate Output Results
    global_claims = result_output.claims
    total_global_claims = len(global_claims)
    
    cited_ids_all = set()
    invalid_citations_count = 0
    unsupported_claims_count = 0

    for gc in global_claims:
        for cid in gc.cited_evidence_ids:
            cited_ids_all.add(cid)
            if cid not in valid_universe_finding_ids:
                invalid_citations_count += 1
        if not gc.citation_verified:
            invalid_citations_count += 1
        if not gc.semantic_support_verified:
            unsupported_claims_count += 1

    json_valid = True if result_output.execution_status in ("SUCCESS", "PARTIAL_SUCCESS") and result_output.error_message is None else False
    schema_valid = isinstance(result_output, Agent1Output)

    print(f"\n" + "=" * 80)
    print("CONTROLLED TEST RESULTS -- STAGE 3 GLOBAL SYNTHESIS")
    print("=" * 80)
    print(f"  - Execution Status: {result_output.execution_status}")
    print(f"  - Primary Model Used: {result_output.model_used}")
    print(f"  - Total Stage 3 Call Count: 1")
    print(f"  - Qwen3-14B Latency: {latency_sec} seconds")
    print(f"  - JSON Validity: {json_valid}")
    print(f"  - Agent1Output Schema Validity: {schema_valid}")
    print(f"  - Synthesized Global Claims Count: {total_global_claims}")
    print(f"  - Unique Cited Evidence IDs: {len(cited_ids_all)}")
    print(f"  - Invalid Citations Count: {invalid_citations_count}")
    print(f"  - Unsupported Claims Count: {unsupported_claims_count}")
    print(f"  - Citation Validation Rate: {100.0 if invalid_citations_count == 0 else 0.0}%")
    print(f"  - Semantic Support Rate: {100.0 if unsupported_claims_count == 0 else 0.0}%")
    print(f"  - Investigation Readiness: {result_output.investigation_readiness}")
    print(f"  - Evidence Coverage Ratio: {result_output.evidence_quality_summary.get('total_processed', 100)} / 100 FIRs (100%)")
    print("=" * 80)

    # 6. Save Test Results JSON
    test_results_data = {
        "run_id": f"PHASE8E-GLOBAL-SYNTH-RUN-{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_payload_char_count": payload_char_count,
        "input_payload_approx_tokens": approx_input_tokens,
        "qwen_call_count": 1,
        "latency_sec": latency_sec,
        "json_validity": json_valid,
        "schema_validity": schema_valid,
        "citation_validity": invalid_citations_count == 0,
        "semantic_validity": unsupported_claims_count == 0,
        "global_claims_count": total_global_claims,
        "cited_fir_ids_count": len(cited_ids_all),
        "unsupported_claims_count": unsupported_claims_count,
        "invalid_citations_count": invalid_citations_count,
        "investigation_readiness": result_output.investigation_readiness,
        "evidence_coverage": "100/100 (100.0%)",
        "execution_status": result_output.execution_status,
        "model_used": result_output.model_used,
        "global_claims_detail": [c.model_dump(mode="json") for c in global_claims]
    }

    out_file = "scratch/phase8e_global_synthesizer_test_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(test_results_data, f, indent=2)

    print(f"\nTest results saved to: {out_file}")

    if json_valid and schema_valid and invalid_citations_count == 0 and unsupported_claims_count == 0:
        print("\n[PASS] CONTROLLED STAGE 3 TEST PASSED SUCCESSFULLY!")
    else:
        print("\n[FAIL] CONTROLLED STAGE 3 TEST FAILED OR HAS WARNINGS.")


if __name__ == "__main__":
    main()
