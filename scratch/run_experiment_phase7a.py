"""
ARGUS — PHASE 7A: 10-FIR MICRO-BATCH RELIABILITY BENCHMARK
==========================================================
Executes exactly 3 real Qwen3-8B calls via Ollama format="json":
  - TEST A: FIR 1–10
  - TEST B: FIR 11–20
  - TEST C: FIR 21–30

READ-ONLY benchmark — no database persistence, no code mutations.
"""

import sys
import os
import time
import json
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from fir.schemas import FIRFinding
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.schemas import Agent1Output, Agent1Claim
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent

def run_single_test_call(fir_batch, test_name):
    print(f"\n==================================================")
    print(f"[{test_name}]: Executing {len(fir_batch)} FIR findings with Ollama format='json'")
    print(f"==================================================")
    fir_ids = [f.finding_id for f in fir_batch]
    print(f"FIR IDs ({len(fir_ids)}): {fir_ids}")

    xml_blocks_list = []
    for f in fir_batch:
        fid = f.finding_id
        layer = f.layer
        fact_text = f.sanitized_fact or f.fact
        xml_blocks_list.append(f'<evidence_item><finding_id>{fid}</finding_id><layer>{layer}</layer><fact>{fact_text}</fact></evidence_item>')
    xml_blocks = "\n".join(xml_blocks_list)

    case_id = "CASE-2020JIMMYWILSON-E01"
    user_prompt = build_agent1_user_prompt(case_id, xml_blocks)
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen3:8b",
        "prompt": user_prompt,
        "system": AGENT1_SYSTEM_PROMPT,
        "stream": False,
        "format": "json"
    }

    start_ts = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    resp_obj = None
    resp_str = ""
    err_msg = None
    http_status = None

    try:
        r = requests.post(url, json=payload, timeout=600)
        t1 = time.time()
        http_status = r.status_code
        if r.status_code == 200:
            resp_obj = r.json()
            resp_str = resp_obj.get("response", "")
        else:
            err_msg = f"HTTP Error {r.status_code}: {r.text}"
    except Exception as exc:
        t1 = time.time()
        err_msg = str(exc)

    end_ts = datetime.now(timezone.utc).isoformat()
    wall_sec = round(t1 - t0, 2)

    prompt_eval_count = resp_obj.get("prompt_eval_count") if resp_obj else None
    eval_count = resp_obj.get("eval_count") if resp_obj else None

    # Parse JSON
    json_parse_success = False
    parsed_json = None
    exact_parse_error = None

    if resp_str:
        try:
            parsed_json = json.loads(resp_str)
            json_parse_success = True
        except Exception as err:
            exact_parse_error = str(err)
            err_msg = f"JSON Parse Error: {str(err)}"
    else:
        if not err_msg:
            err_msg = "Empty response from Ollama"

    # Validate using Agent1Validator and EvidenceIntelligenceAgent parser
    validator = Agent1Validator()
    fir_map = {f.finding_id: f for f in fir_batch}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(fir_batch)

    raw_claims = []
    validated_claims = []
    extra_meta = {}

    if json_parse_success and isinstance(parsed_json, dict):
        mock_model = lambda p: resp_str
        agent = EvidenceIntelligenceAgent(model=mock_model, fir_repo=None, sanitization_gateway=None, tenant_id="default")
        raw_claims, extra_meta, p_err = agent._parse_json_claims_and_meta(resp_str)
        if raw_claims:
            validated_claims = validator.validate_claims(
                claims=raw_claims,
                valid_finding_ids=valid_finding_ids,
                valid_lineage_ids=valid_lineage_ids,
                fir_map=fir_map
            )

    cited_ids_all = []
    for c in validated_claims:
        cited_ids_all.extend(c.cited_evidence_ids)

    citation_verified_all = len(validated_claims) > 0 and all(c.citation_verified for c in validated_claims)
    semantic_support_all = len(validated_claims) > 0 and all(c.semantic_support_verified for c in validated_claims)

    telemetry = {
        "test_name": test_name,
        "start_timestamp": start_ts,
        "end_timestamp": end_ts,
        "wall_clock_sec": wall_sec,
        "model": "qwen3:8b",
        "input_fir_count": len(fir_batch),
        "fir_ids": fir_ids,
        "output_char_count": len(resp_str),
        "prompt_tokens": prompt_eval_count,
        "output_tokens": eval_count,
        "json_parse_success": json_parse_success,
        "exact_parse_error": exact_parse_error,
        "err_msg": err_msg,
        "claims_count": len(validated_claims),
        "total_cited_evidence_ids": len(cited_ids_all),
        "cited_evidence_ids": cited_ids_all,
        "citation_verification_passed": citation_verified_all,
        "semantic_support_passed": semantic_support_all,
        "investigation_readiness": extra_meta.get("investigation_readiness"),
        "evidence_trust_score": extra_meta.get("evidence_trust_score"),
        "possible_analyses": extra_meta.get("possible_analyses"),
        "performed_analyses": extra_meta.get("performed_analyses"),
        "raw_response": resp_str,
        "validated_claims": [c.model_dump() for c in validated_claims]
    }

    print(f"Start: {start_ts} | End: {end_ts}")
    print(f"Wall-clock Latency: {wall_sec} s")
    print(f"Output Chars: {len(resp_str)} | Output Tokens: {eval_count}")
    print(f"JSON Parse Success: {json_parse_success}")
    if exact_parse_error:
        print(f"Exact Parse Error: {exact_parse_error}")
    print(f"Claims Count: {len(validated_claims)}")
    print(f"Citation Verification Passed: {citation_verified_all}")
    print(f"Semantic Support Passed: {semantic_support_all}")
    print(f"Investigation Readiness: {extra_meta.get('investigation_readiness')}")

    return telemetry

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 7A: 10-FIR MICRO-BATCH RELIABILITY BENCHMARK")
    print("=" * 80)

    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    # Deterministic Selection: 30 FIRs (1-10 = Test A, 11-20 = Test B, 21-30 = Test C)
    raw_30 = raw_data[:30]

    fir_objects = []
    for item in raw_30:
        fid = item["finding_id"]
        ev_ref = item.get("evidence_reference") or ["EVID-3286-DEFAULT"]
        if isinstance(ev_ref, str):
            ev_ref = [ev_ref]

        ts_str = item.get("timestamp")
        parsed_ts = None
        if ts_str:
            try:
                parsed_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                parsed_ts = datetime.now(timezone.utc)

        finding_obj = FIRFinding(
            finding_id=fid,
            case_id=item.get("case_id", "CASE-2020JIMMYWILSON-E01"),
            tenant_id=item.get("tenant_id", "default"),
            fact=item.get("sanitized_fact") or "Filesystem artifact record",
            sanitized_fact=item.get("sanitized_fact"),
            injection_flagged=item.get("injection_flagged", False),
            injection_score=item.get("injection_score", 0.0),
            confidence=item.get("confidence", 0.88),
            severity=item.get("severity", "informational"),
            mitre_mapping=item.get("mitre_mapping"),
            timestamp=parsed_ts,
            evidence_reference=ev_ref,
            layer=item.get("layer", "endpoint.filesystem_analyzer"),
            source_artifact_id=item.get("source_artifact_id")
        )
        fir_objects.append(finding_obj)

    test_a_firs = fir_objects[0:10]
    test_b_firs = fir_objects[10:20]
    test_c_firs = fir_objects[20:30]

    print(f"[DATASET SELECTION]: 30 real FIR Findings loaded deterministically from {json_path}")
    print(f"  --> TEST A: 10 FIRs ({test_a_firs[0].finding_id} .. {test_a_firs[-1].finding_id})")
    print(f"  --> TEST B: 10 FIRs ({test_b_firs[0].finding_id} .. {test_b_firs[-1].finding_id})")
    print(f"  --> TEST C: 10 FIRs ({test_c_firs[0].finding_id} .. {test_c_firs[-1].finding_id})")

    # TEST A
    res_a = run_single_test_call(test_a_firs, "TEST A (FIR 1-10)")

    # TEST B
    res_b = run_single_test_call(test_b_firs, "TEST B (FIR 11-20)")

    # TEST C
    res_c = run_single_test_call(test_c_firs, "TEST C (FIR 21-30)")

    # Aggregated Summary
    telemetry_all = [res_a, res_b, res_c]
    successful_calls = sum(1 for r in telemetry_all if r["json_parse_success"])
    failed_calls = 3 - successful_calls
    success_rate = (successful_calls / 3.0) * 100.0

    latencies = [r["wall_clock_sec"] for r in telemetry_all]
    successful_latencies = [r["wall_clock_sec"] for r in telemetry_all if r["json_parse_success"]]
    char_counts = [r["output_char_count"] for r in telemetry_all]
    successful_char_counts = [r["output_char_count"] for r in telemetry_all if r["json_parse_success"]]

    avg_latency = round(sum(latencies) / len(latencies), 2)
    avg_success_latency = round(sum(successful_latencies) / len(successful_latencies), 2) if successful_latencies else 0.0
    min_latency = min(latencies)
    max_latency = max(latencies)
    sorted_latencies = sorted(latencies)
    median_latency = sorted_latencies[1]

    avg_chars = round(sum(char_counts) / len(char_counts), 2)
    max_chars = max(char_counts)

    claims_per_successful_call = [r["claims_count"] for r in telemetry_all if r["json_parse_success"]]
    avg_claims = round(sum(claims_per_successful_call) / len(claims_per_successful_call), 2) if claims_per_successful_call else 0.0

    citation_verif_rate = (sum(1 for r in telemetry_all if r["citation_verification_passed"]) / float(successful_calls or 1)) * 100.0
    semantic_verif_rate = (sum(1 for r in telemetry_all if r["semantic_support_passed"]) / float(successful_calls or 1)) * 100.0

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_calls": 3,
        "successful_json_calls": successful_calls,
        "failed_json_calls": failed_calls,
        "observed_json_success_rate_pct": success_rate,
        "avg_wall_clock_latency_sec": avg_latency,
        "avg_successful_latency_sec": avg_success_latency,
        "median_latency_sec": median_latency,
        "min_latency_sec": min_latency,
        "max_latency_sec": max_latency,
        "avg_output_chars": avg_chars,
        "max_output_chars": max_chars,
        "avg_claims_per_successful_call": avg_claims,
        "citation_verification_success_rate_pct": citation_verif_rate,
        "semantic_validation_success_rate_pct": semantic_verif_rate,
        "test_a": res_a,
        "test_b": res_b,
        "test_c": res_c
    }

    out_file = ARGUS_ROOT / "scratch" / "phase7a_10fir_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    print("\n" + "=" * 80)
    print("PHASE 7A EXPERIMENT COMPLETED")
    print("=" * 80)
    print(f"Results saved to: {out_file}")
    print(f"Observed Success Rate: {successful_calls}/3 ({success_rate:.1f}%)")
    print(f"Avg Latency: {avg_latency}s | Min: {min_latency}s | Max: {max_latency}s | Median: {median_latency}s")
    print(f"Max Chars: {max_chars} | Avg Chars: {avg_chars}")

if __name__ == "__main__":
    main()
