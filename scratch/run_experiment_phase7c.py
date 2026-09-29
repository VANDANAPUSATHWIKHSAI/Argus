"""
ARGUS — PHASE 7C: COMBINED GENERATION HARDENING RELIABILITY TEST
==================================================================
Executes EXACTLY 5 independent Qwen3-8B generation calls using COMBINED controls:
  - format = Agent1Output JSON Schema
  - options = {"repeat_penalty": 1.15}

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
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent

EXPECTED_FIR_IDS = [
    "da2c8653-6488-4064-8b65-9be97b3503b6",
    "42c5a1ee-4c28-4e3e-97c1-cb362650f744",
    "ee1ca311-c86f-4509-8ced-c9a584f1faa3",
    "ec729017-262a-49e1-8098-d5146f5a39c0",
    "098db7dd-5a91-42c7-a6ab-81fbf67e999f",
    "51d11b01-626e-46b2-b434-08b41a5fec47",
    "1f3357ba-311d-4b54-8a4c-ab33ca14527c",
    "e68b1bdc-5bbd-4667-9e0e-80f04ac20970",
    "c46a00a3-11cd-42b6-ad88-f3937b9b617d",
    "f2fbda42-d7ed-487c-ac4a-6f3bda50defe"
]

AGENT1_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "investigation_readiness": {
            "type": "string",
            "enum": ["READY", "LIMITED", "UNREADY"]
        },
        "possible_analyses": {
            "type": "array",
            "items": {"type": "string"}
        },
        "performed_analyses": {
            "type": "array",
            "items": {"type": "string"}
        },
        "claims": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim_id": {"type": "string"},
                    "summary": {"type": "string"},
                    "findings_summary": {"type": "string"},
                    "cited_evidence_ids": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "assessed_importance": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "informational"]
                    },
                    "confidence_score": {"type": "number"},
                    "missing_evidence_noted": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "uncertainties_or_conflicts": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "reasoning_notes": {"type": "string"}
                },
                "required": ["claim_id", "summary", "findings_summary", "cited_evidence_ids", "assessed_importance", "confidence_score"]
            }
        }
    },
    "required": ["investigation_readiness", "possible_analyses", "performed_analyses", "claims"]
}

def analyze_repetition(raw_text: str):
    if not raw_text:
        return {"repetition_detected": False, "key_phrase_counts": {}, "max_key_phrase_count": 0}
    key_phrases = ["\"investigation_readiness\"", "\"claims\"", "CLM-AG1-001"]
    counts = {phrase: raw_text.count(phrase) for phrase in key_phrases}
    max_count = max(counts.values()) if counts else 0
    return {
        "repetition_detected": max_count > 1,
        "key_phrase_counts": counts,
        "max_key_phrase_count": max_count
    }

def run_single_combined_call(call_index, fir_batch):
    print(f"\n==================================================")
    print(f"[CALL {call_index} / 5]: Executing 10 FIRs with JSON Schema + repeat_penalty=1.15")
    print(f"==================================================")
    
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
        "format": AGENT1_JSON_SCHEMA,
        "options": {
            "repeat_penalty": 1.15
        }
    }

    start_ts = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    resp_obj = None
    resp_str = ""
    err_msg = None

    try:
        r = requests.post(url, json=payload, timeout=600)
        t1 = time.time()
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

    rep_analysis = analyze_repetition(resp_str)
    truncation_detected = bool(exact_parse_error and ("Unterminated" in exact_parse_error or "delimiter" in exact_parse_error))

    validator = Agent1Validator()
    fir_map = {f.finding_id: f for f in fir_batch}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(fir_batch)
    valid_universe = valid_finding_ids.union(valid_lineage_ids)

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
    out_of_bounds_ids = []
    for c in validated_claims:
        cited_ids_all.extend(c.cited_evidence_ids)
        for cid in c.cited_evidence_ids:
            if cid not in valid_universe:
                out_of_bounds_ids.append(cid)

    citation_verified_all = len(validated_claims) > 0 and all(c.citation_verified for c in validated_claims)
    semantic_support_all = len(validated_claims) > 0 and all(c.semantic_support_verified for c in validated_claims)
    readiness_valid = extra_meta.get("investigation_readiness") in ("READY", "LIMITED", "UNREADY")
    schema_valid = json_parse_success and isinstance(parsed_json, dict) and "claims" in parsed_json and "investigation_readiness" in parsed_json

    call_success = (
        json_parse_success and
        schema_valid and
        len(validated_claims) > 0 and
        citation_verified_all and
        semantic_support_all and
        readiness_valid and
        not rep_analysis["repetition_detected"] and
        not truncation_detected and
        len(out_of_bounds_ids) == 0
    )

    telemetry = {
        "call_number": call_index,
        "start_timestamp": start_ts,
        "end_timestamp": end_ts,
        "wall_clock_sec": wall_sec,
        "input_fir_count": len(fir_batch),
        "fir_ids": [f.finding_id for f in fir_batch],
        "output_char_count": len(resp_str),
        "prompt_tokens": prompt_eval_count,
        "output_tokens": eval_count,
        "json_parse_success": json_parse_success,
        "schema_valid": schema_valid,
        "exact_parse_error": exact_parse_error,
        "err_msg": err_msg,
        "claims_count": len(validated_claims),
        "cited_evidence_ids": cited_ids_all,
        "out_of_bounds_evidence_ids": out_of_bounds_ids,
        "citation_verification_passed": citation_verified_all,
        "semantic_support_passed": semantic_support_all,
        "investigation_readiness": extra_meta.get("investigation_readiness"),
        "repetition_detected": rep_analysis["repetition_detected"],
        "truncation_detected": truncation_detected,
        "call_success": call_success,
        "raw_response": resp_str,
        "validated_claims": [c.model_dump() for c in validated_claims]
    }

    print(f"Call {call_index} Result: {'SUCCESS' if call_success else 'FAIL'}")
    print(f"Latency: {wall_sec}s | Chars: {len(resp_str)} | Tokens: {eval_count}")
    print(f"JSON Valid: {json_parse_success} | Schema Valid: {schema_valid}")
    print(f"Claims: {len(validated_claims)} | Citation Pass: {citation_verified_all} | Semantic Pass: {semantic_support_all}")
    print(f"Repetition Detected: {rep_analysis['repetition_detected']} | Truncation: {truncation_detected}")

    return telemetry

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 7C: COMBINED GENERATION HARDENING RELIABILITY TEST")
    print("=" * 80)

    # 1. Dataset Verification
    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    raw_10 = raw_data[:10]
    actual_ids = [item["finding_id"] for item in raw_10]
    match = actual_ids == EXPECTED_FIR_IDS
    print(f"[DATASET VERIFICATION]: 10 FIRs loaded from {json_path}")
    print(f"  Exact Match with Phase 7A Test A: {match}")
    if not match:
        print("ERROR: FIR IDs do not match Phase 7A Test A! Aborting.")
        sys.exit(1)

    fir_objects = []
    for item in raw_10:
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

    # 2. Run Exactly 5 Calls
    call_results = []
    for i in range(1, 6):
        res = run_single_combined_call(i, fir_objects)
        call_results.append(res)

    successful_calls = sum(1 for c in call_results if c["call_success"])
    failed_calls = 5 - successful_calls
    success_rate = (successful_calls / 5.0) * 100.0

    latencies = [c["wall_clock_sec"] for c in call_results]
    token_counts = [c["output_tokens"] for c in call_results if c["output_tokens"] is not None]

    avg_latency = round(sum(latencies) / len(latencies), 2)
    avg_tokens = round(sum(token_counts) / len(token_counts), 2) if token_counts else 0.0

    overall_decision = "PASS" if successful_calls == 5 else "FAIL"

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_calls": 5,
        "successful_calls": successful_calls,
        "failed_calls": failed_calls,
        "observed_success_rate_pct": success_rate,
        "avg_wall_clock_latency_sec": avg_latency,
        "avg_output_tokens": avg_tokens,
        "overall_decision": overall_decision,
        "call_results": call_results
    }

    out_file = ARGUS_ROOT / "scratch" / "phase7c_combined_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    print("\n" + "=" * 80)
    print("PHASE 7C COMBINED RELIABILITY TEST COMPLETED")
    print("=" * 80)
    print(f"Results saved to: {out_file}")
    print(f"Observed Success: {successful_calls}/5 ({success_rate:.1f}%)")
    print(f"Avg Latency: {avg_latency}s | Avg Tokens: {avg_tokens}")
    print(f"Overall Decision: {overall_decision}")

if __name__ == "__main__":
    main()
