"""
ARGUS — PHASE 7B: QWEN3-8B GENERATION HARDENING BENCHMARK
==========================================================
Tests generation controls independently on fixed 10-FIR Phase 7A Test A dataset:
  - CANDIDATE A: num_predict = 1536
  - CANDIDATE B: format = JSON Schema
  - CANDIDATE C: options = {"repeat_penalty": 1.15}

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

EXPECTED_FIR_IDS_TEST_A = [
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
    """
    Deterministically inspect output for repeated JSON objects or claim fragments.
    """
    if not raw_text:
        return {"repetition_detected": False, "repeated_patterns": [], "repetition_ratio": 0.0}

    # Count occurrences of key top-level JSON structures or claim headers
    key_phrases = ["\"investigation_readiness\"", "\"claims\"", "CLM-AG1-001"]
    counts = {phrase: raw_text.count(phrase) for phrase in key_phrases}
    
    max_count = max(counts.values()) if counts else 0
    repetition_detected = max_count > 1

    return {
        "repetition_detected": repetition_detected,
        "key_phrase_counts": counts,
        "max_key_phrase_count": max_count,
        "raw_char_len": len(raw_text)
    }

def run_candidate(fir_batch, candidate_id, candidate_name, payload_kwargs):
    print(f"\n==================================================")
    print(f"[{candidate_id}: {candidate_name}]")
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
    }
    payload.update(payload_kwargs)

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

    # repetition analysis
    rep_analysis = analyze_repetition(resp_str)

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
    readiness_valid = extra_meta.get("investigation_readiness") in ("READY", "LIMITED", "UNREADY")

    # Decision classification: PASS, FAIL, INCONCLUSIVE, NOT_AVAILABLE
    decision = "FAIL"
    if json_parse_success and len(validated_claims) > 0 and citation_verified_all and semantic_support_all and readiness_valid and not rep_analysis["repetition_detected"]:
        decision = "PASS"
    elif json_parse_success and (rep_analysis["repetition_detected"] or not citation_verified_all or not semantic_support_all):
        decision = "FAIL"
    elif not json_parse_success:
        decision = "FAIL"

    telemetry = {
        "candidate_id": candidate_id,
        "candidate_name": candidate_name,
        "payload_kwargs": payload_kwargs,
        "start_timestamp": start_ts,
        "end_timestamp": end_ts,
        "wall_clock_sec": wall_sec,
        "output_char_count": len(resp_str),
        "prompt_tokens": prompt_eval_count,
        "output_tokens": eval_count,
        "json_parse_success": json_parse_success,
        "exact_parse_error": exact_parse_error,
        "err_msg": err_msg,
        "claims_count": len(validated_claims),
        "cited_evidence_ids": cited_ids_all,
        "citation_verification_passed": citation_verified_all,
        "semantic_support_passed": semantic_support_all,
        "investigation_readiness": extra_meta.get("investigation_readiness"),
        "repetition_analysis": rep_analysis,
        "decision": decision,
        "raw_response": resp_str,
        "validated_claims": [c.model_dump() for c in validated_claims]
    }

    print(f"Latency: {wall_sec}s | Chars: {len(resp_str)} | Tokens: {eval_count}")
    print(f"JSON Parse Success: {json_parse_success}")
    if exact_parse_error:
        print(f"Parse Error: {exact_parse_error}")
    print(f"Claims Count: {len(validated_claims)}")
    print(f"Citation Verification: {citation_verified_all}")
    print(f"Semantic Support: {semantic_support_all}")
    print(f"Repetition Detected: {rep_analysis['repetition_detected']} (Max count: {rep_analysis['max_key_phrase_count']})")
    print(f"Decision: {decision}")

    return telemetry

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 7B: QWEN3-8B GENERATION HARDENING BENCHMARK")
    print("=" * 80)

    # 1. Inspect Ollama Version
    version_res = requests.get("http://localhost:11434/api/version").json()
    ollama_version = version_res.get("version", "UNKNOWN")
    print(f"[OLLAMA VERSION]: {ollama_version}")

    # 2. Fixed Dataset Verification
    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    raw_10 = raw_data[:10]
    actual_ids = [item["finding_id"] for item in raw_10]
    
    match = actual_ids == EXPECTED_FIR_IDS_TEST_A
    print(f"[FIXED DATASET VERIFICATION]: 10 FIRs loaded from {json_path}")
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

    # 3. Candidate A — Output Bound (num_predict = 1536)
    res_a = run_candidate(
        fir_objects,
        "CANDIDATE A",
        "OUTPUT BOUND (num_predict = 1536)",
        {
            "format": "json",
            "options": {"num_predict": 1536}
        }
    )

    # 4. Candidate B — Native JSON Schema
    # Check if Ollama API accepts JSON schema format parameter
    res_b = run_candidate(
        fir_objects,
        "CANDIDATE B",
        "NATIVE JSON SCHEMA (format = JSON Schema)",
        {
            "format": AGENT1_JSON_SCHEMA
        }
    )

    # 5. Candidate C — Repetition Control (repeat_penalty = 1.15)
    res_c = run_candidate(
        fir_objects,
        "CANDIDATE C",
        "REPETITION CONTROL (repeat_penalty = 1.15)",
        {
            "format": "json",
            "options": {"repeat_penalty": 1.15}
        }
    )

    phase7b_results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ollama_version": ollama_version,
        "dataset_verified": match,
        "candidate_a": res_a,
        "candidate_b": res_b,
        "candidate_c": res_c
    }

    out_file = ARGUS_ROOT / "scratch" / "phase7b_hardening_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(phase7b_results, f, indent=2, default=str)

    print("\n" + "=" * 80)
    print("PHASE 7B HARDENING BENCHMARK COMPLETED")
    print("=" * 80)
    print(f"Results saved to: {out_file}")

if __name__ == "__main__":
    main()
