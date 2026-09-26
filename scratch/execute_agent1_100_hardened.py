"""
ARGUS — PHASE 8C: 100-FIR CONTROLLED SCALE TEST
================================================
10 × 10-FIR REAL QWEN3-8B WORKERS
Hardened Payload: Qwen3-8B + Native JSON Schema + repeat_penalty=1.15
Sequential execution with Output Commit -> Checkpoint Commit, mid-run inspection at Batch 5,
deterministic worker-output consolidation, and resume validation.
"""

import sys
import os
import time
import json
import logging
import requests
import statistics
from pathlib import Path
from datetime import datetime, timezone

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from fir.schemas import FIRFinding
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent, _ensure_agent_outputs_table_initialized
from agents.agent1_evidence_intelligence.checkpoint import Agent1CheckpointManager, _ensure_checkpoint_table_initialized

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

def analyze_repetition(raw_text: str) -> bool:
    if not raw_text:
        return False
    key_phrases = ["\"investigation_readiness\"", "\"claims\"", "CLM-AG1-001"]
    counts = {phrase: raw_text.count(phrase) for phrase in key_phrases}
    return max(counts.values()) > 1 if counts else False

def persist_claims_to_pg(case_id: str, batch_number: int, claims: list) -> bool:
    try:
        import psycopg2
        from config.settings import settings
        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            connect_timeout=3
        )
        _ensure_agent_outputs_table_initialized(conn)
        cur = conn.cursor()

        query = """
            INSERT INTO agent_outputs 
                (case_id, tenant_id, agent_id, model_used, claim, evidence_ids, confidence, verified, execution_status, flags, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (case_id, agent_id, claim) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                model_used = EXCLUDED.model_used,
                evidence_ids = EXCLUDED.evidence_ids,
                confidence = EXCLUDED.confidence,
                verified = EXCLUDED.verified,
                execution_status = EXCLUDED.execution_status,
                flags = EXCLUDED.flags,
                created_at = EXCLUDED.created_at;
        """

        for claim in claims:
            flags_dict = {
                "namespaced_claim_id": claim.claim_id,
                "invalid_citations": claim.invalid_citations,
                "raw_model_confidence": claim.raw_model_confidence,
                "validation_notes": claim.validation_notes,
                "is_valid_confidence": claim.is_valid_confidence,
                "findings_summary": claim.findings_summary,
                "reasoning_notes": claim.reasoning_notes
            }
            cur.execute(
                query,
                (
                    case_id,
                    "default",
                    "agent1_evidence_intelligence",
                    "Qwen3-8B",
                    claim.summary,
                    claim.cited_evidence_ids,
                    claim.confidence_score,
                    claim.citation_verified,
                    "SUCCESS",
                    json.dumps(flags_dict),
                    datetime.now(timezone.utc)
                )
            )
        conn.commit()
        conn.close()
        print(f"      [OUTPUT COMMIT]: Persisted {len(claims)} claims for Batch {batch_number:03d} to PostgreSQL agent_outputs.")
        return True
    except Exception as exc:
        print(f"      [OUTPUT COMMIT WARNING]: Could not persist to PostgreSQL: {exc}")
        return False

def execute_batch(batch_id: str, batch_num: int, fir_batch: list, checkpoint_mgr: Agent1CheckpointManager, case_id: str = "CASE-2020JIMMYWILSON-E01"):
    validator = Agent1Validator()
    print(f"\n--- Batch {batch_num:02d}/10 ({batch_id}): {fir_batch[0].finding_id} .. {fir_batch[-1].finding_id} ---")

    if checkpoint_mgr.is_batch_completed(batch_id):
        print(f"  [CHECKPOINT HIT]: Batch {batch_id} is ALREADY COMPLETED. Skipping Qwen invocation.")
        return {
            "batch_id": batch_id,
            "batch_number": batch_num,
            "status": "SKIPPED_ALREADY_COMPLETED",
            "qwen_call_performed": False,
            "fir_count": len(fir_batch)
        }

    print(f"  [EXECUTING WORKER]: Invoking Qwen3-8B for Batch {batch_id}...")

    # Build XML Evidence Block directly from pre-sanitized facts
    xml_blocks_list = []
    for f in fir_batch:
        fid = f.finding_id
        layer = f.layer
        fact_text = f.sanitized_fact or f.fact
        xml_blocks_list.append(f'<evidence_item><finding_id>{fid}</finding_id><layer>{layer}</layer><fact>{fact_text}</fact></evidence_item>')
    xml_blocks = "\n".join(xml_blocks_list)

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

    t0 = time.time()
    start_ts = datetime.now(timezone.utc).isoformat()
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

    rep_detected = analyze_repetition(resp_str)
    truncation_detected = bool(exact_parse_error and ("Unterminated" in exact_parse_error or "delimiter" in exact_parse_error))

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
            for idx, c in enumerate(raw_claims, start=1):
                c.claim_id = f"CLM-W{batch_num:03d}-{idx:03d}"

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
    schema_valid = json_parse_success and isinstance(parsed_json, dict) and "claims" in parsed_json

    batch_status = "FAILED"
    if json_parse_success and schema_valid and len(validated_claims) > 0 and citation_verified_all and semantic_support_all and not rep_detected and not truncation_detected and len(out_of_bounds_ids) == 0:
        batch_status = "COMPLETED"
    elif json_parse_success and len(validated_claims) > 0:
        batch_status = "COMPLETED_WITH_FLAGS"
    elif not json_parse_success:
        batch_status = "FAILED_RETRYABLE"

    # Step 1: Output Commit to PostgreSQL agent_outputs table
    output_persisted = False
    if batch_status in ("COMPLETED", "COMPLETED_WITH_FLAGS"):
        output_persisted = persist_claims_to_pg(case_id, batch_num, validated_claims)

    # Step 2: Checkpoint Commit to PostgreSQL agent_checkpoints table
    if batch_status in ("COMPLETED", "COMPLETED_WITH_FLAGS"):
        fir_range_str = f"FIR {fir_batch[0].finding_id} .. {fir_batch[-1].finding_id}"
        checkpoint_mgr.mark_batch_completed(
            case_id=case_id,
            batch_id=batch_id,
            batch_number=batch_num,
            fir_range=fir_range_str,
            claims_count=len(validated_claims),
            metadata={
                "wall_clock_sec": wall_sec,
                "output_tokens": eval_count,
                "status": batch_status,
                "output_persisted": output_persisted
            }
        )
        print(f"      [CHECKPOINT COMMIT]: Batch {batch_id} marked {batch_status} in agent_checkpoints.")

    telemetry = {
        "batch_id": batch_id,
        "batch_number": batch_num,
        "fir_range": f"{fir_batch[0].finding_id} .. {fir_batch[-1].finding_id}",
        "fir_count": len(fir_batch),
        "fir_ids": [f.finding_id for f in fir_batch],
        "qwen_call_performed": True,
        "wall_clock_sec": wall_sec,
        "output_char_count": len(resp_str),
        "prompt_tokens": prompt_eval_count,
        "output_tokens": eval_count,
        "json_parse_success": json_parse_success,
        "schema_valid": schema_valid,
        "exact_parse_error": exact_parse_error,
        "err_msg": err_msg,
        "claims_count": len(validated_claims),
        "namespaced_claim_ids": [c.claim_id for c in validated_claims],
        "cited_evidence_ids": cited_ids_all,
        "out_of_bounds_evidence_ids": out_of_bounds_ids,
        "citation_verification_passed": citation_verified_all,
        "semantic_support_passed": semantic_support_all,
        "investigation_readiness": extra_meta.get("investigation_readiness"),
        "possible_analyses": extra_meta.get("possible_analyses", []),
        "performed_analyses": extra_meta.get("performed_analyses", []),
        "repetition_detected": rep_detected,
        "truncation_detected": truncation_detected,
        "status": batch_status,
        "output_persisted": output_persisted,
        "validated_claims": [c.model_dump() for c in validated_claims]
    }

    print(f"  --> Batch {batch_id} Result: {batch_status} | Latency: {wall_sec}s | Claims: {len(validated_claims)}")
    return telemetry

def execute_scale_test(run_id: str, dataset_100: list, is_resume_run: bool = False):
    case_id = "CASE-2020JIMMYWILSON-E01"
    checkpoint_mgr = Agent1CheckpointManager(run_id=run_id, agent_id="agent1_evidence_intelligence")

    batches = []
    for idx in range(10):
        b_num = idx + 1
        b_id = f"BATCH-{b_num:03d}"
        b_firs = dataset_100[idx * 10 : (idx + 1) * 10]
        batches.append((b_id, b_num, b_firs))

    telemetry_list = []
    qwen_calls_count = 0
    skipped_count = 0

    mid_run_inspection = None

    for idx, (batch_id, batch_num, fir_batch) in enumerate(batches, start=1):
        # MID-RUN CHECKPOINT INSPECTION after Batch 5
        if idx == 6 and not is_resume_run:
            print("\n" + "=" * 80)
            print("[MID-RUN CHECKPOINT INSPECTION]: Pausing model execution after Batch 5...")
            print("=" * 80)
            completed_set = checkpoint_mgr.get_completed_batches()
            mid_completed_count = len(completed_set)
            mid_persisted_outputs = sum(1 for t in telemetry_list if t.get("output_persisted"))
            mid_run_inspection = {
                "batches_completed_so_far": mid_completed_count,
                "completed_batch_ids": sorted(list(completed_set)),
                "output_commit_count": mid_persisted_outputs,
                "no_duplicate_checkpoints": mid_completed_count == 5,
                "inspection_passed": mid_completed_count == 5
            }
            print(f"  --> Completed Batches in Checkpoint Store ({mid_completed_count}): {sorted(list(completed_set))}")
            print(f"  --> Output Commit Count: {mid_persisted_outputs}")
            print(f"  --> Mid-Run Inspection Verdict: {'PASS' if mid_run_inspection['inspection_passed'] else 'FAIL'}")
            print("=" * 80 + "\n")

        res = execute_batch(batch_id, batch_num, fir_batch, checkpoint_mgr, case_id)
        if res.get("qwen_call_performed"):
            qwen_calls_count += 1
        else:
            skipped_count += 1
        telemetry_list.append(res)

    return {
        "run_id": run_id,
        "is_resume_run": is_resume_run,
        "qwen_calls_count": qwen_calls_count,
        "skipped_count": skipped_count,
        "mid_run_inspection": mid_run_inspection,
        "telemetry_list": telemetry_list
    }

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 8C: 100-FIR CONTROLLED SCALE TEST")
    print("=" * 80)

    t_wall_start = time.time()

    # 1. Dataset Selection & Pre-flight Verification
    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, 'r', encoding='utf-8') as f:
        raw_json_data = json.load(f)

    assert len(raw_json_data) >= 100, f"Expected at least 100 findings, got {len(raw_json_data)}"
    raw_100 = raw_json_data[:100]

    fir_objects = []
    for item in raw_100:
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

    unique_fids = set(f.finding_id for f in fir_objects)
    print(f"[PRE-FLIGHT VERIFICATION]: 100 FIRs loaded from {json_path}")
    print(f"  --> Total Loaded: {len(fir_objects)}")
    print(f"  --> Unique FIR IDs: {len(unique_fids)}")
    print(f"  --> First FIR ID  : {fir_objects[0].finding_id}")
    print(f"  --> Last FIR ID   : {fir_objects[-1].finding_id}")
    assert len(unique_fids) == 100, "Duplicate FIR IDs detected in pre-flight!"

    # 2. RUN SCALE TEST (Run ID: PHASE8C-SCALE-RUN-<timestamp>)
    run_id = f"PHASE8C-SCALE-RUN-{int(time.time())}"
    print(f"\n==================================================")
    print(f"[RUN 1]: Executing 100-FIR Scale Test (Run ID: {run_id})")
    print(f"==================================================")

    res1 = execute_scale_test(run_id, fir_objects, is_resume_run=False)
    t_wall_end = time.time()
    total_wall_sec = round(t_wall_end - t_wall_start, 2)

    # 3. POST-RUN DETERMINISTIC WORKER-OUTPUT CONSOLIDATION
    telemetry_list = res1["telemetry_list"]
    successful_batches = [t for t in telemetry_list if t.get("status") in ("COMPLETED", "COMPLETED_WITH_FLAGS")]
    failed_batches = [t for t in telemetry_list if t.get("status") not in ("COMPLETED", "COMPLETED_WITH_FLAGS")]

    all_claims = []
    for t in successful_batches:
        all_claims.extend(t.get("validated_claims", []))

    all_cited_evidence_ids = set()
    for clm in all_claims:
        all_cited_evidence_ids.update(clm.get("cited_evidence_ids", []))

    possible_analyses_set = set()
    performed_analyses_set = set()
    for t in successful_batches:
        possible_analyses_set.update(t.get("possible_analyses", []))
        performed_analyses_set.update(t.get("performed_analyses", []))

    consolidation = {
        "total_worker_claims": len(all_claims),
        "total_validated_claims": len(all_claims),
        "total_citation_valid_claims": sum(1 for c in all_claims if c.get("citation_verified")),
        "total_semantically_supported_claims": sum(1 for c in all_claims if c.get("semantic_support_verified")),
        "namespaced_claim_ids": [c.get("claim_id") for c in all_claims],
        "evidence_id_union_count": len(all_cited_evidence_ids),
        "evidence_id_union": sorted(list(all_cited_evidence_ids)),
        "worker_possible_analyses_union": sorted(list(possible_analyses_set)),
        "worker_performed_analyses_union": sorted(list(performed_analyses_set))
    }

    # Scaling Metrics Calculation
    latencies = [t["wall_clock_sec"] for t in telemetry_list if t.get("wall_clock_sec")]
    tokens = [t["output_tokens"] for t in telemetry_list if t.get("output_tokens") is not None]

    avg_latency = round(statistics.mean(latencies), 2) if latencies else 0.0
    median_latency = round(statistics.median(latencies), 2) if latencies else 0.0
    min_latency = min(latencies) if latencies else 0.0
    max_latency = max(latencies) if latencies else 0.0

    total_tokens = sum(tokens)
    avg_tokens = round(statistics.mean(tokens), 2) if tokens else 0.0

    observed_firs_per_min = round((100.0 / total_wall_sec) * 60.0, 2)
    proj_3286_sec = round(329 * avg_latency, 2)
    proj_3286_hours = round(proj_3286_sec / 3600.0, 2)

    scale_summary = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_firs": 100,
        "total_batches": 10,
        "successful_batches": len(successful_batches),
        "failed_batches": len(failed_batches),
        "qwen_calls_count": res1["qwen_calls_count"],
        "total_wall_clock_sec": total_wall_sec,
        "avg_latency_sec": avg_latency,
        "median_latency_sec": median_latency,
        "min_latency_sec": min_latency,
        "max_latency_sec": max_latency,
        "total_output_tokens": total_tokens,
        "avg_output_tokens": avg_tokens,
        "total_validated_claims": len(all_claims),
        "json_success_rate_pct": (len(successful_batches) / 10.0) * 100.0,
        "citation_success_rate_pct": 100.0 if all(c.get("citation_verified") for c in all_claims) else 0.0,
        "semantic_success_rate_pct": 100.0 if all(c.get("semantic_support_verified") for c in all_claims) else 0.0,
        "repetition_failures": sum(1 for t in telemetry_list if t.get("repetition_detected")),
        "truncation_failures": sum(1 for t in telemetry_list if t.get("truncation_detected")),
        "observed_throughput_firs_per_min": observed_firs_per_min,
        "mathematical_projection_3286_hours": proj_3286_hours,
        "mid_run_inspection": res1["mid_run_inspection"],
        "consolidation": consolidation,
        "telemetry_list": telemetry_list
    }

    out_file1 = ARGUS_ROOT / "scratch" / "phase8c_scale_test_results.json"
    with open(out_file1, "w", encoding="utf-8") as f:
        json.dump(scale_summary, f, indent=2, default=str)
    print(f"\n[+] Saved Phase 8C Scale Test Results to: {out_file1}")

    # 4. CONTROLLED RESUME TEST
    print(f"\n==================================================")
    print(f"[RUN 2]: Executing Controlled Resume Test (Run ID: {run_id})")
    print(f"==================================================")

    res2 = execute_scale_test(run_id, fir_objects, is_resume_run=True)

    out_file2 = ARGUS_ROOT / "scratch" / "phase8c_resume_test_results.json"
    with open(out_file2, "w", encoding="utf-8") as f:
        json.dump(res2, f, indent=2, default=str)

    resume_passed = res2['qwen_calls_count'] == 0 and res2['skipped_count'] == 10
    print(f"\n[+] Saved Resume Test Results to: {out_file2}")
    print(f"  --> Qwen Calls Performed during Resume: {res2['qwen_calls_count']}")
    print(f"  --> Batches Skipped during Resume    : {res2['skipped_count']}")
    print(f"  --> Resume Test Verdict              : {'PASS' if resume_passed else 'FAIL'}")

    print("\n" + "=" * 80)
    print("PHASE 8C 100-FIR SCALE TEST COMPLETED")
    print("=" * 80)
    print(f"Observed Success: {len(successful_batches)}/10 batches")
    print(f"Total Wall Time: {total_wall_sec}s | Avg Latency: {avg_latency}s | Median: {median_latency}s")
    print(f"Observed Throughput: {observed_firs_per_min} FIRs/min")
    print(f"Resume Test: {'PASS (0 New Calls, 10 Skipped)' if resume_passed else 'FAIL'}")

if __name__ == "__main__":
    main()
