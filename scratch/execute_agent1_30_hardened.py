"""
ARGUS — PHASE 8B: HARDENED AGENT 1 MULTI-BATCH WORKER PILOT
============================================================
30 REAL FIRs / 3 × 10-FIR WORKERS
Hardened Payload: Qwen3-8B + Native JSON Schema + repeat_penalty=1.15
Sequential worker execution with mandatory output commit -> checkpoint commit order.
Includes automated pilot restart / resume verification test.
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

def analyze_repetition(raw_text: str):
    if not raw_text:
        return False
    key_phrases = ["\"investigation_readiness\"", "\"claims\"", "CLM-AG1-001"]
    counts = {phrase: raw_text.count(phrase) for phrase in key_phrases}
    return max(counts.values()) > 1 if counts else False

def persist_claims_to_pg(case_id: str, batch_number: int, claims: list) -> bool:
    """Persists validated worker claims to PostgreSQL agent_outputs table."""
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

def execute_worker_pilot(run_id: str, dataset_30: list, is_resume_run: bool = False):
    case_id = "CASE-2020JIMMYWILSON-E01"
    checkpoint_mgr = Agent1CheckpointManager(run_id=run_id, agent_id="agent1_evidence_intelligence")
    completed_batches = checkpoint_mgr.get_completed_batches()

    batches = [
        ("BATCH-001", 1, dataset_30[0:10]),
        ("BATCH-002", 2, dataset_30[10:20]),
        ("BATCH-003", 3, dataset_30[20:30])
    ]

    telemetry_list = []
    qwen_calls_count = 0
    skipped_count = 0

    validator = Agent1Validator()

    for batch_id, batch_num, fir_batch in batches:
        print(f"\n--- Checking {batch_id} (Batch {batch_num}/3: {fir_batch[0].finding_id} .. {fir_batch[-1].finding_id}) ---")
        
        if checkpoint_mgr.is_batch_completed(batch_id):
            print(f"  [CHECKPOINT HIT]: Batch {batch_id} is ALREADY COMPLETED. Skipping Qwen invocation.")
            skipped_count += 1
            telemetry_list.append({
                "batch_id": batch_id,
                "batch_number": batch_num,
                "status": "SKIPPED_ALREADY_COMPLETED",
                "qwen_call_performed": False,
                "fir_count": len(fir_batch)
            })
            continue

        qwen_calls_count += 1
        print(f"  [EXECUTING WORKER]: Invoking Qwen3-8B for Batch {batch_id}...")

        # Construct XML Evidence Block directly from pre-sanitized facts (NO redundant gateway pass!)
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
                # Deterministic Claim ID Namespacing: CLM-W001-001, CLM-W001-002, etc.
                for idx, c in enumerate(raw_claims, start=1):
                    c.claim_id = f"CLM-W{batch_num:03d}-{idx:03d}"

                validated_claims = validator.validate_claims(
                    claims=raw_claims,
                    valid_finding_ids=valid_finding_ids,
                    valid_lineage_ids=valid_lineage_ids,
                    fir_map=fir_map
                )

        citation_verified_all = len(validated_claims) > 0 and all(c.citation_verified for c in validated_claims)
        semantic_support_all = len(validated_claims) > 0 and all(c.semantic_support_verified for c in validated_claims)

        batch_status = "FAILED"
        if json_parse_success and len(validated_claims) > 0 and citation_verified_all and semantic_support_all and not rep_detected:
            batch_status = "COMPLETED"
        elif json_parse_success and len(validated_claims) > 0:
            batch_status = "COMPLETED_WITH_FLAGS"
        elif not json_parse_success:
            batch_status = "FAILED_RETRYABLE"

        # ── REQUIRED ORDERING OF COMMITS ──────────────────────────────────
        # Step 1: Output Commit to agent_outputs table
        output_persisted = False
        if batch_status in ("COMPLETED", "COMPLETED_WITH_FLAGS"):
            output_persisted = persist_claims_to_pg(case_id, batch_num, validated_claims)

        # Step 2: Checkpoint Commit to agent_checkpoints table
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
            "schema_valid": json_parse_success and isinstance(parsed_json, dict) and "claims" in parsed_json,
            "exact_parse_error": exact_parse_error,
            "err_msg": err_msg,
            "claims_count": len(validated_claims),
            "namespaced_claim_ids": [c.claim_id for c in validated_claims],
            "citation_verification_passed": citation_verified_all,
            "semantic_support_passed": semantic_support_all,
            "investigation_readiness": extra_meta.get("investigation_readiness"),
            "repetition_detected": rep_detected,
            "status": batch_status,
            "output_persisted": output_persisted,
            "validated_claims": [c.model_dump() for c in validated_claims]
        }

        print(f"  --> Batch {batch_id} Result: {batch_status} | Latency: {wall_sec}s | Claims: {len(validated_claims)}")
        telemetry_list.append(telemetry)

    return {
        "run_id": run_id,
        "is_resume_run": is_resume_run,
        "qwen_calls_count": qwen_calls_count,
        "skipped_count": skipped_count,
        "telemetry_list": telemetry_list
    }

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 8B: HARDENED AGENT 1 MULTI-BATCH WORKER PILOT")
    print("=" * 80)

    # 1. Dataset Selection & Verification
    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, 'r', encoding='utf-8') as f:
        raw_json_data = json.load(f)

    assert len(raw_json_data) >= 30, f"Expected at least 30 findings, got {len(raw_json_data)}"
    raw_30 = raw_json_data[:30]

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

    print(f"[DATASET VERIFICATION]: 30 FIRs loaded from {json_path}")
    print(f"  Batch 001 (1-10) : {fir_objects[0].finding_id} .. {fir_objects[9].finding_id}")
    print(f"  Batch 002 (11-20): {fir_objects[10].finding_id} .. {fir_objects[19].finding_id}")
    print(f"  Batch 003 (21-30): {fir_objects[20].finding_id} .. {fir_objects[29].finding_id}")

    # 2. RUN PILOT EXECUTION (Run ID: PHASE8B-PILOT-RUN-001)
    run_id = f"PHASE8B-PILOT-RUN-{int(time.time())}"
    print(f"\n==================================================")
    print(f"[RUN 1]: Executing Worker Pilot (Run ID: {run_id})")
    print(f"==================================================")

    res1 = execute_worker_pilot(run_id, fir_objects, is_resume_run=False)

    out_file1 = ARGUS_ROOT / "scratch" / "phase8b_worker_pilot_results.json"
    with open(out_file1, "w", encoding="utf-8") as f:
        json.dump(res1, f, indent=2, default=str)

    print(f"\n[+] Saved Initial Pilot Results to: {out_file1}")
    print(f"  --> Qwen Calls Performed: {res1['qwen_calls_count']}")
    print(f"  --> Batches Skipped     : {res1['skipped_count']}")

    # 3. CONTROLLED PILOT RESTART / RESUME TEST
    print(f"\n==================================================")
    print(f"[RUN 2]: Executing Controlled Resume Test (Run ID: {run_id})")
    print(f"==================================================")

    res2 = execute_worker_pilot(run_id, fir_objects, is_resume_run=True)

    out_file2 = ARGUS_ROOT / "scratch" / "phase8b_resume_test_results.json"
    with open(out_file2, "w", encoding="utf-8") as f:
        json.dump(res2, f, indent=2, default=str)

    print(f"\n[+] Saved Resume Test Results to: {out_file2}")
    print(f"  --> Qwen Calls Performed during Resume: {res2['qwen_calls_count']}")
    print(f"  --> Batches Skipped during Resume    : {res2['skipped_count']}")

    # Verification of Resume Criteria
    resume_passed = res2['qwen_calls_count'] == 0 and res2['skipped_count'] == 3
    print(f"\n[RESUME TEST VERDICT]: {'PASS (0 New Calls, 3 Skipped)' if resume_passed else 'FAIL'}")

if __name__ == "__main__":
    main()
