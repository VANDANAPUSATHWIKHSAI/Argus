"""
ARGUS — PHASE 6: TWO 20-FIR SUB-BATCH CONSOLIDATION EXPERIMENT
===============================================================
Executes exactly 2 real Qwen3-8B calls via Ollama format="json":
  - Call 1: Batch A (FIR 1-20)
  - Call 2: Batch B (FIR 21-40)
Performs deterministic read-only consolidation analysis without third LLM call or DB persistence.
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("phase6_experiment")

from fir.schemas import FIRFinding
from sanitization.gateway import SanitizationGateway
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.schemas import Agent1Output, Agent1Claim
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent

def run_single_subbatch(fir_batch, batch_name):
    print(f"\n[QWEN CALL for {batch_name}]: Executing {len(fir_batch)} FIR findings with format='json'...")
    xml_blocks_list = []
    for f in fir_batch:
        fid = f.finding_id
        layer = f.layer
        fact_text = f.sanitized_fact or f.fact
        xml_blocks_list.append(f'<evidence_item><finding_id>{fid}</finding_id><layer>{layer}</layer><fact>{fact_text}</fact></evidence_item>')
    xml_blocks = "\n".join(xml_blocks_list)

    user_prompt = build_agent1_user_prompt("CASE-2020JIMMYWILSON-E01", xml_blocks)
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen3:8b",
        "prompt": user_prompt,
        "system": AGENT1_SYSTEM_PROMPT,
        "stream": False,
        "format": "json"
    }

    t0 = time.time()
    try:
        r = requests.post(url, json=payload, timeout=600)
        t1 = time.time()
        wall_sec = round(t1 - t0, 2)

        if r.status_code != 200:
            resp_str = ""
            err_msg = f"HTTP Error {r.status_code}: {r.text}"
        else:
            resp_str = r.json().get("response", "")
            err_msg = None
    except Exception as exc:
        t1 = time.time()
        wall_sec = round(t1 - t0, 2)
        resp_str = ""
        err_msg = str(exc)

    is_empty = len(resp_str.strip()) == 0
    is_markdown = resp_str.strip().startswith("```") or "**Claim" in resp_str or "Here is" in resp_str
    json_parse_success = False
    parsed_json = None
    if not is_empty:
        try:
            parsed_json = json.loads(resp_str)
            json_parse_success = True
        except Exception as err:
            err_msg = str(err)

    validator = Agent1Validator()
    fir_map = {f.finding_id: f for f in fir_batch}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(fir_batch)

    raw_claims = []
    validated_claims = []
    extra_meta = {}

    if json_parse_success and isinstance(parsed_json, dict):
        mock_model = lambda p: resp_str
        gateway = SanitizationGateway()
        agent = EvidenceIntelligenceAgent(model=mock_model, sanitization_gateway=gateway, tenant_id="default")
        raw_claims, extra_meta, p_err = agent._parse_json_claims_and_meta(resp_str)

        if raw_claims:
            validated_claims = validator.validate_claims(
                claims=raw_claims,
                valid_finding_ids=valid_finding_ids,
                valid_lineage_ids=valid_lineage_ids,
                fir_map=fir_map
            )

    return {
        "batch_name": batch_name,
        "fir_count": len(fir_batch),
        "wall_clock_sec": wall_sec,
        "resp_char_count": len(resp_str),
        "is_empty": is_empty,
        "is_markdown_prose": is_markdown,
        "json_parse_success": json_parse_success,
        "err_msg": err_msg,
        "parsed_json": parsed_json,
        "raw_claims_count": len(raw_claims),
        "validated_claims": [c.model_dump() for c in validated_claims],
        "extra_meta": extra_meta,
        "fir_ids": [f.finding_id for f in fir_batch]
    }

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 6: TWO 20-FIR SUB-BATCH CONSOLIDATION EXPERIMENT")
    print("=" * 80)

    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    # Deterministic Selection: 40 FIRs (1-20 = Batch A, 21-40 = Batch B)
    raw_40 = raw_data[:40]

    fir_objects = []
    for item in raw_40:
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

    batch_a_firs = fir_objects[:20]
    batch_b_firs = fir_objects[20:40]

    print(f"[FIXTURE SELECTION]: 40 FIR Findings loaded from {json_path}")
    print(f"  --> Batch A: {len(batch_a_firs)} FIRs ({batch_a_firs[0].finding_id} .. {batch_a_firs[-1].finding_id})")
    print(f"  --> Batch B: {len(batch_b_firs)} FIRs ({batch_b_firs[0].finding_id} .. {batch_b_firs[-1].finding_id})")

    # Call 1: Batch A
    res_a = run_single_subbatch(batch_a_firs, "Batch A (FIR 1-20)")
    print(f"--> Batch A Wall Time: {res_a['wall_clock_sec']} s | JSON Success: {res_a['json_parse_success']} | Claims: {len(res_a['validated_claims'])}")

    # Call 2: Batch B
    res_b = run_single_subbatch(batch_b_firs, "Batch B (FIR 21-40)")
    print(f"--> Batch B Wall Time: {res_b['wall_clock_sec']} s | JSON Success: {res_b['json_parse_success']} | Claims: {len(res_b['validated_claims'])}")

    # Consolidation Data
    phase6_results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_firs": 40,
        "batch_a": res_a,
        "batch_b": res_b,
        "total_inference_time_sec": round(res_a['wall_clock_sec'] + res_b['wall_clock_sec'], 2),
        "avg_batch_latency_sec": round((res_a['wall_clock_sec'] + res_b['wall_clock_sec']) / 2, 2)
    }

    out_json = ARGUS_ROOT / "scratch" / "phase6_consolidation_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(phase6_results, f, indent=2, default=str)
    print(f"\n[+] Saved Phase 6 raw experimental results to: {out_json}")

if __name__ == "__main__":
    main()
