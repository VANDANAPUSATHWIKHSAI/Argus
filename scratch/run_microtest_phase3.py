"""
ARGUS — PHASE 3: QWEN3-8B STRUCTURED JSON MICRO-TEST
======================================================
Single-run micro-test evaluating Ollama native format="json" on 10 real FIR findings.
No production code changes. No PostgreSQL persistence. Maximum ONE Qwen inference call.
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
logger = logging.getLogger("phase3_microtest")

from fir.schemas import FIRFinding
from sanitization.gateway import SanitizationGateway
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.schemas import Agent1Output, Agent1Claim
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    print("=" * 80)
    print("ARGUS — PHASE 3: QWEN3-8B STRUCTURED JSON MICRO-TEST")
    print("=" * 80)

    # Load exactly 10 FIR findings
    json_path = ARGUS_ROOT / "scratch" / "full_3286_sanitized_findings.json"
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    batch_10_raw = raw_data[:10]
    fir_batch = []
    for item in batch_10_raw:
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
        fir_batch.append(finding_obj)

    print(f"[MICRO-TEST FIXTURE]: Loaded fixed batch of {len(fir_batch)} FIR findings.")

    # Build XML evidence blocks
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
        "format": "json"  # THE ONLY EXPERIMENTAL VARIABLE TESTED
    }

    print("\n[EXACTLY ONE QWEN3-8B INFERENCE CALL]: Executing with format='json'...")
    t0 = time.time()
    try:
        r = requests.post(url, json=payload, timeout=600)
        t1 = time.time()
        wall_sec = round(t1 - t0, 2)

        if r.status_code != 200:
            raw_resp = f"HTTP Error {r.status_code}: {r.text}"
            resp_str = ""
        else:
            resp_str = r.json().get("response", "")
            raw_resp = resp_str

    except Exception as exc:
        t1 = time.time()
        wall_sec = round(t1 - t0, 2)
        raw_resp = f"Request Exception: {exc}"
        resp_str = ""

    print(f"--> Wall-Clock Time : {wall_sec} s")
    print(f"--> Response Length : {len(resp_str)} characters")
    print(f"--> Raw Response Preview:\n{resp_str[:300]}...")

    # Evaluate response properties
    is_empty = len(resp_str.strip()) == 0
    is_markdown = resp_str.strip().startswith("```") or "**Claim" in resp_str or "Here is" in resp_str

    # JSON Parsing & Agent 1 Schema mapping
    json_parse_success = False
    parsed_json = None
    parse_error = None
    if not is_empty:
        try:
            parsed_json = json.loads(resp_str)
            json_parse_success = True
        except Exception as err:
            parse_error = str(err)

    # In-Memory Agent 1 Validation (No DB persistence)
    validator = Agent1Validator()
    fir_map = {f.finding_id: f for f in fir_batch}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(fir_batch)

    claims_parsed = []
    validated_claims = []
    schema_compatible = False

    if json_parse_success and isinstance(parsed_json, dict):
        # Instantiate EvidenceIntelligenceAgent helper to parse JSON claims
        mock_model = lambda p: resp_str
        gateway = SanitizationGateway()
        agent = EvidenceIntelligenceAgent(model=mock_model, sanitization_gateway=gateway, tenant_id="default")
        raw_claims, extra_meta, p_err = agent._parse_json_claims_and_meta(resp_str)
        claims_parsed = raw_claims

        if raw_claims:
            validated_claims = validator.validate_claims(
                claims=raw_claims,
                valid_finding_ids=valid_finding_ids,
                valid_lineage_ids=valid_lineage_ids,
                fir_map=fir_map
            )
            schema_compatible = True

    # Determine Verdict:
    # PASS criteria:
    # 1. Response non-empty
    # 2. Response valid JSON
    # 3. Maps to Agent 1 output contract
    # 4. Claims are structured
    # 5. Claims contain evidence IDs where required
    # 6. No markdown wrapper required
    # 7. No truncation
    verdict = "A. JSON_FORMAT_WORKS" if (json_parse_success and schema_compatible and len(validated_claims) > 0 and not is_markdown) else "B. JSON_FORMAT_FAILED"

    microtest_output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fixture_fir_count": len(fir_batch),
        "model_used": "qwen3:8b",
        "ollama_format_setting": "json",
        "wall_clock_sec": wall_sec,
        "response_char_count": len(resp_str),
        "is_empty": is_empty,
        "is_markdown_prose": is_markdown,
        "json_parse_success": json_parse_success,
        "parse_error": parse_error,
        "schema_compatible": schema_compatible,
        "parsed_claims_count": len(claims_parsed),
        "validated_claims_count": len(validated_claims),
        "verdict": verdict,
        "raw_response": resp_str
    }

    out_json = ARGUS_ROOT / "scratch" / "phase3_microtest_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(microtest_output, f, indent=2, default=str)
    print(f"\n[+] Saved Phase 3 micro-test results to: {out_json}")
    print(f"[+] Final Verdict: {verdict}")

if __name__ == "__main__":
    main()
