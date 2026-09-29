"""
ARGUS Agent 1 — Qwen3-8B Deep Performance Investigation Script
Executes Phases 1 to 7 of the Qwen Performance Investigation.
Extracts exact Ollama nanosecond timing telemetry, GPU metrics, token accounting, and output analysis.
"""

import sys
import os
import time
import json
import logging
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
import psycopg2

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from config.settings import settings
from fir.schemas import FIRFinding, ReviewStatus
from sanitization.gateway import SanitizationGateway
from agents.agent1_evidence_intelligence.prompts import AGENT1_SYSTEM_PROMPT, build_agent1_user_prompt
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Claim

# Try importing pynvml for exact NVIDIA GPU telemetry
try:
    import pynvml
    pynvml.nvmlInit()
    NVML_AVAILABLE = True
except Exception:
    NVML_AVAILABLE = False


def get_gpu_telemetry() -> Dict[str, Any]:
    if not NVML_AVAILABLE:
        return {"gpu_util_pct": None, "vram_used_mb": None, "vram_total_mb": None, "temp_c": None}
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        return {
            "gpu_util_pct": util.gpu,
            "vram_used_mb": round(mem.used / (1024 * 1024), 2),
            "vram_total_mb": round(mem.total / (1024 * 1024), 2),
            "temp_c": temp
        }
    except Exception as e:
        return {"error": str(e)}


def fetch_ollama_model_info(model_name: str = "qwen3:8b") -> Dict[str, Any]:
    try:
        r = requests.post("http://localhost:11434/api/show", json={"name": model_name}, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        return {"error": str(e)}
    return {}


def query_ollama_with_telemetry(prompt: str, system_prompt: str = None, options: Dict[str, Any] = None, timeout: int = 600) -> Dict[str, Any]:
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "qwen3:8b",
        "prompt": prompt,
        "stream": False
    }
    if system_prompt:
        payload["system"] = system_prompt
    if options:
        payload["options"] = options

    t0 = time.time()
    gpu_before = get_gpu_telemetry()
    r = requests.post(url, json=payload, timeout=timeout)
    t1 = time.time()
    gpu_after = get_gpu_telemetry()

    if r.status_code != 200:
        raise RuntimeError(f"Ollama returned HTTP {r.status_code}: {r.text}")

    data = r.json()
    total_dur_sec = data.get("total_duration", 0) / 1e9
    load_dur_sec = data.get("load_duration", 0) / 1e9
    prompt_eval_dur_sec = data.get("prompt_eval_duration", 0) / 1e9
    eval_dur_sec = data.get("eval_duration", 0) / 1e9
    prompt_eval_tokens = data.get("prompt_eval_count", 0)
    eval_tokens = data.get("eval_count", 0)
    done_reason = data.get("done_reason", "unknown")
    response_text = data.get("response", "")

    return {
        "raw_response": response_text,
        "wall_time_sec": t1 - t0,
        "ollama_total_dur_sec": total_dur_sec,
        "ollama_load_dur_sec": load_dur_sec,
        "ollama_prefill_dur_sec": prompt_eval_dur_sec,
        "ollama_eval_dur_sec": eval_dur_sec,
        "input_tokens": prompt_eval_tokens,
        "output_tokens": eval_tokens,
        "done_reason": done_reason,
        "gpu_before": gpu_before,
        "gpu_after": gpu_after,
        "prefill_tok_per_sec": prompt_eval_tokens / max(0.001, prompt_eval_dur_sec),
        "decode_tok_per_sec": eval_tokens / max(0.001, eval_dur_sec),
        "overall_tok_per_sec": (prompt_eval_tokens + eval_tokens) / max(0.001, total_dur_sec)
    }


def fetch_real_fir_subset(subset_size: int) -> List[FIRFinding]:
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        connect_timeout=5
    )
    cur = conn.cursor()
    cur.execute("""
        SELECT case_id FROM fir_findings 
        GROUP BY case_id 
        HAVING COUNT(*) >= %s 
        LIMIT 1
    """, (subset_size,))
    row = cur.fetchone()
    target_case_id = row[0] if row else None

    if target_case_id:
        cur.execute("""
            SELECT finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                   evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                   injection_flagged, injection_score, layer, timestamp
            FROM fir_findings
            WHERE case_id = %s
            LIMIT %s
        """, (target_case_id, subset_size))
    else:
        cur.execute("""
            SELECT finding_id, case_id, tenant_id, fact, sanitized_fact, confidence, severity, mitre_mapping,
                   evidence_reference, source_artifact_id, finding_fingerprint, review_status, reviewed_by,
                   injection_flagged, injection_score, layer, timestamp
            FROM fir_findings
            LIMIT %s
        """, (subset_size,))

    rows = cur.fetchall()
    findings = []
    for r in rows:
        f_id, c_id, t_id, fact, s_fact, conf, sev, mitre, evid_ref, src_art, fp, st_val, rev_by, inj_flg, inj_sc, lyr, ts = r
        fnd = FIRFinding(
            finding_id=f_id,
            case_id=target_case_id or c_id or "CASE-E01-BENCH",
            tenant_id=t_id or "default",
            fact=fact,
            sanitized_fact=s_fact or fact,
            confidence=float(conf),
            severity=sev or "medium",
            mitre_mapping=mitre,
            evidence_reference=list(evid_ref) if isinstance(evid_ref, (list, tuple)) else ["EVID-DISK-2-FULL"],
            source_artifact_id=src_art or f_id,
            finding_fingerprint=fp or "",
            review_status=ReviewStatus.ANALYST_CONFIRMED if st_val == "analyst_confirmed" else ReviewStatus.PENDING_REVIEW,
            reviewed_by=rev_by,
            injection_flagged=bool(inj_flg),
            injection_score=float(inj_sc or 0.0),
            layer=lyr or "unknown",
            timestamp=ts
        )
        findings.append(fnd)
    conn.close()
    return findings


def run_investigation():
    print("=" * 80)
    print("ARGUS AGENT 1 — QWEN3-8B TELEMETRY & PERFORMANCE INVESTIGATION")
    print("=" * 80)

    # 1. Fetch Ollama Model Configuration
    model_info = fetch_ollama_model_info("qwen3:8b")
    print("\n--- OLLAMA MODEL CONFIGURATION (/api/show) ---")
    print(f"Model Details: {json.dumps(model_info.get('details', {}), indent=2)}")
    print(f"Modelfile Snippet: {model_info.get('modelfile', '')[:500]}")
    print(f"Parameters: {model_info.get('parameters', '')}")

    gateway = SanitizationGateway()
    validator = Agent1Validator()

    investigation_results = {}

    for subset_size in (25, 50, 100):
        print(f"\n" + "-" * 80)
        print(f"MEASURING BENCHMARK FOR {subset_size} REAL FIR FINDINGS")
        print("-" * 80)

        fir_subset = fetch_real_fir_subset(subset_size)
        case_id = fir_subset[0].case_id

        # Batching: 50 FIRs per batch
        batch_size = 50
        batches = [fir_subset[i:i + batch_size] for i in range(0, len(fir_subset), batch_size)]

        batch_telemetry = []

        for b_idx, b_firs in enumerate(batches, start=1):
            sanitized_batch = [gateway.sanitize_finding(f) for f in b_firs]
            xml_blocks = "\n".join(ctx.xml_evidence_block for ctx in sanitized_batch)
            user_prompt = build_agent1_user_prompt(case_id, xml_blocks)

            print(f"Executing Batch {b_idx}/{len(batches)} ({len(b_firs)} FIRs)...", flush=True)
            t_res = query_ollama_with_telemetry(prompt=user_prompt, system_prompt=AGENT1_SYSTEM_PROMPT, timeout=600)

            print(f"  Wall time: {t_res['wall_time_sec']:.2f}s | Ollama total: {t_res['ollama_total_dur_sec']:.2f}s")
            print(f"  Load time: {t_res['ollama_load_dur_sec']:.4f}s | Prefill: {t_res['ollama_prefill_dur_sec']:.2f}s ({t_res['prefill_tok_per_sec']:.1f} tok/s)")
            print(f"  Decode: {t_res['ollama_eval_dur_sec']:.2f}s ({t_res['decode_tok_per_sec']:.2f} tok/s) | Stop: {t_res['done_reason']}")
            print(f"  Tokens: Input={t_res['input_tokens']} | Output={t_res['output_tokens']}")
            print(f"  GPU VRAM: {t_res['gpu_after'].get('vram_used_mb')}MB / {t_res['gpu_after'].get('vram_total_mb')}MB | GPU Util: {t_res['gpu_after'].get('gpu_util_pct')}%")

            # Check raw output characteristics
            raw_text = t_res['raw_response']
            has_think_tag = "<think>" in raw_text or "</think>" in raw_text
            json_start = raw_text.find("{")
            leading_text_len = json_start if json_start != -1 else 0

            t_res["has_think_tag"] = has_think_tag
            t_res["leading_text_len"] = leading_text_len
            t_res["raw_text_char_len"] = len(raw_text)

            batch_telemetry.append(t_res)

        investigation_results[f"{subset_size}_FIR"] = batch_telemetry

    # Save findings
    out_file = Path(__file__).parent / "qwen_telemetry_investigation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(investigation_results, f, indent=2, default=str)
    print(f"\nSaved investigation telemetry to {out_file}")


if __name__ == "__main__":
    run_investigation()
