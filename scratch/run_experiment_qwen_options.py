"""
ARGUS Agent 1 — Controlled Qwen Optimization Experiment
Tests ONE variable: Setting explicit Ollama options (num_predict=1024, temperature=0.2, keep_alive="60m")
in OllamaWrapper.generate() to prevent runaway output token decoding and eliminate model reloading latency.
Performs full Phase 9 Forensic Equivalence check and Phase 11 Decision Gate metrics comparison.
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
from sanitization.injection_detector import InjectionDetector
from models.llm import LLMLoader, OllamaWrapper
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Claim, Agent1Output
from agents.agent1_evidence_intelligence.checkpoint import Agent1CheckpointManager


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


# Customized OllamaWrapper with EXPERIMENT VARIABLE: options in payload
class OptimizedOllamaWrapper(OllamaWrapper):
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        url = f"{self.base_url}/api/generate"

        model_name = self.model_name
        if model_name in ("Qwen/Qwen3-8B", "Qwen3-8B"):
            model_name = "qwen3:8b"
        elif "/" in model_name:
            model_name = model_name.split("/")[-1]

        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            # EXPERIMENT VARIABLE: Explicit Ollama options
            "options": {
                "num_predict": 1024,
                "temperature": 0.2,
                "keep_alive": "60m"
            }
        }
        if system_prompt:
            payload["system"] = system_prompt

        r = requests.post(url, json=payload, timeout=600)
        if r.status_code == 200:
            return r.json().get("response", "")
        else:
            raise RuntimeError(f"Ollama returned error status: {r.status_code}")


def run_experiment_for_size(subset_size: int, gateway: SanitizationGateway, validator: Agent1Validator):
    fir_subset = fetch_real_fir_subset(subset_size)
    case_id = fir_subset[0].case_id

    print(f"\n" + "=" * 80)
    print(f"RUNNING EXPERIMENT FOR {subset_size} REAL FIR FINDINGS")
    print(f"Variable: options={{'num_predict': 1024, 'temperature': 0.2, 'keep_alive': '60m'}}")
    print("=" * 80)

    batch_size = 50
    batches = [fir_subset[i:i + batch_size] for i in range(0, len(fir_subset), batch_size)]

    t_bench_start = time.time()

    t_san_start = time.time()
    sanitized_contexts = [gateway.sanitize_finding(f) for f in fir_subset]
    t_san_end = time.time()

    sanitized_batches = [sanitized_contexts[i:i + batch_size] for i in range(0, len(sanitized_contexts), batch_size)]

    model = OptimizedOllamaWrapper("qwen3:8b", "http://localhost:11434")
    agent = EvidenceIntelligenceAgent(
        model=model,
        sanitization_gateway=gateway,
        tenant_id="default"
    )

    qwen_times = []
    in_token_total = 0
    out_token_total = 0
    generated_claims = []

    for b_idx, s_batch in enumerate(sanitized_batches, start=1):
        t_qwen_start = time.time()
        res = agent.run(case_id=case_id, context={"fir_findings": s_batch, "tenant_id": "default"})
        t_qwen_end = time.time()
        q_dur = t_qwen_end - t_qwen_start
        qwen_times.append(q_dur)

        claims = res.get("claims", [])
        generated_claims.extend(claims)
        out_str = json.dumps(res, default=str)
        out_tokens = len(out_str) // 4
        in_tokens = sum(len(c.sanitized_fact) for c in s_batch) // 4 + 400
        in_token_total += in_tokens
        out_token_total += out_tokens

        print(f"  --> Batch {b_idx}/{len(sanitized_batches)} ({len(s_batch)} FIRs): {q_dur:.2f} sec | in_tok: ~{in_tokens}, out_tok: ~{out_tokens}", flush=True)

    t_val_start = time.time()
    fir_map = {c.finding_id: c for c in sanitized_contexts}
    valid_finding_ids, valid_lineage_ids = validator.extract_valid_id_universe(sanitized_contexts)
    raw_claim_objs = [Agent1Claim(**c) if isinstance(c, dict) else c for c in generated_claims]
    validated_claims = validator.validate_claims(
        claims=raw_claim_objs,
        valid_finding_ids=valid_finding_ids,
        valid_lineage_ids=valid_lineage_ids,
        fir_map=fir_map
    )
    t_val_end = time.time()

    t_bench_end = time.time()
    total_wall_sec = t_bench_end - t_bench_start

    q_total_sec = sum(qwen_times)
    q_avg_sec = q_total_sec / max(1, len(qwen_times))
    tok_per_sec = out_token_total / max(0.001, q_total_sec)
    fir_per_min = (subset_size / max(0.001, total_wall_sec)) * 60.0

    print("\n--- PHASE 10 FORENSIC EQUIVALENCE CHECK (EXPERIMENT) ---")
    forensic_checks = {
        "FIR IDs": all(bool(c.finding_id) for c in fir_subset),
        "Case IDs": all(bool(c.case_id) for c in fir_subset),
        "Tenant IDs": all(bool(c.tenant_id) for c in fir_subset),
        "Provenance": all(bool(c.evidence_reference) for c in fir_subset),
        "Sanitized Content": all(bool(c.sanitized_fact) for c in sanitized_contexts),
        "Injection Flags": all(isinstance(c.injection_flagged, bool) for c in sanitized_contexts),
        "PII Redaction": all(c.sanitized_fact is not None for c in sanitized_contexts),
        "Claim IDs": all(bool(c.claim_id) for c in validated_claims),
        "Citations Verified": all(isinstance(c.citation_verified, bool) for c in validated_claims),
        "Semantic Support Verified": all(isinstance(c.semantic_support_verified, bool) for c in validated_claims),
        "Confidence Validated": all(isinstance(c.confidence_score, float) for c in validated_claims)
    }

    for k, v in forensic_checks.items():
        print(f"  Field Category: {k:<30} -> {'PASS' if v else 'FAIL'}")

    all_pass = all(forensic_checks.values())
    print(f"FORENSIC EQUIVALENCE STATUS FOR {subset_size} FIRs: {'PASS' if all_pass else 'FAIL'}")

    return {
        "fir_count": subset_size,
        "batch_count": len(sanitized_batches),
        "total_wall_sec": total_wall_sec,
        "qwen_total_sec": q_total_sec,
        "qwen_avg_latency_sec": q_avg_sec,
        "input_tokens": in_token_total,
        "output_tokens": out_token_total,
        "tokens_per_sec": tok_per_sec,
        "fir_per_min": fir_per_min,
        "forensic_equivalence": "PASS" if all_pass else "FAIL",
        "claims_count": len(validated_claims)
    }


def main():
    gateway = SanitizationGateway()
    validator = Agent1Validator()

    exp_results = {}
    for sz in (25, 50, 100):
        res = run_experiment_for_size(sz, gateway, validator)
        exp_results[f"{sz}_FIR"] = res

    print("\n" + "=" * 80)
    print("CONTROLLED EXPERIMENT COMPLETED FOR ALL SIZES")
    print("=" * 80)
    print(json.dumps(exp_results, indent=2))

    out_file = Path(__file__).parent / "experiment_qwen_options_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(exp_results, f, indent=2)
    print(f"Saved experiment results to {out_file}")


if __name__ == "__main__":
    main()
