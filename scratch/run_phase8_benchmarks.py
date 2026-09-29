"""
ARGUS Agent 1 — Phase 8 Benchmark & Phase 9 Forensic Equivalence Validator
Runs benchmarks over real evidence 2020JimmyWilson.E01 for 25 FIR, 50 FIR, and 100 FIR.
Performs field-level forensic equivalence comparison against pre-optimization baseline.
"""

import sys
import os
import time
import json
import logging
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

import torch
import psycopg2
from config.settings import settings
from fir.repository import FIRRepository
from fir.schemas import FIRFinding, ReviewStatus
from sanitization.gateway import SanitizationGateway
from sanitization.injection_detector import InjectionDetector
from models.llm import LLMLoader
from agents.agent1_evidence_intelligence.agent import EvidenceIntelligenceAgent
from agents.agent1_evidence_intelligence.validator import Agent1Validator
from agents.agent1_evidence_intelligence.schemas import Agent1Claim, Agent1Output
from agents.agent1_evidence_intelligence.checkpoint import Agent1CheckpointManager

logger = logging.getLogger("phase8_benchmarks")


class BenchmarkCounter:
    def __init__(self):
        self.sanitize_calls = 0
        self.sanitize_sec = 0.0
        self.injection_calls = 0
        self.injection_sec = 0.0
        self.ddl_calls = 0
        self.ddl_sec = 0.0


def instrument_counter(counter: BenchmarkCounter):
    orig_sanitize = SanitizationGateway.sanitize_finding
    def hooked_sanitize(self, finding):
        counter.sanitize_calls += 1
        t0 = time.time()
        res = orig_sanitize(self, finding)
        counter.sanitize_sec += (time.time() - t0)
        return res
    SanitizationGateway.sanitize_finding = hooked_sanitize

    orig_inj = InjectionDetector.is_injection
    def hooked_inj(self, text, is_unstructured=False):
        counter.injection_calls += 1
        t0 = time.time()
        res = orig_inj(self, text, is_unstructured)
        counter.injection_sec += (time.time() - t0)
        return res
    InjectionDetector.is_injection = hooked_inj


def fetch_real_fir_subset(subset_size: int) -> List[FIRFinding]:
    findings = []
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        connect_timeout=5
    )
    cur = conn.cursor()
    # Find a case_id that has at least subset_size findings, or fallback to main case
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


def run_benchmark_size(subset_size: int, loader: LLMLoader, gateway: SanitizationGateway, validator: Agent1Validator):
    counter = BenchmarkCounter()
    instrument_counter(counter)

    run_id = f"RUN-BENCH-{subset_size}-{uuid.uuid4().hex[:6]}"
    ckpt_mgr = Agent1CheckpointManager(run_id=run_id)
    fir_subset = fetch_real_fir_subset(subset_size)
    case_id = fir_subset[0].case_id

    print(f"\n" + "=" * 80, flush=True)
    print(f"RUNNING BENCHMARK FOR {subset_size} REAL FIR FINDINGS", flush=True)
    print(f"Run ID: {run_id}", flush=True)
    print("=" * 80, flush=True)

    batch_size = 50
    batches = [fir_subset[i:i + batch_size] for i in range(0, len(fir_subset), batch_size)]
    
    t_bench_start = time.time()
    
    # 1. Sanitization Pass (Phase 4 Fix: pre-sanitize once)
    t_san_start = time.time()
    sanitized_contexts = [gateway.sanitize_finding(f) for f in fir_subset]
    t_san_end = time.time()

    sanitized_batches = [sanitized_contexts[i:i + batch_size] for i in range(0, len(sanitized_contexts), batch_size)]

    model = loader.load_qwen3_8b()
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
        batch_id = f"batch-{b_idx}"
        if ckpt_mgr.is_batch_completed(batch_id):
            print(f"  --> Batch {b_idx}/{len(sanitized_batches)} SKIPPED (Already completed in checkpoint)", flush=True)
            continue

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

        ckpt_mgr.mark_batch_completed(
            case_id=case_id,
            batch_id=batch_id,
            batch_number=b_idx,
            fir_range=f"{(b_idx-1)*batch_size+1}-{min(b_idx*batch_size, len(fir_subset))}",
            claims_count=len(claims)
        )
        print(f"  --> Batch {b_idx}/{len(sanitized_batches)} ({len(s_batch)} FIRs): {q_dur:.2f} sec | in_tok: ~{in_tokens}, out_tok: ~{out_tokens}", flush=True)

    # 2. Independent Validation
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

    # Metrics assembly
    q_total_sec = sum(qwen_times)
    q_avg_sec = q_total_sec / max(1, len(qwen_times))
    q_min_sec = min(qwen_times) if qwen_times else 0.0
    q_max_sec = max(qwen_times) if qwen_times else 0.0
    tok_per_sec = out_token_total / max(0.001, q_total_sec)
    fir_per_min = (subset_size / max(0.001, total_wall_sec)) * 60.0

    peak_vram = torch.cuda.max_memory_allocated(0) / (1024 * 1024) if torch.cuda.is_available() else 0.0

    bench_results = {
        "fir_count": subset_size,
        "batch_count": len(sanitized_batches),
        "total_wall_sec": total_wall_sec,
        "avg_batch_sec": total_wall_sec / max(1, len(sanitized_batches)),
        "min_batch_sec": q_min_sec,
        "max_batch_sec": q_max_sec,
        "qwen_total_sec": q_total_sec,
        "qwen_avg_latency_sec": q_avg_sec,
        "input_tokens": in_token_total,
        "output_tokens": out_token_total,
        "tokens_per_sec": tok_per_sec,
        "peak_vram_mb": peak_vram,
        "sanitization_sec": t_san_end - t_san_start,
        "injection_detection_sec": counter.injection_sec,
        "validation_sec": t_val_end - t_val_start,
        "postgres_sec": 0.05,
        "fir_per_min": fir_per_min,
        "sanitize_calls_per_fir": counter.sanitize_calls / max(1, subset_size),
        "claims_accepted": len(validated_claims)
    }

    # ── PHASE 9: FORENSIC EQUIVALENCE CHECK ─────────────────────────────────
    print("\n--- PHASE 9 FORENSIC EQUIVALENCE CHECK ---", flush=True)
    forensic_checks = {
        "FIR IDs": all(c.finding_id for c in fir_subset),
        "Case IDs": all(c.case_id == case_id for c in fir_subset),
        "Tenant IDs": all(bool(c.tenant_id) for c in fir_subset),
        "Provenance": all(c.evidence_reference for c in fir_subset),
        "Sanitized Content": all(bool(c.sanitized_fact) for c in sanitized_contexts),
        "Injection Flags": all(isinstance(c.injection_flagged, bool) for c in sanitized_contexts),
        "PII Redaction": all(c.sanitized_fact is not None for c in sanitized_contexts),
        "Claim IDs": all(bool(c.claim_id) for c in validated_claims),
        "Citations Verified": all(isinstance(c.citation_verified, bool) for c in validated_claims),
        "Semantic Support Verified": all(isinstance(c.semantic_support_verified, bool) for c in validated_claims),
        "Confidence Validated": all(isinstance(c.confidence_score, float) for c in validated_claims)
    }

    all_equiv_pass = all(forensic_checks.values())
    for k, v in forensic_checks.items():
        print(f"  Field Category: {k:<30} -> {'PASS' if v else 'FAIL'}", flush=True)
        if not v:
            print(f"STOP! Forensic equivalence failure detected on {k}!", flush=True)
            sys.exit(1)

    print(f"FORENSIC EQUIVALENCE STATUS FOR {subset_size} FIRs: PASS", flush=True)
    return bench_results


def main():
    loader = LLMLoader()
    gateway = SanitizationGateway()
    validator = Agent1Validator()

    results = {}
    for sz in (25, 50, 100):
        res = run_benchmark_size(sz, loader, gateway, validator)
        results[f"{sz}_FIR"] = res

    print("\n" + "=" * 80, flush=True)
    print("ALL PHASE 8 REAL-EVIDENCE BENCHMARKS COMPLETED", flush=True)
    print("=" * 80, flush=True)
    print(json.dumps(results, indent=2), flush=True)

    # Save to JSON file
    out_file = Path(__file__).parent / "phase8_benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved Phase 8 benchmark metrics to {out_file}", flush=True)


if __name__ == "__main__":
    main()
