import sys
import os
sys.path.insert(0, os.path.abspath("."))

import time
import json
from datetime import datetime, timezone
from models.llm import OllamaWrapper
from models.classifiers import ClassifierLoader
from neo4j import GraphDatabase
from config.settings import settings

def run_performance_reconciliation():
    print("=" * 60)
    print("[*] ARGUS PHASE 8 — PERFORMANCE RECONCILIATION BENCHMARK")
    print("=" * 60)

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hardware": {
            "os": "Windows 11 (win32)",
            "cpu_architecture": "AMD64 / x86_64",
            "inference_mode": "CPU (No CUDA GPU allocated)",
            "ollama_model": "qwen3:8b",
            "deberta_model": "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli"
        },
        "benchmarks": {}
    }

    # 1. Ollama Qwen3-8B Cold vs Warm Latency & Token Rates
    print("\n[1/4] Benchmarking Ollama Qwen3-8B (Cold vs Warm)...")
    llm = OllamaWrapper(model_name="qwen3:8b", base_url="http://localhost:11434", allow_mock=False)

    prompt_short = (
        "Analyze the following evidence finding:\n"
        "Finding: powershell.exe -Enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==\n"
        "Produce 1 structured forensic observation with MITRE technique ID and severity."
    )

    # Run 1: Warm-up / Cold
    t0 = time.perf_counter()
    resp1 = llm.generate(prompt_short)
    t1 = time.perf_counter()
    cold_dur = t1 - t0

    # Run 2: Warm
    t2 = time.perf_counter()
    resp2 = llm.generate(prompt_short)
    t3 = time.perf_counter()
    warm_dur = t3 - t2

    tokens_est1 = len(resp1.split()) * 1.33
    tokens_est2 = len(resp2.split()) * 1.33
    tok_rate_cold = tokens_est1 / cold_dur if cold_dur > 0 else 0
    tok_rate_warm = tokens_est2 / warm_dur if warm_dur > 0 else 0

    print(f"  Cold Run Duration: {cold_dur:.2f}s (~{tokens_est1:.0f} tokens, {tok_rate_cold:.2f} tok/s)")
    print(f"  Warm Run Duration: {warm_dur:.2f}s (~{tokens_est2:.0f} tokens, {tok_rate_warm:.2f} tok/s)")

    results["benchmarks"]["ollama_qwen3_8b"] = {
        "cold_duration_sec": round(cold_dur, 2),
        "warm_duration_sec": round(warm_dur, 2),
        "cold_tokens_per_sec": round(tok_rate_cold, 2),
        "warm_tokens_per_sec": round(tok_rate_warm, 2),
        "tokens_generated": round(tokens_est2, 1)
    }

    # 2. DeBERTa-v3-large-MNLI Latency (Single vs Batch)
    print("\n[2/4] Benchmarking DeBERTa-v3-large-MNLI (CPU NLI Inference)...")
    loader = ClassifierLoader()
    premise = "Registry Run key UpdateHelper created pointing to C:\\Windows\\Temp\\beacon.exe."
    hypothesis = "Registry Run key was created pointing to beacon.exe."

    # Cold call (model weights already in memory from classifier cache)
    t0 = time.perf_counter()
    res_deberta = loader.classify_nli(premise=premise, hypothesis=hypothesis)
    t1 = time.perf_counter()
    deberta_single_dur = t1 - t0

    # 5-pair sequential run
    pairs = [
        (premise, hypothesis),
        ("Firewall dropped connection to 203.0.113.100.", "Outbound connection succeeded."),
        ("User bob downloaded setup.exe.", "User bob downloaded an executable from external domain."),
        ("Process setup.exe spawned cmd.exe.", "Database was dumped."),
        ("LSASS process memory was dumped.", "LSASS memory was dumped to disk.")
    ]
    t2 = time.perf_counter()
    for p, h in pairs:
        loader.classify_nli(premise=p, hypothesis=h)
    t3 = time.perf_counter()
    deberta_batch_dur = t3 - t2
    deberta_avg_per_pair = deberta_batch_dur / len(pairs)

    print(f"  Single NLI classification: {deberta_single_dur:.3f}s (Entailment={res_deberta.get('entailment', 0):.2f})")
    print(f"  5-Pair Batch Duration:    {deberta_batch_dur:.3f}s ({deberta_avg_per_pair:.3f}s / pair)")

    results["benchmarks"]["deberta_v3_mnli"] = {
        "single_pair_latency_sec": round(deberta_single_dur, 3),
        "batch_5_latency_sec": round(deberta_batch_dur, 3),
        "avg_latency_per_pair_sec": round(deberta_avg_per_pair, 3)
    }

    # 3. Neo4j GDS Graph Topology & Metric Calculation Latency
    print("\n[3/4] Benchmarking Neo4j GDS Graph Latency...")
    neo4j_driver = None
    neo4j_dur = 0.0
    try:
        neo4j_driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        t0 = time.perf_counter()
        with neo4j_driver.session() as s:
            rec = s.run("RETURN 1 as test").single()
        t1 = time.perf_counter()
        neo4j_dur = t1 - t0
        print(f"  Neo4j Bolt Round-trip Latency: {neo4j_dur * 1000:.2f}ms")
    except Exception as e:
        print(f"  Neo4j connection error: {e}")

    results["benchmarks"]["neo4j_graph"] = {
        "bolt_roundtrip_ms": round(neo4j_dur * 1000, 2)
    }

    # 4. Save Results
    out_file = "scratch/reconciled_benchmark_evidence.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Performance evidence successfully recorded to {out_file}")

if __name__ == "__main__":
    run_performance_reconciliation()
