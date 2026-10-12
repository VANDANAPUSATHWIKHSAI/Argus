import json
import time
import statistics
from models.llm import OllamaWrapper
from agents.agent4_malware_behaviour import MalwareBehaviourAgent
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway

def run_benchmark():
    print("Loading 25 Agent 2 input samples...")
    with open("agent2_25_samples.json", "r", encoding="utf-8") as f:
        samples = json.load(f)

    # Initialize Agent 4 connected to local qwen3:8b via Ollama
    qwen3_model = OllamaWrapper("qwen3:8b", "http://localhost:11434")
    repo = FIRRepository()
    gateway = SanitizationGateway()
    agent = MalwareBehaviourAgent(
        model=qwen3_model,
        fir_repo=repo,
        sanitization_gateway=gateway,
        tenant_id="default"
    )

    results = []
    execution_times = []
    citation_accuracies = []
    confidence_validities = []
    total_claims_processed = 0
    total_fir_built = 0
    successful_runs = 0

    print(f"\n{'='*70}")
    print(f"  ARGUS AGENT 4 BENCHMARK SUITE — 25 TEST CASES (Qwen3-8B)")
    print(f"{'='*70}\n")

    start_total = time.time()

    for idx, sample in enumerate(samples, 1):
        case_id = sample["case_id"]
        repo.clear()  # Ensure repository state isolation per test case

        t0 = time.time()
        output = agent.execute_analysis(case_id=case_id, agent2_input=sample)
        t1 = time.time()

        dur = t1 - t0
        execution_times.append(dur)

        is_success = output.execution_status.value == "SUCCESS"
        if is_success:
            successful_runs += 1

        claims_count = len(output.claims)
        total_claims_processed += claims_count
        total_fir_built += len(output.fir_findings)

        # Check citation accuracy & confidence score validity across generated claims
        valid_citations = sum(1 for c in output.claims if c.citation_verified)
        cit_acc = (valid_citations / claims_count) * 100 if claims_count > 0 else 100.0
        citation_accuracies.append(cit_acc)

        valid_conf = sum(1 for c in output.claims if c.is_valid_confidence)
        conf_acc = (valid_conf / claims_count) * 100 if claims_count > 0 else 100.0
        confidence_validities.append(conf_acc)

        print(f"Sample {idx:02d}/25 [{case_id}]: Status={output.execution_status.value} | Claims={claims_count} | Time={dur:.2f}s | CitationAcc={cit_acc:.0f}%")

    total_duration = time.time() - start_total

    # Calculate Benchmark Metrics
    avg_time = statistics.mean(execution_times)
    median_time = statistics.median(execution_times)
    min_time = min(execution_times)
    max_time = max(execution_times)

    overall_citation_acc = statistics.mean(citation_accuracies)
    overall_conf_validity = statistics.mean(confidence_validities)
    reliability_rate = (successful_runs / len(samples)) * 100
    throughput = total_claims_processed / total_duration

    summary = {
        "benchmark_summary": {
            "model_used": "Qwen3-8B",
            "total_samples_evaluated": len(samples),
            "successful_runs": successful_runs,
            "reliability_rate_pct": reliability_rate,
            "overall_citation_accuracy_pct": overall_citation_acc,
            "confidence_validity_pct": overall_conf_validity,
            "total_claims_analyzed": total_claims_processed,
            "total_fir_findings_generated": total_fir_built
        },
        "time_performance": {
            "total_duration_sec": round(total_duration, 2),
            "avg_time_per_sample_sec": round(avg_time, 2),
            "median_time_per_sample_sec": round(median_time, 2),
            "min_time_sec": round(min_time, 2),
            "max_time_sec": round(max_time, 2),
            "throughput_claims_per_sec": round(throughput, 2)
        }
    }

    with open("agent4_performance_metrics.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*70}")
    print(f"  BENCHMARK SUMMARY & PERFORMANCE RESULTS")
    print(f"{'='*70}")
    print(f"  • Reliability (Success Rate)   : {reliability_rate:.1f}%")
    print(f"  • Citation Accuracy             : {overall_citation_acc:.1f}%")
    print(f"  • Confidence Bounds Validity   : {overall_conf_validity:.1f}%")
    print(f"  • Average Time Per Case         : {avg_time:.2f}s (Median: {median_time:.2f}s)")
    print(f"  • Total Time (25 cases)         : {total_duration:.2f}s")
    print(f"  • Processing Throughput         : {throughput:.2f} claims/sec")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    run_benchmark()
