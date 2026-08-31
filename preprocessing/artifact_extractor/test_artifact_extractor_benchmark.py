import sys
import os
import time
import unittest
import psutil
import torch
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from preprocessing.schemas import Artifact
from preprocessing.artifact_extractor.extractor import ArtifactExtractor

class TestArtifactExtractorBenchmark(unittest.TestCase):
    """
    Benchmark suite measuring:
    1. Cold vs Warm model loading latency
    2. Warm inference throughput and latency
    3. Peak RAM consumption
    4. CPU/GPU utilization
    """

    @unittest.skipUnless(
        os.getenv("ARGUS_RUN_MODEL_INTEGRATION_TESTS") == "1",
        "requires cached GLiNER weights; set ARGUS_RUN_MODEL_INTEGRATION_TESTS=1 to run benchmark"
    )
    def test_benchmark_performance_profile(self):
        print("\n=== STARTING ARTIFACT EXTRACTOR BENCHMARK PROFILE ===")
        
        # 1. Measure Peak RAM and CPU/GPU before cold startup
        process = psutil.Process(os.getpid())
        ram_before_mb = process.memory_info().rss / (1024 * 1024)
        print(f"Memory utilization before load: {ram_before_mb:.2f} MB")
        
        # 2. Cold Startup Latency
        start_time = time.perf_counter()
        extractor = ArtifactExtractor()
        cold_load_time = time.perf_counter() - start_time
        print(f"Cold model loading latency: {cold_load_time:.4f} seconds")
        
        # 3. Peak RAM after load
        ram_after_mb = process.memory_info().rss / (1024 * 1024)
        print(f"Memory utilization after load: {ram_after_mb:.2f} MB")
        print(f"Net model load RAM overhead: {ram_after_mb - ram_before_mb:.2f} MB")

        # 4. Device Utilization Check
        device = extractor._device
        print(f"Inference running on device: {device}")
        if device == "cuda":
            print(f"CUDA Device Name: {torch.cuda.get_device_name(0)}")
            print(f"CUDA Memory Allocated: {torch.cuda.memory_allocated(0) / (1024 * 1024):.2f} MB")
            print(f"CUDA Memory Cached: {torch.cuda.memory_reserved(0) / (1024 * 1024):.2f} MB")

        # 5. Warm inference profiling
        artifact = Artifact(
            evidence_id="ev-bench",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={
                "description": "APT28 threat-actor used loader malware Wannacry in conjunction with Lazarus Group to establish persistence by spawning cmd.exe."
            }
        )
        
        # Run 10 iterations to measure average and peak warm inference latency
        latencies = []
        for i in range(15):
            iter_start = time.perf_counter()
            entities = extractor.extract([artifact], "ev-bench")
            iter_duration = time.perf_counter() - iter_start
            latencies.append(iter_duration)
        
        # Discard the first run as warm-up
        warm_latencies = latencies[1:]
        avg_warm_latency = sum(warm_latencies) / len(warm_latencies)
        peak_warm_latency = max(warm_latencies)
        
        print(f"Warm Inference Latency (Avg): {avg_warm_latency:.4f} seconds")
        print(f"Warm Inference Latency (Peak): {peak_warm_latency:.4f} seconds")

        # 6. Large payload profiling
        large_sentences = [
            "The malicious actor associated with Lazarus Group deployed Wannacry ransomware on domain controler.",
            "APT28 executed tasksche.exe to establish registry RUN key persistence.",
            "Emotet Trojan connected to command-and-control (C2) servers on IP address 192.168.1.100."
        ]
        large_prose = " ".join(large_sentences * 50)  # ~150 sentences, ~15k characters
        
        large_artifact = Artifact(
            evidence_id="ev-bench-large",
            source_tool="test",
            artifact_type="process_event",
            raw_fields={"description": large_prose}
        )
        
        large_start = time.perf_counter()
        large_entities = extractor.extract([large_artifact], "ev-bench-large")
        large_duration = time.perf_counter() - large_start
        
        char_throughput = len(large_prose) / large_duration
        print(f"Large payload text length: {len(large_prose)} chars")
        print(f"Large payload processing time: {large_duration:.4f} seconds")
        print(f"Large payload throughput: {char_throughput:.2f} chars/second")
        print(f"Large payload extracted entity count: {len(large_entities)}")

        # 7. Final memory and CPU/GPU utilization
        ram_final_mb = process.memory_info().rss / (1024 * 1024)
        cpu_usage_pct = process.cpu_percent(interval=0.1)
        
        print(f"Peak RSS Memory during execution: {ram_final_mb:.2f} MB")
        print(f"CPU Utilization (Process level): {cpu_usage_pct:.1f}%")
        if device == "cuda":
            print(f"CUDA Final Allocated: {torch.cuda.memory_allocated(0) / (1024 * 1024):.2f} MB")
        print("=== END OF ARTIFACT EXTRACTOR BENCHMARK PROFILE ===\n")

        # Sanity thresholds
        self.assertTrue(cold_load_time < 30.0, "Model loading took too long!")
        self.assertTrue(avg_warm_latency < 2.0, "Warm inference is too slow!")

if __name__ == "__main__":
    unittest.main()
