# ARGUS Agent 1 — Runtime Baseline Measurement Report

**Target Evidence:** `2020JimmyWilson.E01` (Size: 309,818,835 bytes ~295.47 MB, 5,002 FIR findings)  
**Execution Environment:** Windows PowerShell / Python 3.13  
**Hardware Platform:** NVIDIA GeForce RTX 3050 6GB Laptop GPU / 12th Gen Intel Core CPU  
**Date of Measurement:** 2026-09-24  

---

## 1. Execution Map & Pipeline Flow

```text
2020JimmyWilson.E01 (295.47 MB)
  │
  ├──> SleuthKit fls Bodyfile Extraction (11,553 raw records)
  │
  ├──> Normalizer & ArtifactExtractor (50,332 atomic entities)
  │
  ├──> FCREngine Correlation (1,369 FCR records)
  │
  ├──> EvidenceConsolidation & process_fcr_batch (5,002 FIR findings)
  │
  ├──> FIRRepository.insert() [Executes 1 DDL statement + write-time PII/injection check per FIR]
  │
  ├──> SanitizationGateway.sanitize_finding() [Stage D: Pre-sanitization before Agent 1]
  │
  ├──> Agent1.run() [Stage D Re-invocation: Sanitizes again if raw findings passed -> 2.0 calls/FIR]
  │     └─> Qwen3-8B Reasoning Call (101 sequential batches for full corpus)
  │
  ├──> Agent1Validator (12-Point Independent Deterministic Python Gate)
  │
  └──> PostgreSQL agent_outputs Persistence
```

---

## 2. Measured Stage Timings Breakdown

Empirical measurement recorded over real evidence subset:

| Stage | Operation / Component | Measured Wall-Clock Time | Percentage of Total Runtime | Category |
| :--- | :--- | :--- | :--- | :--- |
| **A & B** | Preprocessing & FIR Finding Intake | 0.0500 sec | 0.04% | Measured |
| **C** | FIR PostgreSQL Insertion | 0.1546 sec | 0.11% | Measured |
| **C (DDL)** | PostgreSQL DDL Execution (`CREATE TABLE`) | 0.0246 sec | 0.02% | Measured |
| **D** | Sanitization Gateway (`sanitize_finding`) | 0.0038 sec | 0.003% | Measured |
| **E** | Prompt Injection Detection (`is_injection`) | 0.0007 sec | 0.0005% | Measured |
| **F & G** | **Qwen3-8B Model Reasoning Call** | **141.8064 sec** | **99.83%** | **PROVEN BOTTLENECK** |
| **H** | Agent1Validator Python Validation Gate | 0.0002 sec | 0.0001% | Measured |
| **I** | PostgreSQL `agent_outputs` Persistence | 0.0265 sec | 0.02% | Measured |
| **K** | **Total Wall-Clock Runtime (per batch)** | **142.0499 sec** | **100.00%** | **Measured** |

---

## 3. PostgreSQL DDL Verification

- **Number of FIR Inserts Executed:** 5
- **CREATE TABLE Statements Executed:** 5 (1 per `FIRRepository.insert()` call)
- **ALTER TABLE Statements Executed:** 0 (all 8 column definitions bundled in the single multi-line DDL query)
- **Total DDL Statements Executed:** 5
- **DDL Wall-Clock Time:** `0.0246 sec`
- **Percentage of Insertion Runtime:** `15.89%` of insertion time (`0.017%` of total pipeline runtime)
- **Finding:** Repeated DDL execution is wasteful and executed on every insert (`1.0 DDL statements/FIR`), but its wall-clock contribution is small (`~0.0049 sec/FIR`).

---

## 4. Duplicate Sanitization Verification

- **Total FIRs Processed:** 5
- **Total `sanitize_finding()` Calls:** 10
- **Calls / FIR Ratio:** **2.0 calls per FIR** (PROVEN BY MEASUREMENT)
- **Invocation Sites Identified:**
  1. **Call 1 (Explicit Pre-sanitization):** Executed in script pre-loop (`SanitizationGateway.sanitize_finding(f)`).
  2. **Call 2 (Agent 1 Internal Ingestion):** Executed inside `Agent1.run()` (`agents/agent1_evidence_intelligence/agent.py:138`).
- **Total Sanitization Wall-Clock Time:** `0.0038 sec` (0.0027% of runtime)
- **Finding:** Duplicate sanitization is confirmed code-wise and count-wise (`2.0 calls/FIR`), but execution time for sanitization text processing is lightweight (`0.00076 sec/FIR`).

---

## 5. Injection Detector Baseline

- **Total `InjectionDetector.is_injection()` Calls:** 30 calls across 5 FIRs
- **Calls / FIR Ratio:** 6.0 calls/FIR (triggered across finding fields, markdown comment check, base64 payload scan, and rot13 scan)
- **Total Injection Detection Time:** `0.0007 sec`
- **Finding:** Heuristic pre-checks in `InjectionDetector` quickly filter clean forensic text, preventing PyTorch CPU model inference for clean data.

---

## 6. Qwen3-8B Baseline & Token Metrics

- **Number of Qwen Calls:** 1
- **FIRs per Batch:** 5
- **Generation Time per Call:** **141.81 seconds**
- **Average Call Latency:** 141.81 sec
- **Minimum Call Latency:** 141.81 sec
- **Maximum Call Latency:** 141.81 sec
- **Input Tokens (Estimated):** ~540 tokens
- **Output Tokens (Generated):** ~685 tokens
- **Generation Throughput:** **4.83 tokens/sec**
- **Peak GPU VRAM Allocated:** ~5.2 GB (Qwen3-8B Q4_K_M GGUF via Ollama in GPU memory)

---

## 7. IDE / Terminal Attachment Comparison

- **Mode A (Foreground attached to interactive IDE terminal):**
  - High stdout stream logging causes buffer locking when printing large batch outputs over 100+ iterations.
  - Interactive terminal process blocks Node.js event loop when buffer fills.
- **Mode B (Windows-native detached background `Start-Process`):**
  - Stdout/stderr cleanly redirected to `logs/agent1_full_run.log`.
  - Process executes independently of interactive IDE terminal, eliminating UI freezing.

---

## 8. Summary of Classifications

### A. Proven by Measurement
1. **Qwen3-8B call latency is the primary dominant bottleneck**, accounting for **99.83%** of total pipeline runtime (`141.81 sec` out of `142.05 sec`).
2. **Duplicate sanitization exists count-wise** at exactly **2.0 `sanitize_finding()` calls per FIR**.
3. **Repeated PostgreSQL DDL exists count-wise** at **1.0 DDL statement per FIR insert** (5 DDL queries for 5 inserts), but consumes only **0.0246 sec** (0.017% of total runtime).
4. **Agent1Validator is extremely fast**, completing 5 claim validations in **0.000165 sec** (0.0001% of runtime).

### B. Observed from Code
1. `Agent1.run()` contains logic to re-sanitize findings if passed raw FIR objects or fetched from repository.
2. `FIRRepository.insert()` contains inline `CREATE TABLE IF NOT EXISTS` DDL inside the insertion query.

### C. Estimated
1. **Full 5,002-FIR Corpus Runtime (Unoptimized Sequential Baseline):**
   - 101 batches × 141.81 sec/batch = **14,322 seconds = ~3.98 hours**.
