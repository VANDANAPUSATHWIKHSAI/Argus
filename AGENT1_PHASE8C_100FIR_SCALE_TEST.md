# AGENT 1 — PHASE 8C: 100-FIR CONTROLLED SCALE TEST REPORT

**Execution Timestamp:** 2026-09-26T10:24:57Z  
**Environment:** Windows 11 / Local Ollama API (v0.17.1)  
**Target Scale Dataset:** 100 Real Pre-Sanitized FIR Findings from `scratch/full_3286_sanitized_findings.json` (Positions 1–100)  
**Worker Hardening Payload:** Qwen3-8B + Native JSON Schema + `repeat_penalty=1.15` (Phase 7C Validated)  
**Execution Mode:** Controlled Worker Scale Test (10 Sequential Micro-Batches, Mid-Run Inspection, Deterministic Consolidation, Resume Validation)  
**Run ID:** `PHASE8C-SCALE-RUN-1790417755`  

---

## 1. OBJECTIVE

Phase 8B successfully validated the worker architecture across 3 batches (30 FIRs). Phase 8C evaluated the same hardened worker architecture under a **100-FIR scale test** (10 sequential 10-FIR worker batches) to verify whether generation stability, citation correctness, semantic validation, crash-window checkpointing, and resume protection scale predictably across a larger workload.

---

## 2. ENVIRONMENT & WORKER CONFIGURATION

- **Ollama Engine:** `http://localhost:11434/api/generate` (`qwen3:8b`)
- **Generation Controls:**
  - `format`: `Agent1Output` Pydantic-equivalent JSON Schema dictionary
  - `options`: `{"repeat_penalty": 1.15}`
- **Execution Mode:** Sequential worker execution (0 parallel requests).
- **Sanitization:** Consumed pre-sanitized fields directly. Zero redundant gateway passes executed.

---

## 3. DATASET PRE-FLIGHT VERIFICATION

100 real pre-sanitized FIR findings were loaded deterministically from positions 1–100 of `scratch/full_3286_sanitized_findings.json`:
- **Total Loaded:** 100 FIR findings
- **Unique FIR IDs:** 100 / 100 (0 duplicates detected)
- **First FIR ID (Position 1):** `da2c8653-6488-4064-8b65-9be97b3503b6`
- **Last FIR ID (Position 100):** `4997a1c1-5cd9-4919-b7f3-d5a9f2536373`

**Pre-flight Verdict:** **100% VERIFIED MATCH**.

---

## 4. BATCH-BY-BATCH WORKER TELEMETRY

| Batch ID | FIR Range | FIR Count | Latency (s) | Output Tokens | Output Chars | JSON Valid | Claims | Namespaced Claim ID | Citation Valid | Semantic Valid | Checkpoint Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :---: | :---: | :--- |
| **BATCH-001** | FIR 1–10 | 10 | 36.77s | 461 | 1,391 | YES | 1 | `CLM-W001-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-002** | FIR 11–20 | 10 | 37.99s | 553 | 1,616 | YES | 1 | `CLM-W002-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-003** | FIR 21–30 | 10 | 45.01s | 667 | 1,796 | YES | 1 | `CLM-W003-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-004** | FIR 31–40 | 10 | 27.64s | 410 | 1,243 | YES | 1 | `CLM-W004-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-005** | FIR 41–50 | 10 | 39.40s | 585 | 1,406 | YES | 1 | `CLM-W005-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-006** | FIR 51–60 | 10 | 31.98s | 448 | 1,246 | YES | 1 | `CLM-W006-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-007** | FIR 61–70 | 10 | 25.74s | 364 | 1,118 | YES | 1 | `CLM-W007-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-008** | FIR 71–80 | 10 | 41.31s | 597 | 1,504 | YES | 1 | `CLM-W008-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-009** | FIR 81–90 | 10 | 43.39s | 615 | 1,570 | YES | 1 | `CLM-W009-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-010** | FIR 91–100 | 10 | 44.66s | 682 | 1,688 | YES | 1 | `CLM-W010-001` | PASS (100%) | PASS (100%) | `COMPLETED` |

---

## 5. MID-RUN CHECKPOINT INSPECTION (AFTER BATCH 5)

As required by protocol, model execution was paused after Batch 5 for database/in-memory checkpoint verification:
- **Completed Batches in Checkpoint Store (5):** `['BATCH-001', 'BATCH-002', 'BATCH-003', 'BATCH-004', 'BATCH-005']`
- **Duplicate Checkpoints:** 0
- **Missing Checkpoints:** 0
- **Inspection Verdict:** **PASS (Exactly 5 completed batches in checkpoint store)**.

Execution resumed seamlessly for Batches 6–10.

---

## 6. AGGREGATE METRICS & SCALING ANALYSIS

- **Total FIRs Processed:** 100
- **Total Worker Batches:** 10
- **Successful Worker Batches:** 10 / 10 (100.0%)
- **Failed Worker Batches:** 0 / 10
- **Total Qwen3-8B Calls:** 10
- **Total Wall-Clock Time:** 500.73 seconds ($\approx 8.35 \text{ minutes}$)
- **Average Latency per Batch:** 37.39 seconds
- **Median Latency per Batch:** 38.70 seconds
- **Minimum Latency:** 25.74 seconds (Batch 007)
- **Maximum Latency:** 45.01 seconds (Batch 003)
- **Total Output Tokens:** 5,420 tokens
- **Average Output Tokens per Batch:** 542 tokens
- **Total Validated Claims:** 10
- **JSON Success Rate:** 100.0% (10/10)
- **Schema Conformance Rate:** 100.0% (10/10)
- **Citation Success Rate:** 100.0% (10/10)
- **Semantic Validation Success Rate:** 100.0% (10/10)
- **Repetition Failures:** 0
- **Truncation Failures:** 0
- **Observed Pilot Throughput:** **11.98 FIRs / minute**
- **Mathematical Projection for 3,286 FIRs:** $\sim \mathbf{3.42 \text{ hours}}$ ($329 \text{ calls} \times 37.39\text{s} = 12,301.31\text{s}$). *(MATHEMATICAL PROJECTION ONLY)*

---

## 7. COMPARISON WITH PHASES 7C AND 8B

| Metric | Phase 7C | Phase 8B | Phase 8C |
| :--- | :---: | :---: | :---: |
| **Total Worker Calls** | 5 | 3 | **10** |
| **Successful Calls** | 5 | 3 | **10** |
| **Failed Calls** | 0 | 0 | **0** |
| **JSON Success Rate** | 100.0% | 100.0% | **100.0%** |
| **Citation Verification Success** | 100.0% | 100.0% | **100.0%** |
| **Semantic Validation Success** | 100.0% | 100.0% | **100.0%** |
| **Average Latency** | 37.48s | 39.35s | **37.39s** |
| **Minimum Latency** | 26.99s | 36.83s | **25.74s** |
| **Maximum Latency** | 71.01s | 43.28s | **45.01s** |
| **Average Output Tokens** | 569.8 | 550.7 | **542.0** |
| **Repetition Failures** | 0 | 0 | **0** |
| **Truncation Failures** | 0 | 0 | **0** |

---

## 8. POST-RUN DETERMINISTIC WORKER-OUTPUT CONSOLIDATION

The post-run consolidation phase deterministically combined all 10 worker outputs without calling Qwen for global synthesis:

- **Total Worker Claims:** 10
- **Total Validated Claims:** 10
- **Total Citation-Valid Claims:** 10
- **Total Semantically-Supported Claims:** 10
- **Namespaced Claims List:** `CLM-W001-001` .. `CLM-W010-001`
- **Evidence-ID Union Count:** **74 unique FIR finding IDs**
- **Worker Possible Analyses Union:** `["Filesystem analysis", "Log analysis", "Registry analysis"]`
- **Worker Performed Analyses Union:** `["Artifact entity extraction", "Filesystem timeline extraction"]`

*Note: Global fields (Evidence Trust Score, Investigation Readiness, Evidence Coverage) were NOT computed during worker consolidation, preserving the two-stage architecture boundary.*

---

## 9. CONTROLLED RESUME TEST

Immediately following scale test completion, a second runner execution was initiated against the same run ID (`PHASE8C-SCALE-RUN-1790417755`):

- **Batches Checked:** `BATCH-001` through `BATCH-010`
- **Checkpoint Matches:** 10 / 10
- **Qwen Calls Performed during Resume:** **0**
- **Batches Skipped during Resume:** **10**
- **Resume Test Verdict:** **PASS (0 New Qwen Calls, 10 Skipped)**

---

## 10. INTERPRETATION & STATISTICAL BOUNDARY

**Observed Empirical Result:** 10/10 successful observed worker executions in this controlled 100-FIR scale test.

**Statistical Boundary:** While 10/10 success across 100 FIRs confirms local worker execution stability, it is an empirical sample and **NOT** a mathematical guarantee of 100% production-scale reliability across 3,286 FIRs.

---

## 11. AUDIT DECISION

**PHASE 8C STATUS: PASS**

### Summary Matrix:
- **FIRs Processed:** 100 real pre-sanitized FIR findings.
- **Worker Batches:** 10 sequential 10-FIR batches.
- **Qwen Calls:** 10 real Qwen3-8B calls (100% successful).
- **Average Latency:** 37.39 seconds / batch.
- **Observed Throughput:** 11.98 FIRs / minute.
- **Mid-Run Checkpoint Inspection:** PASS (Verified after Batch 5).
- **Resume Test:** PASS (0 new calls, 10 skipped).
- **Global Synthesis:** NONE attempted (Boundary strictly preserved).
- **Production Changes:** NONE (Read-Only Scale Test completed cleanly).

---

## 12. RECOMMENDATIONS FOR PHASE 8D

1. **Proceed to Global Synthesis Architecture (Phase 8D):** With worker execution stability empirically demonstrated across 100 FIRs, Phase 8D should design and test the global Qwen synthesis layer over consolidated worker claims and metrics.
2. **Preserve Hardened Worker Payload:** Maintain `format = Agent1Output JSON Schema` + `options: {"repeat_penalty": 1.15}` for all worker invocations.

---

```
============================================================
FINAL RESPONSE SUMMARY
============================================================
PHASE 8C STATUS:
PASS

FIRs:
100 real pre-sanitized FIR findings (positions 1–100)

BATCHES:
10 sequential worker batches (10 FIRs/batch)

QWEN CALLS:
10 executed during scale test

SUCCESS:
10 / 10 (100.0%)

FAILURES:
0 (0 model failures, 0 JSON syntax errors, 0 repetition loops, 0 truncation errors)

AVG LATENCY:
37.39 seconds

MEDIAN LATENCY:
38.70 seconds

MIN/MAX LATENCY:
Min: 25.74s (Batch 007) / Max: 45.01s (Batch 003)

OBSERVED THROUGHPUT:
11.98 FIRs / minute

JSON:
100% valid JSON (10/10)

CITATION:
100% valid citations (10/10)

SEMANTIC:
100% semantically supported (10/10)

CLAIMS:
10 validated claims (CLM-W001-001 .. CLM-W010-001), 74 unique cited evidence IDs unioned

MID-RUN CHECKPOINT:
PASS (Verified exactly 5 completed batches after Batch 5)

RESUME:
PASS

NEW QWEN CALLS DURING RESUME:
0 (10/10 batches skipped via checkpoint manager)

PRODUCTION CHANGES:
NONE (Runner script created in scratch/; zero production code mutations)

REPORT:
AGENT1_PHASE8C_100FIR_SCALE_TEST.md
============================================================
```
