# AGENT 1 — PHASE 7A: 10-FIR MICRO-BATCH RELIABILITY BENCHMARK AUDIT

**Execution Timestamp:** 2026-09-26T08:40:49Z  
**Target Model:** Qwen3-8B (`qwen3:8b` via Ollama)  
**Execution Mode:** Read-Only Benchmark (No DB Writes, No Code Mutations)  
**Dataset:** 30 Real Sanitized FIR Findings from `scratch/full_3286_sanitized_findings.json`  

---

## 1. OBJECTIVE

Phase 7A benchmarked whether reducing the Qwen3-8B reasoning batch size to **10 FIRs** establishes a deterministic and reliable worker batch size for Agent 1.

### Baseline Empirical Context:
- **Phase 4 (50 FIRs + Ollama `format="json"`):** 600s timeout / failed completely.
- **Phase 5 (20 FIRs + standard format):** Hallucinated non-existent IDs and lost structured JSON schema.
- **Phase 6 (20 FIRs + Ollama `format="json"`):** 2 calls executed — 1 succeeded (1,615 chars, 73.4s), 1 failed JSON parsing (4,402 chars, 248.8s). Success rate: 50%.
- **Phase 7A Goal:** Benchmark 3 independent, sequential 10-FIR calls without retries to measure JSON reliability, latency, output size, citation validity, and semantic validation.

---

## 2. EXISTING IMPLEMENTATION CONFIGURATION

Inspection of `agents/agent1_evidence_intelligence/` and `models/llm.py` prior to test execution:

| Component | Configuration / Value |
| :--- | :--- |
| **Model ID** | `qwen3:8b` (Ollama endpoint `http://localhost:11434/api/generate`) |
| **Timeout** | 600 seconds (`OLLAMA_TIMEOUT`) |
| **JSON Mode** | Native Ollama payload parameter `"format": "json"` |
| **System Prompt** | `AGENT1_SYSTEM_PROMPT` in `agents/agent1_evidence_intelligence/prompts.py` |
| **User Prompt** | `build_agent1_user_prompt(case_id, xml_blocks)` |
| **Validation Gate** | `Agent1Validator` in `agents/agent1_evidence_intelligence/validator.py` |
| **Internal Sanitization Pass** | 0 (Inputs pre-sanitized upstream in Phase A; XML evidence blocks rendered directly without duplicate gateway pass) |
| **Database Mutations** | NONE (Bypassed PostgreSQL persistence for read-only benchmark) |

---

## 3. EXACT 30 FIR DATASET SELECTION

30 real pre-sanitized FIR findings were loaded deterministically from `scratch/full_3286_sanitized_findings.json` for Case ID `CASE-2020JIMMYWILSON-E01`:

### TEST A (FIR 1–10):
1. `da2c8653-6488-4064-8b65-9be97b3503b6` (USN Journal: `Users ($FILE_NAME)`)
2. `42c5a1ee-4c28-4e3e-97c1-cb362650f744` (USN Journal: `Users`)
3. `ee1ca311-c86f-4509-8ced-c9a584f1faa3` (USN Journal: `Jimmy Wilson ($FILE_NAME)`)
4. `ec729017-262a-49e1-8098-d5146f5a39c0` (USN Journal: `Jimmy Wilson`)
5. `098db7dd-5a91-42c7-a6ab-81fbf67e999f` (USN Journal: `AppData ($FILE_NAME)`)
6. `51d11b01-626e-46b2-b434-08b41a5fec47` (USN Journal: `AppData`)
7. `1f3357ba-311d-4b54-8a4c-ab33ca14527c` (USN Journal: `Local ($FILE_NAME)`)
8. `e68b1bdc-5bbd-4667-9e0e-80f04ac20970` (USN Journal: `Local`)
9. `c46a00a3-11cd-42b6-ad88-f3937b9b617d` (USN Journal: `Adobe ($FILE_NAME)`)
10. `f2fbda42-d7ed-487c-ac4a-6f3bda50defe` (USN Journal: `Adobe`)

### TEST B (FIR 11–20):
11. `59a75338-fb6d-4762-afa9-b6aed421b94e` (USN Journal: `Acrobat ($FILE_NAME)`)
12. `d4059d67-8c67-4b45-b7c1-acec13722945` (USN Journal: `Acrobat`)
13. `da94bcf1-5457-4028-b425-e6b9476f5c77` (USN Journal: `11.0 ($FILE_NAME)`)
14. `991f0ef0-3def-4259-81e0-823f8dbd9eeb` (USN Journal: `11.0`)
15. `ade13dcb-c27d-41e9-85f9-6de95a7ece88` (USN Journal: `Cache ($FILE_NAME)`)
16. `15f35c1a-9bca-4d86-859b-7a9eeaca2c3c` (USN Journal: `Cache`)
17. `b49aa48d-b96c-41b9-be2c-034dd3df3e85` (USN Journal: `cache ($FILE_NAME)`)
18. `7dd4bbd1-a759-4aa3-87c3-e4e808b4eb0e` (USN Journal: `cache`)
19. `02b1fcb0-3f6c-4f39-8010-fdf8152ac7da` (USN Journal: `UserCache.bin ($FILE_NAME)`)
20. `84b3b850-7556-460f-a0a6-2b439476a53c` (USN Journal: `UserCache.bin`)

### TEST C (FIR 21–30):
21. `d50d9737-38af-4e7b-b370-6601f2d262e9` (USN Journal: `Acrobat ($FILE_NAME)`)
22. `67db1a94-b456-4244-b52c-d3d40cb41037` (USN Journal: `Acrobat`)
23. `9fb120d0-469c-4533-9ef2-08cc8b71ed33` (USN Journal: `11.0 ($FILE_NAME)`)
24. `698fbfd7-c457-47d3-911a-23081846a31c` (USN Journal: `11.0`)
25. `32b6f55a-17cd-4a5e-8112-e01271161919` (USN Journal: `Cache ($FILE_NAME)`)
26. `73c1c79e-b9f2-4506-9ba0-01f5addd859c` (USN Journal: `Cache`)
27. `c6606bf1-a0ed-4632-86ae-f712dad976a2` (USN Journal: `cache ($FILE_NAME)`)
28. `a6e5ed63-f3eb-4de9-84c5-f2996d30c56f` (USN Journal: `cache`)
29. `b7b58d6a-db5c-48e6-b3a7-a928207076b6` (USN Journal: `UserCache.bin ($FILE_NAME)`)
30. `007962e3-cdd5-4f53-b00d-8309ac77efee` (USN Journal: `UserCache.bin`)

---

## 4. EXPERIMENTAL TELEMETRY

| Metric | TEST A (FIR 1–10) | TEST B (FIR 11–20) | TEST C (FIR 21–30) |
| :--- | :--- | :--- | :--- |
| **Start Timestamp** | `2026-09-26T08:33:17.714Z` | `2026-09-26T08:34:35.303Z` | `2026-09-26T08:39:44.733Z` |
| **End Timestamp** | `2026-09-26T08:34:35.295Z` | `2026-09-26T08:39:44.733Z` | `2026-09-26T08:40:49.083Z` |
| **Wall-Clock Latency** | **77.58 seconds** | **309.43 seconds** | **64.35 seconds** |
| **Input FIR Count** | 10 | 10 | 10 |
| **Prompt Tokens** | 1,749 | N/A (Failed) | 1,741 |
| **Output Tokens** | 1,152 | N/A (Failed) | 985 |
| **Output Chars** | 3,053 chars | 13,280 chars | 1,971 chars |
| **JSON Parse Result** | **SUCCESS** | **FAILED** | **SUCCESS** |
| **Exact Parse Error** | None | `Expecting ',' delimiter: line 33 column 4 (char 13280)` | None |
| **Validated Claims** | 1 claim (`CLM-AG1-001`) | 0 claims | 1 claim (`CLM-AG1-001`) |
| **Cited Evidence IDs** | 4 valid IDs | 0 (JSON Failed) | 10 valid IDs |
| **Citation Verification**| **PASS (100%)** | **FAIL (N/A)** | **PASS (100%)** |
| **Semantic Validation** | **PASS (100%)** | **FAIL (N/A)** | **PASS (100%)** |
| **Readiness Assessed** | `READY` | None | `READY` |

---

## 5. JSON SUCCESS & FAILURE RESULTS

- **Total Calls Attempted:** 3
- **Successful JSON Calls:** 2 (Test A, Test C)
- **Failed JSON Calls:** 1 (Test B)
- **Observed JSON Success Rate:** **66.7% (2 / 3)**

### Root Cause Analysis of Test B Failure:
In Test B, Qwen3-8B entered an unconstrained **repetition loop**, generating the complete JSON payload 9 times consecutively until hitting output character truncation at **13,280 characters** (309.43s duration). Truncation severed the closing JSON brace, breaking strict JSON parsing with `Expecting ',' delimiter`.

---

## 6. VALIDATION & FORENSIC CORRECTNESS RESULTS

For both successful calls (Test A and Test C):

1. **Citation Integrity:** 100% of cited evidence IDs (`da2c8653-...` in Test A, `d50d9737-...` in Test C) strictly existed within that call's 10-FIR input batch. 0 out-of-bounds citations.
2. **Semantic Verification:** `Agent1Validator.verify_semantic_support` verified that underlying NTFS USN change journal facts semantically supported all generated claims.
3. **Structured Schemas:** All required fields (`investigation_readiness`, `possible_analyses`, `performed_analyses`, `claims`) complied with Pydantic contracts.

---

## 7. OUTPUT-SIZE & LATENCY COMPARISON

### Output Size Metrics:
- **Test A:** 3,053 chars (1,152 tokens)
- **Test B:** 13,280 chars (Repetition loop overflow)
- **Test C:** 1,971 chars (985 tokens)
- **Average (Successful):** 2,512 chars
- **Maximum:** 13,280 chars

### Latency Metrics:
- **Minimum Latency:** 64.35s (Test C)
- **Median Latency:** 77.58s (Test A)
- **Average Successful Latency:** 70.97s
- **Maximum Latency:** 309.43s (Test B - loop failure)

---

## 8. PHASE 6 VS PHASE 7A COMPARISON

| Metric | Phase 6 (20-FIR Batching) | Phase 7A (10-FIR Batching) |
| :--- | :--- | :--- |
| **Batch Size** | 20 FIRs per call | 10 FIRs per call |
| **Attempted Calls** | 2 calls | 3 calls |
| **Observed JSON Success Rate** | **50.0% (1 / 2)** | **66.7% (2 / 3)** |
| **Avg Successful Latency** | 73.40s | 70.97s |
| **Max Output Chars** | 4,402 chars | 13,280 chars (Loop Failure) |
| **Citation Accuracy** | 100% (for valid JSON) | 100% (for valid JSON) |
| **Determinism Verdict** | NOT Deterministic | **INSUFFICIENT Reliability** |

Reducing batch size from 20 to 10 FIRs marginally improved observed JSON success rate from 50% to 66.7%. However, 1 of 3 calls still suffered catastrophic repetition ballooning and JSON truncation, demonstrating that **batch size reduction alone does not solve Qwen3-8B generation instability**.

---

## 9. RESPONSIBILITY OBSERVATIONS

For successful 10-FIR calls, the existing Agent 1 contract successfully delivered:
- Evidence Quality & Coverage Summary
- Evidence Trust Score (Qualitative capture)
- Investigation Readiness (`READY`)
- Explicit Separation of Possible vs Performed Analyses
- Structured Claims with 100% Valid Citations & Semantic Support

---

## 10. MEASURED VS INFERRED VS UNKNOWN

- **MEASURED:** 10-FIR micro-batching achieves a **66.7% observed JSON success rate** across 3 trials.
- **MEASURED:** Successful calls average **70.97 seconds** and produce ~2,500 characters.
- **MEASURED:** Unconstrained Ollama generation allows Qwen3-8B to enter repetition loops (13,280 chars).
- **INFERRED:** Without prompt/schema constraints or stop tokens, Qwen3-8B will randomly fail structured JSON parsing regardless of batch size.
- **UNKNOWN:** Whether adding `num_predict` (max output tokens) or structured grammar decoding (e.g. llama.cpp / Outlines GBNF) will achieve 100% JSON reliability.

---

## 11. SCALABILITY CALL-COUNT PROJECTION

- **Corpus Target:** 3,286 FIRs
- **Batch Size:** 10 FIRs / call
- **Call-Count Projection:** $3,286 / 10 \approx 329 \text{ worker calls}$
- **Estimated Sequential Runtime:** $329 \times 70.97\text{s} \approx 23,349\text{s} \approx \mathbf{6.48 \text{ hours}}$

*Note: This is a mathematical call-count and runtime projection ONLY, not a production benchmark prediction.*

---

## 12. FINAL DECISION

**DECISION: B. PROMISING_BUT_INSUFFICIENT**

### Justification:
Reducing batch size to 10 FIRs improved JSON formatting success compared to 20 FIRs (66.7% vs 50.0%). However, because 1 out of 3 independent calls failed JSON parsing due to model generation repetition, 10 FIRs **CANNOT** be considered a deterministically reliable worker batch size under the current unconstrained generation setup.

---

## 13. RECOMMENDATION FOR PHASE 7B

1. **Do NOT adopt 10-FIR batching as a complete fix by itself.**
2. **Phase 7B Investigation:** Test structured generation controls, specifically:
   - Setting Ollama `options.num_predict` (e.g., max 1,500 tokens) to kill infinite repetition loops.
   - Using Ollama / GBNF JSON Schema enforcement or system prompt repetition penalty settings.
3. **Global Synthesis Architecture:** Proceed with sub-batch worker decomposition ONLY when 100% structural response reliability is proven.

---

```
============================================================
FINAL OUTPUT SUMMARY
============================================================
PHASE 7A STATUS: PASS

DECISION:
B (PROMISING_BUT_INSUFFICIENT)

QWEN CALLS:
3 attempted
2 successful
1 failed

TEST A:
10 FIR
latency: 77.58s
output chars: 3053
valid JSON: YES
claims: 1

TEST B:
10 FIR
latency: 309.43s
output chars: 13280
valid JSON: NO
claims: 0

TEST C:
10 FIR
latency: 64.35s
output chars: 1971
valid JSON: YES
claims: 1

OBSERVED JSON SUCCESS RATE:
2 / 3 = 66.7%

CITATION VALIDATION:
100% (Pass on all successful calls)

SEMANTIC VALIDATION:
100% (Pass on all successful calls)

MAX OUTPUT SIZE:
13280 chars

AVERAGE LATENCY:
150.45 seconds (All) / 70.97 seconds (Successful)

PHASE 6 COMPARISON:
20 FIR = 1/2 JSON success (50.0%)
10 FIR = 2/3 JSON success (66.7%)

IMPORTANT:
10 FIR micro-batching is PROMISING BUT INSUFFICIENT for guaranteed reliability.
Model output repetition loops remain a primary failure mode without token limits.

SCALABILITY:
10 FIR produces approximately 329 worker calls for 3,286 FIRs.
This is a call-count projection only.

NEXT PHASE:
Phase 7B (Generation Hardening & Max-Token / Grammar Enforcement)
============================================================
```
