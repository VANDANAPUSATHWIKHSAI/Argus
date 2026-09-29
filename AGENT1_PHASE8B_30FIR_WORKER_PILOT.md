# AGENT 1 — PHASE 8B: HARDENED MULTI-BATCH WORKER PILOT REPORT

**Execution Timestamp:** 2026-09-26T10:10:22Z  
**Target Pilot Dataset:** 30 Real Pre-Sanitized FIR Findings from `scratch/full_3286_sanitized_findings.json` (FIRs 1–30)  
**Worker Configuration:** Qwen3-8B + Native JSON Schema + `repeat_penalty=1.15` (Phase 7C Validated)  
**Execution Mode:** Controlled Implementation & Pilot Execution (Worker Layer Only, No Global Synthesis)  
**Run ID:** `PHASE8B-PILOT-RUN-1790417246`  

---

## 1. IMPLEMENTATION SUMMARY

Phase 8B implemented and validated the **Agent 1 Multi-Batch Worker Layer** over 30 real pre-sanitized FIR findings divided into 3 sequential 10-FIR worker batches:
- **Runner Script Created:** `scratch/execute_agent1_30_hardened.py`
- **Worker Hardening:** Applied native GBNF JSON Schema constrained decoding + `repeat_penalty=1.15`.
- **Pre-Sanitization:** Input consumed pre-sanitized XML evidence blocks directly. Zero redundant `SanitizationGateway.sanitize_finding()` passes were executed inside the worker.
- **Deterministic Namespacing:** Claim IDs were deterministically namespaced per batch (`CLM-W001-001`, `CLM-W002-001`, `CLM-W003-001`).
- **Commit Ordering:** Enforced Output Commit before Checkpoint Commit.
- **Resume Test:** Verified that restarting the runner on an existing run ID executes **0 new Qwen calls** and skips all completed batches.

---

## 2. EXACT FILES CREATED & UNCHANGED

### Files Created:
- `scratch/execute_agent1_30_hardened.py` (Worker pilot runner)
- `scratch/phase8b_worker_pilot_results.json` (Pilot execution telemetry)
- `scratch/phase8b_resume_test_results.json` (Resume test telemetry)
- `AGENT1_PHASE8B_30FIR_WORKER_PILOT.md` (This audit report)

### Files NOT Modified (Strictly Preserved):
- `models/llm.py`
- `agents/agent1_evidence_intelligence/prompts.py`
- `agents/agent1_evidence_intelligence/schemas.py`
- `agents/agent1_evidence_intelligence/validator.py`
- `agents/agent1_evidence_intelligence/agent.py`
- `fir/repository.py`
- PostgreSQL schema definitions

---

## 3. DATASET & BATCH VERIFICATION

30 real pre-sanitized FIR findings were loaded deterministically from `scratch/full_3286_sanitized_findings.json` and assigned to 3 worker batches:

- **Batch 001 (FIR 1–10):** `da2c8653-6488-4064-8b65-9be97b3503b6` .. `f2fbda42-d7ed-487c-ac4a-6f3bda50defe`
- **Batch 002 (FIR 11–20):** `59a75338-fb6d-4762-afa9-b6aed421b94e` .. `84b3b850-7556-460f-a0a6-2b439476a53c`
- **Batch 003 (FIR 21–30):** `d50d9737-38af-4e7b-b370-6601f2d262e9` .. `007962e3-cdd5-4f53-b00d-8309ac77efee`

**Verification Verdict:** **100% Verified Match (30/30 FIR IDs loaded sequentially)**.

---

## 4. WORKER PILOT EXECUTION TELEMETRY

| Batch ID | FIR Range | FIR Count | Latency (s) | Output Tokens | Output Chars | JSON Valid | Claims | Namespaced Claim ID | Citation Valid | Semantic Valid | Checkpoint Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :---: | :---: | :--- |
| **BATCH-001** | FIR 1–10 | 10 | 36.83s | 458 | 1,327 | YES | 1 | `CLM-W001-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-002** | FIR 11–20 | 10 | 37.95s | 547 | 1,468 | YES | 1 | `CLM-W002-001` | PASS (100%) | PASS (100%) | `COMPLETED` |
| **BATCH-003** | FIR 21–30 | 10 | 43.28s | 647 | 1,624 | YES | 1 | `CLM-W003-001` | PASS (100%) | PASS (100%) | `COMPLETED` |

---

## 5. AGGREGATE METRICS

- **Total Worker Batches Processed:** 3
- **Successful Worker Batches:** 3 / 3 (100.0%)
- **Failed Worker Batches:** 0 / 3
- **Total Qwen3-8B Generation Calls:** 3
- **Total Wall-Clock Runtime:** 118.06 seconds
- **Average Latency per Batch:** 39.35 seconds
- **Average Output Tokens per Batch:** 550.7 tokens
- **Total Validated Claims Produced:** 3
- **Overall Execution Verdict:** **PASS**

---

## 6. CLAIM ID NAMESPACING & PROVENANCE INTEGRITY

- **Claim ID Namespacing:** Original model-produced claim IDs (`CLM-AG1-001`) were re-namespaced deterministically to `CLM-W001-001`, `CLM-W002-001`, and `CLM-W003-001`.
- **Schema Field Limitation Note:** The existing `Agent1Claim` schema does not contain an explicit `worker_original_claim_id` field. To respect non-negotiable rules against modifying production schemas during Phase 8B, this limitation was recorded without editing `schemas.py`.
- **Provenance Integrity:** 100% of cited evidence IDs (`da2c8653...`, `59a75338...`, `d50d9737...`) were preserved intact. Zero FIR IDs or source artifact references were modified, dropped, or corrupted.

---

## 7. PERSISTENCE & CHECKPOINT VERIFICATION

- **Commit Sequence:** Order of operations strictly enforced: Output Commit attempt $\rightarrow$ Checkpoint Commit.
- **Checkpoint Manager:** `Agent1CheckpointManager` successfully tracked `BATCH-001`, `BATCH-002`, and `BATCH-003` as `COMPLETED` under run ID `PHASE8B-PILOT-RUN-1790417246`.

---

## 8. CONTROLLED PILOT RESUME TEST

Immediately following pilot completion, a second invocation was initiated against the same run ID (`PHASE8B-PILOT-RUN-1790417246`):

- **Batch BATCH-001 Checkpoint Check:** `COMPLETED` $\rightarrow$ Skipped
- **Batch BATCH-002 Checkpoint Check:** `COMPLETED` $\rightarrow$ Skipped
- **Batch BATCH-003 Checkpoint Check:** `COMPLETED` $\rightarrow$ Skipped
- **Qwen Calls Performed during Resume:** **0**
- **Batches Skipped during Resume:** **3**
- **Resume Test Verdict:** **PASS (0 New Qwen Calls, 3 Skipped)**

---

## 9. FORENSIC VALIDATION SUMMARY

 Across all 3 worker batches:
1. **JSON & Schema Conformance:** 100% (3/3 batches produced valid JSON matching `Agent1Output`).
2. **Citation Verification:** 100% Pass (Batch 1: 5/5 valid IDs; Batch 2: 8/8 valid IDs; Batch 3: 10/10 valid IDs).
3. **Semantic Validation:** 100% Pass (All cited USN journal facts semantically support generated claims).
4. **Out-of-Bounds Citations:** 0
5. **No Global Synthesis:** Global synthesis was **NOT** attempted (Phase 8B strictly tested the worker layer).

---

```
============================================================
FINAL RESPONSE SUMMARY
============================================================
PHASE 8B STATUS:
PASS

BATCHES:
3 attempted
3 successful
0 failed

QWEN CALLS:
3 executed during pilot

SUCCESS:
3 / 3 (100.0%)

FAILURES:
0

AVG LATENCY:
39.35 seconds per 10-FIR batch (Total time: 118.06s)

TOTAL CLAIMS:
3 validated claims produced (CLM-W001-001, CLM-W002-001, CLM-W003-001)

CITATION VALIDATION:
100% PASS across all 3 batches

SEMANTIC VALIDATION:
100% PASS across all 3 batches

RESUME TEST:
PASS

NEW QWEN CALLS DURING RESUME:
0 (3 batches skipped via checkpoint manager)

PRODUCTION CHANGES:
NONE (Runner script created in scratch/; zero production code mutations)

REPORT:
AGENT1_PHASE8B_30FIR_WORKER_PILOT.md
============================================================
```
