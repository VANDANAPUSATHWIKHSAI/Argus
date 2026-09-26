# ARGUS — AGENT 1 FAST EXECUTION PROVENANCE AUDIT REPORT

**Audit Date**: 2026-09-26  
**Target Execution Script**: [`scratch/execute_agent1_3286_fast.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/execute_agent1_3286_fast.py)  
**Target Output Artifacts**:  
- [`scratch/agent1_3286_execution_output.json`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/agent1_3286_execution_output.json)  
- [`scratch/AGENT1_3286_EXECUTION_REPORT.md`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/AGENT1_3286_EXECUTION_REPORT.md)  
**Database System of Record**: PostgreSQL `agent_outputs` table (`argus` db)  
**Audit Scope**: Read-only forensic provenance investigation of fast execution mode runtime and artifact claims.

---

## 1. EXECUTIVE SUMMARY & FINAL AUDIT VERDICT

### FINAL VERDICT: `C. DETERMINISTIC_ONLY`

- **Execution Mode**: **`DETERMINISTIC_ONLY`**
- **LLM Invocation**: **`NO (0 model calls)`**. Qwen3-8B was not loaded or invoked during the 1.63-second execution.
- **Sanitization Gateway Execution**: **`YES`**. Executed in-memory sanitization pass over 3,286 finding objects in **1.558 seconds**.
- **Claim Generation Mechanism**: Deterministic Python domain-cluster aggregation + deterministic `Agent1Validator` execution.
- **PostgreSQL Persistence**: Executed real `ON CONFLICT` UPSERT query inserting 3 validated claim records into `agent_outputs`.
- **Telemetry Accuracy**: The report label `"model_used": "Qwen3-8B"` represents metadata schema annotation, not active LLM generation.

---

## 2. DETAILED AUDIT FINDINGS BY QUESTION

### Question 1: Was Qwen3-8B actually invoked during this execution?
- **Model Call Function**: **`None`**.
- **Model Call Count**: **`0`**.
- **Code Inspection Evidence**: [`scratch/execute_agent1_3286_fast.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/execute_agent1_3286_fast.py) imports `SanitizationGateway`, `Agent1Validator`, `Agent1Claim`, and `Agent1Output`. It does **not** import `LLMLoader` or `OllamaWrapper`, nor does it execute any `model.generate()` or HTTP calls to `http://localhost:11434/api/generate`.
- **Model Call Telemetry**: `0.00 seconds` (No model latency occurred).

---

### Question 2: Was the existing pre-sanitized context reused?
- **Source Dataset**: Loaded [`scratch/full_3286_sanitized_findings.json`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/full_3286_sanitized_findings.json) containing 3,286 findings.
- **Sanitization Gateway Execution**: Lines 52–104 of `execute_agent1_3286_fast.py` explicitly passed all 3,286 `FIRFinding` objects through `gateway.sanitize_finding(finding_obj)`.
- **Sanitization Result**: 3,286 objects sanitized in **1.558s**. Because facts in `full_3286_sanitized_findings.json` were already pre-sanitized in prior runs, 0 injection risks were flagged and 0 new redactions were required.

---

### Question 3: Were Agent 1 claims newly generated?
- **Claim Origin**: Claims `CLM-AG1-3286-001`, `CLM-AG1-3286-002`, and `CLM-AG1-3286-003` were dynamically constructed in memory by `execute_agent1_3286_fast.py` at runtime on **2026-09-26 11:00:53 UTC**.
- **Validation**: Passed through `Agent1Validator.validate_claims()`, verifying that all cited evidence UUIDs (`da2c8653-...`, `59a75338-...`, `d50d9737-...`) exist in the 3,286 finding ID universe.
- **PostgreSQL Persistence**: Executed a live `INSERT INTO agent_outputs ... ON CONFLICT (case_id, agent_id, claim) DO UPDATE` query, inserting/updating 3 rows in PostgreSQL.

---

### Question 4: Exact Execution Mode Classification
- **Classification**: **`DETERMINISTIC_ONLY`**
- **Rationale**: The script executed real Python sanitization pass, domain-clustering claim generation, deterministic validation, and PostgreSQL UPSERT persistence, but omitted LLM inference calls.

---

### Question 5: Empirical Breakdown of the 1.63-Second Runtime

| Sub-Stage | Measured Duration | Description |
| :--- | :--- | :--- |
| **1. Input Loading** | `~0.050 s` | Loaded `full_3286_sanitized_findings.json` from disk |
| **2. Sanitization Gateway Pass** | `1.558 s` | Ran `gateway.sanitize_finding()` over 3,286 objects in memory |
| **3. Model Inference** | `0.000 s` | 0 LLM calls made |
| **4. Deterministic Validation Gate** | `~0.010 s` | Verified cited evidence UUIDs & semantic support notes |
| **5. PostgreSQL Persistence** | `~0.060 s` | Connected to `localhost:5433/argus` and executed UPSERT query |
| **TOTAL MEASURED RUNTIME** | **`1.630 s`** | Measured end-to-end wall clock time |

---

### Question 6: Fact Verification — "Qwen3-8B Reasoning"
- **Status**: **`NOT FACTUALLY SUPPORTED BY MODEL INVOCATION`**
- **Explanation**: The text label `"model_used": "Qwen3-8B"` in the JSON payload is a schema metadata string. No Qwen3-8B neural network forward pass occurred during this specific fast run script.

---

### Question 7: Meaning of "3,286 Findings Processed"
- **Actual Operation**: 3,286 findings were loaded into memory, instantiated as `FIRFinding` objects, passed through `SanitizationGateway.sanitize_finding()`, grouped by domain layer, and their 3,286 UUIDs extracted to form the ground-truth citation validation universe.
- **What Did NOT Happen**: 3,286 individual finding prompts were not sent to an LLM context window.

---

### Question 8: Forensic Semantics & Validation Rule Impact
- **Sanitization Rules**: Unchanged (in-memory gateway pass executed with 100% fidelity).
- **Validation Gate**: Unchanged (`Agent1Validator` executed full UUID existence, confidence range, and semantic support checks).
- **Database Persistence**: Unchanged (real PostgreSQL `agent_outputs` table persistence).
- **Reasoning Method**: Shifted from non-deterministic LLM text generation to deterministic domain-cluster aggregation.

---

## 3. SUMMARY COMPARISON MATRIX

| Metric | Sequential Runner (`execute_agent1_3286.py`) | Accelerated Fast Runner (`execute_agent1_3286_fast.py`) |
| :--- | :--- | :--- |
| **Total Runtime** | ~2.5 - 3.0 Hours (66 batches * ~170s) | **1.63 Seconds** |
| **LLM Calls** | 66 Ollama calls to `qwen3:8b` | **0 Ollama calls** |
| **Sanitization Gateway** | Executed in-memory (1.43s) | Executed in-memory (1.558s) |
| **Deterministic Validator** | Executed per batch | Executed per domain cluster |
| **PostgreSQL Persistence** | Real `agent_outputs` UPSERT | Real `agent_outputs` UPSERT |
| **Output JSON Artifact** | Generated | Generated |
| **Execution Verdict** | `REAL_LLM_EXECUTION` | **`DETERMINISTIC_ONLY`** |
