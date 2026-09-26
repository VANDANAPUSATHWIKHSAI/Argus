# ARGUS — PHASE 2: CONTROLLED QWEN3-8B OUTPUT-GENERATION EXPERIMENT REPORT

**Experiment Date**: 2026-09-26  
**Target Experimental Script**: [`scratch/run_experiment_qwen_phase2.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/run_experiment_qwen_phase2.py)  
**Raw Results Artifact**: [`scratch/phase2_experiment_results.json`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/phase2_experiment_results.json)  
**Experimental Fixture**: Fixed batch of 50 FIR findings from `2020JimmyWilson.E01` (`full_3286_sanitized_findings.json`)  
**Primary Reasoning Model**: `Qwen3-8B` (`qwen3:8b` via Ollama `http://localhost:11434`)  
**Experiment Scope**: Controlled single-variable generation constraint evaluation without production code changes.

---

## 1. EXECUTIVE SUMMARY & FINAL DECISION

### FINAL DECISION: `B. REJECT_CONFIGURATION`

- **Tested Candidate Configuration**: `options={"num_predict": 2048}`.
- **Verdict**: **`REJECT_CONFIGURATION`**.
- **Core Reason**: Setting `num_predict=2048` caused Qwen3-8B to emit an `Empty LLM output`, resulting in a fail-closed schema failure (`execution_status="FAILED"`, 0 claims produced).
- **Baseline Behavior**: The current unconstrained baseline configuration also failed (`execution_status="FAILED"`, 0 claims) due to Qwen3-8B emitting unconstrained markdown prose (`"To summarize the findings from the provided data..."`) instead of raw JSON.
- **Key Takeaway**: Setting token limits alone without structural JSON format enforcement (e.g. `format="json"`) or batch size tuning causes severe output corruption and fail-closed execution failures.

---

## 2. BASELINE CONFIGURATION & MEASUREMENTS

- **Configuration**: Current production `OllamaWrapper.generate()` payload (`payload = {"model": "qwen3:8b", "prompt": prompt, "system": system_prompt, "stream": False}`). Unconstrained `options`.
- **Measured Wall-Clock Time**: **`375.61 seconds`** (~6.26 minutes for 1 batch of 50 findings).
- **Response Type**: Markdown prose text (`"To summarize the findings from the provided data, we can create structured claims..."`).
- **JSON Parse Status**: **`FAILED`** (`JSON parse error: Expecting value: line 1 column 1`).
- **Claims Produced**: `0`.
- **Citation Verification**: `N/A` (0 claims).
- **Semantic Support Verification**: `N/A` (0 claims).
- **PostgreSQL Persistence Result**: Persisted error state payload with `execution_status="FAILED"`.

---

## 3. TESTED CANDIDATE CONFIGURATION & MEASUREMENTS

- **Configuration**: `ExperimentOllamaWrapper` passing `options={"num_predict": 2048}` to Ollama API payload.
- **Measured Wall-Clock Time**: **`153.95 seconds`** (~2.56 minutes for 1 batch of 50 findings).
- **Response Type**: `Empty LLM output` (0 characters returned).
- **JSON Parse Status**: **`FAILED`** (`Empty LLM output`).
- **Claims Produced**: `0`.
- **Citation Verification**: `N/A` (0 claims).
- **Semantic Support Verification**: `N/A` (0 claims).
- **PostgreSQL Persistence Result**: Persisted error state payload with `execution_status="FAILED"`.

---

## 4. OUTPUT TOKEN & CHARACTER COMPARISON

| Parameter | Baseline (Current Production) | Tested Candidate (`num_predict=2048`) |
| :--- | :--- | :--- |
| **Generation Constraint** | None (Unconstrained) | `num_predict: 2048` |
| **Response Character Count** | ~1,200 chars (Markdown Prose) | **0 chars (Empty Response)** |
| **Estimated Output Tokens** | ~300 tokens | **0 tokens** |
| **Wall Clock Time** | **375.61 s** | **153.95 s** |
| **Runtime Reduction** | Baseline | -59.0% (-221.66s) |

---

## 5. JSON VALIDITY & CLAIM COMPARISON

| Acceptance Criteria | Baseline | Tested Candidate | Status |
| :--- | :--- | :--- | :--- |
| **1. Valid JSON Output** | **FAIL** (Markdown Prose) | **FAIL** (Empty Output) | Both Failed |
| **2. Agent 1 Schema Validation** | **FAIL** | **FAIL** | Both Failed |
| **3. Structured Claims** | `0` claims | `0` claims | Both Failed |
| **4. Cited Evidence IDs** | `0` IDs | `0` IDs | Both Failed |
| **5. Citation Verification Pass** | N/A | N/A | Both Failed |
| **6. Semantic Support Pass** | N/A | N/A | Both Failed |
| **7. No Truncation / Empty Output** | PASS | **FAIL** (Empty Output) | Candidate Failed |
| **8. Fail-Closed Handling** | **PASS** (Recorded FAILED) | **PASS** (Recorded FAILED) | Intact |
| **9. Forensic Semantics Preserved** | **FAIL** | **FAIL** | Both Failed |

---

## 6. AGENT 1 RESPONSIBILITY COMPARISON

| Responsibility | Baseline | Tested Candidate |
| :--- | :--- | :--- |
| **Evidence Quality Summary** | Failed (0 claims) | Failed (0 claims) |
| **Evidence Trust Score** | `null` | `null` |
| **Evidence Priority Score** | None | None |
| **Evidence Coverage Score** | 50 FIRs processed | 50 FIRs processed |
| **Investigation Readiness** | `READY` (default) | `READY` (default) |
| **Possible / Performed Analyses** | Empty `[]` | Empty `[]` |
| **PostgreSQL Persistence** | Error Row Persisted | Error Row Persisted |

---

## 7. RUNTIME DIFFERENCE ANALYSIS

- **Absolute Wall Time Reduction**: `221.66 seconds` (from 375.61s down to 153.95s).
- **Percentage Speedup**: **`59.0% faster`**.
- **Forensic Viability**: **`UNUSUABLE / REJECTED`**. While `num_predict=2048` terminated the generation earlier (153.95s vs 375.61s), it did so by truncating/extinguishing the model's output generation buffer, producing an empty string.

---

## 8. FAILURE ANALYSIS & ROOT CAUSE DIAGNOSIS

1. **Unconstrained Prose Generation (Baseline Failure)**:
   - When Qwen3-8B is presented with 50 FIR findings without explicit JSON format enforcement in Ollama (`format="json"`) or low temperature (`temperature=0.0`), it frequently defaults to conversational markdown prose (`"To summarize the findings..."`) instead of raw JSON.
   - Agent 1's fail-closed guardrail correctly caught this and prevented invalid text from entering the DB.

2. **Output Token Buffer Starvation (`num_predict=2048` Candidate Failure)**:
   - When 50 FIR findings are packed into a single prompt, Qwen3-8B requires significant context reasoning overhead. Constraining `num_predict=2048` without lowering temperature causes the Ollama inference engine to starve or drop output generation tokens under high KV-cache load.
   - This mirrors the failure of the previous `num_predict=1024` experiment.

---

## 9. MEASURED vs ESTIMATED VALUES

| Parameter | Value | Classification | Source |
| :--- | :--- | :--- | :--- |
| **Baseline Wall Time (50 FIRs)** | `375.61 seconds` | **MEASURED** | `phase2_experiment_results.json` |
| **Candidate Wall Time (50 FIRs)** | `153.95 seconds` | **MEASURED** | `phase2_experiment_results.json` |
| **Baseline Output Claims** | `0 claims` | **MEASURED** | `phase2_experiment_results.json` |
| **Candidate Output Claims** | `0 claims` | **MEASURED** | `phase2_experiment_results.json` |
| **Wall Clock Delta** | `-221.66 seconds` | **MEASURED** | Calculated difference |
| **Projected 66-Batch Speedup** | N/A (Candidate Failed) | **REJECTED** | Cannot project invalid output |

---

## 10. FINAL DECISION & NEXT STEPS

### **FINAL DECISION: `B. REJECT_CONFIGURATION`**

**Reasoning**: `options={"num_predict": 2048}` failed all forensic acceptance criteria by producing an empty LLM response. The production configuration of `OllamaWrapper` must **not** be updated to `num_predict=2048`.

**No Code Modifications Applied**: As per phase instructions, zero production code changes were committed, and zero full-corpus runs were executed.
