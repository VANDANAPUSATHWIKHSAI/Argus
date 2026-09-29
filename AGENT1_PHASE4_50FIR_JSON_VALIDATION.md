# ARGUS — PHASE 4: 50-FIR STRUCTURED JSON VALIDATION REPORT

**Validation Date**: 2026-09-26  
**Target Validation Script**: [`scratch/run_validation_phase4.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/run_validation_phase4.py)  
**Raw Results Artifact**: [`scratch/phase4_validation_results.json`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/phase4_validation_results.json)  
**Experimental Fixture**: Fixed production-sized batch of 50 FIR findings from `2020JimmyWilson.E01` (`full_3286_sanitized_findings.json`)  
**Primary Model**: `Qwen3-8B` (`qwen3:8b` via Ollama `http://localhost:11434`)  
**Single Variable Tested**: Ollama Native GGUF Grammar Constraint `format="json"` over 50 FIR findings  
**Inference Count**: **Exactly 1 Qwen3-8B Inference Call**  
**PostgreSQL Persistence**: None (0 DB operations)  
**Production Code Changes**: None (0 production changes)

---

## 1. EXECUTIVE SUMMARY & FINAL DECISION

### FINAL DECISION: `B. FAIL_50FIR_JSON`

- **Verdict**: **`FAIL_50FIR_JSON`**
- **Core Cause**: Requesting Ollama native `format="json"` over a single prompt containing 50 FIR findings caused the Ollama GGUF grammar sampler to hit the **600-second HTTP timeout (`602.09 seconds`)** and return an **empty 0-byte response**.
- **Empirical Failure Details**:
  1. Response was **empty** (`0 characters`).
  2. JSON parsing **FAILED** (`is_empty: true`, `json_parse_success: false`).
  3. Schema mapping **FAILED** (`schema_compatible: false`).
  4. Claims produced: **0 claims**.
  5. Citation & Semantic validation: **FAILED** (0 evidence IDs cited).
  6. Truncation status: **`is_truncated: true`** (extinguished by timeout).

---

## 2. EXACT EXPERIMENTAL CONFIGURATION

- **FIR Finding Fixture**: 50 real correlated domain FIR findings from partition offset 65664 on `2020JimmyWilson.E01` (identical fixture as Phase 2 experiment).
- **System Prompt**: Production `AGENT1_SYSTEM_PROMPT`.
- **User Prompt**: Production `build_agent1_user_prompt("CASE-2020JIMMYWILSON-E01", xml_blocks)`.
- **Ollama API Payload**:
  ```json
  {
    "model": "qwen3:8b",
    "prompt": "<user_prompt>",
    "system": "<system_prompt>",
    "stream": false,
    "format": "json"
  }
  ```
- **Temperature / num_predict**: Unchanged / Default.

---

## 3. EMPIRICAL MEASUREMENTS

| Metric | Measured Value | Status |
| :--- | :--- | :--- |
| **Inference Call Count** | **1 call** | Compliant |
| **Wall-Clock Latency** | **602.09 seconds** | **FAILED (Timeout at 600s)** |
| **Response Character Length** | **0 characters** | **FAILED (Empty)** |
| **Is Response Empty?** | **YES** | **FAILED** |
| **Is Response Truncated / Extinguished?** | **YES** | **FAILED** |
| **JSON Parse Result** | **FAILED** (`json_parse_success: false`) | **FAILED** |
| **Agent 1 Schema Compatibility** | **FAILED** (`schema_compatible: false`) | **FAILED** |
| **Structured Claims Count** | **0 Claims** | **FAILED** |
| **Cited Evidence IDs Count** | **0 IDs** | **FAILED** |
| **Citation Verification Result** | **FAILED** | **FAILED** |
| **Semantic Support Verification Result** | **FAILED** | **FAILED** |

---

## 4. TRUNCATION & TIMEOUT ANALYSIS

1. **Context Scaling Limit**:
   - In **Phase 3** (10 FIR findings), `format="json"` succeeded cleanly in **50.27 seconds**, generating 1,489 characters of 100% valid Agent 1 JSON.
   - In **Phase 4** (50 FIR findings), packing 50 XML evidence blocks (~10,000 prompt characters) into a single LLM request while constraining grammar via `format="json"` caused the local Ollama GGUF grammar sampler's state graph to explode, exceeding the 600s timeout.

2. **Scale Incompatibility**:
   - Applying `format="json"` directly to a batch of 50 findings without prompt chunking or smaller sub-batching is **not scale-compatible** for a single HTTP request on local hardware.

---

## 5. MEASURED vs ESTIMATED VALUES

| Parameter | Value | Classification | Source |
| :--- | :--- | :--- | :--- |
| **Fixture Size** | `50 FIR Findings` | **MEASURED** | `run_validation_phase4.py` |
| **Inference Call Count** | `1 Call` | **MEASURED** | `run_validation_phase4.py` |
| **Wall-Clock Latency** | `602.09 seconds` | **MEASURED** | `phase4_validation_results.json` |
| **Response Character Length** | `0 characters` | **MEASURED** | `phase4_validation_results.json` |
| **JSON Parse Status** | `FAILED (Empty)` | **MEASURED** | `phase4_validation_results.json` |
| **Valid Claims Produced** | `0 Claims` | **MEASURED** | `phase4_validation_results.json` |
| **Cited Evidence IDs** | `0 IDs` | **MEASURED** | `phase4_validation_results.json` |
| **Extrapolated 3,286 Runtime** | N/A (Phase Failed) | **REJECTED** | Single batch timeout |

---

## 6. FINAL DECISION

### **FINAL DECISION: `B. FAIL_50FIR_JSON`**

**Summary**: While native `format="json"` works perfectly for 10-FIR batches (50.27s), scaling `format="json"` to 50 FIR findings in a single prompt causes Ollama to time out at 600s and return an empty response. Production batch sizing or sub-batching is required to maintain JSON format correctness. Zero production code changes were committed.
