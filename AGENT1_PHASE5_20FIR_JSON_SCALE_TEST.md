# ARGUS — PHASE 5: 20-FIR JSON SCALE MICRO-TEST REPORT

**Test Date**: 2026-09-26  
**Target Scale Test Script**: [`scratch/run_scale_phase5.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/run_scale_phase5.py)  
**Raw Results Artifact**: [`scratch/phase5_scale_results.json`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/scratch/phase5_scale_results.json)  
**Experimental Fixture**: Fixed batch of exactly 20 FIR findings from `2020JimmyWilson.E01` (`full_3286_sanitized_findings.json`)  
**Primary Model**: `Qwen3-8B` (`qwen3:8b` via Ollama `http://localhost:11434`)  
**Single Variable Tested**: Ollama Native GGUF Grammar Constraint `format="json"` over 20 FIR findings  
**Inference Count**: **Exactly 1 Qwen3-8B Inference Call**  
**PostgreSQL Persistence**: None (0 DB operations)  
**Production Code Changes**: None (0 production changes)

---

## 1. EXECUTIVE SUMMARY & FINAL DECISION

### FINAL DECISION: `A. PASS_20FIR_JSON`

- **Verdict**: **`PASS_20FIR_JSON`**
- **Empirical Proof**:
  1. Response was **non-empty** (1,417 characters).
  2. Response was **valid JSON** (`json_parse_success: true`, 0 parse errors).
  3. Response was **100% free of markdown prose wrappers** (0 markdown backticks or conversational intros).
  4. Response **perfectly mapped to the Agent 1 output contract** (`investigation_readiness: "READY"`, `possible_analyses`, `performed_analyses`, `claims`).
  5. Claims were **structured** and cited **5 real evidence finding UUIDs** (`da2c8653-6488-4064-8b65-9be97b3503b6`, `ec729017-...`, `d4059d67-...`, `15f35c1a-...`, `f2fbda42-...`).
  6. In-memory `Agent1Validator` verification **PASSED** (`citation_verification_pass: true`, `semantic_support_verification_pass: true`).
  7. No truncation occurred (`is_truncated: false`).

---

## 2. EXACT EXPERIMENTAL CONFIGURATION

- **FIR Finding Fixture**: 20 real correlated domain FIR findings from partition offset 65664 on `2020JimmyWilson.E01`.
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
| **Wall-Clock Latency** | **43.00 seconds** | Measured |
| **Response Character Length** | **1,417 characters** | Measured |
| **Is Response Empty?** | **No** | Pass |
| **Is Response Markdown Prose?** | **No** (0 markdown wrappers) | Pass |
| **Is Response Truncated?** | **No** | Pass |
| **JSON Parse Result** | **PASS** (`json_parse_success: true`) | Pass |
| **Agent 1 Schema Compatibility** | **PASS** | Pass |
| **Structured Claims Count** | **1 Claim** (`CLM-AG1-001`) | Pass |
| **Cited Evidence IDs Count** | **5 Real Finding UUIDs** | Pass |
| **Citation Verification Result** | **PASS (`True`)** | Pass |
| **Semantic Support Verification Result** | **PASS (`True`)** | Pass |

---

## 4. RAW RESPONSE SUMMARY

The raw response returned by Ollama was valid JSON:

```json
{
  "investigation_readiness": "READY",
  "possible_analyses": [
    "Filesystem analysis",
    "Log analysis",
    "Registry analysis"
  ],
  "performed_analyses": [
    "Filesystem timeline extraction",
    "Artifact entity extraction"
  ],
  "claims": [
    {
      "claim_id": "CLM-AG1-001",
      "summary": "File system activity detected for user-related directories",
      "findings_summary": "Multiple NTFS USN change journal records indicate file activity in user directories (Users, Jimmy Wilson, AppData, Local, Adobe) around 2015-05-26...",
      "cited_evidence_ids": [
        "da2c8653-6488-4064-8b65-9be97b3503b6",
        "ec729017-262a-49e1-8098-d5146f5a39c0",
        "d4059d67-8c67-4b45-b7c1-acec13722945",
        "15f35c1a-9bca-4d86-859b-7a9eeaca2c3c",
        "f2fbda42-d7ed-487c-ac4a-6f3bda50defe"
      ],
      "assessed_importance": "high",
      "confidence_score": 0.92,
      "missing_evidence_noted": [
        "Missing memory artifact for process PID 4412"
      ],
      "uncertainties_or_conflicts": [
        "Timestamp conflict between EVTX and registry hive"
      ],
      "reasoning_notes": "The clustered timestamps and repeated directory activity suggest potential user interaction..."
    }
  ]
}
```

---

## 5. IN-MEMORY VALIDATION AUDIT

`Agent1Validator` executed over the returned JSON in memory:
- **`citation_verification_pass`**: `True` (All 5 cited UUIDs matched `da2c8653-...` through `f2fbda42-...` in input universe).
- **`is_valid_confidence`**: `True` (`0.92` within `[0.0, 1.0]`).
- **`semantic_support_verification_pass`**: `True` (Underlying FIR facts semantically support file system timeline claim).

---

## 6. MEASURED vs ESTIMATED VALUES

| Parameter | Value | Classification | Source |
| :--- | :--- | :--- | :--- |
| **Fixtures Ingested** | `20 FIR Findings` | **MEASURED** | `run_scale_phase5.py` |
| **Inference Call Count** | `1 Call` | **MEASURED** | `run_scale_phase5.py` |
| **Wall-Clock Latency** | `43.00 seconds` | **MEASURED** | `phase5_scale_results.json` |
| **Response Length** | `1,417 characters` | **MEASURED** | `phase5_scale_results.json` |
| **JSON Parse Status** | `SUCCESS` | **MEASURED** | `phase5_scale_results.json` |
| **Parsed Claims** | `1 Claim` | **MEASURED** | `phase5_scale_results.json` |
| **Cited Finding UUIDs** | `5 UUIDs` | **MEASURED** | `phase5_scale_results.json` |
| **Extrapolated 3,286 Runtime** | N/A (Not extrapolated) | **REJECTED** | Single scale-test metric |

---

## 7. FINAL DECISION

### **FINAL DECISION: `A. PASS_20FIR_JSON`**

**Summary**: A batch size of 20 FIR findings combined with Ollama native `format="json"` completes in **43.00 seconds**, producing 100% valid, schema-compliant, citation-verified Agent 1 JSON.
