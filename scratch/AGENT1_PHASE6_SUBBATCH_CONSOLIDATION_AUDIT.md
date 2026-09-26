# ARGUS Phase 6: Two 20-FIR Sub-Batch Consolidation Experiment Report

## 1. Objective
The objective of Phase 6 is to evaluate whether splitting evidence into smaller 20-FIR Qwen calls using Ollama native `format="json"` can preserve the Agent 1 output contract and whether sub-batch outputs (Batch A: FIR 1–20, Batch B: FIR 21–40) can be safely consolidated into a single global Agent 1 assessment without modifying production code, prompts, validators, or schemas.

---

## 2. Existing Agent1Output Contract Audit

Inspection of `agents/agent1_evidence_intelligence/agent.py`, `schemas.py`, `prompts.py`, and `validator.py` reveals the following structure:

### Contract Breakdown
| Field Name | Type | Scope | Can Safely Union? | Aggregation Formula Status |
| :--- | :--- | :--- | :--- | :--- |
| `claims` | List[`StructuredClaim`] | Per-claim | **YES** (with dedup & provenance check) | Claim-level preservation |
| `investigation_readiness` | `InvestigationReadiness` | Global | **NO** | **UNDEFINED** (No `min`/`max` rule in code) |
| `evidence_trust_score` | `EvidenceTrustScore` | Global | **NO** | **UNDEFINED** (No formula in code) |
| `evidence_coverage` | `EvidenceCoverage` | Global | **NO** | **UNDEFINED** (Sub-batch subsets only) |
| `evidence_quality_summary` | `EvidenceQualitySummary` | Global | **NO** | **UNDEFINED** (Requires whole-evidence context) |
| `possible_analyses` | List[str] | Global | **PARTIAL** | **UNDEFINED** (Lacks cross-batch context) |
| `performed_analyses` | List[str] | Global | **PARTIAL** | **UNDEFINED** (Lacks cross-batch context) |

### Key Contract Rules
1. **Evidence Trust Score**: **UNDEFINED**. No mathematical aggregation formula exists in code, schemas, or docs to combine two sub-batch trust scores.
2. **Evidence Coverage**: **UNDEFINED**. Each sub-batch output covers only its input FIR subset. Global coverage cannot be calculated deterministically without evaluating total corpus scope.
3. **Investigation Readiness**: **UNDEFINED**. No explicit fallback/aggregation rule (e.g. `min(A, B)`) exists in production code.

---

## 3. Fixed 40-FIR Dataset Selection

The 40 real FIR findings were selected deterministically from the pre-sanitized dataset `scratch/full_3286_sanitized_findings.json` (source case `E01_corpus`):

- **Total Selected FIRs**: 40
- **Batch A**: FIR 1–20 (Indices 0–19)
- **Batch B**: FIR 21–40 (Indices 20–39)

### Batch FIR ID Map
- **Batch A (FIR 1–20)**:
  1. `da2c8653-6488-4064-8b65-9be97b3503b6`
  2. `42c5a1ee-4c28-4e3e-97c1-cb362650f744`
  3. `ee1ca311-c86f-4509-8ced-c9a584f1faa3`
  4. `ec729017-262a-49e1-8098-d5146f5a39c0`
  5. `098db7dd-5a91-42c7-a6ab-81fbf67e999f`
  6. `51d11b01-626e-46b2-b434-08b41a5fec47`
  7. `1f3357ba-311d-4b54-8a4c-ab33ca14527c`
  8. `e68b1bdc-5bbd-4667-9e0e-80f04ac20970`
  9. `c46a00a3-11cd-42b6-ad88-f3937b9b617d`
  10. `f2fbda42-d7ed-487c-ac4a-6f3bda50defe`
  11. `59a75338-fb6d-4762-afa9-b6aed421b94e`
  12. `d4059d67-8c67-4b45-b7c1-acec13722945`
  13. `da94bcf1-5457-4028-b425-e6b9476f5c77`
  14. `991f0ef0-3def-4259-81e0-823f8dbd9eeb`
  15. `ade13dcb-c27d-41e9-85f9-6de95a7ece88`
  16. `15f35c1a-9bca-4d86-859b-7a9eeaca2c3c`
  17. `b49aa48d-b96c-41b9-be2c-034dd3df3e85`
  18. `7dd4bbd1-a759-4aa3-87c3-e4e808b4eb0e`
  19. `02b1fcb0-3f6c-4f39-8010-fdf8152ac7da`
  20. `84b3b850-7556-460f-a0a6-2b439476a53c`

- **Batch B (FIR 21–40)**:
  21. `d50d9737-38af-4e7b-b370-6601f2d262e9`
  22. `67db1a94-b456-4244-b52c-d3d40cb41037`
  23. `9fb120d0-469c-4533-9ef2-08cc8b71ed33`
  24. `698fbfd7-c457-47d3-911a-23081846a31c`
  25. `32b6f55a-17cd-4a5e-8112-e01271161919`
  26. `73c1c79e-b9f2-4506-9ba0-01f5addd859c`
  27. `c6606bf1-a0ed-4632-86ae-f712dad976a2`
  28. `a6e5ed63-f3eb-4de9-84c5-f2996d30c56f`
  29. `b7b58d6a-db5c-48e6-b3a7-a928207076b6`
  30. `007962e3-cdd5-4f53-b00d-8309ac77efee`
  31. `71c73f3d-2ed3-487f-a7e5-0dd0e1fb19c6`
  32. `72553e0e-a2a5-47dc-8f6c-78518d951f26`
  33. `60de544c-59c8-4b1d-8d2b-71e3780fbd6d`
  34. `b7108902-cee2-42e2-875d-d006eb618e7f`
  35. `97a3e275-e408-47c6-a20f-577b3c9b54b6`
  36. `e644f062-9bec-4488-9f0c-593041bd3e12`
  37. `d67b4109-e128-45a3-96c9-51b07f652119`
  38. `a4fdc52a-7567-4cbc-b52a-6cc70730c990`
  39. `01b8ee6f-1525-4bd5-87db-31da7ebf5e40`
  40. `fc9c1829-6a4c-40bb-baa5-bf0bf0c5ac54`

---

## 4. Sanitization Status
- **Input Findings**: Pre-sanitized 40 FIRs.
- **Sanitization Pass**: Skipped redundant pass per protocol.
- **Passed**: 40
- **Blocked / Quarantined / Failed**: 0

---

## 5. Qwen Call Telemetry & Results

### Call #1 (Batch A - FIR 1–20)
- **Model**: `qwen3:8b` via Ollama native `format="json"`
- **Input FIR Count**: 20
- **Wall Clock Latency**: 119.70 seconds
- **Output Character Count**: 4,402 chars
- **JSON Parse Status**: **FAIL** (`Expecting ',' delimiter: line 54 column 1 (char 4402)`)
- **Schema Validation Status**: N/A (JSON syntax malformed / truncated)
- **Validated Claims Count**: 0
- **Investigation Readiness**: N/A
- **Evidence Trust Score**: N/A

### Call #2 (Batch B - FIR 21–40)
- **Model**: `qwen3:8b` via Ollama native `format="json"`
- **Input FIR Count**: 20
- **Wall Clock Latency**: 48.83 seconds
- **Output Character Count**: 1,615 chars
- **JSON Parse Status**: **PASS** (Valid JSON)
- **Schema Validation Status**: **PASS** (`Agent1Validator`)
- **Validated Claims Count**: 1 (`CLM-AG1-001`)
- **Cited Evidence IDs**: 8 IDs (`d50d9737-38af-4e7b-b370-6601f2d262e9`, `67db1a94-b456-4244-b52c-d3d40cb41037`, `9fb120d0-469c-4533-9ef2-08cc8b71ed33`, `32b6f55a-17cd-4a5e-8112-e01271161919`, `73c1c79e-b9f2-4506-9ba0-01f5addd859c`, `71c73f3d-2ed3-487f-a7e5-0dd0e1fb19c6`, `97a3e275-e408-47c6-a20f-577b3c9b54b6`, `d67b4109-e128-45a3-96c9-51b07f652119`)
- **Citation Validation**: 100% PASSED (All 8 cited evidence IDs exist in Batch B input)
- **Semantic Support Validation**: 100% PASSED (Supported by underlying FIR facts)
- **Investigation Readiness**: `READY`
- **Possible Analyses**: `["Filesystem analysis", "Log analysis", "Registry analysis"]`
- **Performed Analyses**: `["Filesystem timeline extraction", "Artifact entity extraction"]`

---

## 6. Read-Only Consolidation Analysis

### A. Claim Union
- **Batch A Claims**: 0 (JSON parse failure)
- **Batch B Claims**: 1 (`CLM-AG1-001`)
- **Union Claims Total**: 1
- **Provenance Verification**: `CLM-AG1-001` retains valid evidence citations to 8 FIR findings in Batch B.

### B. Citation & Coverage
- **Batch A Cited IDs**: 0
- **Batch B Cited IDs**: 8
- **Union Cited IDs**: 8 / 40 total FIRs
- **Uncited FIRs**: 32 FIRs (20 in Batch A due to JSON parse error; 12 in Batch B unreferenced).

### C. Investigation Readiness
- **Batch A**: Undefined (Parse failure)
- **Batch B**: `READY`
- **Global Assessment**: **REQUIRES_GLOBAL_SYNTHESIS**. No formula in code permits determining global readiness from sub-batches.

### D. Evidence Trust Score
- **Batch A**: Undefined
- **Batch B**: Null / Unspecified
- **Global Assessment**: **REQUIRES_GLOBAL_SYNTHESIS**. No formula exists.

### E. Evidence Coverage
- **Global Assessment**: **REQUIRES_GLOBAL_SYNTHESIS**. Per-batch subsets cannot infer full corpus coverage without a global evaluation pass.

### F. Evidence Quality Summary
- **Global Assessment**: **REQUIRES_GLOBAL_SYNTHESIS**. Whole-evidence reasoning is required to produce a unified quality assessment.

### G. Possible / Performed Analyses
- **Batch B Possible**: `Filesystem analysis`, `Log analysis`, `Registry analysis`
- **Batch B Performed**: `Filesystem timeline extraction`, `Artifact entity extraction`
- **Global Assessment**: **REQUIRES_GLOBAL_SYNTHESIS**. A simple set union is incomplete because cross-artifact analysis capability requires evaluating full evidence relations.

---

## 7. Performance Analysis

- **Batch A Latency**: 119.70 s
- **Batch B Latency**: 48.83 s
- **Total Qwen Inference Time**: 168.53 s (2 calls)
- **Average Latency**: 84.27 s / call
- **Comparison to 50-FIR Call**: 50 FIR with `format="json"` timed out at 600s. Two 20-FIR calls completed in 168.53s total, representing a successful wall-clock execution, but 1 of the 2 calls produced invalid JSON syntax.

---

## 8. Responsibility Preservation Matrix

| Responsibility | Preserved Status | Reason / Explanation |
| :--- | :--- | :--- |
| **Evidence Quality** | ❌ NOT PRESERVED | Global quality summary requires whole-evidence reasoning; no aggregation formula exists. |
| **Evidence Trust Score** | ❌ NOT PRESERVED | No aggregation formula defined in code/schema. |
| **Evidence Priority** | ❌ NOT PRESERVED | Priority calculation relies on full corpus relative weighting. |
| **Evidence Coverage** | ❌ NOT PRESERVED | Sub-batches evaluate partial scope only; global coverage is undefined. |
| **Investigation Readiness** | ❌ NOT PRESERVED | No deterministic `min()` / `max()` aggregation rule exists. |
| **Possible Analyses** | ❌ NOT PRESERVED | Cross-batch analysis capability requires whole-evidence context. |
| **Performed Analyses** | ❌ NOT PRESERVED | Union is partial and lacks global synthesis. |
| **Structured Claims** | ⚠️ PARTIALLY PRESERVED | Claims retain validity when JSON succeeds, but Qwen sub-batches exhibit formatting errors. |
| **Evidence-ID Citations** | ✅ PRESERVED | Cited evidence IDs strictly map to input sub-batch FIRs with 100% validity. |
| **Evidence Provenance** | ✅ PRESERVED | Fact verification succeeds for generated claims. |

**Score**: 3 / 10 Responsibilities Preserved Deterministically without Global Synthesis.

---

## 9. Measured vs Inferred vs Unknown

- **Measured**:
  - Batch A latency (119.70s), character output (4,402 chars), JSON parse error (`Expecting ',' delimiter`).
  - Batch B latency (48.83s), character output (1,615 chars), 1 claim, 8 cited FIR IDs, 100% citation & semantic validation pass.
  - Total 2-call runtime (168.53s).
- **Inferred**:
  - `qwen3:8b` with `format="json"` at 20 FIRs remains susceptible to JSON syntax truncation / malformation.
- **Unknown**:
  - Behavior of Qwen output formatting across larger sub-batch counts (e.g., 15-FIR or 10-FIR batches).

---

## 10. Final Decision

**DECISION**: **B. CLAIMS_SAFE_BUT_GLOBAL_FIELDS_REQUIRE_SYNTHESIS**

*(Note: Output formatting non-determinism in Batch A also demonstrates that 20-FIR `format="json"` sub-batching requires retry/fallback mechanics or smaller sub-batch sizes).*

### Decision Rationale:
1. **Claim-Level Reasoning & Provenance**: Successfully preserved per sub-batch when JSON parses.
2. **Global Assessment Fields**: Global Readiness, Trust Score, Coverage, Quality Summary, and Analysis Capabilities cannot be derived safely via simple union or math; they require an explicit global synthesis pass.
3. **Format Reliability**: 1 of 2 Qwen calls failed JSON parsing due to string truncation, showing that 20 FIRs is near the stability threshold for `qwen3:8b` output token generation under `format="json"`.

---

## 11. Recommendations for Next Phase

1. **Implement Explicit Global Synthesis Pass**: If evidence is sub-batched into Agent 1 worker calls to extract claims, a lightweight consolidation pass (or deterministic aggregator + synthesis prompt) must be defined for global fields.
2. **Sub-Batch Size Calibration**: Test 10–15 FIR sub-batch sizes to ensure 100% JSON parse reliability, avoiding the 4,400+ character response truncation observed in Batch A.
