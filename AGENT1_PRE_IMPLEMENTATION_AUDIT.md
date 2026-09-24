# ARGUS AGENT 1 — PRE-IMPLEMENTATION AUDIT REPORT

**Date**: 2026-09-23  
**Repository Branch**: `agent-1`  
**Master Architecture Source**: `ARGUS_DETAILS_UPDATED_NEO4J_QDRANT_REQUIRED (1).txt`  
**Target Evidence Image**: `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01`  

---

## 1. Executive Summary & Purpose

This pre-implementation audit report establishes the authoritative baseline status of **Agent 1 (Evidence Intelligence)** and the underlying disk-image forensic pipeline before executing any code changes. 

In strict adherence to the Master Architecture Document and user directives:
* **No code has been modified during this initial audit phase.**
* **Independent Validation Rule Enforced**: Agent 1 output validation (claims, evidence citations, provenance, and verification status) is performed **100% independently of Qwen3-8B** using deterministic Python code (`Agent1Validator`). The LLM is **never** permitted to self-certify its own claims, citations, or verification status.

---

## 2. Real Raw Evidence Ground Truth

* **Evidence Path**: `C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01`
* **File Type**: EnCase Forensic Image (E01)
* **File Size**: `309,818,835 bytes` (~295.47 MB)
* **SHA-256 Hash**: `6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5`
* **Access Mode**: Strictly Read-Only (no in-place modifications, moves, or renames)

---

## 3. Pipeline & Physical Layer Execution Path

The complete forensic processing chain for `2020JimmyWilson.E01` operates via the following execution sequence:

```
[2020JimmyWilson.E01]
       │
       ▼ (Physical / Disk Layer)
  mmls.exe (Dynamic Partition Discovery) ➔ Sector Offset: 65664 (NTFS Volume)
       │
       ▼ (Filesystem Extraction)
  fls.exe -o 65664 -r -m / ➔ 11,553 Bodyfile Metadata Records
       │
       ▼ (JSON Normalization)
  preprocessing/normalizer.py ➔ 11,553 Normalized Artifact Records
       │
       ▼ (Artifact Extraction Engine)
  preprocessing/artifact_extractor/ ➔ 50,332 Atomic Entities
       │
       ▼ (Forensic Correlation Record Engine)
  preprocessing/fcr_engine/ ➔ 1,369 FCR Records
       │
       ▼ (Domain Analysis & FIR Generation)
  forensic_analysis/ & fir/repository.py ➔ 5,002 FIR Findings
       │
       ▼ (Shared Security Boundary)
  sanitization/gateway.py ➔ 5,002 Sanitized Agent Contexts (<untrusted_evidence_data>)
       │
       ▼ (AI Reasoning Stage)
  agents/agent1_evidence_intelligence/ (Qwen3-8B Reasoning)
       │
       ▼ (INDEPENDENT DETERMINISTIC VALIDATION GATE)
  validator.py (Independent Citation & Provenance Verification — NO LLM Self-Certification)
       │
       ▼ (PostgreSQL System of Record)
  `agent_outputs` table persistence
```

### Empirical Pipeline Baseline Metrics

| Pipeline Stage | Expected / Reference Baseline | Actual Observed Count | Status |
| :--- | :---: | :---: | :--- |
| **Partition Offset (`mmls`)** | `65664` | `65664` | Verified |
| **Raw Bodyfile Records (`fls`)** | `11,553` | `11,553` | Verified (Task 178) |
| **Normalized Artifacts** | `11,553` | `11,553` | Verified |
| **Atomic Entities** | `50,332` | `50,332` | Verified |
| **FCR Records** | `1,369` | `1,369` | Verified |
| **Domain Findings / FIR** | `5,002` | `5,002` | Verified |
| **Sanitized Contexts** | `5,002` | `5,002` | Verified |

---

## 4. Independent Validation & Feature Audit

### Independent Model Validation Boundary
Qwen3-8B produces raw candidate interpretations and cited Evidence IDs. The validation process is **strictly external and independent**:
1. **Citation Verification**: `Agent1Validator.validate_claims()` checks every cited ID against the set of FIR finding IDs and source lineage IDs extracted directly from `fir_findings`.
2. **No Model Self-Certification**: If Qwen3-8B outputs `"citation_verified": true`, that value is ignored. Only `Agent1Validator` determines `citation_verified`.
3. **Range Validation**: Model confidence values outside `[0.0, 1.0]` are flagged deterministically.

### Scoring Implementation Classification

| Feature / Metric | Master Doc Section | Classification | Current Code Status & Remediation Strategy |
| :--- | :--- | :--- | :--- |
| **Evidence Trust Score (ETS)** | Sec 28, 17 | **Category D: Not yet defined** | No hardcoded math in code. Add structured fields to output contracts while documenting scoring methodology status. |
| **Evidence Quality Score** | Sec 28, 1 | **Category D: Not yet defined** | Add structured field interface without fabricating arbitrary math formulas. |
| **Evidence Priority Score** | Sec 28, 1 | **Category D: Not yet defined** | Supported via `assessed_importance` rating per claim. |
| **Evidence Coverage Score** | Sec 28, 1 | **Category D: Not yet defined** | Add coverage breakdown and missing artifact reporting interface. |
| **Investigation Readiness** | Sec 28, 1 | **Category D: Not yet defined** | Add explicit readiness assessment field (`READIES` / `LIMITED`). |
| **Possible vs. Performed** | Sec 28, 1 | **Defect** | Currently implicit. Prompt and schema must explicitly separate *Possible Analyses* from *Performed Analyses*. |
| **Malformed Output Handling** | Sec 28, 27 | **Defect** | `_parse_json_claims` creates a fallback claim (`"Raw unparsed model reasoning"`). Must fail closed with `execution_status="FAILED"`. |
| **Unreviewed Findings Filter**| Sec 13 | **Defect** | `Agent1Input.allow_unreviewed_findings=False` is defined but not enforced in `agent.py`. |

---

## 5. PostgreSQL Persistence Audit

* **Table**: `agent_outputs`
* **Audit Finding**: Structured columns exist for core fields. Score metadata, invalid citations, and quality summaries are serialized inside `flags` (JSONB), maintaining queryability, auditability, and case/tenant isolation.

---

## 6. Pre-Implementation Audit Verdict & Next Steps

1. **Raw Evidence Pipeline**: Real disk image ingestion via `mmls`/`fls` is functional and fully verified.
2. **Independent Validation Boundary**: Re-confirmed that Qwen3-8B does not self-certify output. `Agent1Validator` deterministically validates all citations and lineage.
3. **Defects Identified**:
   - Defect A: Fallback pseudo-claim creation on JSON parse failure (violates fail-closed safety).
   - Defect B: Missing explicit fields for ETS, Quality, Coverage, Readiness, and Possible vs. Performed Analyses.
   - Defect C: Ignored `allow_unreviewed_findings=False` filter.
4. **Action**: Update `implementation_plan.md` to reflect the strict independent validation requirement.
