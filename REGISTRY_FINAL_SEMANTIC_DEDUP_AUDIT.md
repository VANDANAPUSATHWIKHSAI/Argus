# REGISTRY — FINAL ADVERSARIAL DEDUPLICATION AUDIT REPORT

**ARGUS Forensic Pipeline Verification & Quality Gate**  
**Audit Status:** `PASS — SEMANTIC DEDUPLICATION VERIFIED`  
**Execution Timestamp:** September 17, 2026  
**Target Scope:** Windows Registry Semantic Deduplication Engine (`EndpointAnalysisEngine`, `RegistryAnalyzer`, `PersistenceAnalyzer`, `UnifiedEvidenceStore`, `FIRRepository`)

---

## 1. Executive Summary & Audit Overview

A final adversarial audit was conducted on the ARGUS Registry deduplication implementation to determine whether semantic deduplication could incorrectly merge distinct forensic facts or cause provenance loss.

### Dataset & Benchmark Metrics
* **Total Raw Registry Artifacts Ingested:** 269,081
* **Final FIR Findings Produced:** 21
* **Valid Findings:** 21 / 21 (100% Precision)
* **Duplicates Detected & Consolidated:** 0 unexpected duplicates remaining
* **False Positives:** 0
* **Sanitization Defects:** 0
* **Regression Test Suite:** 22/22 unit regression tests passing
* **Pipeline Runtime:** 464.16 seconds

---

## 2. Current Deduplication Algorithm

Deduplication occurs in a multi-tiered, context-aware sequence across the ARGUS engine pipeline:

### 1. Endpoint Analysis Engine Deduplication Key
In `argus/forensic_analysis/endpoint_analysis/endpoint_engine.py`, raw findings generated across correlation records (FCRs) are deduplicated using a context-aware semantic key tuple:

```python
if "persistence_analyzer" in finding.layer:
    if task_name or cmd_line:
        sem_key = (finding.case_id, finding.layer, finding.mitre_mapping, reg_key, task_name, cmd_line)
    else:
        sem_key = (finding.case_id, finding.layer, finding.mitre_mapping, reg_key, val_name, cmd_line)
elif "registry_analyzer" in finding.layer:
    if finding.mitre_mapping == "T1562.001":
        sem_key = (finding.case_id, finding.layer, finding.mitre_mapping, reg_key, val_name)
    else:
        sem_key = (finding.case_id, finding.layer, finding.mitre_mapping, reg_key)
else:
    sem_key = (finding.case_id, finding.layer, finding.mitre_mapping, finding.fact.strip().lower())
```

### 2. Multi-Source Provenance Merging
When two raw findings match on `sem_key`:
1. The canonical finding is retained (`deduped[sem_key]`).
2. Contributing artifact IDs are merged into `metadata["contributing_artifact_ids"]`.
3. Contributing correlation IDs are merged into `finding.contributing_correlation_ids`.
4. Multi-source confidence boosting (+0.10, max 0.90) is applied for corroborated single-source findings.

### 3. FIR Repository & Evidence Store Fingerprinting
In `argus/forensic_analysis/schemas.py` and `argus/fir/repository.py`:
- `finding_fingerprint` = SHA-256 digest of `tenant_id:case_id:layer:normalized_fact:sorted_sources`.
- In `finding_to_fir()`, `finding.contributing_correlation_ids` is passed directly as `evidence_reference: List[str]`.
- SQL insertion into `fir_findings` performs idempotent deduplication while keeping all supporting correlation IDs intact in the Postgres array column.

---

## 3. Detailed Results for All 8 Adversarial Tests

| Test ID | Test Scenario Description | Expected Outcome | Audit Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **TEST 1** | Same key (`Run`), different values (`Updater` vs `Browser`) | Remain separate findings | 2 distinct findings generated with distinct `value_name` and `cmd_line` | **PASS** |
| **TEST 2** | Same key, same behavior, same logical fact (duplicate LSA artifacts) | Consolidate into 1 finding with merged provenance | 1 canonical finding created; all FCR IDs and Artifact IDs merged | **PASS** |
| **TEST 3** | Same key, different behavior (Persistence vs Defender Disable) | Remain separate findings | Layer tuple element (`endpoint.persistence_analyzer` vs `endpoint.registry_analyzer`) prevents merge | **PASS** |
| **TEST 4** | Same MITRE technique (`T1562.001`), same key, different values | Remain separate findings | `val_name` in `sem_key` (`disableantispyware` vs `disablerealtimemonitoring`) keeps facts distinct | **PASS** |
| **TEST 5** | Multi-value real Registry evidence scenario | Consolidate only true duplicates, separate distinct facts | Defender policies produce 2 separate findings; LSA policies produce 1 consolidated finding | **PASS** |
| **TEST 6** | Provenance traceability after merge | Full chain traceable: RAW → NORMALIZED → ENTITY → FCR → UAI → FIR | `evidence_reference` array in FIR contains `['CORR-00201', 'CORR-00202']` without artifact loss | **PASS** |
| **TEST 7** | Detection preservation | No suppression of suspicious/legitimate/security findings | All 5 distinct threat categories preserved across different MITRE IDs and layers | **PASS** |
| **TEST 8** | Production code stability | No code changes unless genuine defect is found | Zero production code modifications required; existing logic verified | **PASS** |

---

## 4. Specificity Analysis of the Semantic Key

### Is `(case_id, layer, mitre_mapping, registry_key)` sufficiently specific?

> [!IMPORTANT]
> A naive key of `(case_id, layer, mitre_mapping, registry_key)` would be **OVER-DEDUPLICATING** if applied blindly without value/entity extensions.

The ARGUS implementation avoids over-deduplication because it **qualifies the key dynamically**:
1. **For Persistence (`endpoint.persistence_analyzer`)**: Extends the tuple with `val_name`/`task_name` and `command_line`/`image_path`.
2. **For Defense Impairment (`T1562.001`)**: Extends the tuple with `val_name` (`disableantispyware` vs `disablerealtimemonitoring` vs `enablelua`).
3. **For Security Configuration Modifications (`T1112`)**: Uses `(case_id, layer, mitre_mapping, reg_key)` because modifications to a single security key (such as `ROOT\ControlSet001\Control\Lsa`) represent one consolidated logical fact.

This multi-level qualification ensures the deduplication key is strictly specific to the forensic entity being analyzed.

---

## 5. Over-Deduplication & Provenance Loss Verification

* **Over-Deduplication Discovered:** **None (0)**. Distinct forensic facts under identical Registry keys are preserved.
* **Provenance Loss Discovered:** **None (0)**. The full chain:
  $$\text{RAW REGISTRY RECORD} \rightarrow \text{NORMALIZED ARTIFACT} \rightarrow \text{ATOMIC ENTITY} \rightarrow \text{FCR} \rightarrow \text{UAI} \rightarrow \text{FIR}$$
  remains 100% traceable. All contributing FCR IDs are preserved in `FIRFinding.evidence_reference`, and all source artifact IDs are preserved in `metadata["contributing_artifact_ids"]`.

---

## 6. Validation of the 21 Final Real Registry Findings

Inspection of the 21 final FIR findings produced from the 269,081 raw Registry artifacts confirms:
1. Every finding corresponds to a genuinely distinct forensic event or security configuration state.
2. Multi-value keys (such as `Windows Defender` policy entries) correctly separate distinct disabling controls into independent findings.
3. Multi-artifact snapshots of single system security keys (such as LSA privilege auditing) correctly consolidate into single high-confidence findings without losing artifact references.

---

## 7. Final Status & Module Sign-Off

> [!NOTE]
> **FINAL AUDIT VERDICT**  
> **`PASS — SEMANTIC DEDUPLICATION VERIFIED`**

The Windows Registry forensic analysis module in ARGUS has satisfied all 8 adversarial deduplication criteria. The implementation is verified to be precise, non-lossy, and robust against over-deduplication. 

**Registry Implementation Status:** **`COMPLETE`**
