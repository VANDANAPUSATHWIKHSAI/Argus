# ARGUS Layer 4 FIR Generation Audit Report

## 1. Executive Summary
A comprehensive code-level audit, hardening, testing, and verification of **Layer 4 — FIR (Forensic Investigation Report / Finding) Generation** (`fir/schemas.py`, `fir/repository.py`, `fir/service.py`, and `forensic_analysis/schemas.py`) was conducted on the ARGUS digital forensics platform.

The audit verified that FIR generation converts Stage 3 deterministic analysis findings into canonical `FIRFinding` records without AI reasoning, prompt injection execution, or evidence fabrication. All 30 Layer 4 audit tests (`L4-T01` through `L4-T30`) and all 694 unit tests across the repository passed with a **100% regression pass rate**.

---

## 2. FIR Architecture
Layer 4 is the **Forensic Investigation Report / Finding Tier** of the ARGUS architecture:

```
RAW EVIDENCE (Layer 1)
  ↓
PARSING & NORMALIZATION (Layer 2)
  ↓
DETERMINISTIC ANALYSIS & FCR ENGINE (Layer 3)
  ↓
FIR GENERATION & CONVERSION (Layer 4)
  ├── FIRFinding Canonical Schema & Validation Gate
  ├── Deterministic Fingerprint Deduplication (`FFP-...`)
  ├── Write-Time PII Redaction (`sanitized_fact`) & Prompt Injection Check (`injection_flagged`)
  ├── Analyst Review Lifecycle State Machine (`pending_review` → `analyst_confirmed` / `analyst_rejected`)
  ├── FIRRepository (Class-Level In-Memory Store & PostgreSQL `fir_findings` Table)
  └── AnalystFindingService (Query, Export Review-Gate, and Integrated Timeline)
  ↓
SANITIZATION GATEWAY & AI AGENTS (Downstream Layers)
```

FIR Guarantees:
1. 100% deterministic, evidence-derived finding generation (0 AI calls before FIR creation).
2. Complete provenance retention (`case_id`, `tenant_id`, `evidence_reference`, `source_artifact_id`, `layer`).
3. Multi-tenant and multi-case isolation on every query and update operation.
4. Parameterized SQL queries preventing SQL injection vulnerabilities.
5. Review-gate enforcement preventing unreviewed findings from exporting to downstream consumers unless explicitly authorized.

---

## 3. Active Execution Path
1. Stage 3 deterministic analysis engines output `Finding` instances.
2. `finding_to_fir(finding, tenant_id)` converts `Finding` into a canonical `FIRFinding`.
3. `FIRRepository.insert(finding)` executes:
   - Fingerprint lookup `self._fingerprints[case_id][fp]` to overwrite duplicate findings cleanly while preserving original `finding_id`.
   - Write-time PII redaction (`PIIRedactor.redact()`) producing `sanitized_fact` without altering raw `fact`.
   - Prompt injection validation (`InjectionGate.check()`) populating `injection_flagged` and `injection_score`.
   - Storage in in-memory repository dictionary and parameterized SQL `INSERT ... ON CONFLICT DO UPDATE` into PostgreSQL `fir_findings` table.
4. `AnalystFindingService.list_findings()` / `export_report()` / `mark_review()` handles human analyst queries and lifecycle state transitions.

---

## 4. Files Audited
- `fir/schemas.py` (`FIRFinding`, `ReviewStatus`, `UnreviewedFindingError`)
- `fir/repository.py` (`FIRRepository`, `_ensure_fir_table_initialized`, PII & injection integration)
- `fir/service.py` (`AnalystFindingService`, export gating, analyst workflow)
- `forensic_analysis/schemas.py` (`finding_to_fir` adapter function)

---

## 5. FIR Schema Audit
Audited `FIRFinding` in `fir/schemas.py`:
- `finding_id`: Unique identifier string.
- `case_id`: Non-empty string validation.
- `tenant_id`: Non-empty string validation (defaults to `"default"`).
- `fact`: Non-empty string validation (unaltered source fact).
- `sanitized_fact`: Optional PII-redacted string.
- `confidence`: Validated float in range `[0.0, 1.0]`.
- `severity`: Validated string in `{"informational", "low", "medium", "high", "critical"}`.
- `evidence_reference`: Coerces scalar strings or validates non-empty `list[str]`.
- `review_status`: Default `ReviewStatus.PENDING_REVIEW`.

---

## 6. FCR → FIR Lineage
Lineage validation confirmed:
- `finding_to_fir()` maps Layer 3 `Finding` fields to `FIRFinding`.
- `evidence_reference` preserves all contributing correlation IDs and artifact IDs.
- `source_artifact_id` and `layer` remain explicitly tracked.

---

## 7. Evidence Reference Audit
- Verified that `evidence_reference` cannot be empty or `None`.
- Coercion validator handles legacy scalar strings gracefully while enforcing non-empty string entries.

---

## 8. Fingerprint / Deduplication Audit
- `finding_fingerprint` formula: `SHA-256` hash of `tenant_id + case_id + layer + normalized_fact + sorted_unique_sources`.
- Excludes timestamps, `finding_id`, or random UUIDs.
- Deduplication in `FIRRepository.insert()` ensures duplicate physical events reuse original `finding_id`.

---

## 9. Confidence Audit
- Verified strict validation: confidence values $< 0.0$ or $> 1.0$ raise `ValueError`.
- Confidence values originate from deterministic Stage 3 rules (`0.30 + 0.15*(dt-1) + 0.20*(sc-1)`).

---

## 10. Severity Audit
- Verified strict enum validation against `{"informational", "low", "medium", "high", "critical"}`.
- Invalid severity strings (e.g. `"SUPER_CRITICAL"`) raise `ValueError`.

---

## 11. MITRE Mapping Audit
- MITRE ATT&CK technique IDs (e.g., `T1053.005`) are passed strictly from deterministic Stage 3 rule matching.
- No unsupported technique IDs are fabricated.

---

## 12. Fact-vs-Conclusion Audit
- Raw `fact` field preserves the objective forensic observation (e.g. `"PowerShell.exe executed with encoded command string..."`).
- No premature intent, threat actor attribution, or speculative narratives are inserted during FIR creation.

---

## 13. Raw / Sanitized Data Boundary
- Original `fact` remains completely untouched.
- PII-redacted text is stored in `sanitized_fact` with `redactor_version` recorded.

---

## 14. Prompt Injection Boundary
- `InjectionGate` evaluates untrusted evidence text, setting `injection_flagged=True` and `injection_score`.
- Prompt injection text (e.g., `"Ignore previous instructions..."`) is treated purely as untrusted data and cannot alter FIR execution flow or schema properties.

---

## 15. Review Workflow Audit
- Lifecycle state transitions:
  `PENDING_REVIEW` $\rightarrow$ `ANALYST_CONFIRMED` or `ANALYST_REJECTED`.
- State changes can ONLY occur through `FIRRepository.mark_reviewed()`.
- Reversion to `PENDING_REVIEW` is prohibited.
- `for_export(allow_unreviewed=False)` raises `UnreviewedFindingError` when findings are unreviewed.

---

## 16. Case Locking Audit
- `AnalystFindingService.export_report()` enforces review status gates, ensuring unreviewed findings are not exported to downstream reports unless `allow_unreviewed=True` is explicitly passed.

---

## 17. Tenant / Case Isolation
- `FIRRepository.get_by_case(tenant_id, case_id)` and `mark_reviewed(tenant_id, ...)` enforce strict tenant isolation.
- Tenant `TENANT-A` cannot read, modify, or review findings for `TENANT-B`.

---

## 18. PostgreSQL Audit
- Table `fir_findings` schema verified.
- `FIRRepository.insert()` uses parameterized SQL binding placeholders (`%s`) for all columns, preventing SQL injection.

---

## 19. Transaction Integrity
- PostgreSQL insertion uses `ON CONFLICT (finding_id) DO UPDATE`.
- Database disconnection triggers clean fallback to in-memory repository store without throwing unhandled crashes or losing findings.

---

## 20. Failure Semantics
- Parameter validation errors (empty `case_id`, invalid confidence, missing evidence reference) raise explicit `ValueError` or `KeyError`.
- Database failures log errors and fall back gracefully to in-memory store.

---

## 21. Security Audit
- Verified 0 SQL injection risks via parameterized query placeholders.
- Verified prompt injection payloads in evidence are safely flagged without altering execution.

---

## 22. Determinism Audit
- Tested 10 repeated FIR generation iterations over identical inputs: 100% identical `finding_fingerprint`, `fact`, `confidence`, `severity`, and `evidence_reference` were produced.

---

## 23. Bugs Found
1. `FIRFinding` schema lacked strict field validation for confidence bounds ($0.0 \le \text{confidence} \le 1.0$) and severity enum membership.
2. `FIRFinding` schema allowed empty string values for `case_id`, `fact`, or `tenant_id`.

---

## 24. Bugs Fixed
1. Added `@field_validator("confidence")` in `fir/schemas.py` enforcing $0.0 \le \text{confidence} \le 1.0$.
2. Added `@field_validator("severity")` enforcing membership in `{"informational", "low", "medium", "high", "critical"}`.
3. Added `@field_validator("case_id", "fact", "tenant_id")` enforcing non-empty strings.

---

## 25. Tests Added
Created `tests/unit/test_layer4_fir_comprehensive_audit.py` containing 30 comprehensive unit tests:
- `L4-T01`: FIR input contract
- `L4-T02`: FIR schema validation & evidence_reference coercion
- `L4-T03`: FCR → FIR lineage & multi-correlation reference preservation
- `L4-T04`: Evidence reference integrity validation
- `L4-T05`: Source artifact ID linkage validation
- `L4-T06`: Deterministic fingerprint reproducibility
- `L4-T07`: Duplicate finding suppression in FIRRepository
- `L4-T08`: Confidence score propagation
- `L4-T09`: Confidence boundary validation ($0.0 \le c \le 1.0$)
- `L4-T10`: Severity rule validation
- `L4-T11`: MITRE mapping correctness
- `L4-T12`: Invalid severity enum rejection
- `L4-T13`: Raw fact preservation
- `L4-T14`: Raw data preservation & PII redaction
- `L4-T15`: Sanitized fact boundary validation
- `L4-T16`: Prompt-injection inertness & injection flagging
- `L4-T17`: Review status state machine validation
- `L4-T18`: Review metadata integrity & reviewer validation
- `L4-T19`: Unreviewed export gating & `UnreviewedFindingError`
- `L4-T20`: Multi-tenant finding isolation
- `L4-T21`: Multi-case finding isolation
- `L4-T22`: PostgreSQL parameterized query verification
- `L4-T23`: Transactional consistency & in-memory lookup
- `L4-T24`: Analytical failure exception semantics
- `L4-T25`: Audit logging & `_review_gate` export metadata
- `L4-T26`: Repeated-run deterministic FIR generation
- `L4-T27`: Forged empty evidence reference rejection
- `L4-T28`: Authentic evidence reference verification
- `L4-T29`: Duplicate fingerprint existing ID reuse
- `L4-T30`: End-to-end FCR → Finding → FIRFinding lineage

---

## 26. Test Results
- **Layer 4 Comprehensive Suite (`tests/unit/test_layer4_fir_comprehensive_audit.py`)**:
  - Passed: **30 / 30**
  - Failed: **0**
  - Execution Time: `22.66s`

---

## 27. Full Regression
- **Full Unit Test Suite (`pytest tests/unit/ -v`)**:
  - Passed: **694**
  - Failed: **0**
  - Skipped: **2** (Digital Corpora raw evidence directory skipped; Live TSA integration test skipped unless flag set)
  - Execution Time: `137.51s`

---

## 28. Live Database Verification
- Unit tests verify SQL parameterization and schema initialization via mocks when PostgreSQL is offline.
- Real PostgreSQL connection tests execute `_ensure_fir_table_initialized` and `INSERT ... ON CONFLICT DO UPDATE` when a PostgreSQL server is active.

---

## 29. Remaining Limitations
- Live PostgreSQL tests run against a local/containerized PostgreSQL database when `settings.postgres_host` is reachable; when offline, `FIRRepository` falls back safely to in-memory store.

---

## 30. Out-of-Scope Findings
- **Sanitization Gateway**: Intentionally untouched per Layer 4 scope boundaries.
- **Agents 1-7**: Intentionally untouched per Layer 4 scope boundaries.

---

## 31. Final Status

LAYER 4 STATUS:
READY
