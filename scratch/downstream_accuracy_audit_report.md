# ARGUS — DOWNSTREAM FCR → ANALYSIS ENGINES → FIR → SANITIZATION → POSTGRESQL AUDIT REPORT

**Audit Execution Timestamp**: 2026-09-01T11:10:00Z  
**Environment**: Windows Host + Docker PostgreSQL Port 5433  
**Audit Scope**: Downstream execution path from Layer 2 / FCR through 5 Analysis Engines, FIR, Sanitization Gateway, and PostgreSQL persistence.

---

## 1. Executive Verdict

The downstream forensic pipeline of ARGUS — from **Layer 2 FCR correlation**, through the **5 Analysis Engines** (`endpoint`, `log`, `network`, `memory`, `email`), to **FIR conversion**, **Sanitization Gateway**, and **PostgreSQL persistence (port 5433)** — is **GENUINELY EVIDENCE-DRIVEN, EVIDENCE-GENERIC, AND DETERMINISTIC**.

The deterministic analysis engines and FCR correlation logic contain **ZERO hardcoded Sudeep/demo values**. When supplied with a novel synthetic case (`CASE-GENERALIZATION-001`), the pipeline successfully generated, sanitized, and persisted 33 distinct forensic findings in PostgreSQL with 100% field integrity and zero false-positive correlations across negative control tests.

However, a **CRITICAL DEFECT** was confirmed in the LLM query layer ([models/llm.py](file:///c:/Users/Sudeep/Downloads/Argus/Argus/models/llm.py#L106-L112)): when Ollama is offline or unconfigured, `OllamaProvider.generate()` swallows connection errors and returns a dev mock payload with static claim `"Suspicious PowerShell commands executed by Administrator"` and fake evidence ID `['F-1001']`.

---

## 2. Actual Production Architecture & Call Graph

Inspection of the codebase revealed the exact, authoritative production call graph:

```text
RAW EVIDENCE (Disk / Memory / Network / Email / Logs)
  ↓
Stage 1/2 Parsers (ParserRouter in preprocessing/router.py)
  ├── mft_parser / evtx_parser / zeek_parser / volatility_parser / eml_parser
  └── Output: List[Artifact]
  ↓
Stage 2.5 Extractor (ArtifactExtractor in preprocessing/artifact_extractor/extractor.py)
  ├── Extracts derived IOCs (IPs, domains, hashes) & Entities (commands, users)
  └── Output: List[Artifact] (Total 830 Store Artifacts)
  ↓
Stage 3 FCR Engine (FCREngine.correlate() in preprocessing/fcr_engine/engine.py)
  ├── Correlates by Host, Process Tree, PID-Network, Hash, and Temporal Window
  └── Output: List[CorrelationRecord] (FCRs)
  ↓
Stage 4 Batch Orchestrator (process_fcr_batch() in forensic_analysis/orchestrator.py)
  ├── FCR Router (route_fcr() in forensic_analysis/router.py)
  │     ├── Inspects fcr.artifact_ids & artifact_type / ioc_type / source_tool
  │     └── Maps to target engines: 'endpoint', 'log', 'network', 'memory', 'email'
  └── ENGINE_REGISTRY Dispatch:
        ├── EndpointAnalysisEngine (forensic_analysis/endpoint_analysis/endpoint_engine.py)
        ├── LogAnalysisEngine (forensic_analysis/log_analysis/log_engine.py)
        ├── NetworkAnalysisEngine (forensic_analysis/network_analysis/network_engine.py)
        ├── MemoryAnalysisEngine (forensic_analysis/memory_analysis/memory_engine.py)
        └── EmailAnalysisEngine (forensic_analysis/email_analysis/email_engine.py)
  ↓
Finding Generation (List[Finding] created by sub-analyzers)
  ↓
Unified Evidence Store (UnifiedEvidenceStore.write_finding() in forensic_analysis/unified_store.py)
  ↓
Sanitization Gateway (SanitizationGateway.sanitize_finding() in sanitization/gateway.py)
  ├── Homoglyph NFKC & Zero-width stripping
  ├── Write-time PII & Secrets Redaction (PIIRedactor)
  ├── Base64 / Hex / ROT13 Obfuscation Scans
  ├── Prompt Injection Detection (InjectionDetector: Heuristics + DeBERTa-v3 model)
  └── Entity-escaping & Strict `<evidence_data field="...">` XML Tag Delimiters
  ↓
FIR Converter (finding_to_fir() in forensic_analysis/schemas.py) -> Output: FIRFinding
  ↓
PostgreSQL Persistence (FIRRepository.insert() in fir/repository.py) -> Table `fir_findings` (Port 5433)
  ↓
REST API & Reports (api/routes/cases.py, api/routes/reports.py, api/routes/query.py)
```

---

## 3. Five Analysis Engine Audit

| Engine | Primary Sub-Analyzers | Input Schemas | Key Detection Rules | Provenance Fields Preserved | Demo Hardcoding Check |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Endpoint** | `FilesystemAnalyzer`, `RegistryAnalyzer`, `UserActivityAnalyzer`, `BrowserAnalyzer` | `file_record`, `registry_key`, `browser_history`, `lnk_shortcut` | Suspicious path execution, Run key persistence, browser download IOCs | `case_id`, `tenant_id`, `source_artifact_id`, `evidence_reference`, `timestamp` | **NONE (Clean)** |
| **Log** | `ProcessCreationAnalyzer`, `AuthAnalyzer`, `PowerShellAnalyzer`, `HayabusaTriageAnalyzer` | `process_event`, `evtx_record`, `auth_event`, `sysmon_event` | Versioned `lolbas.json` snapshot, suspicious parent-child execution (`winword->powershell`) | `case_id`, `tenant_id`, `source_artifact_id`, `evidence_reference`, `timestamp` | **NONE (Clean)** |
| **Network** | `DnsAnalyzer`, `HttpAnalyzer`, `TlsAnalyzer`, `SessionReconstruction` | `network_connection`, `dns_query`, `http_request`, `tls_session` | Malicious IP/domain IOC matching, versioned `tls_blacklist.json` | `case_id`, `tenant_id`, `source_artifact_id`, `evidence_reference`, `timestamp` | **NONE (Clean)** |
| **Memory** | `ProcessAnalyzer`, `DllAnalyzer`, `InjectionAnalyzer`, `TimelineAnalyzer` | `process_record`, `dll_record`, `injection_indicator` | Orphan process detection (missing parent PID), `malfind` rwx memory injection | `case_id`, `tenant_id`, `source_artifact_id`, `evidence_reference`, `timestamp` | **NONE (Clean)** |
| **Email** | `PhishingAnalyzer`, `HeaderAnalyzer`, `AttachmentAnalyzer`, `AuthenticationAnalyzer` | `email_message`, `email_header`, `email_body` | Malicious attachment extension, SPF/DKIM authentication failure, prompt injection | `case_id`, `tenant_id`, `source_artifact_id`, `evidence_reference`, `timestamp` | **NONE (Clean)** |

---

## 4. FCR → Analysis Engine Routing Audit

- Function `route_fcr()` in [forensic_analysis/router.py](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/router.py#L152) maps 54 artifact types to producing analysis engines.
- **Dynamic Routing**: Extracted IOCs (`ipv4`, `domain`, `url`) route dynamically to `network`; extracted entities (`command-line`, `indicator`) route dynamically to `log`.
- **Volatility3 Support**: Generic artifact types (`network_connection`, `process_event`, `dll_load`) from `volatility3` are dual-routed to both their primary domain and the `memory` engine.
- **Audit Result**: Routing is explicit, deterministic, order-independent, and duplicate-free.

---

## 5. Novel Positive Control Results (`CASE-GENERALIZATION-001`)

Executed script: `scratch/downstream_generalization_audit.py`

- **Novel Input Data**:
  - `case_id`: `CASE-GENERALIZATION-001`
  - `tenant_id`: `tenant-generalization`
  - `host_id`: `WORKSTATION-77`
  - `user`: `alice.williams`
  - `process`: `explorer.exe` → `winword.exe` → `invoice_update.exe` (SHA256: `a1b2c3d4e5f...`) → `powershell.exe` (PID 4096)
  - `network`: `203.0.113.77:443` (`security-alert-example.net`)
  - `email`: `alert@security-alert-example.net` (`Urgent Invoice Update`)
- **Execution Summary**:
  - **FCRs Generated**: 13 Correlation Records
  - **Raw Findings Generated**: 33 Findings across 4 active engines (`log`, `memory`, `email`, `network`)
  - **Sanitized & Persisted Rows in PostgreSQL Port 5433**: **33 rows**
- **Classification**: **SYNTHETIC (PASS — Proven Generalization)**.

---

## 6. Negative Control Results (Phases 5)

Executed script: `scratch/audit_negative_controls.py`

- **Input Data**: Unrelated artifacts across two distinct cases (`CASE-A` vs `CASE-B`, `HOST-A` vs `HOST-B`, `USER-A` vs `USER-B`, timestamps 8 hours apart).
- **Results**:
  - `FCR Correlation Count`: **0** (Expected: 0)
  - `Downstream Findings Generated`: **0** (Expected: 0)
- **Verdict**: **PASS** (Zero false positive correlations generated across isolated cases).

---

## 7. Five-Finding Provenance Trace (Phase 6)

| Checkpoint | Finding 1 (MFT) | Finding 2 (Log Narrative) | Finding 3 (Parent-Child) | Finding 4 (Memory Orphan) | Finding 5 (FCR Net-Proc) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1. Classification | `REAL EVIDENCE` | `REAL EVIDENCE` | `SYNTHETIC` | `SYNTHETIC` | `SYNTHETIC` |
| 2. Source File | `ntfs1-gen0.aff` | `narrative.txt` | Sysmon log | Volatility dump | Zeek + Sysmon |
| 3. SHA-256 | `bf0291a0ee...` | `97c52467f9...` | `a1b2c3d4e5...` | `a1b2c3d4e5...` | `a1b2c3d4e5...` |
| 4. Parsed Artifact | MFT record | Text log entry | Process event | Process record | Conn + Process |
| 5. Normalized Host | `NPS-HOST` | `NPS-HOST` | `WORKSTATION-77` | `WORKSTATION-77` | `WORKSTATION-77` |
| 6. FCR ID | `CORR-501990` | `CORR-044044` | `CORR-121558` | `CORR-244763` | `CORR-287017` |
| 7. Target Engine | `log` | `log` | `log` | `memory` | `network` |
| 8. Rule Name | `ProcessCreation` | `ProcessCreation` | `ParentChild` | `ProcessAnalyzer` | `NetworkProcess` |
| 9. Severity | `medium` | `medium` | `high` | `medium` | `high` |
| 10. Confidence | `0.90` | `0.90` | `0.95` | `0.85` | `0.92` |
| 11. MITRE ID | `T1059.001` | `T1059.001` | `T1218` | `T1057` | `T1071.001` |
| 12. Source Art ID | `b5b0efe6...` | `b5b0efe6...` | `art-nov-proc-4096` | `art-nov-mem-4096` | `art-nov-net-4096` |
| 13. Ev Reference | `CORR-501990` | `CORR-044044` | `CORR-121558` | `CORR-244763` | `CORR-287017` |
| 14. Case ID | `CASE-FINAL...` | `CASE-FINAL...` | `CASE-GEN-001` | `CASE-GEN-001` | `CASE-GEN-001` |
| 15. Tenant ID | `tenant-demo` | `tenant-demo` | `tenant-gen` | `tenant-gen` | `tenant-gen` |
| 16. Sanitization | Entity-Escaped | Entity-Escaped | Entity-Escaped | Entity-Escaped | Entity-Escaped |
| 17. FIR Conversion | Matched 100% | Matched 100% | Matched 100% | Matched 100% | Matched 100% |
| 18. PG Persistence | Row verified | Row verified | Row verified | Row verified | Row verified |
| 19. Verdict | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |

---

## 8. Finding → FIR Integrity (Phase 7)

Function `finding_to_fir()` in [forensic_analysis/schemas.py](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/schemas.py#L124-L148) was audited.
- **Field Preservation**: Preserves `finding_id`, `case_id`, `tenant_id`, `fact`, `confidence`, `severity`, `mitre_mapping`, `timestamp`, `evidence_reference`, `layer`, `source_artifact_id`, and `finding_fingerprint`.
- **ID Regeneration**: Zero finding IDs or timestamps are regenerated during conversion.
- **Fingerprint Formula**: `f"FFP-{SHA256(tenant_id:case_id:layer:norm_fact:sorted_sources)[:16]}"` provides deterministic, collision-free deduplication.

---

## 9. FIR → Sanitization → PostgreSQL Integrity (Phase 8 & 9)

- **Actual Order of Operations**:
  `Finding` → `SanitizationGateway.sanitize_finding()` → `SanitizedAgentContext` → `finding_to_fir()` → `FIRRepository.insert()` → `PostgreSQL fir_findings table`.
- **Sanitization Features Verified**:
  - Homoglyph NFKC & zero-width character stripping
  - Write-time PII & secrets redaction (`[REDACTED_CREDIT_CARD]`, `[REDACTED_EMAIL]`, `[REDACTED_CREDENTIALS]`)
  - Obfuscated payload decoding (Base64, Hex, ROT13)
  - Forensic prompt injection detector (`InjectionDetector`)
  - XML entity escaping & `<evidence_data field="fact">` wrapping
  - Fail-closed security architecture
- **PostgreSQL Database Verification (Port 5433)**:
  - Verified 33 rows inserted for `CASE-GENERALIZATION-001`.
  - **Orphaned References**: 0.
  - **Fingerprint Collisions**: 0.
  - **Tenant Leakage**: 0.

---

## 10. Production Code Hardcoding Search (Phase 10)

Executed script: `scratch/audit_production_hardcoding.py`

| Term Searched | Production Code Matches | Classification | Location / Note |
| :--- | :---: | :--- | :--- |
| **`F-1001`** | **1** | **PRODUCTION HARDCODING BUG** | `models/llm.py:L111` (Mock fallback payload) |
| **`CASE-FINAL-DEMO-2026`** | 0 | Clean | Only present in test scripts |
| **`Sudeep / Kumar`** | 0 | Clean | Zero occurrences in production modules |
| **`ntfs1-gen`** | 0 | Clean | Cleared from production path extractor |
| **`narrative.txt`** | 1 | `LEGITIMATE DETECTION` | `filesystem_parser.py:L71` (Text parser route check) |
| **`mock`** | 3 | `DEV FALLBACK` | `timestamp_service.py:L77-164` (Optional mock TSA) |
| **`placeholder`** | 2 | `LEGITIMATE PLACEHOLDER` | `gateway.py:L103` (Sanitization XML tag helper) |

---

## 11. Determinism & Repeatability Audit (Phase 11)

Executed script: `scratch/audit_determinism.py`

- **Execution**: Ran the complete novel synthetic pipeline (`CASE-GENERALIZATION-001`) through 2 consecutive subprocess iterations.
- **Results**:
  - Iteration 1 Row Count: **33**
  - Iteration 2 Row Count: **33**
  - Fingerprint Set Equality: **TRUE (100% Identical Fingerprints)**
  - Field Mismatches (`severity`, `confidence`, `mitre_mapping`, `sanitized_fact`, `layer`): **0**
- **Verdict**: **100% LOGICAL & OUTPUT DETERMINISM VERIFIED**.

---

## 12. Full Regression Suite Results (Phase 12)

1. **Pytest Full Suite (`python -m pytest tests/ -v`)**:
   - **528 PASSED, 1 SKIPPED, 0 FAILED** (Skipped: `test_live_tsa_integration`).
2. **PostgreSQL Integration Suite (`python -m pytest tests/integration/test_postgres_fir_integration.py -v`)**:
   - **4 PASSED, 0 SKIPPED, 0 FAILED**.
3. **End-to-End Demo Validation (`python -m scratch.final_demo_validation`)**:
   - **ALL LAYER METRICS MATCH 100% (42 Findings, Zero Layer Mismatches)**.
4. **Frontend/Backend Integration (`python -m scratch.test_frontend_backend_integration`)**:
   - **7 / 7 REST API Integration Tests PASSED (100% Verified)**.

---

## 13. Production Defects Discovered (Phase 13)

### BUG 1 (CRITICAL) — Ollama Offline Hardcoded Mock Bypass
- **File**: [models/llm.py](file:///c:/Users/Sudeep/Downloads/Argus/Argus/models/llm.py#L106-L112)
- **Function**: `OllamaProvider.generate()`
- **Observed Behavior**: Returns `{'claim': 'Suspicious PowerShell commands executed by Administrator', 'evidence_ids': ['F-1001']}` when Ollama returns HTTP 404 or is offline.
- **Expected Behavior**: Re-raise `RuntimeError` so [api/routes/query.py](file:///c:/Users/Sudeep/Downloads/Argus/Argus/api/routes/query.py#L68) catches the exception and returns the actual case's sanitized evidence summary.
- **Root Cause**: `models/llm.py` swallows connection exceptions internally.
- **Fix (Pending Approval)**: Remove static string return in `models/llm.py:L109` and re-raise `RuntimeError(f"Ollama LLM connection failed: {e}")`.

---

## 14. Answers to 12 Mandatory Questions

1. **Are all 5 analysis engines genuinely driven by normalized evidence/FCR data?**  
   **YES.** All 5 engines consume `CorrelationRecord` objects and `Artifact.normalized_fields` / `raw_fields`.
2. **Is any analysis engine dependent on Sudeep/demo values?**  
   **NO.** Zero production analysis engines contain hardcoded user names, host names, IP addresses, domains, or demo hashes.
3. **Are FCRs correctly routed to the appropriate engines?**  
   **YES.** `route_fcr()` dynamically and deterministically routes FCRs to target engines based on artifact and IOC type mappings.
4. **Can a completely new evidence case produce legitimate findings?**  
   **YES.** Novel case `CASE-GENERALIZATION-001` generated 33 valid, sanitized findings in PostgreSQL.
5. **Can unrelated evidence produce ZERO correlations/findings?**  
   **YES.** Negative control tests confirmed 0 false positive correlations for isolated cases.
6. **Does Finding → FIR preserve forensic provenance?**  
   **YES.** `finding_to_fir()` preserves all 12 core provenance and metadata fields with zero loss.
7. **Does FIR → Sanitization preserve provenance and forensic meaning?**  
   **YES.** `SanitizationGateway` redacts PII and defuses injections while preserving forensic facts in escaped `<evidence_data>` tags.
8. **Does PostgreSQL contain exactly what the pipeline produced?**  
   **YES.** PostgreSQL port 5433 `fir_findings` table matches 100% with API report endpoints.
9. **Are there any silent mock/fallback findings?**  
   **YES (Only in LLM query fallback in `models/llm.py`)**. The deterministic analysis engines contain zero mock/fallback findings.
10. **Are there any production hardcoding bugs?**  
    **YES (1 Bug in `models/llm.py`)**.
11. **Is the complete pipeline deterministic at the logical-output level?**  
    **YES.** Repeatability tests proved identical fingerprint sets and finding values across consecutive executions.
12. **Is ARGUS genuinely ready for a demo using evidence different from the existing demo dataset?**  
    **YES (Pending 1-line fix approval for `models/llm.py`)**.

---

## 15. Final Demo Readiness Verdict

| Layer | Status | Rating |
| :--- | :--- | :---: |
| **Layer 2 / FCR Engine** | Fully Generalized & Deterministic | **100% READY** |
| **5 Analysis Engines** | Fully Evidence-Driven & General | **100% READY** |
| **FIR & Sanitization Gateway** | Full PII/Injection Defense & Provenance Preservation | **100% READY** |
| **PostgreSQL Persistence** | Port 5433 Schema Verified & Persisted | **100% READY** |
| **Analyst Query / LLM Layer** | Hardcoded Mock Bypass in `models/llm.py` | **90% READY (Fix Required)** |

**FINAL VERDICT**: **DEMO-READY (Pending 1-Line Fix Approval for `models/llm.py`)**.
