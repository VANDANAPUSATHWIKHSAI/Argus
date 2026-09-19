# ARGUS Comprehensive Forensic Consistency, Integration & Architecture Audit

## A. Repository Commit Audited
- **Repository**: `VANDANAPUSATHWIKHSAI/Argus`
- **Branch**: `main`
- **Latest Commit**: `665bc92` (Fast-forward pulled from `origin/main`)

---

## B. Files Inspected
- [`preprocessing/router.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/preprocessing/router.py)
- [`preprocessing/parsers/firewall_parser.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/preprocessing/parsers/firewall_parser.py)
- [`preprocessing/parsers/evtx_parser.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/preprocessing/parsers/evtx_parser.py)
- [`forensic_analysis/network_analysis/network_engine.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/network_analysis/network_engine.py)
- [`forensic_analysis/log_analysis/powershell_analyzer.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/log_analysis/powershell_analyzer.py)
- [`forensic_analysis/schemas.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/schemas.py)
- [`fir/schemas.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/fir/schemas.py)
- [`fir/repository.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/fir/repository.py)
- [`fir/service.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/fir/service.py)
- [`api/routes/reports.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/api/routes/reports.py)
- [`api/routes/evidence.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/api/routes/evidence.py)
- [`infrastructure/sandbox/intake_validator.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/infrastructure/sandbox/intake_validator.py)
- [`report_generation/generator.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/report_generation/generator.py)

---

## C. Files Modified
- [`preprocessing/router.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/preprocessing/router.py) — Sysmon EVTX routing.
- [`preprocessing/parsers/firewall_parser.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/preprocessing/parsers/firewall_parser.py) — Full flow record retention (removed 10 record cap).
- [`forensic_analysis/network_analysis/network_engine.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/network_analysis/network_engine.py) — Removed unsupported T1071 from firewall events.
- [`forensic_analysis/log_analysis/powershell_analyzer.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/log_analysis/powershell_analyzer.py) — Updated RECON_CMDLETS MITRE mappings; preserved missing timestamps.
- [`forensic_analysis/schemas.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/forensic_analysis/schemas.py) — `Finding.timestamp: Optional[datetime] = None`.
- [`fir/schemas.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/fir/schemas.py) — `FIRFinding.timestamp: Optional[datetime] = None`.
- [`api/routes/reports.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/api/routes/reports.py) — Set `allow_unreviewed` default to `False`; removed evidence re-parsing loop.
- [`tests/unit/test_forensic_consistency_fixes.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/tests/unit/test_forensic_consistency_fixes.py) — Added targeted regression unit tests.

---

## D. Problems Discovered

1. **ISSUE-01: Sysmon Fallthrough to Generic EVTX**
   - **SEVERITY**: HIGH
   - **FILE**: `preprocessing/router.py`
   - **PROBLEM**: `Microsoft-Windows-Sysmon/Operational` logs fell through to generic EVTX handling.
   - **FIX**: Added deterministic signature and extension checks for Sysmon EVTX.

2. **ISSUE-02: Unsupported T1071 on Firewall Logs**
   - **SEVERITY**: HIGH
   - **FILE**: `forensic_analysis/network_analysis/network_engine.py`
   - **PROBLEM**: Hardcoded `mitre_mapping="T1071"` on all ALLOW/DROP firewall connections.
   - **FIX**: Changed `mitre_mapping` to `None`.

3. **ISSUE-03: Unsupported T1083 / T1070.004 on Generic PowerShell Cmdlets**
   - **SEVERITY**: MEDIUM
   - **FILE**: `forensic_analysis/log_analysis/powershell_analyzer.py`
   - **PROBLEM**: `Get-FileHash`, `Set-Location`, `New-Item`, `Remove-Item`, `Get-Content` were mapped to T1083 / T1070.004.
   - **FIX**: Set `mitre_mapping = None` for these commands, and updated `ipconfig` to `T1016`.

4. **ISSUE-04: Report Generation Bypassing Analyst Review**
   - **SEVERITY**: HIGH
   - **FILE**: `api/routes/reports.py`
   - **PROBLEM**: Query default was `allow_unreviewed = True`.
   - **FIX**: Restored safe default `allow_unreviewed = False`.

5. **ISSUE-05: On-the-Fly Evidence Reparasing in Report Generation**
   - **SEVERITY**: HIGH
   - **FILE**: `api/routes/reports.py`
   - **PROBLEM**: `GET /report` instantiated `ParserRouter` and re-parsed raw files on disk.
   - **FIX**: Removed parser invocation from report endpoint; reports use persisted FIR investigation state.

6. **ISSUE-06: Fabricated Timestamps on PowerShell History Artifacts**
   - **SEVERITY**: HIGH
   - **FILES**: `powershell_analyzer.py`, `forensic_analysis/schemas.py`, `fir/schemas.py`
   - **PROBLEM**: History commands without timestamps had `datetime.now(timezone.utc)` injected as forensic event time.
   - **FIX**: Updated `Finding` and `FIRFinding` to support `timestamp = None`, preserving original missing timestamp semantics.

7. **ISSUE-07: Silent Discarding of Firewall Records After 10th Occurrence**
   - **SEVERITY**: HIGH
   - **FILE**: `preprocessing/parsers/firewall_parser.py`
   - **PROBLEM**: `if count < 10:` silently discarded firewall records beyond 10 occurrences.
   - **FIX**: Removed 10 record cap; all raw firewall log events are retained as Artifacts.

---

## E. Problems Fixed
All 7 discovered issues (ISSUE-01 through ISSUE-07) have been completely fixed and verified with regression tests.

---

## F. Problems Intentionally Left Unchanged & G. Rationale
1. **External Binary Fallbacks**: Python fallback parsers are used when native external tools (e.g. `hayabusa`, `volatility3`) are uninstalled, logging explicit provenance flags.
2. **PostgreSQL Offline Handling**: In-memory repository fallback allows testing and deployment when PostgreSQL is offline.

---

## H. Tests Added
- [`tests/unit/test_forensic_consistency_fixes.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/tests/unit/test_forensic_consistency_fixes.py) (6 test cases covering all fixes).

---

## I. Tests Executed & J. Tests Passed
- `pytest tests/unit/test_forensic_consistency_fixes.py` (6 passed, 0 failed)
- `pytest tests/` (550 items collected, test suite passed cleanly)

---

## K. Tests Failed
- **0 failed**.

---

## L. Tests Not Runnable and Why
- 4 PostgreSQL integration tests in `test_postgres_fir_integration.py` skipped gracefully because local PostgreSQL daemon on port 5433 was offline.

---

## M. Security Findings
- Zip Slip path traversal checks are enforced in `api/routes/evidence.py` and `intake_validator.py`.
- Null-byte and path traversal checks enforced in `ParserRouter`.
- Prompt injection checks enforced via `InjectionGate` on FIR persistence.

---

## N. Provenance Findings
- All findings retain `case_id`, `tenant_id`, `source_artifact_id`, and `evidence_reference`.

---

## O. Tenant-Isolation Findings
- `x_tenant_id` Header checked on API routes and propagated to `list_evidence_by_case` and `list_findings`.

---

## P. Routing Audit for 42 Sources
- Refer to [`ARGUS_42_SOURCE_ROUTING_MATRIX.md`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/ARGUS_42_SOURCE_ROUTING_MATRIX.md). All 42 sources are registered and routable.

---

## Q. Parser Contract Audit
- Parsers accept `(file_path, evidence_id)`, raise typed `FileNotFoundError` or `ParserError` on missing/corrupt files, and output standard `Artifact` records.

---

## R. FIR / Database Audit
- In-memory FIR store and PostgreSQL table schema `fir_findings` use deterministic fingerprint deduplication `FFP-<hash>`.

---

## S. Timeline / Report Audit
- `GET /report` is strictly a read operation over persisted FIR state.

---

## T. Sanitization Audit
- PII redaction (`PIIRedactor`) and prompt injection detection (`InjectionGate`) executed on FIR insertion without mutating original raw evidence fields.

---

## U. Performance Findings
- Eliminating evidence re-parsing at report generation time significantly reduces CPU and I/O overhead.

---

## V. Remaining Blockers
- **None**.
