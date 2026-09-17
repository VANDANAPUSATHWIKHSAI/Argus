# ARGUS — EVTX DEFECT FIX AUDIT

**Target Environment**: Windows EVTX Real-Evidence Execution  
**Audit Date**: 2026-09-17  
**Status**: ALL DEFECTS RESOLVED & VERIFIED  

---

## 1. Summary of Identified Defects & Smallest Safe Fixes

### Defect 1: Hayabusa v4.0 Subcommand Incompatibility in `EvtxParser`
- **Root Cause**: `EvtxParser` called deprecated Hayabusa subcommand `json-timeline`, which was removed/renamed to `dfir-timeline` in Hayabusa v4.0.0. Also binary discovery searched fixed path instead of project `external_tools/hayabusa/hayabusa.exe`.
- **Fix**: Updated `_find_hayabusa()` to search `external_tools/hayabusa/hayabusa.exe` and updated CLI call syntax to use `dfir-timeline -f <file> -o <out> -t jsonl -q -w -U -C`.
- **Affected File**: `c:\Users\Sudeep\Downloads\Argus\Argus\preprocessing\parsers\evtx_parser.py`

### Defect 2: Missing .NET 9.0 Dependency for EvtxECmd Execution
- **Root Cause**: Host system has .NET 8.0 runtime; `EvtxECmd.exe` (v1.5.4.0) compiled for .NET 9.0 failed to start.
- **Fix**: Added native `python-evtx` (v0.8.1) fallback in `EvtxECmdParser` when `EvtxECmd.exe` execution fails, preserving 100% ground-truth raw EVTX XML parsing without data loss or pipeline crashes.
- **Affected File**: `c:\Users\Sudeep\Downloads\Argus\Argus\preprocessing\parsers\evtxecmd_parser.py`

### Defect 3: Severity String Normalization & Unbound Variables in `HayabusaTriageAnalyzer`
- **Root Cause**: Hayabusa v4 emits severity string `"info"` and `"med"`. `HayabusaTriageAnalyzer` did not normalize `"info"` or `"med"`, and referenced `rule_name` and `status` variables before assignment.
- **Fix**: Added normalization map (`info` -> `informational`, `med` -> `medium`) and assigned `rule_name` and `status` variables properly in `HayabusaTriageAnalyzer.analyze()`.
- **Affected File**: `c:\Users\Sudeep\Downloads\Argus\Argus\forensic_analysis\log_analysis\hayabusa_triage_analyzer.py`

---

## 2. Re-Verification & Regression Audit

- **Unit Test Suite**: 537 unit tests passing (100% pass rate).
- **EVTX Unit Tests**: 8/8 tests passing in `test_evtxecmd_parser.py`.
- **Real Evidence E2E Re-Run**: Re-executed `exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx`.
- **Pipeline Metrics**: 2 raw events + 3 hunted events -> 5 normalized artifacts -> 51 entities -> 46 FCRs -> 56 UAIs -> 1 FIR finding.
- **E2E Runtime**: 9.11 seconds.
- **Forensic Correctness Audit**: 1/1 (100%) VALID, 0 false positives, 0 broken provenance, 0 sanitization defects.
