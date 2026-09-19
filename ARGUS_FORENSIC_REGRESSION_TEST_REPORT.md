# ARGUS Forensic Regression Test Report

This document records the exact results of unit, integration, and targeted regression tests executed to verify forensic consistency and prevent regressions across ARGUS.

## 1. Executive Summary

- **Total Test Suite Items**: 556
- **Test Session Result**: PASS
- **Targeted Consistency Fixes Suite**: `tests/unit/test_forensic_consistency_fixes.py` (6 passed, 0 failed)
- **Regressions Introduced**: None.
- **Validated Pipeline Integrity**: All previously validated real-evidence pipelines (Memory, PCAP, EVTX, Registry, Chrome) remain intact.

---

## 2. Test Execution Breakdown

| Test File / Suite | Category | Items | Status | Key Verifications |
|---|---|---|---|---|
| `tests/unit/test_forensic_consistency_fixes.py` | Unit / Regression | 6 | **PASS** | Sysmon routing, Firewall MITRE mapping=None, PowerShell MITRE mapping=None, PowerShell timestamp preservation, Firewall >10 flow retention, Report allow_unreviewed=False gating, Report determinism. |
| `tests/unit/test_router_42_sources.py` | Unit | 44 | **PASS** | Routing resolution for all 42 sources in `_SOURCE_PARSER_MAP`. |
| `tests/unit/test_firewall_defender_parsers.py` | Unit | 15 | **PASS** | Firewall log parsing, W3C line parsing, Defender XML/log parsing. |
| `tests/unit/test_powershell_wmi_parsers.py` | Unit | 10 | **PASS** | PowerShell script block, encoded command, and WMI persistence analysis. |
| `tests/unit/test_analysis_engines.py` | Unit | 21 | **PASS** | Stage 4 forensic analysis engines (Network, Log, Memory, Endpoint, Email). |
| `tests/unit/test_api_and_report_generation.py` | Integration | 9 | **PASS** | Report export, FastAPI endpoints, review gate filtering. |
| `tests/unit/test_pcap_semantic_dedup.py` | Unit | 7 | **PASS** | Network telemetry deduplication and FCR correlation. |
| `tests/unit/test_registry_dedup_and_fp.py` | Unit | 8 | **PASS** | Registry finding fingerprint calculation and idempotency. |
| `tests/integration/test_postgres_fir_integration.py` | Integration | 4 | **SKIPPED (DB offline)** | PostgreSQL FIR persistence. Skipped safely when local DB is offline. |

---

## 3. Targeted Regression Tests Added

### Test File: [`tests/unit/test_forensic_consistency_fixes.py`](file:///c:/Users/Sudeep/Downloads/Argus/Argus/tests/unit/test_forensic_consistency_fixes.py)

1. `test_sysmon_vs_generic_evtx_routing`:
   - Validates that `Microsoft-Windows-Sysmon%4Operational.evtx` routes to `EvtxParser` with `evidence_type = "Sysmon Operational Logs"`.
   - Validates Defender EVTX routes to `WindowsDefenderParser` ("Windows Defender Logs").
   - Validates Group Policy EVTX routes to `GroupPolicyLogParser` ("Group Policy Application Logs").
   - Validates generic EVTX remains `evidence_type = "Windows Event Logs (EVTX) — threat-hunted"`.

2. `test_firewall_mitre_mapping_is_none`:
   - Validates Firewall `ALLOW` and `DROP` findings produce `mitre_mapping = None` (removing unjustified T1071).

3. `test_powershell_mitre_and_timestamp_preservation`:
   - Validates `Get-FileHash` produces `mitre_mapping = None` (removing unjustified T1083).
   - Validates PowerShell history commands without timestamps preserve `timestamp = None` without substituting current system time.

4. `test_firewall_over_10_records_retention`:
   - Parses a log containing 15 identical firewall flow lines.
   - Confirms all 15 raw events are retained as Artifacts and `flow_occurrence_count = 15`.

5. `test_report_export_gating_unreviewed_default`:
   - Confirms `AnalystFindingService.export_report(..., allow_unreviewed=False)` excludes unreviewed findings.
   - Confirms `allow_unreviewed=True` includes unreviewed findings annotated with `_review_gate.unreviewed = True`.

6. `test_report_generator_determinism`:
   - Confirms multiple report generations on identical payload produce identical JSON output.

---

## 4. Verification Command & Environment

```powershell
pytest tests/unit/test_forensic_consistency_fixes.py
pytest tests/
```

- **Environment**: Windows 11 / Python 3.13.2 / pytest-9.1.1
- **All 6 targeted regression tests passed cleanly in 22.32 seconds.**
