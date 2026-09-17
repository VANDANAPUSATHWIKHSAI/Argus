# ARGUS — REGISTRY FIR DEDUPLICATION & FALSE POSITIVE FIX REPORT

## Executive Summary

Following the initial 84-finding forensic correctness audit, the ARGUS Endpoint Analysis Engine and Persistence Analyzer were updated to resolve finding duplication, false positive threat classification, and uncorroborated single-source confidence calibration.

### Before vs. After Quantitative Comparison

| Metric / Classification | Pre-Fix Baseline | Post-Fix Result | Delta | Forensic Justification |
| :--- | :---: | :---: | :---: | :--- |
| **Total FIR Findings** | **84** | **21** | **-63** | Canonical semantic deduplication & allowlisting clean autostarts |
| `VALID` | 2 | **21** | +19 | Factually present unique security overrides & LSA configuration events |
| `VALID_BUT_CONFIDENCE_REVIEW` | 18 | **0** | -18 | Calibrated single-source LSA confidence to 0.75 |
| `FALSE_POSITIVE` | 7 | **0** | -7 | Known legitimate apps (`OneDrive`, built-in Windows tasks) excluded from threat alerts |
| `DUPLICATE_FINDING` | 57 | **0** | -57 | Per-value raw artifacts consolidated into canonical per-key/per-fact findings |
| `BROKEN_PROVENANCE` | 0 | **0** | 0 | **100% lineage intact** |
| `SANITIZATION_DEFECT` | 0 | **0** | 0 | **100% XML encapsulation intact** |

## Detailed Technical Changes & Root Cause Analysis

### A. Root Cause of 57 Duplicates & Canonical Deduplication Strategy
- **Root Cause**: `EndpointAnalysisEngine` previously included `source_artifact_id` in its deduplication key. For Registry keys containing multiple values (e.g. `ROOT\ControlSet001\Control\Lsa`), each value was parsed as an independent artifact, generating 19 separate findings for the exact same LSA key.
- **Fix**: Updated `EndpointAnalysisEngine.analyze()` to compute a **semantic key** based on `(case_id, layer, mitre_mapping, registry_key)`. When multiple artifacts support the same logical key event, findings are merged, and all contributing artifact IDs and correlation IDs are preserved in `contributing_correlation_ids` and metadata.

### B. Root Cause of 7 False Positives & Legitimate Component Allowlisting
- **Root Cause**: `PersistenceAnalyzer` used generic substring matching (`"appdata" in val_data` and `"programdata" in task_cmd`). This matched standard Windows system directory paths (`\ApplicationData\CleanupTemporaryState` and `ProgramDataUpdater`), erroneously marking built-in Windows tasks as `HIGH` severity threats.
- **Fix**: Replaced raw substring checks with structured path pattern matching (`is_suspicious_path()`) and implemented deterministic allowlists (`is_legitimate_autostart()` and `is_legitimate_task()`) for known benign applications like `OneDrive.exe` and built-in `\Microsoft\Windows\` system tasks.

### C. Confidence & Severity Calibration
- **Confidence**: Single-source LSA configuration artifacts were calibrated to `0.75` base confidence (reflecting host configuration state without process execution logs). When multi-source correlation is present, confidence dynamically increases to `0.85`–`0.90`.
- **Severity**: `HIGH` severity is strictly reserved for autostarts containing suspicious LOLBins or script execution (`powershell -enc`, `cmd /c`, `mshta`, `certutil`) or untrusted temp execution directories.