# Memory Analysis Engine — Verification Report

## Verification Command
```powershell
$env:PYTHONPATH="c:\Users\Sudeep\Downloads\Argus\argus;c:\Users\Sudeep\Downloads\Argus"
python -m pytest argus/tests/unit/test_analysis_engines.py argus/tests/unit/test_endpoint_analysis.py argus/tests/unit/test_memory_analysis.py argus/tests/unit/test_fir_schema_coercion.py argus/tests/unit/test_fir_database_schema_contract.py -v
```

## Summary of Results
- **Total Tests Executed**: 61
- **Passed**: 61
- **Failed**: 0
- **Execution Time**: ~16.72s

## Test Breakdown
- `test_analysis_engines.py`: 21 passed (Network Engine, Log Engine, UnifiedStore, FIR handoff, AST security).
- `test_endpoint_analysis.py`: 14 passed (Endpoint Router Dispatch, Persistence, Filesystem, Registry, Browser, USB, UserActivity, Deduplication, Batch Integration, AST Security).
- `test_memory_analysis.py`: 19 passed (Memory Router Dispatch, Process, DLL, Network, Injection, Rootkit, Credential Redaction, Timeline, Deduplication, Batch Integration, AST Security).
- `test_fir_schema_coercion.py`: 4 passed (FIRFinding `list[str]` coercion, scalar fallback warning logging).
- `test_fir_database_schema_contract.py`: 3 passed (`fir_findings` table contract, `evidence_reference TEXT[]` SQL migration).

## AST Security Scan Audit Results
- `eval()` calls: 0
- `exec()` calls: 0
- `shell=True` arguments: 0
- `os.system()` calls: 0
- `pickle.loads()` calls: 0
- Raw password/hash leaks in Findings/FIR/logs: 0
