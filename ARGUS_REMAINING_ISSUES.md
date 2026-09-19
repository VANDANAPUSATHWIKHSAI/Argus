# ARGUS Remaining Issues & Technical Debt Inventory

This document records all remaining issues, technical debt items, known architectural limitations, and operational dependencies across ARGUS.

---

## A. FIXED ISSUES SUMMARY

1. **Sysmon EVTX Routing (FIX 1)**: Resolved. `Microsoft-Windows-Sysmon/Operational` EVTX files now deterministically route to `EvtxParser` with explicit `Sysmon Operational Logs` evidence type in both signature and extension detection layers.
2. **Firewall MITRE Mapping (FIX 2)**: Resolved. Unjustified `T1071` mapping removed from Windows Firewall `ALLOW` and `DROP` events in `network_engine.py`. `mitre_mapping` set to `None`.
3. **PowerShell MITRE Mappings (FIX 3)**: Resolved. Unjustified `T1083` / `T1070.004` mappings removed from non-reconnaissance cmdlets (`Get-FileHash`, `Set-Location`, `New-Item`, `Remove-Item`, `Get-Content`). `ipconfig` mapped to `T1016`.
4. **Report Review Gating (FIX 4)**: Resolved. Default query parameter `allow_unreviewed` restored to `False` on `GET /{case_id}/report`.
5. **Report-Time Evidence Reparasing (FIX 5)**: Resolved. Removed `ParserRouter` instantiation and raw evidence parsing loop from `GET /report` API route.
6. **PowerShell Timestamp Integrity (FIX 6)**: Resolved. `Finding.timestamp` and `FIRFinding.timestamp` updated to `Optional[datetime] = None`. `PowerShellAnalyzer` preserves `timestamp = None` without substituting current system processing time.
7. **Firewall Flow Aggregation (FIX 7)**: Resolved. Removed `if count < 10:` restriction in `WindowsFirewallParser`. Every raw firewall log line is retained as an Artifact without dropping records.

---

## B. INTENTIONALLY UNCHANGED / KNOWN ARCHITECTURAL LIMITATIONS

1. **External Forensic Tool Binaries**:
   - **Severity**: LOW (INFO)
   - **Description**: External forensic tools (`hayabusa`, `volatility3`, `EvtxECmd`, `PECmd`, `LECmd`, `JLECmd`, `RBCmd`, `AmcacheParser`, `SrumECmd`, `fls`) require binary installations on host OS.
   - **Rationale**: ARGUS includes built-in pure Python fallback parsers for all core evidence types. When an external tool binary is absent, ARGUS logs a controlled fallback message and uses the Python parser without fabricating external tool execution.

2. **AFF Disk Image Dependency**:
   - **Severity**: LOW (INFO)
   - **Description**: Parsing `.aff` disk images requires SleuthKit `fls` compiled with `libaff`.
   - **Rationale**: When `fls` lacks AFF support, `ParserRouter` returns a controlled `BLOCKED` status with reason `BLOCKED_MISSING_LIBAFF`.

3. **PostgreSQL Service Requirement for Integration Tests**:
   - **Severity**: INFO
   - **Description**: `test_postgres_fir_integration.py` tests skip when local PostgreSQL instance on port 5433 is unreachable.
   - **Rationale**: In-memory FIR persistence and FastAPI report endpoints operate seamlessly using `FIRRepository` in-memory fallback store when PostgreSQL is offline.

---

## C. REMAINING BLOCKERS

- **None**. No critical or high-severity blockers remain.
