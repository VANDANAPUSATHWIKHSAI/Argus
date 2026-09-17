# ARGUS — MEMORY VOLATILITY 3 PLUGIN COVERAGE & GAP AUDIT REPORT

**Target Evidence:** `Triage-Memory.mem` (5.00 GB)  
**Volatility 3 Framework Version:** 2.28.0  
**Audit Timestamp:** 2026-09-17T14:20:12.553313+00:00  

## 1. Plugin Execution Matrix

| Plugin Name | Output Artifact Type | Status | Artifacts Extracted | Runtime | Verdict &
| :--- | :--- | :---: | :---: | :---: | :--- |
| `windows.pslist` | Memory Domain Artifact | **ACTIVE** | 65 | 2.19s | 100% Operational |
| `windows.pstree` | Memory Domain Artifact | **ACTIVE** | 7 | 2.18s | 100% Operational |
| `windows.psscan` | Memory Domain Artifact | **ACTIVE** | 66 | 32.87s | 100% Operational |
| `windows.cmdline` | Memory Domain Artifact | **ACTIVE** | 65 | 2.38s | 100% Operational |
| `windows.cmdscan` | Memory Domain Artifact | **INACTIVE_ERROR** | 0 | 4.16s | Inapplicable / Namespace relocated in Volatility 3 |
| `windows.netscan` | Memory Domain Artifact | **ACTIVE** | 78 | 42.15s | 100% Operational |
| `windows.malfind` | Memory Domain Artifact | **ACTIVE** | 36 | 64.59s | 100% Operational |
| `windows.dlllist` | Memory Domain Artifact | **ACTIVE** | 3,756 | 9.82s | 100% Operational |
| `windows.handles` | Memory Domain Artifact | **ACTIVE** | 20,481 | 38.53s | 100% Operational |
| `windows.filescan` | Memory Domain Artifact | **ACTIVE** | 2,656 | 47.66s | 100% Operational |
| `windows.hivelist` | Memory Domain Artifact | **INACTIVE_ERROR** | 0 | 1.26s | Inapplicable / Namespace relocated in Volatility 3 |

---

## 2. Inactive Plugins Investigation & Coverage Gap Audit

### A. `windows.cmdscan`
- **Status:** `INAPPLICABLE / EXPECTED`  
- **Technical Root Cause:** `windows.cmdscan` targets legacy Windows XP 32-bit `csrss.exe` command buffer heaps. On Windows 7/10 64-bit kernel memory dumps, command buffers do not use XP heap structures.  
- **Coverage Assessment:** **No coverage gap**. Process command lines are 100% captured by `windows.cmdline` (65 command lines extracted).  

### B. `windows.hivelist`
- **Status:** `COVERAGE GAP (SUPERSORTED NAMESPACE)`  
- **Technical Root Cause:** Volatility 3 Framework 2.28.0 relocated `windows.hivelist` to `windows.registry.hivelist`.  
- **Coverage Assessment:** Registry hive references were captured by `windows.filescan` (2,656 file objects), but updating `MemoryParser` plugin list to include `windows.registry.hivelist` will provide direct registry hive symbol table coverage in future releases.  

