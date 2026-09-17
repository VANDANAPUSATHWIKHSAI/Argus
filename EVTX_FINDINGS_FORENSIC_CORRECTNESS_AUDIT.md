# ARGUS — EVTX FINDINGS FORENSIC CORRECTNESS AUDIT

**Target Environment**: Windows EVTX Telemetry  
**Evidence File**: `exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx`  
**Total FIR Findings Audited**: 1  

---

## 1. Audit Summary Matrix

| Classification | Count | Percentage |
| :--- | :--- | :--- |
| **VALID** | **1** | **100.0%** |
| **VALID_BUT_CONFIDENCE_REVIEW** | 0 | 0.0% |
| **SEVERITY_REVIEW** | 0 | 0.0% |
| **FALSE_POSITIVE** | 0 | 0.0% |
| **DUPLICATE_FINDING** | 0 | 0.0% |
| **OVERSTATED_CLAIM** | 0 | 0.0% |
| **BROKEN_PROVENANCE** | 0 | 0.0% |
| **UNSUPPORTED_MITRE_MAPPING** | 0 | 0.0% |
| **SANITIZATION_DEFECT** | 0 | 0.0% |

---

## 2. Comprehensive Forensic Audit of Individual Findings

### Finding 1: Potentially Suspicious Rundll32 Activity via Advpack.DLL

- **FIR ID**: `FIR-EVTX-001`
- **Finding Layer**: `log.process_creation`
- **Factual Statement**: `Rundll32 command line executed advpack.dll,RegisterOCX: rundll32.exe advpack.dll,RegisterOCX c:\Windows\System32\calc.exe`
- **Severity**: `HIGH`
- **Confidence**: `0.90`
- **MITRE ATT&CK Mapping**: `T1218.011` (System Binary Proxy Execution: Rundll32)

#### Detailed Verification & Audit Criteria:
1. **Raw EVTX Support**: **SUPPORTED**. Sysmon Event ID 1 (Record 16452) explicitly contains `Image`: `C:\Windows\System32\rundll32.exe` and `CommandLine`: `rundll32.exe advpack.dll,RegisterOCX c:\Windows\System32\calc.exe`.
2. **Factual Accuracy**: **ACCURATE**. The factual statement accurately captures the command line binary and argument parameters.
3. **Severity Justification**: **JUSTIFIED (HIGH)**. Execution of `advpack.dll,RegisterOCX` with an arbitrary path payload (`calc.exe`) is a well-documented LOLBIN technique (MITRE ATT&CK T1218.011) used to bypass application whitelisting and execute code via Windows signed binaries.
4. **Confidence Justification**: **JUSTIFIED (0.90)**. High confidence based on deterministic process execution arguments in Sysmon EID 1.
5. **MITRE ATT&CK Mapping**: **SUPPORTED (T1218.011)**. Exactly matches Sub-technique T1218.011 for Rundll32 execution.
6. **Duplicate Check**: **NOT A DUPLICATE**. Unique logical process execution finding.
7. **False Positive Check**: **NOT A FALSE POSITIVE**. The execution of `rundll32.exe advpack.dll,RegisterOCX` calling `calc.exe` represents an adversarial test artifact designed to demonstrate LOLBIN proxy execution.
8. **Claim Assessment**: **ACCURATE & DEFENSIBLE**. Factual boundary between process creation event and LOLBIN interpretation is maintained.
9. **Provenance Integrity**: **INTACT**. Full trace back to Raw EVTX XML Record 16452 -> Normalized Artifact -> Entity -> FCR -> UAI -> Finding -> FIR.
10. **Sanitization Gateway**: **PASSED**. No prompt injection escape; XML and command line strings cleanly delimited.

- **Classification Result**: **VALID**

---

## 3. End-to-End Provenance Trace

```
[RAW EVTX RECORD 16452]
  Event ID: 1 (Sysmon Process Creation)
  Computer: WIN-EVTX-HOST
  Image: C:\Windows\System32\rundll32.exe
  CommandLine: rundll32.exe advpack.dll,RegisterOCX c:\Windows\System32\calc.exe
  ParentCommandLine: cmd.exe
  │
  ▼
[NORMALIZED ARTIFACT]
  artifact_id: ART-EVTX-002
  source_tool: evtxecmd / python-evtx
  artifact_type: log_event
  host: WIN-EVTX-HOST
  process_name: rundll32.exe
  process_command_line: rundll32.exe advpack.dll,RegisterOCX c:\Windows\System32\calc.exe
  │
  ▼
[ATOMIC ENTITIES]
  entity_type: process_name -> "rundll32.exe"
  entity_type: file_path -> "c:\Windows\System32\calc.exe"
  entity_type: command_line -> "rundll32.exe advpack.dll,RegisterOCX c:\Windows\System32\calc.exe"
  │
  ▼
[FCR CORRELATION]
  fcr_id: FCR-EVTX-002
  correlation_type: process_creation
  contributing_artifacts: [ART-EVTX-002]
  │
  ▼
[UAI CONSOLIDATION]
  uai_id: UAI-EVTX-002
  layer: log_event
  │
  ▼
[FORENSIC FINDING]
  finding_id: FINDING-EVTX-001
  layer: log.process_creation
  fact: Rundll32 command line executed advpack.dll,RegisterOCX: rundll32.exe advpack.dll,RegisterOCX c:\Windows\System32\calc.exe
  severity: high
  mitre_mapping: T1218.011
  │
  ▼
[SANITIZED FIR FINDING]
  fir_id: FIR-EVTX-001
  status: SANITIZED_AND_PERSISTED
```

---

## 4. Final Verdict

- **Total Audited**: 1
- **Valid**: 1
- **Defects Found**: 0
- **Final Classification**: **VALID**
