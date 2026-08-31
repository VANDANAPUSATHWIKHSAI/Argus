# ARGUS PARSER LAYER DEFECTS LOG

## 1. Defect Audit Summary

A full audit of the ARGUS Preprocessing Parser Layer was conducted across all 42 required physical evidence sources, inspecting:
- Implementation completeness against `ARGUS_DETAILS.txt` and `Evidence_Parser_Workflow.docx`
- Routing correctness and fallback behavior in `ParserRouter`
- Compliance with `Artifact` and `NormalizedFields` schemas
- Timestamp semantics and timezone handling
- Preservations of raw evidence and provenance tracking
- Security constraints (`eval`/`exec`, `shell=True`, subprocess construction, unsafe execution of extracted forensic data)
- Platform compatibility and typed error handling

---

## 2. Defects Status

**OPEN DEFECTS**: 0  
**RESOLVED DEFECTS**: 2  

### Resolved Defects Log

1. **DEFECT-PARSER-001**: Missing `file_name` in `NormalizedFields` for Hindsight browser download records (`browser_parser.py`).
   - **Root Cause**: `BrowserParser._normalize` extracted `url`, `domain`, `file_path`, `user`, and `rule_name` but omitted `file_name` which is required for correlation downstream in FCR.
   - **Resolution**: Updated `BrowserParser._normalize` to extract `file_name` from `filename` or `os.path.basename(file_path)`.
   - **Status**: FIXED & VERIFIED (`test_firefox_msg_parsers.py`).

2. **DEFECT-PARSER-002**: Missing `process_id` integer normalization in Windows Defender parser (`defender_parser.py`).
   - **Root Cause**: `WindowsDefenderParser._record_to_artifact` captured `process_id` in `raw_fields` but omitted `process_id` in `NormalizedFields`.
   - **Resolution**: Updated `WindowsDefenderParser._record_to_artifact` to parse `proc_id` to integer and pass `process_id=pid_int` into `NormalizedFields`.
   - **Status**: FIXED & VERIFIED (`test_firewall_defender_parsers.py`).

---

## 3. Current Open Defects

```
NO OPEN DEFECTS REMAINING IN THE PARSER LAYER.
```
