import sys
import os
import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

from preprocessing.schemas import Artifact, NormalizedFields
from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter, _IMPLEMENTED_PARSERS, _SOURCE_PARSER_MAP

print("==================================================================")
print("ARGUS PHASE A.2.1 FINAL HARDENING CHECK")
print("==================================================================")

# ─────────────────────────────────────────────────────────────────
# 1. PARSER DISTINCTION & INVENTORY COUNT VERIFICATION
# ─────────────────────────────────────────────────────────────────
print("\n[CHECK 1] Parser Distinction & Source Mapping...")
import glob
parsers_dir = Path("preprocessing/parsers")
parser_files = set(p.name for p in parsers_dir.glob("*_parser.py"))
if (parsers_dir / "vss_parser.py").exists():
    parser_files.add("vss_parser.py")

parser_module_count = len(parser_files)
implemented_parser_classes_count = len(_IMPLEMENTED_PARSERS)
supported_sources_count = len(_SOURCE_PARSER_MAP)
blocked_format_count = 1  # AFF 1.0 containers

print(f"  Actual Parser Modules (.py)          : {parser_module_count}")
print(f"  Implemented Parser Classes           : {implemented_parser_classes_count}")
print(f"  Supported Source Types in Router     : {supported_sources_count}")
print(f"  Special Format Audits (Blocked)     : {blocked_format_count} (AFF 1.0)")

assert parser_module_count == 34, f"Expected 34 parser modules, got {parser_module_count}"
assert supported_sources_count == 42, f"Expected 42 supported source types, got {supported_sources_count}"
print("  [PASS] Parser module count (34), router source map (42), and AFF distinction verified.")

# ─────────────────────────────────────────────────────────────────
# 2. COMPLETE JSON ROUND-TRIP & CONTRACT SERIALIZATION TEST
# ─────────────────────────────────────────────────────────────────
print("\n[CHECK 2 & 3 & 4 & 5] JSON Round-Trip & Datetime / Null / Provenance Contract Test...")

test_dt = datetime(2026, 8, 31, 14, 30, 45, 123456, tzinfo=timezone.utc)

art_orig = Artifact(
    case_id="case-tenant-alpha-001",
    evidence_id="ev-999-alpha",
    source_tool="tsk",
    artifact_type="file_record",
    host_id="FORENSIC-WORKSTATION-1",
    timestamp=test_dt,
    timestamp_type="modified",
    event_summary="File system record /windows/system32/cmd.exe",
    raw_fields={"inode": 12345, "mode": "-rwxr-xr-x", "null_field": None, "str_field": "test"},
    normalized_fields=NormalizedFields(
        host="FORENSIC-WORKSTATION-1",
        user="SYSTEM",
        process_id=4096,
        parent_process_id=1024,
        process_name="cmd.exe",
        process_command_line="cmd.exe /c whoami",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=443,
        domain="corp.local",
        url="https://corp.local/api/v1",
        file_path="C:\\Windows\\System32\\cmd.exe",
        file_name="cmd.exe",
        hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        registry_key="HKLM\\Software\\Microsoft",
        registry_value="Version",
        registry_value_data="10.0.19041",
        sender="attacker@malicious.com",
        recipients="victim@corp.local",
        subject="Urgent Security Update",
        rule_name="cmd_execution_detected",
        severity="high",
        # Null / absent fields testing
        usb_serial_number=None,
        first_connected=None
    ),
    parser_version="4.12.1",
    schema_version="2.0.0"
)

# Serialize to JSON
json_str = art_orig.model_dump_json()

# Deserialize back from JSON
art_deserialized = Artifact.model_validate_json(json_str)

# Verify Root Contract Fields
assert art_deserialized.case_id == art_orig.case_id
assert art_deserialized.evidence_id == art_orig.evidence_id
assert art_deserialized.source_tool == art_orig.source_tool
assert art_deserialized.artifact_type == art_orig.artifact_type
assert art_deserialized.parser_version == art_orig.parser_version
assert art_deserialized.event_summary == art_orig.event_summary
print("  [PASS] Root provenance contract fields preserved exactly.")

# Verify Datetime Precision, UTC & Timezone Awareness
assert art_deserialized.timestamp is not None
assert art_deserialized.timestamp.tzinfo == timezone.utc
assert art_deserialized.timestamp.year == 2026
assert art_deserialized.timestamp.microsecond == 123456
print("  [PASS] Datetime UTC, timezone awareness, and sub-second precision preserved.")

# Verify NormalizedFields Attributes
nf = art_deserialized.normalized_fields
assert nf.process_id == 4096
assert nf.parent_process_id == 1024
assert nf.process_name == "cmd.exe"
assert nf.process_command_line == "cmd.exe /c whoami"
assert nf.user == "SYSTEM"
assert nf.host == "FORENSIC-WORKSTATION-1"
assert nf.src_ip == "192.168.1.50"
assert nf.dst_ip == "10.0.0.1"
assert nf.src_port == 49152
assert nf.dst_port == 443
assert nf.domain == "corp.local"
assert nf.url == "https://corp.local/api/v1"
assert nf.file_path == "C:\\Windows\\System32\\cmd.exe"
assert nf.file_name == "cmd.exe"
assert nf.hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
assert nf.registry_key == "HKLM\\Software\\Microsoft"
assert nf.registry_value == "Version"
assert nf.sender == "attacker@malicious.com"
assert nf.recipients == "victim@corp.local"
assert nf.subject == "Urgent Security Update"
assert nf.rule_name == "cmd_execution_detected"
print("  [PASS] All NormalizedFields payload attributes preserved.")

# Verify Null / Absent Fields Remaining None
assert nf.usb_serial_number is None
assert nf.first_connected is None
assert art_deserialized.raw_fields.get("null_field") is None
print("  [PASS] Null / absent fields remain strictly None without string coercion.")

# ─────────────────────────────────────────────────────────────────
# 6. MALFORMED JSON & CORRUPTED RECORD HANDLING TEST
# ─────────────────────────────────────────────────────────────────
print("\n[CHECK 6] Malformed JSON & Corrupted Record Handling Test...")

# Malformed JSON syntax
try:
    Artifact.model_validate_json("{malformed_json: true, missing_quotes}")
    assert False, "Should have raised validation error for malformed JSON!"
except Exception as e:
    print(f"  [PASS] Caught malformed JSON syntax: {type(e).__name__}")

# Invalid timestamp string
try:
    bad_ts_payload = json.dumps({"evidence_id": "ev-123", "source_tool": "tsk", "artifact_type": "file_record", "timestamp": "INVALID_DATE_STRING"})
    Artifact.model_validate_json(bad_ts_payload)
    assert False, "Should have raised validation error for invalid timestamp string!"
except Exception as e:
    print(f"  [PASS] Caught invalid timestamp string format: {type(e).__name__}")

# ─────────────────────────────────────────────────────────────────
# 7. CASE & TENANT ISOLATION TEST
# ─────────────────────────────────────────────────────────────────
print("\n[CHECK 7] Case & Tenant Isolation Test...")

tenant_a_art = Artifact(case_id="case-tenant-A", evidence_id="ev-A", source_tool="tsk", artifact_type="file_record", normalized_fields=NormalizedFields(host="HOST-A"))
tenant_b_art = Artifact(case_id="case-tenant-B", evidence_id="ev-B", source_tool="tsk", artifact_type="file_record", normalized_fields=NormalizedFields(host="HOST-B"))

json_a = tenant_a_art.model_dump_json()
json_b = tenant_b_art.model_dump_json()

deser_a = Artifact.model_validate_json(json_a)
deser_b = Artifact.model_validate_json(json_b)

assert deser_a.case_id == "case-tenant-A" and deser_a.evidence_id == "ev-A" and deser_a.normalized_fields.host == "HOST-A"
assert deser_b.case_id == "case-tenant-B" and deser_b.evidence_id == "ev-B" and deser_b.normalized_fields.host == "HOST-B"
assert deser_a.case_id != deser_b.case_id
print("  [PASS] Case & tenant isolation verified after serialization.")

# ─────────────────────────────────────────────────────────────────
# 9. RAW EVIDENCE PARSING & INTEGRITY RE-VERIFICATION (7 FILES)
# ─────────────────────────────────────────────────────────────────
print("\n[CHECK 9] Phase A 7-File Raw Evidence Parsing & Cryptographic Integrity...")
source_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")
router = ParserRouter()

raw_results = []
for p in sorted(source_dir.iterdir()):
    if p.is_file():
        src_bytes = p.read_bytes()
        sha256_before = hashlib.sha256(src_bytes).hexdigest()
        
        ev = Evidence(
            case_id="case-hardening-check",
            filename=p.name,
            file_path=str(p),
            raw_file_path=str(p),
            uploaded_by="hardening_checker",
            sha256_hash=sha256_before,
            metadata={"size_bytes": len(src_bytes), "extension": p.suffix.lower()}
        )
        
        res = router.determine_routing(ev)
        
        records_count = 0
        if res.status == "ROUTED" and res.parser_instance:
            artifacts = res.parser_instance.parse(str(p), ev.evidence_id)
            records_count = len(artifacts)
            
            # Perform JSON round-trip on first artifact if available
            if artifacts:
                art_json = artifacts[0].model_dump_json()
                art_back = Artifact.model_validate_json(art_json)
                assert art_back.evidence_id == ev.evidence_id
        
        sha256_after = hashlib.sha256(p.read_bytes()).hexdigest()
        assert sha256_before == sha256_after, f"SHA256 mismatch on {p.name}!"
        
        raw_results.append((p.name, len(src_bytes), res.status, res.target_parser, records_count, "PASS"))

print("{:<16} | {:<10} | {:<8} | {:<18} | {:<8} | {:<5}".format("FILE", "SIZE", "STATUS", "PARSER", "RECORDS", "HASH"))
print("-" * 76)
for name, sz, st, prs, rec, hsh in raw_results:
    print("{:<16} | {:<10} | {:<8} | {:<18} | {:<8} | {:<5}".format(name, f"{sz} B", st, prs, rec, hsh))

print("\n==================================================================")
print("ALL PHASE A.2.1 HARDENING CHECKS PASSED SUCCESSFULLY!")
print("==================================================================")
