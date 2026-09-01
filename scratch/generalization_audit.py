import os
import sys
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List

# Ensure Argus root is on sys.path
sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GeneralizationAudit")

# Imports from Argus codebase
from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine

def run_layer2_and_fcr_audit():
    print("============================================================")
    print("ARGUS — CRITICAL GENERALIZATION AUDIT TEST SUITE")
    print("============================================================")
    print("Using 100% Synthetic Novel Evidence (Zero Sudeep/Demo values)\n")

    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    # ------------------------------------------------------------
    # PART 3 & 4: SYNTHETIC ARTIFACT BUILDER
    # ------------------------------------------------------------

    case_id = "CASE-AUDIT-2026"
    host_id = "WORKSTATION-77"

    # Artifact 1: explorer.exe (parent)
    art_explorer = Artifact(
        artifact_id="ART-SYN-001",
        evidence_id="EV-SYN-01",
        case_id=case_id,
        host_id=host_id,
        source_tool="volatility3",
        artifact_type="process_event",
        timestamp=t0,
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            process_name="explorer.exe",
            process_id=1024,
            parent_process_id=400,
            command_line="C:\\Windows\\explorer.exe"
        ),
        raw_fields={"Image": "C:\\Windows\\explorer.exe", "PID": 1024, "PPID": 400}
    )

    # Artifact 2: winword.exe (child of explorer, parent of powershell)
    art_winword = Artifact(
        artifact_id="ART-SYN-002",
        evidence_id="EV-SYN-01",
        case_id=case_id,
        host_id=host_id,
        source_tool="volatility3",
        artifact_type="process_event",
        timestamp=t0 + timedelta(seconds=2),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            process_name="winword.exe",
            process_id=2048,
            parent_process_id=1024,
            command_line="\"C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE\" C:\\Users\\alice.williams\\Downloads\\invoice_update.doc"
        ),
        raw_fields={"Image": "WINWORD.EXE", "PID": 2048, "PPID": 1024}
    )

    # Artifact 3: powershell.exe (child of winword)
    art_ps = Artifact(
        artifact_id="ART-SYN-003",
        evidence_id="EV-SYN-01",
        case_id=case_id,
        host_id=host_id,
        source_tool="hayabusa",
        artifact_type="process_event",
        timestamp=t0 + timedelta(seconds=5),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            process_name="powershell.exe",
            process_id=4096,
            parent_process_id=2048,
            command_line="powershell.exe -ExecutionPolicy Bypass -Command Start-Process C:\\Users\\alice.williams\\Downloads\\invoice_update.exe"
        ),
        raw_fields={"Image": "powershell.exe", "PID": 4096, "PPID": 2048}
    )

    # Artifact 4: Network Connection from powershell.exe
    art_net = Artifact(
        artifact_id="ART-SYN-004",
        evidence_id="EV-SYN-02",
        case_id=case_id,
        host_id=host_id,
        source_tool="zeek",
        artifact_type="network_connection",
        timestamp=t0 + timedelta(seconds=7),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            src_ip="10.44.77.21",
            src_port=49152,
            dst_ip="203.0.113.77",
            dst_port=443,
            process_id=4096,
            domain="security-alert-example.net"
        ),
        raw_fields={"id.orig_h": "10.44.77.21", "id.resp_h": "203.0.113.77", "id.resp_p": 443}
    )

    # Artifact 5: File creation (invoice_update.exe)
    art_file = Artifact(
        artifact_id="ART-SYN-005",
        evidence_id="EV-SYN-03",
        case_id=case_id,
        host_id=host_id,
        source_tool="mftecmd",
        artifact_type="file_record",
        timestamp=t0 + timedelta(seconds=1),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            file_path="C:\\Users\\alice.williams\\Downloads\\invoice_update.exe",
            file_name="invoice_update.exe",
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        raw_fields={"FileName": "invoice_update.exe", "FilePath": "C:\\Users\\alice.williams\\Downloads\\invoice_update.exe"}
    )

    # Artifact 6: Execution of invoice_update.exe
    art_proc_invoice = Artifact(
        artifact_id="ART-SYN-006",
        evidence_id="EV-SYN-01",
        case_id=case_id,
        host_id=host_id,
        source_tool="hayabusa",
        artifact_type="process_event",
        timestamp=t0 + timedelta(seconds=10),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            process_name="invoice_update.exe",
            process_id=8192,
            parent_process_id=4096,
            command_line="C:\\Users\\alice.williams\\Downloads\\invoice_update.exe",
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        raw_fields={"Image": "invoice_update.exe", "PID": 8192, "PPID": 4096}
    )

    # Artifact 7: Registry modification (Run Key)
    art_reg = Artifact(
        artifact_id="ART-SYN-007",
        evidence_id="EV-SYN-04",
        case_id=case_id,
        host_id=host_id,
        source_tool="regripper",
        artifact_type="registry_key",
        timestamp=t0 + timedelta(seconds=12),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            url="C:\\Users\\alice.williams\\Downloads\\invoice_update.exe"
        ),
        raw_fields={"Key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Value": "C:\\Users\\alice.williams\\Downloads\\invoice_update.exe"}
    )

    # Artifact 8: Email artifact containing URL
    art_email = Artifact(
        artifact_id="ART-SYN-008",
        evidence_id="EV-SYN-05",
        case_id=case_id,
        host_id=host_id,
        source_tool="python_email",
        artifact_type="email_header",
        timestamp=t0 - timedelta(minutes=5),
        normalized_fields=NormalizedFields(
            user="alice.williams",
            host=host_id,
            sender="alert@security-alert-example.net",
            recipients="alice@example-test.org",
            subject="Urgent Password Verification Required",
            url="https://security-alert-example.net/login",
            domain="security-alert-example.net"
        ),
        raw_fields={
            "From": "alert@security-alert-example.net",
            "To": "alice@example-test.org",
            "Body": "Please click https://security-alert-example.net/login immediately."
        }
    )

    all_synthetic_arts = [
        art_explorer, art_winword, art_ps, art_net, 
        art_file, art_proc_invoice, art_reg, art_email
    ]

    # ------------------------------------------------------------
    # ARTIFACT EXTRACTION STEP
    # ------------------------------------------------------------
    extractor = ArtifactExtractor()
    extracted_entities = extractor.extract(all_synthetic_arts, evidence_id="EV-SYN-GEN")

    print(f"[EXTRACTOR] Total Extracted Observables: {len(extracted_entities)}")
    for e in extracted_entities:
        print(f"  - Entity Type: {e.entity_type:15s} | Value: {e.value:50s} | Parent Art: {e.artifact_id}")

    # ------------------------------------------------------------
    # FCR CORRELATION STEP
    # ------------------------------------------------------------
    fcr_engine = FCREngine()
    fcrs = fcr_engine.correlate(all_synthetic_arts, extracted_entities=extracted_entities)

    print(f"\n[FCR ENGINE] Total Correlation Records Generated: {len(fcrs)}")
    for f in fcrs:
        print(f"\n--- FCR: {f.correlation_id} ---")
        print(f"  Case ID:                {f.case_id}")
        print(f"  Host:                   {f.host}")
        print(f"  Relationship Type:      {f.relationship_type}")
        print(f"  Contributing Artifacts: {f.artifact_ids}")
        print(f"  Shared Value:           {f.shared_value}")
        print(f"  Confidence:             {f.confidence}")
        print(f"  Distinct Types:         {f.distinct_artifact_types}")
        print(f"  Source Count:           {f.source_count}")
        print(f"  Strategy Params:        {f.strategy_params}")

    # ------------------------------------------------------------
    # INDIVIDUAL TEST VERIFICATIONS (PART 4)
    # ------------------------------------------------------------
    print("\n============================================================")
    print("PART 4: FCR GENERALIZATION TEST VERIFICATION")
    print("============================================================")

    # Test A: Process Tree (explorer -> winword -> powershell)
    proc_tree_fcrs = [f for f in fcrs if "process_tree" in f.relationship_type]
    print(f"\nTEST A (Process Relationship): Generated {len(proc_tree_fcrs)} process_tree FCRs.")
    for p in proc_tree_fcrs:
        print(f"  -> FCR {p.correlation_id}: Artifacts {p.artifact_ids}, PIDs: {p.strategy_params}")

    # Test B: Process + Network (powershell.exe -> 203.0.113.77:443 via PID 4096)
    net_proc_fcrs = [f for f in fcrs if "network_process" in f.relationship_type]
    print(f"\nTEST B (Process + Network): Generated {len(net_proc_fcrs)} network_process FCRs.")
    for n in net_proc_fcrs:
        print(f"  -> FCR {n.correlation_id}: Artifacts {n.artifact_ids}, Reason: {n.strategy_params}")

    # Test C: File + Process (invoice_update.exe created -> executed, linked by shared Hash)
    hash_fcrs = [f for f in fcrs if f.shared_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    print(f"\nTEST C (File + Process): Generated {len(hash_fcrs)} FCRs linked by Hash.")
    for h in hash_fcrs:
        print(f"  -> FCR {h.correlation_id}: Artifacts {h.artifact_ids}, Shared Hash: {h.shared_value[:16]}...")

    # Test D: Registry + Process
    reg_fcrs = [f for f in fcrs if "ART-SYN-007" in f.artifact_ids]
    print(f"\nTEST D (Registry + Process): Generated {len(reg_fcrs)} FCRs containing Registry Artifact.")
    for r in reg_fcrs:
        print(f"  -> FCR {r.correlation_id}: Rel: {r.relationship_type}, Artifacts: {r.artifact_ids}, Shared: {r.shared_value}")

    # Test E: Email + Network/URL (security-alert-example.net)
    email_url_fcrs = [f for f in fcrs if "security-alert-example.net" in (f.shared_value or "")]
    print(f"\nTEST E (Email + URL/Domain): Generated {len(email_url_fcrs)} FCRs linked by Domain/URL.")
    for e in email_url_fcrs:
        print(f"  -> FCR {e.correlation_id}: Artifacts: {e.artifact_ids}, Domain: {e.shared_value}")

    # ------------------------------------------------------------
    # TEST F: COMPLETELY UNRELATED ARTIFACTS (NEGATIVE TEST)
    # ------------------------------------------------------------
    print("\n------------------------------------------------------------")
    print("TEST F: COMPLETELY UNRELATED ARTIFACTS (NEGATIVE TEST)")
    print("------------------------------------------------------------")

    art_unrelated_1 = Artifact(
        artifact_id="ART-UNREL-001",
        evidence_id="EV-UNREL-01",
        case_id="CASE-ALPHA",
        host_id="HOST-A",
        source_tool="volatility3",
        artifact_type="process_event",
        timestamp=datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc),
        normalized_fields=NormalizedFields(
            user="user_alpha",
            host="HOST-A",
            process_name="processA.exe",
            process_id=9999,
            hash="1111111111111111111111111111111111111111111111111111111111111111"
        )
    )

    art_unrelated_2 = Artifact(
        artifact_id="ART-UNREL-002",
        evidence_id="EV-UNREL-02",
        case_id="CASE-BETA", # Different case
        host_id="HOST-B",   # Different host
        source_tool="zeek",
        artifact_type="network_connection",
        timestamp=datetime(2026, 9, 1, 18, 0, 0, tzinfo=timezone.utc), # 8 hours later
        normalized_fields=NormalizedFields(
            user="user_beta",
            host="HOST-B",
            src_ip="192.0.2.50",
            dst_ip="198.51.100.99",
            hash="2222222222222222222222222222222222222222222222222222222222222222"
        )
    )

    unrelated_fcrs = fcr_engine.correlate([art_unrelated_1, art_unrelated_2])
    print(f"Negative Test Result: FCRs generated = {len(unrelated_fcrs)} (Expected: 0)")
    if len(unrelated_fcrs) == 0:
        print(">>> TEST F PASSED: ZERO FALSE FCRs GENERATED <<<")
    else:
        print(">>> TEST F FAILED: UNRELATED ARTIFACTS PRODUCED FALSE FCR <<<")

if __name__ == "__main__":
    run_layer2_and_fcr_audit()
