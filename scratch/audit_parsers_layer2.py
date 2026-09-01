import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))

from preprocessing.parsers.email_parser import EmailParser
from preprocessing.parsers.powershell_history_parser import PowerShellHistoryParser
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.normalizer import Normalizer

def test_parsers():
    print("============================================================")
    print("LAYER 2 PARSER & NORMALIZATION GENERALIZATION AUDIT")
    print("============================================================")

    # 1. Email Parser Test
    email_content = """From: alert@security-alert-example.net
To: alice@example-test.org
Subject: Security Alert
Date: Tue, 01 Sep 2026 10:00:00 +0000

Dear Alice,

Please visit https://security-alert-example.net/login immediately to update your invoice_update.exe preferences.
"""
    tmp_dir = tempfile.mkdtemp()
    eml_path = os.path.join(tmp_dir, "test_alert.eml")
    with open(eml_path, "w", encoding="utf-8") as f:
        f.write(email_content)

    email_parser = EmailParser()
    email_artifacts = email_parser.parse(eml_path, evidence_id="EV-EML-01")
    print(f"[EmailParser] Parsed {len(email_artifacts)} artifacts from novel .eml")
    for a in email_artifacts:
        print(f"  Artifact ID: {a.artifact_id} | Type: {a.artifact_type} | Sender: {a.normalized_fields.sender} | Recipients: {a.normalized_fields.recipients} | URL: {a.normalized_fields.url}")

    # 2. PowerShell History Parser Test
    ps_content = """Get-Process
Start-Process C:\\Users\\alice.williams\\Downloads\\invoice_update.exe -ArgumentList "-ip 203.0.113.77"
"""
    ps_path = os.path.join(tmp_dir, "ConsoleHost_history.txt")
    with open(ps_path, "w", encoding="utf-8") as f:
        f.write(ps_content)

    ps_parser = PowerShellHistoryParser()
    ps_artifacts = ps_parser.parse(ps_path, evidence_id="EV-PS-01")
    print(f"\n[PowerShellHistoryParser] Parsed {len(ps_artifacts)} artifacts from novel history file")
    for a in ps_artifacts:
        print(f"  Artifact ID: {a.artifact_id} | Type: {a.artifact_type} | Cmd: {a.raw_fields.get('command')}")

    # 3. Artifact Extractor on parsed outputs
    all_arts = email_artifacts + ps_artifacts
    extractor = ArtifactExtractor()
    entities = extractor.extract(all_arts, evidence_id="EV-PARSED-COMBINED")
    print(f"\n[ArtifactExtractor] Extracted {len(entities)} entities from parsed artifacts:")
    for e in entities:
        print(f"  Entity Type: {e.entity_type:15s} | Value: {e.value}")

if __name__ == "__main__":
    test_parsers()
