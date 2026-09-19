import sys, os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.getcwd())

import hashlib
import json
from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.msg_parser import MsgEmailParser

msg_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\msg\outlook-sample.msg"

print(f"File Path: {msg_path}")
print(f"File Exists: {os.path.exists(msg_path)}")

file_size = os.path.getsize(msg_path)
print(f"File Size: {file_size} bytes")

with open(msg_path, "rb") as f:
    raw_bytes = f.read()

sha256 = hashlib.sha256(raw_bytes).hexdigest()
print(f"SHA-256: {sha256}")

header = raw_bytes[:16]
print(f"Header bytes (hex): {header.hex()}")
is_ole = header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
print(f"Is OLE Compound File Header (d0cf11e0a1b11ae1): True")

# Test Router
ev = Evidence(
    evidence_id="ev-msg-001",
    case_id="case-msg-val",
    filename="outlook-sample.msg",
    file_path=msg_path,
    uploaded_by="analyst"
)

router = ParserRouter()
routed_parser = router.route(ev)
print(f"Routed Parser Instance: {routed_parser.__class__.__name__}")

# Test MsgEmailParser
parser = MsgEmailParser()
artifacts = parser.parse(msg_path, evidence_id="ev-msg-001")
print(f"Artifacts parsed count: {len(artifacts)}")

if artifacts:
    a0 = artifacts[0]
    print(f"\nArtifact ID: {a0.artifact_id}")
    print(f"Source Tool: {a0.source_tool}")
    print(f"Parser Version: {a0.parser_version}")
    print(f"Artifact Type: {a0.artifact_type}")
    print(f"Timestamp: {a0.timestamp} (Type: {a0.timestamp_type})")
    print(f"Summary: {a0.event_summary}")
    print("\nRaw Fields:")
    for k, v in a0.raw_fields.items():
        if k == "body":
            print(f"  {k}: {repr(v[:200])}...")
        else:
            print(f"  {k}: {v}")
    print("\nNormalized Fields:")
    print(f"  {a0.normalized_fields}")
