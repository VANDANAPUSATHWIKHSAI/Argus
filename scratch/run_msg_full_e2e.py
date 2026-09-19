import sys, os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.getcwd())

import json
import time
from datetime import datetime, timezone
import hashlib

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.msg_parser import MsgEmailParser
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from forensic_analysis.endpoint_analysis.endpoint_engine import EndpointAnalysisEngine
from sanitization.gateway import SanitizationGateway

msg_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\msg\outlook-sample.msg"
case_id = "CASE-MSG-AUDIT-001"
tenant_id = "TENANT-MSG-001"
evidence_id = "EVID-MSG-001"

print("==================================================")
print("1. RAW EVIDENCE INTEGRITY & CHECKSUMS")
print("==================================================")
file_size = os.path.getsize(msg_path)
with open(msg_path, "rb") as f:
    raw_bytes = f.read()
sha256 = hashlib.sha256(raw_bytes).hexdigest()

header = raw_bytes[:16]
is_ole = header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")

print(f"Path: {msg_path}")
print(f"File Size: {file_size} bytes")
print(f"SHA-256: {sha256}")
print(f"Header bytes (hex): {header.hex()}")
print(f"OLE Compound File Signature Verified: {is_ole}")

print("\n==================================================")
print("2. ROUTING & STAGE 1 PARSER EXTRACTION")
print("==================================================")
t0 = time.time()
ev = Evidence(
    evidence_id=evidence_id,
    case_id=case_id,
    filename="outlook-sample.msg",
    file_path=msg_path,
    uploaded_by="analyst"
)
router = ParserRouter()
routed_parser = router.route(ev)
print(f"Routed Parser Instance: {routed_parser.__class__.__name__}")

parser = MsgEmailParser()
raw_artifacts = parser.parse(msg_path, evidence_id=evidence_id)
t_ext = time.time() - t0
print(f"Extracted Raw Artifacts: {len(raw_artifacts)} in {t_ext:.4f}s")

for art in raw_artifacts:
    art.case_id = case_id

a0 = raw_artifacts[0]
print(f"Artifact Type: {a0.artifact_type}")
print(f"Source Tool: {a0.source_tool}")
print(f"Timestamp: {a0.timestamp} (Type: {a0.timestamp_type})")
print(f"Sender: {a0.raw_fields.get('sender')}")
print(f"Recipients: {a0.raw_fields.get('recipients')}")
print(f"Subject: {a0.raw_fields.get('subject')}")
print(f"Message-ID: {a0.raw_fields.get('message_id')}")

print("\n==================================================")
print("3. STAGE 2 NORMALIZATION & ATOMIC ENTITY EXTRACTION")
print("==================================================")
t1 = time.time()
normalizer = Normalizer()
norm_arts = normalizer.normalize(raw_artifacts)

extractor = ArtifactExtractor()
extracted_entities = extractor.extract(norm_arts, evidence_id=evidence_id)
t_norm = time.time() - t1

print(f"Normalized Artifacts Count: {len(norm_arts)}")
print(f"Extracted Atomic Entities Count: {len(extracted_entities)}")

entity_counts = {}
unique_entity_vals = set()
for e in extracted_entities:
    entity_counts[e.entity_type] = entity_counts.get(e.entity_type, 0) + 1
    unique_entity_vals.add((e.entity_type, e.value))

print(f"Unique Atomic Entities Count: {len(unique_entity_vals)}")
print("Entity Type Breakdown:")
for k, v in entity_counts.items():
    print(f"  {k}: {v}")

print("\nSample Extracted Entities:")
for e in extracted_entities[:10]:
    print(f"  [{e.entity_type}] '{e.value}' (field: {e.source_field}, conf: {e.confidence})")

print("\n==================================================")
print("4. STAGE 3 FCR CORRELATION ENGINE")
print("==================================================")
t2 = time.time()
fcr_engine = FCREngine()
fcrs = fcr_engine.correlate(norm_arts, extracted_entities=extracted_entities)
t_fcr = time.time() - t2
print(f"FCR Correlation Records Produced: {len(fcrs)} in {t_fcr:.4f}s")

fcr_rel_types = {}
for f in fcrs:
    rel = tuple(f.relationship_type) if isinstance(f.relationship_type, list) else str(f.relationship_type)
    fcr_rel_types[rel] = fcr_rel_types.get(rel, 0) + 1
print("FCR Relationship Types:")
for k, v in fcr_rel_types.items():
    print(f"  {k}: {v}")

print("\n==================================================")
print("5. STAGE 4 EVIDENCE CONSOLIDATION ENGINE (UAI)")
print("==================================================")
t3 = time.time()
consolidation_engine = EvidenceConsolidationEngine()
expected_categories = ["email"]
uais, conflicts, meta = consolidation_engine.consolidate(
    norm_arts,
    fcrs=fcrs,
    expected_categories=expected_categories,
    tenant_id=tenant_id
)
t_uai = time.time() - t3
print(f"Unified Artifact Indicators (UAI) Produced: {len(uais)} in {t_uai:.4f}s")

print("\n==================================================")
print("6. STAGE 5 ENDPOINT / FORENSIC ANALYSIS ENGINE")
print("==================================================")
t4 = time.time()
endpoint_engine = EndpointAnalysisEngine()
art_map = {art.artifact_id: art for art in norm_arts}
engine_findings = endpoint_engine.analyze(fcrs, art_map)
t_fir = time.time() - t4

print(f"EndpointEngine Findings Produced: {len(engine_findings)} in {t_fir:.4f}s")

for idx, f in enumerate(engine_findings):
    print(f"\nFinding {idx+1}:")
    print(f"  Fact: {f.fact}")
    print(f"  Severity: {f.severity}")
    print(f"  Confidence: {f.confidence}")
    print(f"  MITRE Mapping: {f.mitre_mapping}")

print("\n==================================================")
print("7. STAGE 6 SANITIZATION GATEWAY & PROMPT INJECTION AUDIT")
print("==================================================")
t5 = time.time()
gateway = SanitizationGateway()
sanitized_contexts = [gateway.sanitize_finding(f) for f in engine_findings]
t_san = time.time() - t5
print(f"Sanitized Contexts Count: {len(sanitized_contexts)} in {t_san:.4f}s")
inj_detections = [c for c in sanitized_contexts if c.injection_flagged]
print(f"Prompt Injection Detections: {len(inj_detections)}")

total_time = time.time() - t0
print(f"\nTOTAL E2E PIPELINE RUNTIME: {total_time:.4f}s")

# Stage timing breakdown
print("\nStage Timing Summary:")
print(f"  Parser Extraction: {t_ext:.4f}s")
print(f"  Normalization & Entities: {t_norm:.4f}s")
print(f"  FCR Correlation: {t_fcr:.4f}s")
print(f"  UAI Consolidation: {t_uai:.4f}s")
print(f"  Endpoint Forensic Engine: {t_fir:.4f}s")
print(f"  Sanitization Gateway: {t_san:.4f}s")
print(f"  Total: {total_time:.4f}s")
