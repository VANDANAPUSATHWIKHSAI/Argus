import sys
import os
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.repository import FCRRepository
from preprocessing.fcr_engine.schemas import CorrelationRecord, compute_confidence
from forensic_analysis.router import route_fcr, ARTIFACT_TYPE_TO_ENGINE

print("==================================================================")
print("ARGUS PHASE A.3 DEEP FCR & TIMELINE AUDIT SCRIPT")
print("==================================================================")

source_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")
router = ParserRouter()
extractor = ArtifactExtractor()
fcr_engine = FCREngine()
fcr_repo = FCRRepository()

print("\n[1] Processing Real Raw Evidence Dataset (nps-2009-ntfs1)...")
t0 = time.perf_counter()

all_parsed_artifacts = []
artifacts_by_id = {}

for p in sorted(source_dir.iterdir()):
    if p.is_file():
        src_bytes = p.read_bytes()
        ev = Evidence(
            case_id="CASE-AUDIT-A3",
            filename=p.name,
            file_path=str(p),
            raw_file_path=str(p),
            uploaded_by="audit_checker",
            sha256_hash=hashlib.sha256(src_bytes).hexdigest(),
            metadata={"size_bytes": len(src_bytes), "extension": p.suffix.lower()}
        )
        res = router.determine_routing(ev)
        if res.status == "ROUTED" and res.parser_instance:
            arts = res.parser_instance.parse(str(p), ev.evidence_id)
            for a in arts:
                a.case_id = "CASE-AUDIT-A3"
                a.host_id = "NTFS1-HOST"
                a.normalized_fields.host = "NTFS1-HOST"
                artifacts_by_id[a.artifact_id] = a
            all_parsed_artifacts.extend(arts)

t1 = time.perf_counter()
print(f"  Parsed Input Artifacts Count : {len(all_parsed_artifacts)} (in {t1-t0:.2f}s)")

# Artifact Extraction
t2 = time.perf_counter()
extracted_artifacts = extractor.extract_artifacts(all_parsed_artifacts, "EV-AUDIT-A3")
for e in extracted_artifacts:
    e.case_id = "CASE-AUDIT-A3"
    e.host_id = "NTFS1-HOST"
    e.normalized_fields.host = "NTFS1-HOST"
    artifacts_by_id[e.artifact_id] = e

t3 = time.perf_counter()
print(f"  Extracted Observables Count  : {len(extracted_artifacts)} (in {t3-t2:.2f}s)")

# FCR Correlation Engine
t4 = time.perf_counter()
combined_artifacts = all_parsed_artifacts + extracted_artifacts
fcr_records = fcr_engine.correlate(combined_artifacts, window_seconds=3600.0)
t5 = time.perf_counter()
print(f"  FCR Correlation Records      : {len(fcr_records)} (in {t5-t4:.2f}s)")

# Store in FCR Repository
added_count = fcr_repo.add_records(fcr_records)
print(f"  FCR Repository Stored Records: {added_count}")

# ─────────────────────────────────────────────────────────────────
# 2. RULE & RELATIONSHIP AUDIT
# ─────────────────────────────────────────────────────────────────
print("\n[2] FCR Relationship Breakdown & Rule Audit...")
rel_counts = {}
for r in fcr_records:
    for rel in r.relationship_type:
        rel_counts[rel] = rel_counts.get(rel, 0) + 1

for rel, count in rel_counts.items():
    print(f"  Relationship Type '{rel:<20}': {count} records")

# Check FCR Routing to Analysis Engines
routed_engines = set()
for r in fcr_records:
    engines = route_fcr(r, artifacts_by_id)
    routed_engines.update(engines)

print(f"\n[3] Downstream Analysis Engine Routing Target Coverage: {sorted(list(routed_engines))}")

print("\n==================================================================")
print("PHASE A.3 AUDIT SCRIPT COMPLETE")
print("==================================================================")
