import sys
import os
import time
import hashlib
from pathlib import Path

sys.path.insert(0, ".")

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine

print("==================================================================")
print("ARGUS PHASE A.2.2 ARTIFACT EXTRACTION TEST")
print("==================================================================")

source_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")
router = ParserRouter()
extractor = ArtifactExtractor()
fcr_engine = FCREngine()

all_parsed_artifacts = []
file_metrics = []

for p in sorted(source_dir.iterdir()):
    if p.is_file():
        src_bytes = p.read_bytes()
        sha256_before = hashlib.sha256(src_bytes).hexdigest()
        
        ev = Evidence(
            case_id="case-phase-a22",
            filename=p.name,
            file_path=str(p),
            raw_file_path=str(p),
            uploaded_by="extractor_tester",
            sha256_hash=sha256_before,
            metadata={"size_bytes": len(src_bytes), "extension": p.suffix.lower()}
        )
        
        res = router.determine_routing(ev)
        
        parsed_count = 0
        extracted_entities_count = 0
        extracted_artifacts = []
        
        if res.status == "ROUTED" and res.parser_instance:
            artifacts = res.parser_instance.parse(str(p), ev.evidence_id)
            parsed_count = len(artifacts)
            all_parsed_artifacts.extend(artifacts)
            
            # Run Artifact Extraction Layer
            t0 = time.perf_counter()
            extracted_entities = extractor.extract_entities(artifacts, ev.evidence_id) if hasattr(extractor, "extract_entities") else []
            t1 = time.perf_counter()
            extracted_entities_count = len(extracted_entities)
            
        sha256_after = hashlib.sha256(p.read_bytes()).hexdigest()
        integrity = "PASS" if sha256_before == sha256_after else "FAIL"
        
        file_metrics.append((p.name, len(src_bytes), res.status, res.target_parser, parsed_count, extracted_entities_count, integrity))

print("{:<16} | {:<10} | {:<8} | {:<18} | {:<8} | {:<10} | {:<5}".format("FILE", "SIZE", "STATUS", "PARSER", "PARSED", "ENTITIES", "HASH"))
print("-" * 88)
for name, sz, st, prs, p_cnt, e_cnt, hsh in file_metrics:
    print("{:<16} | {:<10} | {:<8} | {:<18} | {:<8} | {:<10} | {:<5}".format(name, f"{sz} B", st, prs, p_cnt, e_cnt, hsh))

print("-" * 88)
print(f"Total Normalized Artifacts Extracted : {len(all_parsed_artifacts)}")

# FCR Contract Integration Test
print("\nTesting FCR Engine consumption of extracted artifacts...")
fcr_records = fcr_engine.correlate(all_parsed_artifacts)
print(f"FCR Engine output records count     : {len(fcr_records)}")
print("==================================================================")
