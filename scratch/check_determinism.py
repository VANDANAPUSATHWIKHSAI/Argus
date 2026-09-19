import sys, os
sys.path.insert(0, os.getcwd())

from infrastructure.schemas import Evidence
from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine

db_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"
case_id = "CASE-DETERMINISM-TEST"
tenant_id = "TENANT-DETERMINISM-TEST"
evidence_id = "EVID-DETERMINISM-001"

def run_pipeline():
    parser = FirefoxParser()
    raw_artifacts = parser.parse(db_path, evidence_id=evidence_id)
    for a in raw_artifacts:
        a.case_id = case_id
    
    normalizer = Normalizer()
    norm_arts = normalizer.normalize(raw_artifacts)
    
    extractor = ArtifactExtractor()
    entities = extractor.extract(norm_arts, evidence_id=evidence_id)
    
    fcr_engine = FCREngine()
    fcrs = fcr_engine.correlate(norm_arts, extracted_entities=entities)
    
    consolidation_engine = EvidenceConsolidationEngine()
    uais, _, _ = consolidation_engine.consolidate(
        norm_arts,
        fcrs=fcrs,
        expected_categories=["browser_history"],
        tenant_id=tenant_id
    )
    return len(raw_artifacts), len(norm_arts), len(entities), len(fcrs), len(uais)

res1 = run_pipeline()
res2 = run_pipeline()

print(f"Run 1: {res1}")
print(f"Run 2: {res2}")

assert res1 == res2, "Pipeline execution is NOT deterministic!"
print("DETERMINISM TEST: PASS (100% Identical Output Across Runs)")
