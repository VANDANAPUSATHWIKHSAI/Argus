import sys
import time
from pathlib import Path

ARGUS_ROOT = Path(__file__).resolve().parents[1]
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from preprocessing.parsers.filesystem_parser import FilesystemParser
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine

img_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01"

print("1. Running FilesystemParser on 2020JimmyWilson.E01 with mmls partition discovery...")
t0 = time.time()
parser = FilesystemParser()
artifacts = parser.parse(img_path, evidence_id="EVID-TEST-JIMMY")
t1 = time.time()
print(f"--> Extracted {len(artifacts):,} bodyfile Artifact records in {t1-t0:.2f} seconds.")

if artifacts:
    sample = artifacts[0]
    print(f"--> Sample Artifact: {sample.event_summary}")
    print(f"    Timestamp: {sample.timestamp}")
    print(f"    Raw Fields: {sample.raw_fields}")

print("\n2. Normalizing artifacts...")
normalizer = Normalizer()
norm_arts = normalizer.normalize(artifacts)
print(f"--> Normalized {len(norm_arts):,} artifacts.")

print("\n3. Running ArtifactExtractor...")
extractor = ArtifactExtractor()
t2 = time.time()
extracted_entities = extractor.extract(norm_arts, evidence_id="EVID-TEST-JIMMY")
t3 = time.time()
print(f"--> Extracted {len(extracted_entities):,} atomic entities in {t3-t2:.2f} seconds.")

if extracted_entities:
    print(f"--> Sample Extracted Entity: {extracted_entities[0]}")

print("\n4. Running FCREngine...")
fcr_engine = FCREngine()
t4 = time.time()
fcrs = fcr_engine.correlate(norm_arts, extracted_entities=extracted_entities)
t5 = time.time()
print(f"--> Generated {len(fcrs):,} FCR Correlation Records in {t5-t4:.2f} seconds.")

if fcrs:
    print(f"--> Sample FCR: {fcrs[0]}")
