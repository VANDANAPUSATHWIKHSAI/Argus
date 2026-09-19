import sys, os
sys.path.insert(0, os.getcwd())

import json
from datetime import datetime
from pathlib import Path

from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.router import ParserRouter
from normalization.normalize import NormalizationEngine
from fcr.correlation_engine import FCRCorrelationEngine
from uai.uai_engine import UAIEngine
from forensic_analysis.endpoint_analysis.endpoint_engine import EndpointAnalysisEngine
from reports.sanitizer import PromptSanitizer, SanitizedReportContext

evidence_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"
tenant_id = "tenant-test"
case_id = "case-firefox-val"
evidence_id = "ev-firefox-001"

print("--- PHASE 1 & 2: ROUTING & PARSING ---")
router = ParserRouter()
matched_parser = router.route("firefox_profile", evidence_path)
print(f"Routed parser: {matched_parser.__class__.__name__}")

parser = FirefoxParser()
raw_artifacts = parser.parse(evidence_path, evidence_id=evidence_id)
print(f"Raw artifacts extracted: {len(raw_artifacts)}")

print("\n--- PHASE 3 & 4: NORMALIZATION & ATOMIC ENTITIES ---")
norm_engine = NormalizationEngine()
norm_artifacts = norm_engine.normalize_batch(raw_artifacts)
print(f"Normalized artifacts: {len(norm_artifacts)}")

entities = norm_engine.extract_entities_batch(norm_artifacts)
print(f"Atomic entities extracted: {len(entities)}")

# Entity breakdown
entity_types = {}
for e in entities:
    t = e.entity_type
    entity_types[t] = entity_types.get(t, 0) + 1
print(f"Entity types breakdown: {entity_types}")

print("\n--- PHASE 5: FCR CORRELATION ---")
fcr_engine = FCRCorrelationEngine()
fcrs = fcr_engine.correlate(norm_artifacts, entities, case_id=case_id, tenant_id=tenant_id)
print(f"FCR records created: {len(fcrs)}")

# Check FCR relationship types
fcr_rel_types = {}
for f in fcrs:
    t = f.relationship_type
    fcr_rel_types[t] = fcr_rel_types.get(t, 0) + 1
print(f"FCR relationship types: {fcr_rel_types}")

print("\n--- PHASE 6: UAI GENERATION ---")
uai_engine = UAIEngine()
uais = uai_engine.generate_uais(fcrs, case_id=case_id, tenant_id=tenant_id)
print(f"UAIs generated: {len(uais)}")

print("\n--- PHASE 7 & 8: FIR / FORENSIC ANALYSIS ---")
analysis_engine = EndpointAnalysisEngine()
art_map = {art.id: art for art in norm_artifacts}

raw_findings, fir_findings = analysis_engine.analyze(
    fcrs=fcrs,
    artifacts=art_map,
    case_id=case_id,
    tenant_id=tenant_id
)
print(f"Raw findings produced: {len(raw_findings)}")
print(f"FIR findings produced: {len(fir_findings)}")

for idx, f in enumerate(fir_findings):
    print(f"\nFinding {idx+1}:")
    print(f"  Title: {f.title}")
    print(f"  Category: {f.category}")
    print(f"  Severity: {f.severity}")
    print(f"  Confidence: {f.confidence}")
    print(f"  MITRE Mapping: {f.mitre_mapping}")
    print(f"  Source Artifact IDs count: {len(f.source_artifact_ids)}")
    print(f"  Description: {f.description[:120]}...")

print("\n--- PHASE 10: SANITIZATION & PROMPT INJECTION ---")
sanitizer = PromptSanitizer()
sanitizer_ctx = sanitizer.sanitize_findings(fir_findings)
print(f"Sanitized findings count: {len(sanitizer_ctx.findings)}")
print(f"Detections count: {len(sanitizer_ctx.detections)}")
