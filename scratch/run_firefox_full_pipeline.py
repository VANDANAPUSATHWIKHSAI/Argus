import sys, os
sys.path.insert(0, os.getcwd())

import json
from datetime import datetime, timezone
import time

from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.router import ParserRouter
from normalization.normalize_artifacts import NormalizationEngine
from fcr.fcr_engine import FCRCorrelationEngine
from uai.uai_engine import UAIEngine
from forensic_analysis.endpoint_analysis.endpoint_engine import EndpointAnalysisEngine
from forensic_analysis.endpoint_analysis.browser_analyzer import BrowserAnalyzer
from sanitization.sanitizer import PromptSanitizer

db_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\firefox profile\Sample_History_DB"
evidence_id = "ev-firefox-001"
case_id = "case-firefox-val"
tenant_id = "tenant-test"

t0 = time.time()
# 1. Routing & Extraction
router = ParserRouter()
res = router.route("firefox_profile", db_path)
print(f"Router match: {res.parser_class_name}")

parser = FirefoxParser()
raw_artifacts = parser.parse(db_path, evidence_id=evidence_id)
t_ext = time.time() - t0
print(f"Extraction: {len(raw_artifacts)} raw artifacts in {t_ext:.4f}s")

# 2. Normalization & Entities
t1 = time.time()
norm_engine = NormalizationEngine()
norm_artifacts = norm_engine.normalize_batch(raw_artifacts)
entities = norm_engine.extract_entities_batch(norm_artifacts)
t_norm = time.time() - t1
print(f"Normalization & Entity Extraction: {len(norm_artifacts)} norm artifacts, {len(entities)} entities in {t_norm:.4f}s")

# Unique entities
unique_entities = set()
for e in entities:
    unique_entities.add((e.entity_type, e.entity_value))
print(f"Unique entities: {len(unique_entities)}")

# 3. FCR Correlation
t2 = time.time()
fcr_engine = FCRCorrelationEngine()
fcrs = fcr_engine.correlate(norm_artifacts, entities, case_id=case_id, tenant_id=tenant_id)
t_fcr = time.time() - t2
print(f"FCR Correlation: {len(fcrs)} FCRs in {t_fcr:.4f}s")

# 4. UAI Engine
t3 = time.time()
uai_engine = UAIEngine()
uais = uai_engine.generate_uais(fcrs, case_id=case_id, tenant_id=tenant_id)
t_uai = time.time() - t3
print(f"UAI Generation: {len(uais)} UAIs in {t_uai:.4f}s")

# 5. Endpoint Forensic Engine / BrowserAnalyzer
t4 = time.time()
browser_analyzer = BrowserAnalyzer()
raw_findings = browser_analyzer.analyze(norm_artifacts, case_id=case_id)

endpoint_engine = EndpointAnalysisEngine()
art_map = {art.id: art for art in norm_artifacts}

raw_f_engine, fir_findings = endpoint_engine.analyze(
    fcrs=fcrs,
    artifacts=art_map,
    case_id=case_id,
    tenant_id=tenant_id
)
t_fir = time.time() - t4
print(f"BrowserAnalyzer raw findings: {len(raw_findings)}")
print(f"EndpointEngine raw findings: {len(raw_f_engine)}")
print(f"FIR findings: {len(fir_findings)} in {t_fir:.4f}s")

# 6. Sanitization
t5 = time.time()
sanitizer = PromptSanitizer()
san_ctx = sanitizer.sanitize_findings(fir_findings)
t_san = time.time() - t5
print(f"Sanitization: {len(san_ctx.findings)} findings sanitized, {len(san_ctx.detections)} detections in {t_san:.4f}s")

print(f"TOTAL TIME: {time.time() - t0:.4f}s")

# Check URLs in artifacts
urls_sample = [art.normalized_fields.url for art in norm_artifacts if art.normalized_fields and art.normalized_fields.url]
print(f"\nTotal URLs in artifacts: {len(urls_sample)}")
suspicious_urls = [u for u in urls_sample if any(tld in u.lower() for tld in ('.xyz', '.top', '.tk', '.zip', '.cc', '.biz', '.work', 'duckdns.org', 'ngrok.io'))]
print(f"Suspicious TLD / DynDNS URLs found: {len(suspicious_urls)}")
if suspicious_urls:
    print("Sample suspicious URLs:", suspicious_urls[:5])

# Print sample non-suspicious URLs
print("Sample normal URLs:", urls_sample[:5])
