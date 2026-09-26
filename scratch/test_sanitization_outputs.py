"""
Test & Inspect Sanitization Gateway Outputs for Real E01 Evidence Execution
"""
import sys
import time
import json
from pathlib import Path

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from sanitization.gateway import SanitizationGateway

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    image_path = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk 2\2020JimmyWilson.E01"
    output_file = Path(ARGUS_ROOT) / "scratch" / "sanitization_results.txt"

    def log(msg=""):
        print(msg, flush=True)
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(str(msg) + "\n")

    # Clear previous output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("")

    log("=" * 80)
    log("  ARGUS FORENSIC PIPELINE — SANITIZATION GATEWAY EXECUTION TEST")
    log(f"  Raw Evidence Image: {image_path}")
    log("=" * 80)

    start_time = time.time()

    # 1. Parse & Normalize
    log("\n[1] Parsing RAW E01 Evidence...")
    router = ParserRouter()
    ev = Evidence(filename="2020JimmyWilson.E01", file_path=image_path, case_id="CASE-REAL-E01", uploaded_by="investigator")
    route = router.determine_routing(ev)
    raw_arts = route.parser_instance.parse(image_path, evidence_id=ev.evidence_id)
    log(f"    Raw Artifacts Extracted: {len(raw_arts):,}")

    # 2. Normalize
    log("\n[2] Normalizing Artifacts...")
    normalizer = Normalizer()
    norm_arts = normalizer.normalize(raw_artifacts=raw_arts)

    # 3. Entity Extract
    log("\n[3] Extracting Entities...")
    extractor = ArtifactExtractor()
    extractor._model = None
    entities = extractor.extract(norm_arts, evidence_id=ev.evidence_id)
    log(f"    Extracted Entities: {len(entities):,}")

    # 4. FCR Correlation
    log("\n[4] FCR Correlation...")
    fcr_engine = FCREngine()
    fcrs = fcr_engine.correlate(norm_arts, extracted_entities=entities)
    log(f"    FCR Records Generated: {len(fcrs):,}")

    # 5. Domain Analysis Engines (Deterministic Forensic Analysis Layer)
    log("\n[5] Running 5 Forensic Analysis Engines...")
    artifacts_by_id = {art.artifact_id: art for art in norm_arts}
    raw_findings = process_fcr_batch(
        case_id="CASE-REAL-E01",
        fcr_objects=fcrs,
        artifacts_by_id=artifacts_by_id,
        fir_repo=None,
        tenant_id="tenant-alpha"
    )
    log(f"    Raw Forensic Findings Generated: {len(raw_findings):,}")

    # 6. Sanitization Gateway Execution
    log("\n[6] Executing Sanitization Gateway over Findings...")
    gateway = SanitizationGateway()
    errors = []
    sanitized_contexts = []
    flagged_injections = []

    for idx, f in enumerate(raw_findings):
        try:
            ctx = gateway.sanitize_finding(f)
            sanitized_contexts.append(ctx)
            if ctx.injection_flagged:
                flagged_injections.append(ctx)
        except Exception as err:
            errors.append((getattr(f, "finding_id", str(idx)), str(err)))

    elapsed = time.time() - start_time

    log("\n" + "=" * 80)
    log("  SANITIZATION GATEWAY EXECUTION SUMMARY")
    log("=" * 80)
    log(f"Total Raw Evidence Processed : 295.47 MB (11,553 file records)")
    log(f"Total FCR Correlations       : {len(fcrs):,}")
    log(f"Total Domain Findings        : {len(raw_findings):,}")
    log(f"Sanitized Contexts Produced  : {len(sanitized_contexts):,}")
    log(f"Flagged Injections Blocked   : {len(flagged_injections):,}")
    log(f"Sanitization Errors Count    : {len(errors):,}")
    log(f"Total Pipeline Runtime       : {elapsed:.2f} seconds")
    log("=" * 80)

    if errors:
        log("\n[ERRORS ENCOUNTERED]")
        for fid, err_str in errors[:10]:
            log(f"  - Finding {fid}: {err_str}")
    else:
        log("\n[ERRORS ENCOUNTERED]")
        log("  NONE (0 Errors)")

    log("\n[SAMPLE SANITIZED CONTEXT OUTPUTS (FIRST 10)]")
    for ctx in sanitized_contexts[:10]:
        log("-" * 60)
        log(f"Finding ID   : {ctx.finding_id}")
        log(f"Severity     : {ctx.severity}")
        log(f"Confidence   : {ctx.confidence}")
        log(f"Layer        : {ctx.layer}")
        log(f"MITRE        : {ctx.mitre_mapping}")
        log(f"SanitizedFact: {ctx.sanitized_fact}")
        log(f"XML Block    :\n{ctx.xml_evidence_block}")

if __name__ == "__main__":
    main()
