"""
ARGUS Registry Evidence Execution & Pipeline Audit (Phase 1 through Phase 9)
=============================================================================
Executes full forensic intake, parsing, entity extraction, correlation,
domain analysis, FIR reporting, and sanitization on registry evidence files in:
C:\\Users\\Sudeep\\Downloads\\Argus\\raw evidence\\phase a\\registry
(NTUSER.DAT, SOFTWARE, SYSTEM)
"""

import sys
import os
import time
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ARGUS_ROOT = Path(__file__).parent.parent
if str(ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(ARGUS_ROOT))

from infrastructure.schemas import Evidence, EvidenceStatus, CustodyLogEntry
from infrastructure.repository.evidence_store import create_case_session
from preprocessing.router import ParserRouter
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from fir.schemas import FIRFinding, ReviewStatus
from sanitization.gateway import SanitizationGateway


def execute_registry_pipeline():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

    reg_dir = r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\registry"
    hive_files = [f for f in os.listdir(reg_dir) if os.path.isfile(os.path.join(reg_dir, f))]

    print("=" * 80, flush=True)
    print("  ARGUS FORENSIC PIPELINE — REGISTRY EVIDENCE E2E AUDIT", flush=True)
    print(f"  Target Directory: {reg_dir}", flush=True)
    print(f"  Target Hives    : {', '.join(hive_files)}", flush=True)
    print("=" * 80, flush=True)

    start_time = time.time()
    tenant_id = "tenant-registry-alpha"
    uploaded_by = "registry_analyst"

    # PHASE 1: Intake & Custody Seal
    print("\n--- PHASE 1: Intake, SHA-256 Seal & Custody ---", flush=True)
    case_session = create_case_session(tenant_id=tenant_id, created_by=uploaded_by)
    case_id = case_session.case_id

    evidence_objects = []
    for hf in hive_files:
        hpath = os.path.join(reg_dir, hf)
        hsize = os.path.getsize(hpath)
        
        sha256 = hashlib.sha256()
        with open(hpath, "rb") as f:
            while chunk := f.read(1024 * 1024):
                sha256.update(chunk)
        hhash = sha256.hexdigest()

        ev = Evidence(
            filename=hf,
            file_path=hpath,
            case_id=case_id,
            uploaded_by=uploaded_by,
            status=EvidenceStatus.HASHED,
            sha256_hash=hhash
        )
        ev.custody_log.append(CustodyLogEntry(
            actor="intake_pipeline",
            action="sha256_sealed",
            notes=f"sha256={hhash} size={hsize}bytes"
        ))
        evidence_objects.append(ev)
        print(f" [+] Hive: {hf:<12} | Size: {hsize:>10,} bytes | SHA-256: {hhash[:16]}...", flush=True)

    print(f"Case ID           : {case_id}", flush=True)
    print("Phase 1 Status    : PASS", flush=True)

    # PHASE 2: Router & Parsing
    print("\n--- PHASE 2: Router & Registry Parsing ---", flush=True)
    router = ParserRouter()
    all_raw_artifacts = []
    
    for ev in evidence_objects:
        route_decision = router.determine_routing(ev)
        print(f" [+] {ev.filename:<12} -> Parser: {route_decision.target_parser} (Status: {route_decision.status})", flush=True)
        if route_decision.status != "ROUTED" or not route_decision.parser_instance:
            print(f" [FAIL] Routing failed for {ev.filename}: {route_decision.reason}", flush=True)
            sys.exit(1)

        t_p2_start = time.time()
        hive_artifacts = route_decision.parser_instance.parse(ev.file_path, evidence_id=ev.evidence_id, case_id=ev.case_id)
        print(f"     -> Extracted {len(hive_artifacts):,} Raw Artifacts in {time.time() - t_p2_start:.2f}s", flush=True)
        all_raw_artifacts.extend(hive_artifacts)

    print(f"Total Raw Artifacts Extracted across all hives: {len(all_raw_artifacts):,}", flush=True)
    print("Phase 2 Status    : PASS", flush=True)

    # PHASE 3: Canonical Normalization
    print("\n--- PHASE 3: Canonical JSON Normalization ---", flush=True)
    normalizer = Normalizer()
    normalized_artifacts = normalizer.normalize(all_raw_artifacts)
    print(f"Normalized Artifacts Count: {len(normalized_artifacts):,}", flush=True)
    if normalized_artifacts:
        sample = normalized_artifacts[0]
        print(f"Sample Artifact: type={sample.artifact_type} | timestamp={sample.timestamp} | path={sample.normalized_fields.file_path}", flush=True)
    print("Phase 3 Status    : PASS", flush=True)

    # PHASE 4: Atomic Entity Extraction
    print("\n--- PHASE 4: Atomic Entity Extraction ---", flush=True)
    extractor = ArtifactExtractor()
    extracted_entities = extractor.extract_artifacts(normalized_artifacts, evidence_id=case_id)
    print(f"Atomic Entities Count: {len(extracted_entities):,}", flush=True)
    print("Phase 4 Status    : PASS", flush=True)

    # PHASE 5: FCR Correlation Engine
    print("\n--- PHASE 5: FCR Correlation Engine ---", flush=True)
    fcr_engine = FCREngine()
    fcr_records = fcr_engine.process_entities(extracted_entities, case_id=case_id)
    print(f"FCR Correlation Records: {len(fcr_records):,}", flush=True)
    print("Phase 5 Status    : PASS", flush=True)

    # PHASE 6: Evidence Consolidation
    print("\n--- PHASE 6: Evidence Consolidation Engine ---", flush=True)
    consolidation_engine = EvidenceConsolidationEngine()
    consolidated_uai_records = consolidation_engine.consolidate_case(case_id=case_id)
    print(f"Consolidated UAIs: {len(consolidated_uai_records):,}", flush=True)
    print("Phase 6 Status    : PASS", flush=True)

    # PHASE 7 & 8: Domain Engine & FIR Reporting
    print("\n--- PHASE 7 & 8: Domain Engines & FIR Reporting ---", flush=True)
    process_fcr_batch(fcr_records)
    fir_repo = FIRRepository()
    all_findings = fir_repo.list_findings_by_case(case_id)
    print(f"Total FIR Findings Produced: {len(all_findings):,}", flush=True)
    print("Phase 7/8 Status  : PASS", flush=True)

    # PHASE 9: Sanitization Gateway
    print("\n--- PHASE 9: AI Sanitization Gateway ---", flush=True)
    gateway = SanitizationGateway()
    sanitized_contexts = []
    t_p9_start = time.time()
    
    # Process batch in chunks if count is large
    chunk_size = 500
    for i in range(0, len(all_findings), chunk_size):
        chunk = all_findings[i:i+chunk_size]
        res = gateway.process_fir_findings_batch(chunk, case_id=case_id)
        sanitized_contexts.extend(res)

    print(f"Sanitized Agent Contexts Generated: {len(sanitized_contexts):,} (in {time.time() - t_p9_start:.2f}s)", flush=True)
    print("Phase 9 Status    : PASS", flush=True)

    total_runtime = time.time() - start_time
    print("\n" + "=" * 80, flush=True)
    print(f"  REGISTRY EVIDENCE PIPELINE COMPLETE IN {total_runtime:.2f} SECONDS", flush=True)
    print("=" * 80, flush=True)

    summary_results = {
        "case_id": case_id,
        "hives_processed": hive_files,
        "total_raw_artifacts": len(all_raw_artifacts),
        "total_normalized_artifacts": len(normalized_artifacts),
        "total_atomic_entities": len(extracted_entities),
        "total_fcr_records": len(fcr_records),
        "total_consolidated_uais": len(consolidated_uai_records),
        "total_fir_findings": len(all_findings),
        "total_sanitized_contexts": len(sanitized_contexts),
        "total_runtime_seconds": round(total_runtime, 2)
    }

    print("\nREGISTRY PIPELINE AUDIT SUMMARY JSON:")
    print(json.dumps(summary_results, indent=2), flush=True)


if __name__ == "__main__":
    execute_registry_pipeline()
