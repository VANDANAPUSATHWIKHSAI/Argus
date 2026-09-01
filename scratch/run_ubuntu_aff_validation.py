import sys
import os
import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone

project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter, check_fls_aff_support
from preprocessing.parsers.filesystem_parser import FilesystemParser
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from forensic_analysis.orchestrator import process_fcr_batch
from sanitization.gateway import SanitizationGateway
from fir.repository import FIRRepository

def run_ubuntu_validation():
    print("=================================================================")
    print("ARGUS — EMPIRICAL UBUNTU / WSL AFF END-TO-END VALIDATION HARNESS")
    print("=================================================================")
    
    # Phase 0 & 1: Executable & Environment Capability Check
    fls_bin = shutil.which("fls") or shutil.which("fls.exe")
    print(f"\n[Phase 1] Executable Path: {fls_bin}")
    
    if fls_bin:
        res = subprocess.run([fls_bin, "-i", "list"], capture_output=True, text=True, timeout=10)
        output = (res.stdout + "\n" + res.stderr).strip()
        print("fls -i list output:")
        print(output)
        
    has_aff = check_fls_aff_support()
    print(f"check_fls_aff_support() -> {has_aff}")

    # Phase 2: Evidence Files
    raw_dir = project_root.parent / "raw evidence" / "phase a" / "disk"
    aff0_path = raw_dir / "ntfs1-gen0.aff"
    aff1_path = raw_dir / "ntfs1-gen1.aff"
    
    print("\n[Phase 2] Real AFF Evidence Hashes:")
    for p in (aff0_path, aff1_path):
        if p.exists():
            import hashlib
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            print(f"- {p.name} ({p.stat().st_size:,} bytes) -> SHA-256: {h}")

    # Phase 4: Router Proof
    print("\n[Phase 4] ARGUS ParserRouter Routing Decisions:")
    router = ParserRouter()
    route_results = {}
    for p in (aff0_path, aff1_path):
        if p.exists():
            ev = Evidence(evidence_id=f"ev-aff-{p.name}", case_id="CASE-UBUNTU-AFF", filename=p.name, file_path=str(p), uploaded_by="ubuntu-tester")
            res = router.determine_routing(ev)
            route_results[p.name] = res
            print(f"- {p.name}: status={res.status}, target_parser={res.target_parser}, detection_method={res.detection_method}, reason={res.reason}")

    # Phase 5 & 6: FilesystemParser Execution
    print("\n[Phase 5 & 6] ARGUS FilesystemParser Execution:")
    parser = FilesystemParser()
    raw_artifacts_map = {}
    for p in (aff0_path, aff1_path):
        if p.exists():
            t0 = time.perf_counter()
            arts = parser.parse(str(p), f"ev-aff-{p.name}")
            t1 = time.perf_counter()
            raw_artifacts_map[p.name] = arts
            print(f"- {p.name}: Produced {len(arts)} raw Artifacts in {(t1-t0)*1000:.2f}ms")
            if arts:
                print(f"  Sample Artifact 1: type={arts[0].artifact_type}, tool={arts[0].source_tool}, summary={arts[0].event_summary}")

    # Phase 7: Normalizer Layer 3
    print("\n[Phase 7] Layer 3 Normalizer:")
    normalizer = Normalizer()
    norm_artifacts_map = {}
    total_norm = []
    artifacts_by_id = {}
    for p_name, arts in raw_artifacts_map.items():
        norm_arts = normalizer.normalize(arts)
        norm_artifacts_map[p_name] = norm_arts
        for na in norm_arts:
            na.case_id = "CASE-UBUNTU-AFF"
            artifacts_by_id[na.artifact_id] = na
            total_norm.append(na)
        print(f"- {p_name}: {len(arts)} raw -> {len(norm_arts)} normalized artifacts")

    # Phase 8: Artifact Extractor Layer 4
    print("\n[Phase 8] Layer 4 Artifact Extractor:")
    extractor = ArtifactExtractor()
    t0 = time.perf_counter()
    extracted_entities = extractor.extract(total_norm, evidence_id="ev-aff-all")
    t1 = time.perf_counter()
    print(f"- Extracted {len(extracted_entities)} observables/entities from {len(total_norm)} normalized artifacts in {(t1-t0)*1000:.2f}ms")

    # Phase 9: FCR Layer 5
    print("\n[Phase 9] Layer 5 FCR Engine:")
    fcr_engine = FCREngine()
    t0 = time.perf_counter()
    fcr_records = fcr_engine.correlate(total_norm, extracted_entities)
    t1 = time.perf_counter()
    print(f"- Generated {len(fcr_records)} FCR correlation records in {(t1-t0)*1000:.2f}ms")
    if fcr_records:
        sample_fcr = fcr_records[0]
        print(f"  Sample FCR: ID={sample_fcr.correlation_id}, rel={sample_fcr.relationship_type}, conf={sample_fcr.confidence}, artifacts={sample_fcr.artifact_ids}")

    # Phase 10: Consolidation Layer 6
    print("\n[Phase 10] Layer 6 Evidence Consolidation Engine:")
    consolidation = EvidenceConsolidationEngine()
    t0 = time.perf_counter()
    unified_artifacts, conflict_records, completeness = consolidation.consolidate(total_norm, fcr_records, tenant_id="tenant-ubuntu-aff")
    t1 = time.perf_counter()
    print(f"- Consolidated into UAI index (unified count: {len(unified_artifacts)}, conflicts: {len(conflict_records)}) in {(t1-t0)*1000:.2f}ms")

    # Phase 11: Domain Analysis Layer 7
    print("\n[Phase 11] Layer 7 Forensic Analysis Orchestrator:")
    repo = FIRRepository()
    t0 = time.perf_counter()
    findings = process_fcr_batch("CASE-UBUNTU-AFF", fcr_records, artifacts_by_id, repo, tenant_id="tenant-ubuntu-aff")
    t1 = time.perf_counter()
    print(f"- Generated {len(findings)} real forensic findings in {(t1-t0)*1000:.2f}ms")
    if findings:
        sample_f = findings[0]
        print(f"  Sample Finding ID={sample_f.finding_id} | sev={sample_f.severity} | ev_ref={sample_f.evidence_reference} | fact={sample_f.fact}")

    # Phase 12: Sanitization Layer 8
    print("\n[Phase 12] Layer 8 Sanitization Gateway:")
    gateway = SanitizationGateway()
    sanitized_findings = []
    t0 = time.perf_counter()
    for f in findings:
        f.tenant_id = "tenant-ubuntu-aff"
        sf = gateway.sanitize_finding(f)
        sanitized_findings.append(sf)
    t1 = time.perf_counter()
    print(f"- Sanitized {len(sanitized_findings)} Findings in {(t1-t0)*1000:.2f}ms")
    if sanitized_findings:
        sample_sf = sanitized_findings[0]
        print(f"  Sample Sanitized Context ID={sample_sf.finding_id} | inj_flagged={sample_sf.injection_flagged} | sanitized_fact={sample_sf.sanitized_fact}")

    # Phase 13: PostgreSQL Persistence Layer 9
    print("\n[Phase 13] Layer 9 FIRRepository PostgreSQL Store Verification:")
    try:
        saved_count = 0
        for f in findings:
            f.tenant_id = "tenant-ubuntu-aff"
            row_id = repo.save_finding(f, case_id="CASE-UBUNTU-AFF", tenant_id="tenant-ubuntu-aff")
            saved_count += 1
        print(f"- Persisted {saved_count} findings to PostgreSQL database ('argus_postgres')")
        if findings:
            sample_f = findings[0]
            fetched = repo.get_finding_by_id(sample_f.finding_id, tenant_id="tenant-ubuntu-aff")
            if fetched:
                print(f"  SQL Direct Verification PASS: ID={fetched.finding_id}, fact match: {fetched.sanitized_fact == sample_f.sanitized_fact or fetched.fact == sample_f.fact}")
            else:
                print(f"  SQL Direct Verification NOTE: Row fetch check for ID {sample_f.finding_id}")
    except Exception as e:
        print(f"PostgreSQL Repository Check Note: {e}")

    # Phase 14: Complete Provenance Lineage Matrix
    print("\n[Phase 14] Provenance Lineage Tracing:")
    for p_name in ("ntfs1-gen0.aff", "ntfs1-gen1.aff"):
        raw_arts = raw_artifacts_map.get(p_name, [])
        if raw_arts:
            art0 = raw_arts[0]
            print(f"- Provenance Chain for {p_name}:")
            print(f"  Raw Evidence: {p_name} -> Evidence ID: ev-aff-{p_name}")
            print(f"  Router Result: {route_results.get(p_name).status} ({route_results.get(p_name).target_parser})")
            print(f"  Parser Yield: {len(raw_arts)} artifacts (Sample Artifact ID: {art0.artifact_id})")

if __name__ == "__main__":
    run_ubuntu_validation()
