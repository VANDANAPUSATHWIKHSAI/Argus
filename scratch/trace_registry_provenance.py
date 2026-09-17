"""
Scratch script to verify Registry provenance chain and extract 5 representative UAIs/FIRs.
"""

from __future__ import annotations
import json
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from preprocessing.parsers.registry_parser import RegistryParser
from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence, EvidenceStatus
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
# Imports for trace analysis

def run_trace():
    hive_dir = Path(r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\registry")
    case_id = "CASE-2026-REGISTRY-TRACE"

    hives = ["NTUSER.DAT", "SOFTWARE", "SYSTEM"]
    evidence_objs = []
    for h in hives:
        hp = hive_dir / h
        ev = Evidence(
            tenant_id="tenant-trace",
            evidence_id=f"EV-{h}",
            filename=h,
            file_path=str(hp),
            case_id=case_id,
            uploaded_by="analyst",
            status=EvidenceStatus.HASHED,
            sha256_hash="dummy"
        )
        evidence_objs.append(ev)

    parser = RegistryParser()
    all_raw = []
    for ev in evidence_objs:
        arts = parser.parse(ev.file_path, evidence_id=ev.evidence_id, case_id=case_id)
        all_raw.extend(arts)

    normalizer = Normalizer()
    normalized = normalizer.normalize(all_raw)

    print("SAMPLE PROVENANCE CHECK ACROSS HIVES:")
    for h in hives:
        h_arts = [a for a in normalized if a.evidence_id == f"EV-{h}"]
        print(f"Hive {h:<12}: {len(h_arts):>8,} normalized artifacts | Sample: case_id={h_arts[0].case_id}, evidence_id={h_arts[0].evidence_id}, artifact_id={h_arts[0].artifact_id[:8]}...")

    # Run Phase 4, 5, 6 for trace
    extractor = ArtifactExtractor()
    extractor._pipeline = None
    extracted_entities = extractor.extract_artifacts(normalized, evidence_id=case_id)

    fcr_engine = FCREngine()
    fcrs = fcr_engine.correlate(artifacts=normalized + extracted_entities, allow_single_artifact=True)

    consolidation_engine = EvidenceConsolidationEngine()
    uais, conflicts, completeness = consolidation_engine.consolidate(
        artifacts=normalized + extracted_entities,
        fcrs=fcrs
    )

    print(f"\nTotal Consolidated UAIs: {len(uais):,}")

    # Inspect 5 representative UAIs with non-empty source_artifact_ids and trace provenance
    sample_uais = []
    for uai in uais:
        if len(uai.source_artifact_ids) > 0 and len(uai.source_fcr_ids) > 0:
            sample_uais.append(uai)
            if len(sample_uais) >= 5:
                break

    if len(sample_uais) < 5:
        sample_uais = uais[:5]

    art_map = {a.artifact_id: a for a in (normalized + extracted_entities)}
    fcr_map = {f.correlation_id: f for f in fcrs}

    print("\n--- 5 REPRESENTATIVE UAI PROVENANCE TRACES ---")
    for idx, uai in enumerate(sample_uais, 1):
        print(f"\nUAI #{idx}: {uai.unified_artifact_id}")
        print(f"  ├── case_id               : {uai.case_id}")
        print(f"  ├── canonical_artifact_type: {uai.canonical_artifact_type}")
        print(f"  ├── canonical_value        : {uai.canonical_value[:80]}")
        print(f"  ├── identity_method        : {uai.identity_method}")
        print(f"  ├── source_artifact_count  : {len(uai.source_artifact_ids)}")
        print(f"  ├── source_fcr_count       : {len(uai.source_fcr_ids)}")
        if uai.source_artifact_ids:
            src_art_id = uai.source_artifact_ids[0]
            src_art = art_map.get(src_art_id)
            if src_art:
                print(f"  ├── Raw Artifact Origin    :")
                print(f"  │   ├── evidence_id        : {src_art.evidence_id}")
                print(f"  │   ├── artifact_id        : {src_art.artifact_id}")
                print(f"  │   ├── source_tool        : {src_art.source_tool}")
                print(f"  │   ├── artifact_type      : {src_art.artifact_type}")
                print(f"  │   ├── event_summary      : {src_art.event_summary[:80]}")
        if uai.source_fcr_ids:
            src_fcr_id = uai.source_fcr_ids[0]
            src_fcr = fcr_map.get(src_fcr_id)
            if src_fcr:
                print(f"  └── Correlation FCR        :")
                print(f"      ├── correlation_id    : {src_fcr.correlation_id}")
                print(f"      ├── primary_entity    : {src_fcr.primary_entity}")
                print(f"      ├── entity_type       : {src_fcr.entity_type}")

if __name__ == "__main__":
    run_trace()
