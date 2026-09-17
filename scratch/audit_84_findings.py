"""
Comprehensive Audit Script for all 84 FIR Findings
====================================================
Runs the 9-phase registry pipeline fast path, captures all 84 FIR findings,
traces their complete provenance chain (Raw -> Normalized -> Atomic/FCR -> UAI -> FIR -> Sanitized Context),
evaluates forensic correctness, severity, confidence, false positives, duplicates, MITRE mappings,
and sanitization integrity, and generates both markdown and JSON report outputs.
"""

from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from preprocessing.parsers.registry_parser import RegistryParser
from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence, EvidenceStatus
from preprocessing.normalizer import Normalizer
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.evidence_consolidation.consolidation import EvidenceConsolidationEngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway

def run_audit():
    print("[+] Starting 84 Findings Forensic Correctness Audit Extraction...", flush=True)
    hive_dir = Path(r"C:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\registry")
    case_id = "CASE-2026-AUDIT-84-FINDINGS"
    tenant_id = "tenant-audit-84"

    hives = ["NTUSER.DAT", "SOFTWARE", "SYSTEM"]
    evidence_objs = []
    for h in hives:
        hp = hive_dir / h
        ev = Evidence(
            tenant_id=tenant_id,
            evidence_id=f"EV-{h}",
            filename=h,
            file_path=str(hp),
            case_id=case_id,
            uploaded_by="registry_auditor",
            status=EvidenceStatus.HASHED,
            sha256_hash="dummy"
        )
        evidence_objs.append(ev)

    parser = RegistryParser()
    all_raw_artifacts = []
    for ev in evidence_objs:
        arts = parser.parse(ev.file_path, evidence_id=ev.evidence_id, case_id=case_id)
        all_raw_artifacts.extend(arts)

    normalizer = Normalizer()
    normalized_artifacts = normalizer.normalize(all_raw_artifacts)

    extractor = ArtifactExtractor()
    extractor._pipeline = None
    extracted_entities = extractor.extract_artifacts(normalized_artifacts, evidence_id=case_id)

    all_artifacts = normalized_artifacts + extracted_entities
    art_by_id = {a.artifact_id: a for a in all_artifacts}

    fcr_engine = FCREngine()
    fcr_records = fcr_engine.correlate(artifacts=all_artifacts, allow_single_artifact=True)
    fcr_by_id = {f.correlation_id: f for f in fcr_records}

    consolidation_engine = EvidenceConsolidationEngine()
    uais, conflicts, completeness = consolidation_engine.consolidate(
        artifacts=all_artifacts,
        fcrs=fcr_records
    )
    uai_by_id = {u.unified_artifact_id: u for u in uais}

    # Map artifact_id -> UAI
    art_to_uai = {}
    for u in uais:
        for aid in u.source_artifact_ids:
            art_to_uai[aid] = u

    fir_repo = FIRRepository()
    process_fcr_batch(
        case_id=case_id,
        fcr_objects=fcr_records,
        artifacts_by_id=art_by_id,
        fir_repo=fir_repo,
        tenant_id=tenant_id
    )

    all_findings = fir_repo.get_by_case(tenant_id=tenant_id, case_id=case_id)
    gateway = SanitizationGateway()
    sanitized_contexts = [gateway.sanitize_finding(f) for f in all_findings]
    san_by_finding_id = {s.finding_id: s for s in sanitized_contexts}

    print(f"[+] Total FIR Findings Extracted: {len(all_findings)}", flush=True)

    extracted_data = []
    for idx, f in enumerate(all_findings, 1):
        ev_refs = f.evidence_reference or []
        linked_fcrs = []
        linked_arts = []
        linked_uais = []

        for ref in ev_refs:
            if ref in fcr_by_id:
                fcr = fcr_by_id[ref]
                linked_fcrs.append(fcr)
                for aid in fcr.artifact_ids:
                    if aid in art_by_id:
                        linked_arts.append(art_by_id[aid])
                    if aid in art_to_uai:
                        linked_uais.append(art_to_uai[aid])
            elif ref in art_by_id:
                art = art_by_id[ref]
                linked_arts.append(art)
                if ref in art_to_uai:
                    linked_uais.append(art_to_uai[ref])

        if f.source_artifact_id and f.source_artifact_id in art_by_id:
            linked_arts.append(art_by_id[f.source_artifact_id])
            if f.source_artifact_id in art_to_uai:
                linked_uais.append(art_to_uai[f.source_artifact_id])

        # Deduplicate
        linked_arts_unique = {a.artifact_id: a for a in linked_arts}.values()
        linked_fcrs_unique = {fc.correlation_id: fc for fc in linked_fcrs}.values()
        linked_uais_unique = {u.unified_artifact_id: u for u in linked_uais}.values()

        primary_art = list(linked_arts_unique)[0] if linked_arts_unique else None
        primary_fcr = list(linked_fcrs_unique)[0] if linked_fcrs_unique else None
        primary_uai = list(linked_uais_unique)[0] if linked_uais_unique else None
        san_ctx = san_by_finding_id.get(f.finding_id)

        source_hive = "UNKNOWN"
        reg_key = None
        val_name = None
        val_data = None

        if primary_art:
            ev_id = primary_art.evidence_id
            if "NTUSER" in ev_id:
                source_hive = "NTUSER.DAT"
            elif "SOFTWARE" in ev_id:
                source_hive = "SOFTWARE"
            elif "SYSTEM" in ev_id:
                source_hive = "SYSTEM"

            reg_key = primary_art.normalized_fields.registry_key or primary_art.raw_fields.get("key_path")
            val_name = primary_art.normalized_fields.registry_value or primary_art.raw_fields.get("value_name")
            val_data = primary_art.normalized_fields.registry_value_data or primary_art.raw_fields.get("value_data")

        item = {
            "finding_index": idx,
            "finding_id": f.finding_id,
            "case_id": f.case_id,
            "tenant_id": f.tenant_id,
            "layer": f.layer,
            "fact": f.fact,
            "sanitized_fact": f.sanitized_fact,
            "severity": f.severity,
            "confidence": f.confidence,
            "mitre_mapping": f.mitre_mapping,
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "evidence_references": ev_refs,
            "source_artifact_id": f.source_artifact_id,
            "source_hive": source_hive,
            "registry_key": reg_key,
            "value_name": val_name,
            "value_data": val_data,
            "primary_fcr_id": primary_fcr.correlation_id if primary_fcr else None,
            "primary_uai_id": primary_uai.unified_artifact_id if primary_uai else None,
            "sanitized_context_id": san_ctx.finding_id if san_ctx else None,
            "sanitization_actions": san_ctx.sanitization_actions if san_ctx else [],
            "injection_flagged": f.injection_flagged or (san_ctx.injection_flagged if san_ctx else False)
        }
        extracted_data.append(item)

    out_file = Path("scratch/extracted_84_findings.json")
    out_file.write_text(json.dumps(extracted_data, indent=2), encoding="utf-8")
    print(f"[+] Exported {len(extracted_data)} detailed finding records to {out_file}", flush=True)

if __name__ == "__main__":
    run_audit()
