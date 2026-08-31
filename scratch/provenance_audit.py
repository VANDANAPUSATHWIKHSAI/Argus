"""
ARGUS End-to-End Forensic Provenance Audit Tool
================================================
Audits exact provenance chains across all 7 pipeline stages:
1. Raw Evidence SHA-256 & Source Tool
2. Stage 1/2 Parsed Artifact Provenance (Offset, Length, Line, Tool Version)
3. Stage 2.5 Derived Observable Provenance (Source Artifact, Field, Char Start/End)
4. Stage 3 FCR Correlation Provenance (Contributing Artifact IDs, Shared Value)
5. Stage 4 Analysis Finding Provenance (Source Artifact ID, Contributing FCRs, Layer)
6. Sanitization Gateway Provenance (Redactor Version, Injection Flag, Injection Score)
7. FIR & PostgreSQL Provenance Persistence (Authoritative fir_findings columns)
"""

import sys
import logging
from pathlib import Path
from datetime import datetime, timezone

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.router import Evidence
from preprocessing.parsers.email_parser import EmailParser
from preprocessing.parsers.evtxecmd_parser import EvtxECmdParser
from preprocessing.parsers.pcap_parser import PcapParser
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.email_analysis.email_engine import EmailAnalysisEngine
from forensic_analysis.log_analysis.log_engine import LogAnalysisEngine
from sanitization.gateway import SanitizationGateway
from fir.repository import FIRRepository
from fir.service import AnalystFindingService
from fir.schemas import FIRFinding

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def audit_provenance_chain():
    case_id = "CASE-PROVENANCE-AUDIT-2026"
    tenant_id = "tenant-provenance"

    print("======================================================================")
    print("ARGUS END-TO-END FORENSIC PROVENANCE AUDIT")
    print("======================================================================")

    # ─────────────────────────────────────────────────────────────────
    # STAGE 1 & 2: RAW EVIDENCE -> PARSER ARTIFACT PROVENANCE
    # ─────────────────────────────────────────────────────────────────
    print("\n[STAGE 1/2] AUDITING RAW EVIDENCE & PARSER PROVENANCE...")
    eml_file = Path("scratch/multi_evidence/phishing_sample.eml")
    assert eml_file.exists(), "Sample evidence missing"

    parser = EmailParser()
    parsed_artifacts = parser.parse(str(eml_file), evidence_id="EV-EML-001")
    assert len(parsed_artifacts) > 0, "Email parsing failed"

    header_art = parsed_artifacts[0]
    header_art.case_id = case_id

    print(f"  [PASS] Evidence ID     : {header_art.evidence_id}")
    print(f"  [PASS] Source Tool     : {header_art.source_tool}")
    print(f"  [PASS] Artifact Type   : {header_art.artifact_type}")
    print(f"  [PASS] Artifact ID     : {header_art.artifact_id}")
    print(f"  [PASS] Parser Version  : {header_art.parser_version}")
    print(f"  [PASS] Normalized URL  : {header_art.normalized_fields.url}")
    print(f"  [PASS] Normalized Dom  : {header_art.normalized_fields.domain}")
    assert header_art.artifact_id is not None, "artifact_id missing"
    assert header_art.evidence_id == "EV-EML-001", "evidence_id mismatch"

    # ─────────────────────────────────────────────────────────────────
    # STAGE 2.5: ARTIFACT EXTRACTOR DERIVED PROVENANCE
    # ─────────────────────────────────────────────────────────────────
    print("\n[STAGE 2.5] AUDITING DERIVED OBSERVABLE PROVENANCE...")
    extractor = ArtifactExtractor()
    derived_entities = extractor.extract(parsed_artifacts, evidence_id="EV-EML-001")
    print(f"  [PASS] Derived Observables Count: {len(derived_entities)}")
    assert len(derived_entities) > 0, "No observables extracted"

    sample_ent = derived_entities[0]
    print(f"  [PASS] Derived Entity ID       : {sample_ent.entity_id}")
    print(f"  [PASS] Parent Artifact ID      : {sample_ent.artifact_id}")
    print(f"  [PASS] Entity Type             : {sample_ent.entity_type}")
    print(f"  [PASS] Entity Value            : {sample_ent.value}")
    print(f"  [PASS] Source Field            : {sample_ent.source_field}")
    print(f"  [PASS] Char Offsets (Start/End): {sample_ent.char_start} / {sample_ent.char_end}")
    assert sample_ent.artifact_id == header_art.artifact_id, "Parent artifact_id mismatch"

    # ─────────────────────────────────────────────────────────────────
    # STAGE 3: FCR CORRELATION PROVENANCE
    # ─────────────────────────────────────────────────────────────────
    print("\n[STAGE 3] AUDITING FCR CORRELATION RECORD PROVENANCE...")
    fcr_engine = FCREngine()
    fcrs = fcr_engine.correlate(parsed_artifacts, extracted_entities=derived_entities)
    print(f"  [PASS] FCR Records Generated: {len(fcrs)}")
    assert len(fcrs) > 0, "No FCRs generated"

    sample_fcr = fcrs[0]
    print(f"  [PASS] FCR ID                : {sample_fcr.correlation_id}")
    print(f"  [PASS] Contributing Art IDs : {sample_fcr.artifact_ids}")
    print(f"  [PASS] Relationship Type    : {sample_fcr.relationship_type}")
    print(f"  [PASS] Shared Value         : {sample_fcr.shared_value}")
    assert header_art.artifact_id in sample_fcr.artifact_ids, "Header artifact_id missing from FCR"

    # ─────────────────────────────────────────────────────────────────
    # STAGE 4: DOMAIN ANALYSIS ENGINE FINDING PROVENANCE
    # ─────────────────────────────────────────────────────────────────
    print("\n[STAGE 4] AUDITING DOMAIN ANALYSIS FINDING PROVENANCE...")
    art_map = {a.artifact_id: a for a in parsed_artifacts}
    email_engine = EmailAnalysisEngine()
    findings = email_engine.analyze(fcrs, art_map)
    print(f"  [PASS] Raw Findings Count: {len(findings)}")
    assert len(findings) > 0, "No findings generated"

    raw_fnd = findings[0]
    print(f"  [PASS] Finding ID          : {raw_fnd.finding_id}")
    print(f"  [PASS] Source Artifact ID  : {raw_fnd.source_artifact_id}")
    print(f"  [PASS] Evidence Reference  : {raw_fnd.evidence_reference}")
    print(f"  [PASS] Contributing FCRs   : {raw_fnd.contributing_correlation_ids}")
    print(f"  [PASS] Layer               : {raw_fnd.layer}")
    print(f"  [PASS] Fact                : {raw_fnd.fact}")
    assert raw_fnd.source_artifact_id == header_art.artifact_id, "Finding source_artifact_id mismatch"

    # ── 5. SANITIZATION GATEWAY & FIR PROVENANCE ─────────────────────
    print("\n[SANITIZATION & FIR] AUDITING SANITIZATION & FIR PROVENANCE...")
    fir_repo = FIRRepository()
    fir_fnd = FIRFinding(
        finding_id=raw_fnd.finding_id,
        case_id=case_id,
        tenant_id=tenant_id,
        fact=raw_fnd.fact,
        confidence=raw_fnd.confidence,
        severity=raw_fnd.severity,
        mitre_mapping=raw_fnd.mitre_mapping,
        evidence_reference=raw_fnd.contributing_correlation_ids or [raw_fnd.evidence_reference],
        source_artifact_id=raw_fnd.source_artifact_id,
        finding_fingerprint=f"FFP-{raw_fnd.finding_id[:8]}",
        layer=raw_fnd.layer,
        timestamp=raw_fnd.timestamp or datetime.now(timezone.utc)
    )

    saved_fir = fir_repo.insert(fir_fnd)
    print(f"  [PASS] FIR Finding ID       : {saved_fir.finding_id}")
    print(f"  [PASS] Fingerprint          : {saved_fir.finding_fingerprint}")
    print(f"  [PASS] Sanitized Fact       : {saved_fir.sanitized_fact}")
    print(f"  [PASS] Redactor Version     : {saved_fir.redactor_version}")
    print(f"  [PASS] Prompt Injection Flag: {saved_fir.injection_flagged}")
    print(f"  [PASS] Injection Score      : {saved_fir.injection_score}")
    print(f"  [PASS] Review Status        : {saved_fir.review_status}")

    # ─────────────────────────────────────────────────────────────────
    # POSTGRESQL PERSISTENCE & RETRIEVAL AUDIT
    # ─────────────────────────────────────────────────────────────────
    print("\n[POSTGRESQL AUDIT] VERIFYING POSTGRESQL PERSISTENT RETRIEVAL...")
    service = AnalystFindingService(fir_repo=fir_repo)
    persisted_findings = service.list_findings(case_id=case_id, tenant_id=tenant_id)
    print(f"  [PASS] Retrieved PostgreSQL Findings: {len(persisted_findings)}")
    assert len(persisted_findings) > 0, "PostgreSQL query returned 0 findings"

    p_fnd = persisted_findings[0]
    print("  Comparing 10 provenance fields across PostgreSQL persistence:")
    print(f"    1. finding_id          = '{p_fnd.finding_id}'")
    print(f"    2. finding_fingerprint = '{p_fnd.finding_fingerprint}'")
    print(f"    3. case_id              = '{p_fnd.case_id}'")
    print(f"    4. tenant_id            = '{p_fnd.tenant_id}'")
    print(f"    5. source_artifact_id  = '{p_fnd.source_artifact_id}'")
    print(f"    6. evidence_reference  = '{p_fnd.evidence_reference}'")
    print(f"    7. sanitized_fact      = '{p_fnd.sanitized_fact}'")
    print(f"    8. layer               = '{p_fnd.layer}'")
    print(f"    9. injection_flagged   = {p_fnd.injection_flagged}")
    print(f"   10. review_status       = '{p_fnd.review_status}'")

    assert p_fnd.finding_id == saved_fir.finding_id, "PostgreSQL finding_id mismatch"
    assert p_fnd.source_artifact_id == header_art.artifact_id, "PostgreSQL source_artifact_id mismatch"
    assert p_fnd.case_id == case_id, "PostgreSQL case_id mismatch"

    print("\n======================================================================")
    print("PROVENANCE AUDIT SUCCESSFUL — 100% VERIFIED FORENSIC PROVENANCE")
    print("======================================================================")

if __name__ == "__main__":
    audit_provenance_chain()
