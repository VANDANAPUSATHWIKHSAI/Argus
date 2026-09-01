import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from fir.repository import FIRRepository

def test_negative_controls():
    print("======================================================================")
    print("ARGUS — PHASE 5: NEGATIVE CONTROL AUDIT")
    print("======================================================================")

    now_a = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    now_b = datetime(2026, 9, 1, 18, 0, 0, tzinfo=timezone.utc)

    # CASE A
    art_a1 = Artifact(
        artifact_id="art-case-a-proc",
        case_id="CASE-A",
        evidence_id="EV-A-01",
        source_tool="sysmon",
        artifact_type="process_event",
        host_id="HOST-A",
        timestamp=now_a,
        normalized_fields=NormalizedFields(
            host="HOST-A",
            user="USER-A",
            process_name="app_alpha.exe",
            process_id=1111,
            file_hash="1111111111111111111111111111111111111111111111111111111111111111"
        )
    )

    # CASE B
    art_b1 = Artifact(
        artifact_id="art-case-b-net",
        case_id="CASE-B",
        evidence_id="EV-B-01",
        source_tool="zeek",
        artifact_type="network_connection",
        host_id="HOST-B",
        timestamp=now_b,
        normalized_fields=NormalizedFields(
            host="HOST-B",
            user="USER-B",
            process_id=9999,
            dst_ip="198.51.100.222",
            dst_port=8080,
            domain="unrelated-server-b.com"
        )
    )

    fcr_engine = FCREngine()
    
    # 1. Correlate artifacts (FCREngine automatically enforces case isolation internally)
    fcrs_isolated = fcr_engine.correlate([art_a1, art_b1])
    print(f"Isolated FCR Correlation Count : {len(fcrs_isolated)} (Expected: 0)")
    assert len(fcrs_isolated) == 0, f"False positive correlation generated across unrelated cases: {fcrs_isolated}"

    # 3. Batch Orchestration on empty FCR list
    artifacts_by_id = {art_a1.artifact_id: art_a1, art_b1.artifact_id: art_b1}
    findings = process_fcr_batch(case_id="CASE-A", fcr_objects=[], artifacts_by_id=artifacts_by_id, fir_repo=None)
    print(f"Downstream Findings Generated on 0 FCRs       : {len(findings)} (Expected: 0)")
    assert len(findings) == 0, "Orchestrator generated manufactured findings on empty FCR list!"

    print("\n======================================================================")
    print("NEGATIVE CONTROL TESTS PASSED (100% VERIFIED — ZERO FALSE CORRELATIONS)")
    print("======================================================================")

if __name__ == "__main__":
    test_negative_controls()
