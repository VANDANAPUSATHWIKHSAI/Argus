import sys
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))

from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from infrastructure.schemas import Evidence
from preprocessing.schemas import Artifact, NormalizedFields

def trace_fcr_artifacts():
    demo_case_id = "CASE-FINAL-DEMO-2026"
    raw_dir = Path(r"c:\Users\Sudeep\Downloads\Argus\raw evidence\phase a\disk")
    raw_files = [
        ("narrative.txt", "text/plain"),
        ("ntfs1-gen0.aff", "application/octet-stream"),
        ("ntfs1-gen0.E01", "application/octet-stream"),
        ("ntfs1-gen1.aff", "application/octet-stream"),
        ("ntfs1-gen1.E01", "application/octet-stream"),
        ("ntfs1-gen2.E01", "application/octet-stream"),
        ("ntfs1-gen2.xml", "text/xml")
    ]

    router = ParserRouter()
    extractor = ArtifactExtractor()
    fcr_engine = FCREngine()

    parsed_artifacts = []
    for fname, _ in raw_files:
        fpath = raw_dir / fname
        ev = Evidence(
            case_id=demo_case_id,
            filename=fname,
            file_path=str(fpath),
            raw_file_path=str(fpath),
            uploaded_by="analyst_final",
            sha256_hash=hashlib.sha256(fpath.read_bytes()).hexdigest()
        )
        res = router.determine_routing(ev)
        if res.status == "ROUTED" and res.parser_instance:
            arts = res.parser_instance.parse(str(fpath), f"EV-{fname}")
            if arts:
                for a in arts:
                    a.case_id = demo_case_id
                    a.host_id = "NPS-HOST"
                    if a.normalized_fields:
                        a.normalized_fields.host = "NPS-HOST"
                parsed_artifacts.extend(arts)

    derived = extractor.extract(parsed_artifacts, evidence_id="EV-NPS")
    all_artifacts = parsed_artifacts + list(derived)
    
    synth_proc = Artifact(
        artifact_id="b5b0efe6-28ff-4378-b920-b2cb397546c5",
        case_id=demo_case_id,
        evidence_id="EV-REAL-NPS",
        source_tool="volatility3",
        artifact_type="process_event",
        host_id="NPS-HOST",
        timestamp=datetime.now(timezone.utc),
        normalized_fields=NormalizedFields(host="NPS-HOST", process_name="powershell.exe", parent_process_name="winword.exe", process_id=1234, parent_process_id=5678)
    )
    synth_net = Artifact(
        case_id=demo_case_id,
        evidence_id="EV-REAL-NPS",
        source_tool="zeek",
        artifact_type="network_connection",
        host_id="NPS-HOST",
        timestamp=datetime.now(timezone.utc),
        normalized_fields=NormalizedFields(host="NPS-HOST", process_id=1234, dst_ip="198.51.100.99", dst_port=443)
    )
    all_artifacts.extend([synth_proc, synth_net])

    print("======================================================================")
    print("TOTAL ARTIFACTS CREATED IN FINAL DEMO PIPELINE:", len(all_artifacts))
    distinct_art_ids = set(a.artifact_id for a in all_artifacts)
    print("Distinct Artifact IDs across all 830 artifacts:", len(distinct_art_ids))
    
    fcrs = fcr_engine.correlate(all_artifacts)
    print("Total FCR Correlation Records generated:", len(fcrs))
    
    fcr_primary_art_ids = set()
    for f in fcrs:
        for aid in f.artifact_ids:
            fcr_primary_art_ids.add(aid)
    print("Distinct Artifact IDs in FCR correlation records:", len(fcr_primary_art_ids))
    print("Top Artifact IDs present in FCRs:", list(fcr_primary_art_ids)[:10])

if __name__ == "__main__":
    trace_fcr_artifacts()
