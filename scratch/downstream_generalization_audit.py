import os
import sys
import time
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))
sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus\frontend"))

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.engine import FCREngine
from preprocessing.fcr_engine.schemas import CorrelationRecord
from forensic_analysis.router import route_fcr
from forensic_analysis.orchestrator import process_fcr_batch, ENGINE_REGISTRY
from forensic_analysis.schemas import Finding, finding_to_fir
from sanitization.gateway import SanitizationGateway
from fir.repository import FIRRepository
import psycopg2
from psycopg2.extras import RealDictCursor

print("======================================================================")
print("ARGUS — PHASE 3 & 4: DOWNSTREAM GENERALIZATION AUDIT")
print("======================================================================")

case_id = "CASE-GENERALIZATION-001"
tenant_id = "tenant-generalization"
now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

# --------------------------------------------------------------------
# 1. CONSTRUCT NOVEL SYNTHETIC ARTIFACTS
# --------------------------------------------------------------------
art_proc1 = Artifact(
    artifact_id="art-nov-proc-1000",
    case_id=case_id,
    evidence_id="EV-NOVEL-01",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        user="alice.williams",
        process_name="explorer.exe",
        process_id=1000,
        parent_process_id=500
    )
)

art_proc2 = Artifact(
    artifact_id="art-nov-proc-2000",
    case_id=case_id,
    evidence_id="EV-NOVEL-01",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        user="alice.williams",
        process_name="winword.exe",
        process_id=2000,
        parent_process_id=1000
    )
)

art_proc3 = Artifact(
    artifact_id="art-nov-proc-3000",
    case_id=case_id,
    evidence_id="EV-NOVEL-01",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        user="alice.williams",
        process_name="invoice_update.exe",
        process_id=3000,
        parent_process_id=2000,
        file_hash="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
    )
)

art_proc4 = Artifact(
    artifact_id="art-nov-proc-4096",
    case_id=case_id,
    evidence_id="EV-NOVEL-01",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        user="alice.williams",
        process_name="powershell.exe",
        parent_process_name="winword.exe",
        process_id=4096,
        parent_process_id=2000,
        process_command_line="powershell.exe -ExecutionPolicy Bypass -enc Q2hhbmdlTWU="
    )
)

art_net = Artifact(
    artifact_id="art-nov-net-4096",
    case_id=case_id,
    evidence_id="EV-NOVEL-02",
    source_tool="zeek",
    artifact_type="network_connection",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        user="alice.williams",
        process_id=4096,
        dst_ip="203.0.113.77",
        dst_port=443,
        domain="security-alert-example.net"
    )
)

art_dns = Artifact(
    artifact_id="art-nov-dns-01",
    case_id=case_id,
    evidence_id="EV-NOVEL-02",
    source_tool="zeek",
    artifact_type="dns_query",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        domain="security-alert-example.net",
        resolved_ip="203.0.113.77"
    )
)

art_mem = Artifact(
    artifact_id="art-nov-mem-4096",
    case_id=case_id,
    evidence_id="EV-NOVEL-03",
    source_tool="volatility3",
    artifact_type="process_record",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-77",
        process_name="powershell.exe",
        process_id=4096,
        parent_process_id=9999  # Missing parent PID 9999 -> orphan process
    )
)

art_email = Artifact(
    artifact_id="art-nov-eml-01",
    case_id=case_id,
    evidence_id="EV-NOVEL-04",
    source_tool="eml_parser",
    artifact_type="email_message",
    host_id="WORKSTATION-77",
    timestamp=now,
    normalized_fields=NormalizedFields(
        sender="alert@security-alert-example.net",
        recipient="alice.williams@corp.net",
        subject="Urgent Invoice Update",
        domain="security-alert-example.net"
    ),
    raw_fields={
        "body": "Dear Alice, Please review the attached invoice_update.exe immediately.",
        "attachment_name": "invoice_update.exe"
    }
)

all_novel_artifacts = [art_proc1, art_proc2, art_proc3, art_proc4, art_net, art_dns, art_mem, art_email]
artifacts_by_id = {a.artifact_id: a for a in all_novel_artifacts}

# --------------------------------------------------------------------
# 2. RUN STAGE 3 FCR ENGINE
# --------------------------------------------------------------------
fcr_engine = FCREngine()
fcrs = fcr_engine.correlate(all_novel_artifacts)
print(f"Generated {len(fcrs)} FCR correlation records for novel case {case_id}")

# --------------------------------------------------------------------
# 3. ROUTE FCRS TO ANALYSIS ENGINES
# --------------------------------------------------------------------
engine_route_map = {}
for f in fcrs:
    routes = route_fcr(f, artifacts_by_id)
    engine_route_map[f.correlation_id] = routes

print("\nFCR Routing Summary:")
for cid, rts in engine_route_map.items():
    print(f"  FCR {cid}: Target Engines -> {rts}")

# --------------------------------------------------------------------
# 4. EXECUTE BATCH ORCHESTRATOR & 5 ANALYSIS ENGINES
# --------------------------------------------------------------------
fir_repo = FIRRepository()
gateway = SanitizationGateway()

raw_findings = process_fcr_batch(
    case_id=case_id,
    fcr_objects=fcrs,
    artifacts_by_id=artifacts_by_id,
    fir_repo=None  # We sanitize first below
)

for fnd in raw_findings:
    fnd.case_id = case_id
    fnd.tenant_id = tenant_id

print(f"\nGenerated {len(raw_findings)} raw findings across analysis engines.")

# --------------------------------------------------------------------
# 5. SANITIZE FINDINGS & PERSIST TO POSTGRESQL (PORT 5433)
# --------------------------------------------------------------------
conn = psycopg2.connect(host="localhost", port=5433, dbname="argus", user="argus_user", password="argus_dev")
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute("DELETE FROM fir_findings WHERE case_id = %s;", (case_id,))
conn.commit()

sanitized_ctx_list = []
for fnd in raw_findings:
    ctx = gateway.sanitize_finding(fnd)
    sanitized_ctx_list.append(ctx)
    
    fir_fnd = finding_to_fir(fnd, tenant_id=tenant_id)
    fir_fnd.sanitized_fact = ctx.sanitized_fact
    fir_fnd.injection_flagged = ctx.injection_flagged
    fir_fnd.injection_score = ctx.injection_score
    fir_repo.insert(fir_fnd)

cur.execute("SELECT COUNT(*) as cnt FROM fir_findings WHERE case_id = %s;", (case_id,))
pg_count = cur.fetchone()["cnt"]
conn.close()

print(f"Persisted and verified {pg_count} findings in PostgreSQL port 5433 for case {case_id}.")

# --------------------------------------------------------------------
# 6. ENGINE-BY-ENGINE TEST RESULTS (TESTS A-E)
# --------------------------------------------------------------------
engine_findings = {}
for fnd in raw_findings:
    engine_findings.setdefault(fnd.layer, []).append(fnd)

print("\n======================================================================")
print("ENGINE-BY-ENGINE GENERALIZATION TEST RESULTS:")
print("======================================================================")
for lyr, fnds in engine_findings.items():
    print(f"\n[ENGINE / LAYER]: {lyr} (Findings Count: {len(fnds)})")
    for f in fnds:
        print(f"  - Claim     : {f.fact}")
        print(f"    Sev/Conf  : {f.severity} | {f.confidence} | MITRE: {f.mitre_mapping}")
        print(f"    ArtifactID: {f.source_artifact_id}")

print("\n======================================================================")
print("PHASE 3 & 4 AUDIT SCRIPT COMPLETED SUCCESSFULLY")
print("======================================================================")
