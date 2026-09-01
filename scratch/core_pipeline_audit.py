import os
import sys
import json
import hashlib
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import RealDictCursor

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))
sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus\frontend"))

from fastapi.testclient import TestClient
from api.main import app
import api_client

from preprocessing.schemas import Artifact, NormalizedFields
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.router import route_fcr
from forensic_analysis.orchestrator import process_fcr_batch
from forensic_analysis.schemas import Finding, finding_to_fir
from sanitization.gateway import SanitizationGateway
from fir.repository import FIRRepository

print("======================================================================")
print("ARGUS — CORE PIPELINE EMPIRICAL AUDIT")
print("======================================================================")

client = TestClient(app)
case_id = "CASE-CORE-AUDIT-001"
tenant_id = "tenant-core-audit"
headers = {"X-Tenant-ID": tenant_id}
now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

# --------------------------------------------------------------------
# 1. CREATE NOVEL SYNTHETIC EVIDENCE
# --------------------------------------------------------------------
art_proc = Artifact(
    artifact_id="art-core-proc-01",
    case_id=case_id,
    evidence_id="EV-CORE-01",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="WORKSTATION-99",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-99",
        user="bob.miller",
        process_name="powershell.exe",
        parent_process_name="winword.exe",
        process_id=5000,
        parent_process_id=2500,
        file_hash="99887766554433221100fedcba9876543210fedcba9876543210fedcba987654",
        process_command_line="powershell.exe -ExecutionPolicy Bypass -enc Q2hhbmdlTWU="
    )
)

art_net = Artifact(
    artifact_id="art-core-net-01",
    case_id=case_id,
    evidence_id="EV-CORE-02",
    source_tool="zeek",
    artifact_type="network_connection",
    host_id="WORKSTATION-99",
    timestamp=now,
    normalized_fields=NormalizedFields(
        host="WORKSTATION-99",
        user="bob.miller",
        process_id=5000,
        dst_ip="203.0.113.88",
        dst_port=8443,
        domain="malicious-domain-example.org"
    )
)

all_artifacts = [art_proc, art_net]
artifacts_by_id = {a.artifact_id: a for a in all_artifacts}

# --------------------------------------------------------------------
# 2. RUN FCR ENGINE & ROUTER
# --------------------------------------------------------------------
fcr_engine = FCREngine()
fcrs = fcr_engine.correlate(all_artifacts)
print(f"Generated {len(fcrs)} FCR correlation records for novel case {case_id}")

engine_routes = {}
for f in fcrs:
    engine_routes[f.correlation_id] = route_fcr(f, artifacts_by_id)

print("\nFCR Engine Routes:")
for cid, rts in engine_routes.items():
    print(f"  FCR {cid}: Target Engines -> {rts}")

# --------------------------------------------------------------------
# 3. RUN BATCH ORCHESTRATOR & 5 ANALYSIS ENGINES
# --------------------------------------------------------------------
gateway = SanitizationGateway()
fir_repo = FIRRepository()

# Clear existing findings for clean test run
conn = psycopg2.connect(host="localhost", port=5433, dbname="argus", user="argus_user", password="argus_dev")
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute("DELETE FROM fir_findings WHERE case_id = %s;", (case_id,))
conn.commit()

raw_findings = process_fcr_batch(
    case_id=case_id,
    fcr_objects=fcrs,
    artifacts_by_id=artifacts_by_id,
    fir_repo=None
)

for fnd in raw_findings:
    fnd.case_id = case_id
    fnd.tenant_id = tenant_id

print(f"\nGenerated {len(raw_findings)} raw findings across analysis engines.")

# --------------------------------------------------------------------
# 4. SANITIZE FINDINGS & PERSIST TO POSTGRESQL (PORT 5433)
# --------------------------------------------------------------------
sanitized_count = 0
for fnd in raw_findings:
    ctx = gateway.sanitize_finding(fnd)
    if ctx.sanitized_fact:
        sanitized_count += 1
        
    fir_fnd = finding_to_fir(fnd, tenant_id=tenant_id)
    fir_fnd.sanitized_fact = ctx.sanitized_fact
    fir_fnd.injection_flagged = ctx.injection_flagged
    fir_fnd.injection_score = ctx.injection_score
    fir_repo.insert(fir_fnd)

cur.execute("SELECT COUNT(*) as cnt FROM fir_findings WHERE case_id = %s;", (case_id,))
pg_count = cur.fetchone()["cnt"]

print(f"Sanitized findings count: {sanitized_count}")
print(f"PostgreSQL row count    : {pg_count}")

# --------------------------------------------------------------------
# 5. REST API & REPORT VERIFICATION
# --------------------------------------------------------------------
summary_res = client.get(f"/cases/{case_id}", headers=headers).json()
report_res = client.get(f"/reports/{case_id}/report?format=json&allow_unreviewed=true", headers=headers).json()

print(f"\nAPI GET /cases/{case_id}:")
print(f"  total_findings       : {summary_res['total_findings']}")
print(f"  severity_breakdown   : {summary_res['severity_breakdown']}")
print(f"  source_artifact_count: {summary_res['source_artifact_count']}")

print(f"\nAPI GET /reports/{case_id}/report?format=json:")
print(f"  report findings count: {len(report_res['findings'])}")

assert summary_res["total_findings"] == pg_count
assert len(report_res["findings"]) == pg_count

# --------------------------------------------------------------------
# 6. NEGATIVE CONTROL TEST
# --------------------------------------------------------------------
art_iso_a = Artifact(
    artifact_id="art-iso-a",
    case_id="CASE-CORE-A",
    evidence_id="EV-A",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="HOST-CORE-A",
    timestamp=now,
    normalized_fields=NormalizedFields(host="HOST-CORE-A", process_name="clean1.exe", process_id=101)
)
art_iso_b = Artifact(
    artifact_id="art-iso-b",
    case_id="CASE-CORE-B",
    evidence_id="EV-B",
    source_tool="zeek",
    artifact_type="network_connection",
    host_id="HOST-CORE-B",
    timestamp=now,
    normalized_fields=NormalizedFields(host="HOST-CORE-B", process_id=909, dst_ip="198.51.100.55", dst_port=80)
)

neg_fcrs = fcr_engine.correlate([art_iso_a, art_iso_b])
neg_findings = process_fcr_batch(case_id="CASE-CORE-A", fcr_objects=neg_fcrs, artifacts_by_id={art_iso_a.artifact_id: art_iso_a, art_iso_b.artifact_id: art_iso_b}, fir_repo=None)

print(f"\nNegative Control Test:")
print(f"  Isolated FCRs generated: {len(neg_fcrs)} (Expected: 0)")
print(f"  Isolated Findings      : {len(neg_findings)} (Expected: 0)")
assert len(neg_fcrs) == 0
assert len(neg_findings) == 0

conn.close()

print("\n======================================================================")
print("CORE PIPELINE EMPIRICAL AUDIT COMPLETED SUCCESSFULLY (100% VERIFIED)")
print("======================================================================")
