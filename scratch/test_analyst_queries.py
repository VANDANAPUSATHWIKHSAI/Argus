import os
import sys
import json
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(r"c:\Users\Sudeep\Downloads\Argus\Argus"))
from api.main import app

client = TestClient(app)
case_id = "CASE-FINAL-DEMO-2026"
headers = {"X-Tenant-ID": "default"}

print("======================================================================")
print("TESTING ANALYST NOVEL QUERIES AGAINST CASE-FINAL-DEMO-2026")
print("======================================================================")

# Query A
query_a = "Which findings in this case involve PowerShell, and what evidence supports them?"
print(f"\n[QUERY A]: {query_a}")
res_a = client.post(f"/cases/{case_id}/query", json={"query": query_a}, headers=headers)
print("Status Code:", res_a.status_code)
print("Response JSON:")
print(json.dumps(res_a.json(), indent=2))

# Query B
query_b = "What are the highest-confidence findings in this case?"
print(f"\n[QUERY B]: {query_b}")
res_b = client.post(f"/cases/{case_id}/query", json={"query": query_b}, headers=headers)
print("Status Code:", res_b.status_code)
print("Response JSON:")
print(json.dumps(res_b.json(), indent=2))
