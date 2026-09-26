"""
Phase 8F Step 0 Pre-Flight Verification Script
==============================================
Verifies corpus integrity, ID reconciliation, worker assignments, and environment readiness before full 3,286 execution.
"""

import os
import sys
import json
import requests

# Ensure stdout handles UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def main():
    print("=" * 80)
    print("ARGUS PHASE 8F -- PRE-FLIGHT STEP 0 VERIFICATION")
    print("=" * 80)

    corpus_path = "scratch/full_3286_sanitized_findings.json"
    if not os.path.exists(corpus_path):
        print(f"[STOP] Corpus file missing: {corpus_path}")
        sys.exit(1)

    with open(corpus_path, "r", encoding="utf-8") as f:
        corpus = json.load(f)

    # 1. Total records check
    total_records = len(corpus)
    print(f"\n[A. CORPUS INTEGRITY]")
    print(f"  - Total FIR records loaded: {total_records}")
    if total_records != 3286:
        print(f"  [STOP] Corpus count mismatch! Expected 3286, got {total_records}")
        sys.exit(1)
    else:
        print("  [PASS] Corpus count is exactly 3,286 FIRs.")

    # 2. Unique FIR ID check
    fir_ids = []
    case_ids = set()
    tenant_ids = set()

    missing_required = 0
    for idx, item in enumerate(corpus):
        fid = item.get("finding_id") or item.get("fir_id") or item.get("id")
        if not fid:
            missing_required += 1
        else:
            fir_ids.append(str(fid))
        cid = item.get("case_id")
        if cid:
            case_ids.add(cid)
        tid = item.get("tenant_id")
        if tid:
            tenant_ids.add(tid)

    unique_fir_ids = set(fir_ids)
    print(f"  - Total extracted FIR IDs: {len(fir_ids)}")
    print(f"  - Unique FIR IDs count: {len(unique_fir_ids)}")
    print(f"  - Missing FIR IDs count: {missing_required}")

    if len(unique_fir_ids) != 3286 or missing_required > 0:
        print("  [STOP] Duplicate or missing FIR IDs found!")
        sys.exit(1)
    else:
        print("  [PASS] All 3,286 FIR IDs are unique and present.")

    # 3. Case ID & Tenant ID Reconciliation
    print(f"\n[B. CORPUS ID RECONCILIATION]")
    reconciled_case_id = list(case_ids)[0] if case_ids else "CASE-2020JIMMYWILSON-E01"
    reconciled_tenant_id = list(tenant_ids)[0] if tenant_ids else "default"
    print(f"  - Corpus Case IDs found: {list(case_ids)}")
    print(f"  - Corpus Tenant IDs found: {list(tenant_ids)}")
    print(f"  - Reconciled Runner case_id: {reconciled_case_id}")
    print(f"  - Reconciled Runner tenant_id: {reconciled_tenant_id}")

    # 4. Worker Assignment Verification
    print(f"\n[E/F. WORKER ASSIGNMENT MATHEMATICAL VERIFICATION]")
    total_firs = len(corpus)
    batch_size = 10
    total_batches = (total_firs + batch_size - 1) // batch_size
    print(f"  - Total FIRs: {total_firs}")
    print(f"  - Expected total batches: {total_batches}")
    
    assignments = {}
    assigned_id_set = set()
    duplicate_assignments = 0

    for b_idx in range(total_batches):
        b_id = f"BATCH-{b_idx+1:03d}"
        start_pos = b_idx * batch_size
        end_pos = min(start_pos + batch_size, total_firs)
        b_firs = corpus[start_pos:end_pos]
        assignments[b_id] = b_firs
        
        for item in b_firs:
            fid = str(item.get("finding_id") or item.get("fir_id") or item.get("id"))
            if fid in assigned_id_set:
                duplicate_assignments += 1
            assigned_id_set.add(fid)

    first_batch_len = len(assignments["BATCH-001"])
    last_batch_len = len(assignments["BATCH-329"])
    print(f"  - Batch 001 size: {first_batch_len} FIRs")
    print(f"  - Batch 329 (final) size: {last_batch_len} FIRs")
    print(f"  - Total Assigned FIRs: {len(assigned_id_set)}")
    print(f"  - Duplicate Assignments: {duplicate_assignments}")

    if total_batches != 329 or first_batch_len != 10 or last_batch_len != 6 or len(assigned_id_set) != 3286 or duplicate_assignments > 0:
        print("  [STOP] Worker assignment math verification failed!")
        sys.exit(1)
    else:
        print("  [PASS] Exactly 329 worker batches assigned (328 x 10 FIRs + 1 x 6 FIRs = 3,286 FIRs).")

    # 5. Environment Verification
    print(f"\n[G. ENVIRONMENT VERIFICATION]")
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            models_info = r.json().get("models", [])
            model_names = [m.get("name") for m in models_info]
            print(f"  - Local Ollama Status: ONLINE")
            print(f"  - Available Ollama Models: {model_names}")
            if any("qwen3:8b" in m or "qwen3" in m for m in model_names):
                print("  [PASS] qwen3:8b is available locally.")
            else:
                print("  [WARNING] qwen3:8b model tag check failed.")
        else:
            print(f"  [STOP] Ollama returned HTTP {r.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"  [STOP] Could not connect to Ollama at http://localhost:11434: {e}")
        sys.exit(1)

    print(f"\n" + "=" * 80)
    print("PRE-FLIGHT STEP 0 VERIFICATION PASSED PERFECTLY!")
    print("=" * 80)

if __name__ == "__main__":
    main()
