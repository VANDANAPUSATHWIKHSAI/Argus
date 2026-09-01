import os
import sys
import re

PROD_DIRS = ["preprocessing", "forensic_analysis", "fir", "sanitization", "api", "models", "config", "infrastructure", "seed"]

SUSPICIOUS_TERMS = [
    "F-1001",
    "CASE-FINAL-DEMO-2026",
    "Sudeep",
    "Kumar",
    "ntfs1-gen",
    "narrative.txt",
    "mock",
    "dummy",
    "fake",
    "placeholder"
]

def search_production_code():
    print("======================================================================")
    print("ARGUS — PHASE 10: PRODUCTION HARDCODING & MOCK SEARCH AUDIT")
    print("======================================================================")
    
    matches_found = []

    for pdir in PROD_DIRS:
        if not os.path.exists(pdir):
            continue
        for root, dirs, files in os.walk(pdir):
            if "__pycache__" in root:
                continue
            for file in files:
                if not file.endswith((".py", ".json", ".sql", ".sh")):
                    continue
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for idx, line in enumerate(lines, 1):
                        for term in SUSPICIOUS_TERMS:
                            if term.lower() in line.lower():
                                matches_found.append({
                                    "file": fpath,
                                    "line_num": idx,
                                    "term": term,
                                    "content": line.strip()
                                })
                except Exception as e:
                    print(f"Error reading {fpath}: {e}")

    print(f"Total Matches Found in Production Code: {len(matches_found)}\n")
    
    for m in matches_found:
        print(f"[{m['term'].upper()}] {m['file']}:{m['line_num']} -> {m['content']}")

if __name__ == "__main__":
    search_production_code()
