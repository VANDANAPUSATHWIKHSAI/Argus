import os
import re
import json

KEYWORDS = [
    "sudeep", "kumar", "nps-2009-ntfs1", "ntfs1", "case-vss", "case-demo", 
    "case-123", "mfr-desktop", "analyst_alice", "analyst_john", "analyst_mary", "analyst_bob"
]

TARGET_DIRS = [
    r"c:\Users\Sudeep\Downloads\Argus\Argus\preprocessing",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\forensic_analysis",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\fir",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\sanitization",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\confidence_gate",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\report_generation",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\graph",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\agents",
    r"c:\Users\Sudeep\Downloads\Argus\Argus\models",
]

def main():
    matches = []
    for tdir in TARGET_DIRS:
        if not os.path.exists(tdir):
            continue
        for root, dirs, files in os.walk(tdir):
            if "__pycache__" in root:
                continue
            for file in files:
                if not file.endswith(".py"):
                    continue
                fpath = os.path.join(root, file)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for idx, line in enumerate(lines, 1):
                    line_lower = line.lower()
                    for kw in KEYWORDS:
                        if kw in line_lower:
                            matches.append({
                                "file": fpath,
                                "line": idx,
                                "kw": kw,
                                "content": line.strip()
                            })

    out_file = r"c:\Users\Sudeep\Downloads\Argus\Argus\scratch\hardcoding_audit_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(matches, f, indent=2)

    print(f"Total keyword matches across production code: {len(matches)}")
    for m in matches:
        rel_path = os.path.relpath(m['file'], r"c:\Users\Sudeep\Downloads\Argus\Argus")
        print(f"[{m['kw']}] {rel_path}:{m['line']} => {m['content']}")

if __name__ == "__main__":
    main()
