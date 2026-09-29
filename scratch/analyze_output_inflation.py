"""
ARGUS Agent 1 — Output Inflation Quantification Script
Analyzes exact serialized JSON outputs from Phase 1-7 Qwen baseline runs.
Calculates token distribution across citation array enumeration, reasoning explanations, and structural metadata.
"""

import json
import sys
from pathlib import Path

INVESTIGATION_FILE = Path(__file__).parent / "qwen_telemetry_investigation.json"

def analyze():
    if not INVESTIGATION_FILE.exists():
        print(f"Error: {INVESTIGATION_FILE} does not exist.")
        return

    with open(INVESTIGATION_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("=" * 80)
    print("PHASE 2 — QUANTIFY OUTPUT INFLATION ANALYSIS")
    print("=" * 80)

    for key in ("25_FIR", "50_FIR", "100_FIR"):
        batches = data.get(key, [])
        print(f"\n--- SubsetSize: {key} ({len(batches)} batch(es)) ---")

        for idx, b in enumerate(batches, start=1):
            raw_response = b.get("raw_response", "")
            out_tokens = b.get("output_tokens", 0)
            wall_time = b.get("wall_time_sec", 0)

            # Try parsing JSON
            cleaned = raw_response.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned:
                cleaned = cleaned.split("```")[1].split("```")[0].strip()

            try:
                parsed = json.loads(cleaned)
            except Exception as e:
                print(f"  Batch {idx}: JSON parse error: {e}")
                continue

            claims = parsed.get("claims", [])
            num_claims = len(claims)

            all_cited_ids = []
            citation_chars = 0
            reasoning_chars = 0
            other_chars = 0

            for c in claims:
                cited = c.get("cited_evidence_ids") or c.get("evidence_ids") or []
                if isinstance(cited, list):
                    all_cited_ids.extend(cited)
                    citation_str = json.dumps(cited)
                    citation_chars += len(citation_str)

                expl = str(c.get("findings_summary", "")) + str(c.get("summary", "")) + str(c.get("reasoning_notes", ""))
                reasoning_chars += len(expl)

            total_chars = len(raw_response)
            other_chars = max(0, total_chars - citation_chars - reasoning_chars)

            citation_pct = (citation_chars / max(1, total_chars)) * 100.0
            reasoning_pct = (reasoning_chars / max(1, total_chars)) * 100.0
            other_pct = (other_chars / max(1, total_chars)) * 100.0

            avg_tok_per_claim = out_tokens / max(1, num_claims)
            avg_cited_per_claim = len(all_cited_ids) / max(1, num_claims)
            max_cited_in_claim = max([len(c.get("cited_evidence_ids", [])) for c in claims], default=0)

            print(f"  Batch {idx}:")
            print(f"    Total Output Tokens: {out_tokens} tokens ({total_chars} chars)")
            print(f"    Claims Produced: {num_claims}")
            print(f"    Avg Tokens / Claim: {avg_tok_per_claim:.1f}")
            print(f"    Total Cited Evidence IDs: {len(all_cited_ids)}")
            print(f"    Avg Cited IDs / Claim: {avg_cited_per_claim:.1f}")
            print(f"    Max Cited IDs in single Claim: {max_cited_in_claim}")
            print(f"    Token Share Breakdown:")
            print(f"      - Citation Enumeration String: {citation_chars} chars ({citation_pct:.1f}%)")
            print(f"      - Reasoning & Explanation Text: {reasoning_chars} chars ({reasoning_pct:.1f}%)")
            print(f"      - Structural Metadata JSON: {other_chars} chars ({other_pct:.1f}%)")

if __name__ == "__main__":
    analyze()
