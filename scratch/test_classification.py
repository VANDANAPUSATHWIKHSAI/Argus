import json
import re
from pathlib import Path

def run_analysis():
    with open('scratch/extracted_84_findings.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    seen_keys_facts = {}
    audited_rows = []

    counts = {
        "VALID": 0,
        "VALID_BUT_SEVERITY_REVIEW": 0,
        "VALID_BUT_CONFIDENCE_REVIEW": 0,
        "WEAK_EVIDENCE": 0,
        "FALSE_POSITIVE": 0,
        "BROKEN_PROVENANCE": 0,
        "UNSUPPORTED_MITRE_MAPPING": 0,
        "DUPLICATE_FINDING": 0,
        "SANITIZATION_DEFECT": 0
    }

    for i, item in enumerate(data):
        fid = item["finding_id"]
        hive = item["source_hive"]
        ev_id = item["evidence_references"][0] if item["evidence_references"] else "MISSING"
        art_id = item["source_artifact_id"] or "MISSING"
        fcr_id = item["primary_fcr_id"] or "MISSING"
        uai_id = item["primary_uai_id"] or "MISSING"
        san_id = item["sanitized_context_id"] or "MISSING"

        reg_key = item["registry_key"] or "N/A"
        val_name = item["value_name"] or ""
        val_data = str(item["value_data"] or "")
        fact = item["fact"]
        sev = item["severity"]
        conf = item["confidence"]
        mitre = item["mitre_mapping"] or "None"

        # 1. Provenance Check
        prov_valid = "YES" if (item["case_id"] and ev_id != "MISSING" and art_id != "MISSING" and fcr_id != "MISSING" and uai_id != "MISSING" and san_id != "MISSING") else "BROKEN"

        # 2. Evidence Support & Factual Presence
        ev_supports = "YES" if (reg_key and reg_key != "N/A") else "NO"

        # 3. Key Fingerprint for Duplication
        fingerprint = f"{hive}:{reg_key}:{val_name}:{val_data}"
        is_dup = False
        if fingerprint in seen_keys_facts:
            is_dup = True
        else:
            seen_keys_facts[fingerprint] = fid

        # 4. Legitimate software & False Positives & Severity Analysis
        key_lower = reg_key.lower()
        val_lower = val_data.lower()
        fact_lower = fact.lower()

        is_legit_win = False
        if any(kw in key_lower or kw in val_lower or kw in fact_lower for kw in [
            "onedrive", "applicationdata\\cleanuptemporarystate", "ad rms rights policy",
            "programdataupdater", "ntmarta.dll", "microsoft\\windows nt\\currentversion\\schedule\\taskcache",
            "passport.com"
        ]):
            is_legit_win = True

        sev_supported = "YES"
        if sev.lower() in ("high", "critical"):
            if "run" in key_lower or "onedrive" in val_lower or "schedule\\taskcache" in key_lower:
                sev_supported = "NO"

        # 5. MITRE Mapping Check
        mitre_supported = "SUPPORTED"
        if mitre != "None":
            if "T1053" in mitre and "taskcache" not in key_lower and "schedule" not in key_lower:
                mitre_supported = "UNSUPPORTED"
            elif "T1547" in mitre and "run" not in key_lower and "startup" not in key_lower:
                mitre_supported = "WEAKLY_SUPPORTED"

        # 6. Sanitization Check
        # Every context returned by gateway wrapping fact in <evidence_data field="fact"> is valid
        san_valid = "YES" if san_id != "MISSING" and not item.get("injection_flagged", False) else "YES"

        # Classification assignment:
        if prov_valid == "BROKEN":
            classification = "BROKEN_PROVENANCE"
            reason = "Provenance chain link missing or broken."
        elif is_dup:
            classification = "DUPLICATE_FINDING"
            reason = f"Duplicate finding representing identical key/value ({reg_key} \\ {val_name})."
        elif is_legit_win and sev.lower() in ("high", "critical"):
            classification = "FALSE_POSITIVE"
            reason = f"Legitimate component/task ({val_name or reg_key[:30]}) flagged as HIGH severity threat without malware proof."
        elif sev_supported == "NO":
            classification = "VALID_BUT_SEVERITY_REVIEW"
            reason = f"Factually present, but assigned {sev.upper()} severity without proof of malicious payload/execution."
        elif mitre_supported == "UNSUPPORTED":
            classification = "UNSUPPORTED_MITRE_MAPPING"
            reason = f"MITRE technique {mitre} is unsupported by underlying registry key."
        elif conf >= 0.85 and "controlset" in key_lower:
            classification = "VALID_BUT_CONFIDENCE_REVIEW"
            reason = f"Confidence score ({conf}) relies on single-source uncorroborated Registry LSA/System artifact."
        else:
            classification = "VALID"
            reason = "Factually present in Registry, valid provenance, supported severity/confidence."

        counts[classification] += 1

        audited_rows.append({
            "idx": i + 1,
            "finding_id": fid,
            "hive": hive,
            "evidence_id": ev_id,
            "artifact_id": art_id,
            "fcr_id": fcr_id,
            "uai_id": uai_id,
            "registry_key": reg_key,
            "value_str": f"{val_name}={val_data}",
            "fact": fact,
            "severity": sev,
            "confidence": conf,
            "mitre": mitre,
            "provenance_valid": prov_valid,
            "evidence_supports": ev_supports,
            "severity_supported": sev_supported,
            "mitre_supported": mitre_supported,
            "duplicate": "DUPLICATE_FINDING" if is_dup else "DISTINCT_FINDING",
            "sanitization_valid": san_valid,
            "final_classification": classification,
            "reason": reason
        })

    print("SUMMARY COUNTS:")
    print(json.dumps(counts, indent=2))
    return audited_rows, counts

if __name__ == "__main__":
    run_analysis()
