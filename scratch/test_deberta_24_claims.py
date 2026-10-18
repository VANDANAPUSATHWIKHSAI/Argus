import sys
import os
sys.path.insert(0, os.path.abspath("."))

from models.classifiers import ClassifierLoader
from agents.agent7_supervisor.call2_verification import SupervisorVerification
from fir.schemas import FIRFinding

class DummyFIRRepo:
    def __init__(self, findings):
        self.findings = {f.finding_id: f for f in findings}
    def get_by_id(self, tenant_id, finding_id):
        f = self.findings.get(finding_id)
        if f and f.tenant_id == tenant_id:
            return f
        return None

def make_fir(fid, fact, tenant_id="tenant-eval", case_id="case-eval", sev="high", conf=0.9):
    return FIRFinding(
        finding_id=fid,
        case_id=case_id,
        tenant_id=tenant_id,
        fact=fact,
        layer="endpoint_analyzer",
        source_artifact_id="A-01",
        evidence_reference=["E-01"],
        severity=sev,
        confidence=conf,
        analyst_verdict="confirmed"
    )

def test_eval():
    loader = ClassifierLoader()
    sup = SupervisorVerification(None, None, None, tenant_id="tenant-eval")

    f1 = make_fir("F-01", "Registry Run key UpdateHelper created pointing to C:\\Windows\\Temp\\beacon.exe.")
    f2 = make_fir("F-02", "Firewall dropped connection to 203.0.113.100 on port 4444.")
    f3 = make_fir("F-03", "PowerShell executed with Base64 encoded payload downloading script from http://example.com/a.")
    f4 = make_fir("F-04", "User bob downloaded setup.exe from malicious domain bad-site.com at 08:30 UTC.")
    f5 = make_fir("F-05", "Process setup.exe spawned cmd.exe executing whoami.exe and net user at 08:31 UTC.")
    f6 = make_fir("F-06", "Phishing email containing invoice.xlsm was delivered to user inbox at 09:00 UTC.")
    f7 = make_fir("F-07", "Ransomware encryption began on file share SERVER-01 at 14:00 UTC.")
    f8 = make_fir("F-08", "LSASS process memory was dumped to C:\\Windows\\Temp\\lsass.dmp by procdump.exe.")
    f9 = make_fir("F-09", "Service TermService was stopped and disabled via sc.exe config.")
    f10 = make_fir("F-10", "Scheduled task CleanMgr was modified to run powershell.exe with hidden window.")

    all_firs = [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10]
    sup.fir = DummyFIRRepo(all_firs)

    claims_test = [
        # (claim_dict, fir_subset, expected_verified, category)
        # 1. Direct Entailment
        ({"claim_id": "C-01", "claim": "Registry Run key was created pointing to beacon.exe.", "evidence_ids": ["F-01"], "severity": "high", "confidence": 0.90}, [f1], True, "Direct Entailment"),
        ({"claim_id": "C-02", "claim": "An encoded PowerShell command downloaded a remote script.", "evidence_ids": ["F-03"], "severity": "high", "confidence": 0.90}, [f3], True, "Direct Entailment"),
        ({"claim_id": "C-03", "claim": "LSASS process memory was dumped to disk by procdump.exe.", "evidence_ids": ["F-08"], "severity": "critical", "confidence": 0.95}, [f8], True, "Direct Entailment"),
        ({"claim_id": "C-04", "claim": "Remote Desktop service TermService was disabled.", "evidence_ids": ["F-09"], "severity": "medium", "confidence": 0.85}, [f9], True, "Direct Entailment"),
        ({"claim_id": "C-05", "claim": "Scheduled task CleanMgr was altered to execute hidden PowerShell.", "evidence_ids": ["F-10"], "severity": "high", "confidence": 0.90}, [f10], True, "Direct Entailment"),
        ({"claim_id": "C-06", "claim": "User bob downloaded an executable from external domain bad-site.com.", "evidence_ids": ["F-04"], "severity": "medium", "confidence": 0.90}, [f4], True, "Direct Entailment"),

        # 2. Contradiction
        ({"claim_id": "C-07", "claim": "Outbound connection to 203.0.113.100 succeeded and transferred 10GB.", "evidence_ids": ["F-02"], "severity": "high", "confidence": 0.90}, [f2], False, "Contradiction"),
        ({"claim_id": "C-08", "claim": "TermService was successfully started and enabled on the host.", "evidence_ids": ["F-09"], "severity": "low", "confidence": 0.80}, [f9], False, "Contradiction"),
        ({"claim_id": "C-09", "claim": "PowerShell execution was entirely blocked and rejected by AppLocker.", "evidence_ids": ["F-03"], "severity": "high", "confidence": 0.85}, [f3], False, "Contradiction"),
        ({"claim_id": "C-10", "claim": "LSASS memory access was prevented by Credential Guard.", "evidence_ids": ["F-08"], "severity": "high", "confidence": 0.90}, [f8], False, "Contradiction"),

        # 3. Neutral / Speculative / Domain mismatch
        ({"claim_id": "C-11", "claim": "Active Directory database NTDS.dit was exfiltrated to cloud storage.", "evidence_ids": ["F-01"], "severity": "critical", "confidence": 0.90}, [f1], False, "Neutral / Unsupported"),
        ({"claim_id": "C-12", "claim": "Adversary exploited zero-day vulnerability in Microsoft Exchange Server.", "evidence_ids": ["F-03"], "severity": "critical", "confidence": 0.90}, [f3], False, "Neutral / Unsupported"),
        ({"claim_id": "C-13", "claim": "Threat actor APT29 operated using compromised VPN credentials.", "evidence_ids": ["F-04"], "severity": "high", "confidence": 0.80}, [f4], False, "Neutral / Unsupported"),
        ({"claim_id": "C-14", "claim": "Database tables in SQL Server were truncated and wiped.", "evidence_ids": ["F-05"], "severity": "high", "confidence": 0.85}, [f5], False, "Neutral / Unsupported"),
        ({"claim_id": "C-15", "claim": "Adversary established persistence via Linux SSH authorized_keys.", "evidence_ids": ["F-10"], "severity": "medium", "confidence": 0.80}, [f10], False, "Neutral / Unsupported"),

        # 4. Compound claims with speculative clause
        ({"claim_id": "C-16", "claim": "Scheduled task CleanMgr was modified. Adversary exfiltrated 50GB to Mega.nz.", "evidence_ids": ["F-10"], "severity": "high", "confidence": 0.90}, [f10], False, "Compound Speculative"),
        ({"claim_id": "C-17", "claim": "UpdateHelper Run key was created. Attacker stole all CEO browser passwords.", "evidence_ids": ["F-01"], "severity": "high", "confidence": 0.90}, [f1], False, "Compound Speculative"),
        ({"claim_id": "C-18", "claim": "LSASS memory was dumped. Adversary subsequently deployed LockBit on all domain controllers.", "evidence_ids": ["F-08"], "severity": "critical", "confidence": 0.95}, [f8], False, "Compound Speculative"),
        ({"claim_id": "C-19", "claim": "PowerShell downloaded remote script. Domain administrator password was cracked via hashcat.", "evidence_ids": ["F-03"], "severity": "critical", "confidence": 0.90}, [f3], False, "Compound Speculative"),

        # 5. Unsupported Causal Relationships
        ({"claim_id": "C-20", "claim": "The invoice.xlsm attachment macro directly executed the ransomware encryption on SERVER-01.", "evidence_ids": ["F-06", "F-07"], "severity": "critical", "confidence": 0.90}, [f6, f7], False, "Unsupported Causal"),
        ({"claim_id": "C-21", "claim": "Disabling TermService directly caused the firewall to drop connections to 203.0.113.100.", "evidence_ids": ["F-09", "F-02"], "severity": "medium", "confidence": 0.80}, [f9, f2], False, "Unsupported Causal"),
        ({"claim_id": "C-22", "claim": "Registry key UpdateHelper execution directly forced LSASS memory to be dumped.", "evidence_ids": ["F-01", "F-08"], "severity": "high", "confidence": 0.85}, [f1, f8], False, "Unsupported Causal"),

        # 6. Multi-Finding Joint Entailment
        ({"claim_id": "C-23", "claim": "Downloaded setup.exe executed whoami.exe and net user to discover user accounts.", "evidence_ids": ["F-04", "F-05"], "severity": "high", "confidence": 0.90}, [f4, f5], True, "Multi-Finding Joint"),
        ({"claim_id": "C-24", "claim": "Both malicious scheduled task persistence and registry Run key persistence were established.", "evidence_ids": ["F-01", "F-10"], "severity": "high", "confidence": 0.90}, [f1, f10], True, "Multi-Finding Joint"),
    ]

    print(f"[*] Testing {len(claims_test)} independently authored forensic claims against DeBERTa-v3...")
    tp = fp = tn = fn = 0
    results_by_cat = {}

    for claim, firs, expected, cat in claims_test:
        res = sup.verify(claim, fir_records=firs, tenant_id="tenant-eval", case_id="case-eval")
        actual = res["verified"]
        score = res["support_score"]
        status = res["verification_status"]

        if cat not in results_by_cat:
            results_by_cat[cat] = {"pass": 0, "fail": 0, "total": 0}
        results_by_cat[cat]["total"] += 1

        is_correct = (actual == expected)
        if is_correct:
            results_by_cat[cat]["pass"] += 1
        else:
            results_by_cat[cat]["fail"] += 1

        if expected and actual:
            tp += 1
        elif not expected and not actual:
            tn += 1
        elif not expected and actual:
            fp += 1
        elif expected and not actual:
            fn += 1

        print(f"[{'PASS' if is_correct else 'FAIL'}] {claim['claim_id']} ({cat}): expected={expected}, actual={actual}, score={score:.2f}, status={status}")

    total = len(claims_test)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n=== SUMMARY METRICS ===")
    print(f"Total Sample Size: N={total}")
    print(f"TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    print(f"Accuracy:    {accuracy:.2%}")
    print(f"Precision:   {precision:.2%}")
    print(f"Recall:      {recall:.2%}")
    print(f"Specificity: {specificity:.2%}")
    print(f"F1 Score:    {f1:.2%}")
    print("\nResults by Category:")
    for cat, d in results_by_cat.items():
        print(f"  {cat}: {d['pass']}/{d['total']} correct ({d['pass']/d['total']:.1%})")

if __name__ == "__main__":
    test_eval()
