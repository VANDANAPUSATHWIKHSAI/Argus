import sys
import os
sys.path.insert(0, os.path.abspath("."))
from unittest.mock import MagicMock
from agents.agent5b_campaign_similarity import (
    CampaignSimilarityAgent,
    ValidatedCaseRepository,
    MultiVectorEngine,
    ValidatedCase,
    Agent5bOutput
)
from agents.agent5b_campaign_similarity.schemas import (
    CaseValidationRecord,
    MalwareIdentity,
    CaseBehavioralSignature
)

def make_validated_case(
    case_id: str,
    tenant_id: str = "tenant_test_isolated",
    family: str = "RedLine",
    fingerprint: dict = None,
    attack_pattern: dict = None,
    threat_intel: dict = None,
    campaigns: list = None,
    actor: str = None,
    status: str = "approved",
    approved_by: str = "senior_lead"
) -> ValidatedCase:
    fp = fingerprint or {
        "execution": ["PowerShell Execution (powershell.exe)"],
        "persistence": ["Registry Run Key (Run)"],
        "credential_access": ["Browser credential theft"],
        "command_and_control": ["HTTPS C2 communication"]
    }
    ap = attack_pattern or {
        "infection_source": "Phishing email",
        "stages": ["Initial Access", "Execution", "Credential Theft", "Exfiltration"],
        "path": ["Phishing", "PowerShell", "Browser Stealer", "C2"]
    }
    ti = threat_intel or {
        "mitre_techniques": ["T1059.001", "T1547.001", "T1555.003", "T1071.001"],
        "iocs": ["198.51.100.22", "bad-stealer-c2.net"]
    }
    return ValidatedCase(
        case_id=case_id,
        tenant_id=tenant_id,
        validation=CaseValidationRecord(
            status=status,
            approved_by=approved_by,
            approval_timestamp="2026-02-01T12:00:00Z"
        ),
        malware_identity=MalwareIdentity(family=family, identity_confidence=0.92),
        malware_behavior_fingerprint=fp,
        attack_pattern=ap,
        threat_intelligence=ti,
        associated_campaigns=campaigns or ["Operation Nightfall"],
        threat_actor=actor or "Storm-0501"
    )

class DummyModel:
    def __init__(self, name="Qwen3-8B"):
        self.model_name = name
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        return "{}"

def diagnose_test_05():
    print("=== Diagnosing Test 05 ===")
    vector_engine = MultiVectorEngine()
    repo = ValidatedCaseRepository(vector_engine=vector_engine)
    tenant = "tenant_test_isolated_05"
    agent = CampaignSimilarityAgent(
        model=DummyModel(),
        tenant_id=tenant,
        vector_repo=repo,
        vector_engine=vector_engine
    )
    
    hist_case = make_validated_case(
        "HIST-005", tenant, family="AsyncRAT",
        fingerprint={
            "persistence": ["Registry Run Key (RunOnce)"],
            "defense_evasion": ["Process Hollowing"]
        }
    )
    repo.add_case(hist_case)

    agent5a_out = {
        "threat_intelligence": {
            "candidate_malware_families": ["AsyncRAT"],
            "confidence": 0.85
        },
        "evidence_ids": ["FIR-501"]
    }
    agent4_out = {
        "behavior_fingerprint": {
            "persistence": ["Scheduled Task (schtasks)"],
            "defense_evasion": ["AMSI bypass memory patching"]
        },
        "evidence_ids": ["FIR-502"]
    }

    output = agent.execute_analysis(
        case_id="CURR-005",
        agent4_output=agent4_out,
        agent5a_output=agent5a_out,
        tenant_id=tenant
    )
    hs = output.historical_similarity
    print("Retrieved cases:", [c.case_id for c in hs.retrieved_cases])
    print("Behavior sim:", hs.behavior_similarity)
    print("Composite sim:", hs.composite_similarity)
    print("Different behaviors:", hs.different_behaviors)
    print("Common behaviors:", hs.common_behaviors)
    print("New behaviors:", hs.new_behaviors)

if __name__ == "__main__":
    diagnose_test_05()
