import sys
import json
sys.path.insert(0, '.')

from agents.agent5b_campaign_similarity import (
    CampaignSimilarityAgent,
    ValidatedCaseRepository,
    MultiVectorEngine,
    ValidatedCase,
    Agent5bOutput
)
from agents.agent5b_campaign_similarity.schemas import (
    CaseValidationRecord,
    MalwareIdentity
)

# 1. Initialize Vector Engine and Repository
vector_engine = MultiVectorEngine()
repo = ValidatedCaseRepository(vector_engine=vector_engine)

# 2. Seed a Maker-Checker approved historical case in tenant_enterprise
hist_case = ValidatedCase(
    case_id="HIST-CASE-2025-089",
    tenant_id="tenant_enterprise",
    validation=CaseValidationRecord(
        status="approved",
        approved_by="lead_investigator_42",
        approval_timestamp="2025-11-14T09:30:00Z",
        notes="Confirmed RedLine InfoStealer campaign targeting finance workstations."
    ),
    malware_identity=MalwareIdentity(
        family="RedLine Stealer",
        confidence=0.94,
        identity_confidence=0.94
    ),
    malware_behavior_fingerprint={
        "execution": ["PowerShell Execution (powershell.exe)"],
        "persistence": ["Scheduled Task (schtasks)"],
        "command_and_control": ["HTTPS C2 communication"],
        "credential_access": ["Browser credential theft (SQLite extraction)"]
    },
    attack_pattern={
        "infection_source": "Phishing Email with Malicious LNK",
        "stages": ["Initial Access", "Execution", "Persistence", "Credential Access", "Command and Control"],
        "path": ["Phishing Email -> PowerShell Script -> Scheduled Task -> HTTPS C2"]
    },
    threat_intelligence={
        "mitre_techniques": ["T1566.001", "T1059.001", "T1053.005", "T1555.003", "T1071.001"],
        "iocs": ["198.51.100.22", "c2-gateway-update.net"]
    },
    associated_campaigns=["Operation FrozenSteal"],
    threat_actor="Storm-0501"
)
repo.add_case(hist_case)

# 3. Create Agent 5B Instance
agent = CampaignSimilarityAgent(
    tenant_id="tenant_enterprise",
    vector_repo=repo,
    vector_engine=vector_engine
)

# 4. Define realistic upstream inputs from Agents 3, 4, 5a
agent3_out = {
    "case_id": "CASE-INCIDENT-2026-001",
    "tenant_id": "tenant_enterprise",
    "attack_stages": ["Initial Access", "Execution", "Persistence", "Command and Control"],
    "attack_path": ["Phishing Email -> PowerShell Script -> Run Key Persistence -> HTTPS C2"],
    "infection_source": "Phishing Email with Malicious LNK",
    "tactics": {
        "initial_access": ["Phishing (T1566.001)"],
        "execution": ["Command and Scripting Interpreter: PowerShell (T1059.001)"],
        "persistence": ["Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)"],
        "command_and_control": ["Application Layer Protocol: Web Protocols (T1071.001)"]
    },
    "evidence_ids": ["FIR-2026-01", "FIR-2026-02", "FIR-2026-03"]
}

agent4_out = {
    "case_id": "CASE-INCIDENT-2026-001",
    "tenant_id": "tenant_enterprise",
    "behavior_fingerprint": {
        "execution": ["PowerShell Execution (powershell.exe)"],
        "persistence": ["Registry Run Key (Run)"],
        "command_and_control": ["HTTPS C2 communication"],
        "credential_access": ["LSASS memory dump via MiniDumpWriteDump"]
    },
    "evidence_ids": ["FIR-2026-01", "FIR-2026-03", "FIR-2026-04"]
}

agent5a_out = {
    "case_id": "CASE-INCIDENT-2026-001",
    "tenant_id": "tenant_enterprise",
    "threat_intelligence": {
        "candidate_malware_families": ["RedLine Stealer", "Vidar"],
        "mitre_techniques": ["T1059.001", "T1547.001", "T1071.001", "T1003.001"],
        "ioc_matches": [
            {"indicator": "198.51.100.22", "type": "ipv4", "threat": "C2 Server"},
            {"indicator": "c2-gateway-update.net", "type": "domain", "threat": "C2 Domain"}
        ],
        "cve_references": ["CVE-2024-21412"],
        "confidence": 0.88,
        "freshness": [{"source": "AbuseCH", "freshness_status": "CURRENT"}],
        "source_quality": [{"source": "MISP", "quality": "HIGH"}]
    },
    "evidence_ids": ["FIR-2026-02", "FIR-2026-05"]
}

# Authoritative evidence IDs for current case
authoritative_evidence_ids = [
    "FIR-2026-01", "FIR-2026-02", "FIR-2026-03", "FIR-2026-04", "FIR-2026-05"
]

# 5. Execute Analysis
output: Agent5bOutput = agent.execute_analysis(
    case_id="CASE-INCIDENT-2026-001",
    agent3_output=agent3_out,
    agent4_output=agent4_out,
    agent5a_output=agent5a_out,
    tenant_id="tenant_enterprise",
    evidence_ids=authoritative_evidence_ids
)

out_dict = output.model_dump()

with open("agent5b_final_output.json", "w", encoding="utf-8") as f:
    json.dump(out_dict, f, indent=2)

print("GENERATED_AGENT5B_FINAL_JSON_SUCCESSFULLY")
