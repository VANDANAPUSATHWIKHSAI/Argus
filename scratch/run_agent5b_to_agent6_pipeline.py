import sys
import json
from unittest.mock import MagicMock
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
from agents.agent6_impact_assessment.agent import ImpactAssessmentAgent

# 1. Setup Vector Engine & Repository
vector_engine = MultiVectorEngine()
repo = ValidatedCaseRepository(vector_engine=vector_engine)

# 2. Add approved historical reference case
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
class LLMModel:
    def __init__(self, name="Qwen3-14B"):
        self.model_name = name
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        if "business impact" in prompt.lower():
            return (
                "Critical financial workstations (WORKSTATION-41, SRV-FINANCE-01) compromised by infostealer activity. "
                "Immediate containment and credential revocation required for active directory finance accounts."
            )
        return "{}"

model = LLMModel()
agent5b = CampaignSimilarityAgent(
    model=model,
    tenant_id="tenant_enterprise",
    vector_repo=repo,
    vector_engine=vector_engine
)

# 4. Execute Agent 5B Analysis
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

authoritative_eids = [
    "FIR-2026-01", "FIR-2026-02", "FIR-2026-03", "FIR-2026-04", "FIR-2026-05"
]

agent5b_output: Agent5bOutput = agent5b.execute_analysis(
    case_id="CASE-INCIDENT-2026-001",
    agent3_output=agent3_out,
    agent4_output=agent4_out,
    agent5a_output=agent5a_out,
    tenant_id="tenant_enterprise",
    evidence_ids=authoritative_eids
)

# 5. Hand off to Agent 6 (Impact Assessment)
mock_gateway = MagicMock()
mock_gateway.sanitize = lambda text, field_name="unstructured": text

agent6 = ImpactAssessmentAgent(
    model=model,
    fir_repo=None,
    sanitization_gateway=mock_gateway,
    tenant_id="tenant_enterprise"
)

agent6_context = {
    "affected_assets": ["WORKSTATION-41", "SRV-FINANCE-01"],
    "fir_findings": [
        {
            "finding_id": "FIR-2026-01",
            "tenant_id": "tenant_enterprise",
            "fact": "Process cmd.exe spawned powershell.exe script execution on host WORKSTATION-41 targeting C2 gateway",
            "severity": "critical"
        },
        {
            "finding_id": "FIR-2026-03",
            "tenant_id": "tenant_enterprise",
            "fact": "Scheduled Task updater created in registry persistence on host WORKSTATION-41",
            "severity": "high"
        }
    ],
    "agent5b_handoff": agent5b_output.agent6_handoff.model_dump(),
    "upstream_outputs": {
        "agent3": agent3_out,
        "agent4": agent4_out,
        "agent5a": agent5a_out,
        "agent5b": agent5b_output.model_dump()
    }
}

agent6_output = agent6.run("CASE-INCIDENT-2026-001", agent6_context)

# 6. Combined Integration Result
pipeline_output = {
    "agent5b_output": agent5b_output.model_dump(),
    "agent6_input_context": {
        "case_id": "CASE-INCIDENT-2026-001",
        "tenant_id": "tenant_enterprise",
        "affected_assets": ["WORKSTATION-41", "SRV-FINANCE-01"],
        "received_handoff_from_agent5b": agent5b_output.agent6_handoff.model_dump()
    },
    "agent6_output": agent6_output
}

with open("pipeline_5b_to_6_output.json", "w", encoding="utf-8") as f:
    json.dump(pipeline_output, f, indent=2)

print("PIPELINE_RUN_SUCCESS")
