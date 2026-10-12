import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, '.')

from models.llm import OllamaWrapper
from sanitization.gateway import SanitizationGateway
from agents.agent4_malware_behaviour import MalwareBehaviourAgent
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

class FastMockLLM:
    """Fast deterministic mock for instant dry-run execution."""
    def __init__(self, name="Qwen3-8B"):
        self.model_name = name

    def generate(self, prompt, system_prompt=None):
        return "{}"

def run_dry_run():
    print("=" * 80)
    print("   ARGUS FORENSIC PIPELINE: DRY RUN FOR AGENT 4 & AGENT 5B")
    print("=" * 80)

    # -------------------------------------------------------------
    # STEP 1: INITIALIZE REPOSITORIES AND AGENT 4
    # -------------------------------------------------------------
    print("\n[+] Initializing Agent 4 (Malware Behaviour Analysis & Profiling)...")
    gateway = SanitizationGateway()
    gateway.classifier = None
    gateway.sanitize = lambda text, field_name="fact": text

    # Use FastMockLLM for predictable, ultra-fast, deterministic verification
    model = FastMockLLM(name="Qwen3-8B")
    
    agent4 = MalwareBehaviourAgent(
        model=model,
        fir_repo=None,
        sanitization_gateway=gateway,
        tenant_id="tenant_enterprise"
    )

    case_id = "CASE-DRYRUN-2026-001"
    tenant_id = "tenant_enterprise"

    # Forensic inputs for Agent 4
    fir_findings = [
        {
            "finding_id": "FIR-2026-001",
            "fact": "Process execution: powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\payload.ps1",
            "sanitized_fact": "Process execution: powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\payload.ps1",
            "category": "execution",
            "metadata": {"process": "powershell.exe", "file": "payload.ps1"}
        },
        {
            "finding_id": "FIR-2026-002",
            "fact": "Registry persistence created: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinSecurityUpdater set to powershell.exe",
            "sanitized_fact": "Registry persistence created: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinSecurityUpdater set to powershell.exe",
            "category": "persistence",
            "metadata": {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "WinSecurityUpdater"}
        },
        {
            "finding_id": "FIR-2026-003",
            "fact": "Outbound network connection: powershell.exe established HTTPS C2 connection to 198.51.100.22:443 (c2-gateway-update.net)",
            "sanitized_fact": "Outbound network connection: powershell.exe established HTTPS C2 connection to 198.51.100.22:443 (c2-gateway-update.net)",
            "category": "command_and_control",
            "metadata": {"ip": "198.51.100.22", "domain": "c2-gateway-update.net", "port": 443}
        },
        {
            "finding_id": "FIR-2026-004",
            "fact": "Credential theft: accessed browser SQLite Login Data and dumped credentials from memory via MiniDumpWriteDump",
            "sanitized_fact": "Credential theft: accessed browser SQLite Login Data and dumped credentials from memory via MiniDumpWriteDump",
            "category": "credential_access",
            "metadata": {"target": "Browser SQLite / LSASS"}
        },
        {
            "finding_id": "FIR-2026-005",
            "fact": "Defense evasion: executed Set-MpPreference -DisableRealtimeMonitoring $true to evade Windows Defender",
            "sanitized_fact": "Defense evasion: executed Set-MpPreference -DisableRealtimeMonitoring $true to evade Windows Defender",
            "category": "defense_evasion",
            "metadata": {"target": "Windows Defender"}
        }
    ]

    yara_matches = [
        {
            "finding_id": "FIR-2026-001",
            "rule_name": "Suspicious_PowerShell_Dropper",
            "file_path": "C:\\Users\\Public\\payload.ps1",
            "matched_strings": ["-ExecutionPolicy Bypass", "DownloadString"]
        }
    ]

    agent2_context = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "claims": [
            {
                "claim_id": "CLM-AG2-001",
                "summary": "Correlated PowerShell execution with persistence and C2 network activity",
                "cited_evidence_ids": ["FIR-2026-001", "FIR-2026-002", "FIR-2026-003"],
                "confidence_score": 0.95,
                "behaviour_category": "execution"
            }
        ]
    }

    # -------------------------------------------------------------
    # STEP 2: EXECUTE AGENT 4 DRY RUN
    # -------------------------------------------------------------
    print(f"[+] Executing Agent 4 analysis for {case_id}...")
    agent4_output = agent4.execute_analysis(
        case_id=case_id,
        agent2_input=agent2_context,
        tenant_id=tenant_id,
        fir_findings=fir_findings,
        yara_matches=yara_matches
    )

    agent4_dict = agent4_output.model_dump()
    with open("scratch/agent4_dryrun_output.json", "w", encoding="utf-8") as f:
        json.dump(agent4_dict, f, indent=2)
    print("    -> Agent 4 completed successfully! Saved to scratch/agent4_dryrun_output.json")

    # -------------------------------------------------------------
    # STEP 3: CONFIGURE SEED HISTORICAL CASES IN AGENT 5B RAG
    # -------------------------------------------------------------
    print("\n[+] Setting up Agent 5b (Campaign & Similarity + Validated Case RAG)...")
    vector_engine = MultiVectorEngine()
    case_repo = ValidatedCaseRepository(vector_engine=vector_engine)

    # Historical Case 1: RedLine InfoStealer (Approved Maker-Checker case in tenant_enterprise)
    case_repo.add_case(ValidatedCase(
        case_id="HIST-CASE-2025-089",
        tenant_id=tenant_id,
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
            "persistence": ["Registry Run Key (Run)"],
            "command_and_control": ["HTTPS C2 communication"],
            "credential_access": ["Browser credential theft (SQLite extraction)"]
        },
        attack_pattern={
            "infection_source": "Phishing Email with Malicious LNK",
            "stages": ["Initial Access", "Execution", "Persistence", "Credential Access", "Command and Control"],
            "path": ["Phishing Email -> PowerShell Script -> Registry Run Key -> HTTPS C2"]
        },
        threat_intelligence={
            "mitre_techniques": ["T1566.001", "T1059.001", "T1547.001", "T1555.003", "T1071.001"],
            "iocs": ["198.51.100.22", "c2-gateway-update.net"]
        },
        associated_campaigns=["Operation FrozenSteal"],
        threat_actor="Storm-0501"
    ))

    # Historical Case 2: Vidar InfoStealer (Approved Maker-Checker case)
    case_repo.add_case(ValidatedCase(
        case_id="HIST-CASE-2025-042",
        tenant_id=tenant_id,
        validation=CaseValidationRecord(
            status="approved",
            approved_by="senior_soc_reviewer",
            approval_timestamp="2025-08-20T14:15:00Z",
            notes="Vidar infostealer incident involving scheduled task persistence."
        ),
        malware_identity=MalwareIdentity(
            family="Vidar",
            confidence=0.88,
            identity_confidence=0.88
        ),
        malware_behavior_fingerprint={
            "execution": ["Command Shell (cmd.exe)"],
            "persistence": ["Scheduled Task (schtasks)"],
            "command_and_control": ["HTTPS C2 communication"],
            "credential_access": ["Browser credential theft (SQLite extraction)"]
        },
        attack_pattern={
            "infection_source": "Malvertising ISO download",
            "stages": ["Initial Access", "Execution", "Persistence", "Credential Access", "Command and Control"],
            "path": ["ISO -> LNK -> cmd.exe -> schtasks -> HTTPS C2"]
        },
        threat_intelligence={
            "mitre_techniques": ["T1204.002", "T1059.003", "T1053.005", "T1555.003", "T1071.001"],
            "iocs": ["198.51.100.88", "vidar-fast-sync.org"]
        },
        associated_campaigns=["Vidar Stealer Waves 2025"],
        threat_actor="Unknown / Affiliate"
    ))

    agent5b = CampaignSimilarityAgent(
        model=model,
        fir_repo=None,
        sanitization_gateway=gateway,
        tenant_id=tenant_id,
        vector_repo=case_repo,
        vector_engine=vector_engine
    )

    # -------------------------------------------------------------
    # STEP 4: PREPARE UPSTREAM INPUTS (AGENT 3, 4, 5A)
    # -------------------------------------------------------------
    agent3_output = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "attack_stages": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Command and Control"],
        "attack_path": ["Phishing LNK -> PowerShell Execution -> Registry Run Key -> Defense Evasion -> Browser Credential Theft -> HTTPS C2"],
        "infection_source": "Phishing Email with Malicious LNK",
        "tactics": {
            "execution": ["Command and Scripting Interpreter: PowerShell (T1059.001)"],
            "persistence": ["Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)"],
            "defense_evasion": ["Impair Defenses: Disable or Modify Tools (T1562.001)"],
            "credential_access": ["Credentials from Password Stores: Credentials from Web Browsers (T1555.003)"],
            "command_and_control": ["Application Layer Protocol: Web Protocols (T1071.001)"]
        },
        "evidence_ids": ["FIR-2026-001", "FIR-2026-002", "FIR-2026-003", "FIR-2026-004", "FIR-2026-005"]
    }

    agent5a_output = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "threat_intelligence": {
            "candidate_malware_families": ["RedLine Stealer", "Vidar"],
            "mitre_techniques": ["T1059.001", "T1547.001", "T1562.001", "T1555.003", "T1071.001"],
            "ioc_matches": [
                {"indicator": "198.51.100.22", "type": "ipv4", "threat": "C2 Server", "confidence": 0.95},
                {"indicator": "c2-gateway-update.net", "type": "domain", "threat": "C2 Domain", "confidence": 0.90}
            ],
            "confidence": 0.92
        },
        "evidence_ids": ["FIR-2026-003"]
    }

    # Pass the actual output from Agent 4
    agent4_input_dict = agent4_dict

    authoritative_evidence_ids = [
        "FIR-2026-001", "FIR-2026-002", "FIR-2026-003", "FIR-2026-004", "FIR-2026-005"
    ]

    # -------------------------------------------------------------
    # STEP 5: EXECUTE AGENT 5B DRY RUN
    # -------------------------------------------------------------
    print(f"[+] Executing Agent 5b similarity & RAG analysis for {case_id}...")
    agent5b_output: Agent5bOutput = agent5b.execute_analysis(
        case_id=case_id,
        agent3_output=agent3_output,
        agent4_output=agent4_input_dict,
        agent5a_output=agent5a_output,
        agent2_output=agent2_context,
        tenant_id=tenant_id,
        evidence_ids=authoritative_evidence_ids,
        top_k=5
    )

    agent5b_dict = agent5b_output.model_dump()
    with open("scratch/agent5b_dryrun_output.json", "w", encoding="utf-8") as f:
        json.dump(agent5b_dict, f, indent=2)
    print("    -> Agent 5b completed successfully! Saved to scratch/agent5b_dryrun_output.json")

    # -------------------------------------------------------------
    # STEP 6: PRINT STRUCTURED CONSOLE SUMMARY
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("                 DRY RUN OUTPUT EXECUTIVE SUMMARY")
    print("=" * 80)

    print("\n--- [AGENT 4: MALWARE BEHAVIOUR & PROFILING SUMMARY] ---")
    print(f"Status: {agent4_output.execution_status.value}")
    print(f"Global Threat Classification: {agent4_output.threat_classification.label.upper()} ({agent4_output.threat_classification.reason})")
    print(f"Threat Family Inferred: {agent4_output.malware_profile.threat_family}")
    print(f"Family Similarity: {agent4_output.malware_profile.family_similarity} (Conf: {agent4_output.malware_profile.similarity_confidence})")
    print(f"Primary Objective: {agent4_output.malware_profile.primary_objective}")
    print(f"Likely Objectives: {', '.join(agent4_output.malware_profile.likely_objectives)}")
    print(f"Behavior Observations ({len(agent4_output.behavior_observations)} total):")
    for obs in agent4_output.behavior_observations:
        print(f"  * [{obs.category.upper()}] {obs.behavior} | Mech: {obs.mechanism.type} | Evidence: {obs.evidence_ids}")

    print(f"\nBehavior Fingerprint Categories:")
    for cat, acts in agent4_output.behavior_fingerprint.model_dump().items():
        if acts:
            print(f"  * {cat}: {acts}")

    print(f"\nNovel Threat Analysis:")
    print(f"  * Novel Threat Detected: {agent4_output.novel_threat_detected}")
    print(f"  * Novelty Score: {agent4_output.novelty_score}")
    print(f"  * MITRE Match Found: {agent4_output.mitre_match_found}")

    print("\n--- [AGENT 5B: CAMPAIGN SIMILARITY & VALIDATED CASE RAG SUMMARY] ---")
    print(f"Status: {agent5b_output.execution_status}")
    print(f"Investigative Confidence: {agent5b_output.historical_similarity.confidence:.2f} ({agent5b_output.historical_similarity.confidence_methodology})")
    print(f"Similarity Metrics:")
    print(f"  * Behavior Similarity:     {agent5b_output.historical_similarity.behavior_similarity:.4f}")
    print(f"  * Attack Path Similarity:   {agent5b_output.historical_similarity.attack_similarity:.4f}")
    print(f"  * Threat Intel Similarity:  {agent5b_output.historical_similarity.intelligence_similarity:.4f}")
    print(f"  * Composite Similarity:     {agent5b_output.historical_similarity.composite_similarity:.4f}")

    print(f"\nRetrieved Approved Historical Cases ({len(agent5b_output.historical_similarity.retrieved_cases)}):")
    for rc in agent5b_output.historical_similarity.retrieved_cases:
        print(f"  * Case: {rc.case_id} | Family: {rc.case_data.malware_identity.family} | Retrieval Score: {rc.similarity_score:.4f} | Status: {rc.case_data.validation.status} (by {rc.case_data.validation.approved_by})")

    print(f"\nBehavior Delta Analysis:")
    print(f"  * Common Behaviors:        {len(agent5b_output.historical_similarity.common_behaviors)} -> {agent5b_output.historical_similarity.common_behaviors[:3]}")
    print(f"  * New Behaviors:           {len(agent5b_output.historical_similarity.new_behaviors)} -> {agent5b_output.historical_similarity.new_behaviors}")
    print(f"  * Different Behaviors:     {len(agent5b_output.historical_similarity.different_behaviors)}")
    print(f"  * Historical-Only:         {len(agent5b_output.historical_similarity.historical_only_behaviors)}")
    print(f"  * Novelty Score:           {agent5b_output.historical_similarity.novelty.novelty_score:.4f}")

    print(f"\nAssociated Campaigns: {agent5b_output.historical_similarity.similar_campaigns}")
    print(f"Possible Threat Actor:  {agent5b_output.historical_similarity.possible_actor_context}")

    print(f"\nInvestigative Claim:")
    print(f"  \"{agent5b_output.claim}\"")
    print(f"  Citations: {agent5b_output.evidence_ids}")

    print(f"\nAgent 6 Handoff Package:")
    print(f"  * Case ID: {agent5b_output.agent6_handoff.case_id}")
    print(f"  * Historical References: {agent5b_output.agent6_handoff.validated_historical_references}")
    print(f"  * Attribution Safeguards: {agent5b_output.agent6_handoff.attribution_safeguards}")

    print("\n" + "=" * 80)
    print("                     DRY RUN COMPLETED SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    run_dry_run()
