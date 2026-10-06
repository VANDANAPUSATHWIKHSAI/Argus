"""
Comprehensive test suite verifying all 12 Agent 4 Test Cases specified in the user request.
"""

import unittest
from agents.agent4_malware_behaviour import MalwareBehaviourAgent
from agents.agent4_malware_behaviour.schemas import Agent4Output, ExecutionStatus


class DummyModel:
    def __init__(self, name="Qwen3-8B"):
        self.model_name = name

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        return "{}"


class TestAgent4TwelveCases(unittest.TestCase):

    def setUp(self):
        self.model = DummyModel()
        self.agent = MalwareBehaviourAgent(model=self.model, fir_repo=None, sanitization_gateway=None)

    # Test Case 1 — PowerShell Execution
    def test_case_01_powershell_execution(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC1-01",
                "fact": "Process cmd.exe spawned powershell.exe script execution",
                "category": "process"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC1", {}, fir_findings=fir_findings)
        self.assertEqual(output.execution_status, ExecutionStatus.SUCCESS)

        obs = [o for o in output.behavior_observations if o.category == "execution"]
        self.assertGreaterEqual(len(obs), 1)
        self.assertGreater(obs[0].confidence, 0.0)

        claims = [c for c in output.claims if "T1059.001" in c.mitre_techniques]
        self.assertGreaterEqual(len(claims), 1)

    # Test Case 2 — Registry Persistence
    def test_case_02_registry_persistence(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC2-01",
                "fact": "update.exe created entry in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run Updater",
                "category": "registry"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC2", {}, fir_findings=fir_findings)
        pers_obs = [o for o in output.behavior_observations if o.category == "persistence"]
        self.assertGreaterEqual(len(pers_obs), 1)
        self.assertIn("Registry Run Key", pers_obs[0].behavior)

    # Test Case 3 — Scheduled Task
    def test_case_03_scheduled_task(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC3-01",
                "fact": "schtasks.exe created persistent task for update.exe",
                "category": "process"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC3", {}, fir_findings=fir_findings)
        pers_obs = [o for o in output.behavior_observations if o.category == "persistence"]
        self.assertGreaterEqual(len(pers_obs), 1)

        claims = [c for c in output.claims if "T1053.005" in c.mitre_techniques]
        self.assertGreaterEqual(len(claims), 1)

    # Test Case 4 — Browser Credential Theft
    def test_case_04_browser_credential_theft(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC4-01",
                "fact": "Process opened Chrome SQLite Login Data database",
                "category": "credential_access"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC4", {}, fir_findings=fir_findings)
        cred_obs = [o for o in output.behavior_observations if o.category == "credential_access"]
        self.assertGreaterEqual(len(cred_obs), 1)

    # Test Case 5 — LSASS Access
    def test_case_05_lsass_access(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC5-01",
                "fact": "lsass.exe handle access initiated by update.exe",
                "category": "process"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC5", {}, fir_findings=fir_findings)
        cred_obs = [o for o in output.behavior_observations if o.category == "credential_access"]
        self.assertGreaterEqual(len(cred_obs), 1)

        claims = [c for c in output.claims if "T1003" in c.mitre_techniques]
        self.assertGreaterEqual(len(claims), 1)

    # Test Case 6 — Process Injection
    def test_case_06_process_injection(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC6-01",
                "fact": "Process invoked WriteProcessMemory and CreateRemoteThread for injection",
                "category": "process"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC6", {}, fir_findings=fir_findings)
        evasion_obs = [o for o in output.behavior_observations if o.category == "defense_evasion"]
        self.assertGreaterEqual(len(evasion_obs), 1)
        self.assertEqual(evasion_obs[0].behavior, "Process Injection")

    # Test Case 7 — Command & Control
    def test_case_07_command_and_control(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC7-01",
                "fact": "Persistent outbound HTTPS communication socket established",
                "category": "network"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC7", {}, fir_findings=fir_findings)
        c2_obs = [o for o in output.behavior_observations if o.category == "command_and_control"]
        self.assertGreaterEqual(len(c2_obs), 1)

    # Test Case 8 — Data Exfiltration
    def test_case_08_data_exfiltration(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC8-01",
                "fact": "Archive created and uploaded externally",
                "category": "network"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC8", {}, fir_findings=fir_findings)
        exfil_obs = [o for o in output.behavior_observations if o.category == "exfiltration"]
        self.assertGreaterEqual(len(exfil_obs), 1)

    # Test Case 9 — Novel Threat Candidate
    def test_case_09_novel_threat_candidate(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC9-01",
                "fact": "Uncharacterized anomalous suspicious behavior pattern without MITRE mapping",
                "category": "unclassified"
            }
        ]
        # Simulate suspicious claim without MITRE mapping
        output: Agent4Output = self.agent.execute_analysis("TC9", {}, fir_findings=fir_findings)
        # Verify novel threat detector ran
        self.assertIsNotNone(output.novel_threat_profile)
        self.assertTrue(output.novel_threat_profile.novel_behavior_candidate)

    # Test Case 10 — Contradictory Evidence
    def test_case_10_contradictory_evidence(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC10-01",
                "fact": "Run key created HKCU\\...\\Run Updater",
                "category": "registry"
            },
            {
                "finding_id": "FIR-TC10-02",
                "fact": "Run key deleted HKCU\\...\\Run Updater",
                "category": "registry"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC10", {}, fir_findings=fir_findings)
        self.assertTrue(output.ambiguity_detected)
        self.assertGreaterEqual(len(output.contradictions), 1)

    # Test Case 11 — Missing Evidence
    def test_case_11_missing_evidence(self):
        fir_findings = [
            {
                "finding_id": "FIR-TC11-01",
                "fact": "Generic persistence hypothesis without registry or scheduled task mechanism",
                "category": "persistence"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis("TC11", {}, fir_findings=fir_findings)
        pers_obs = [o for o in output.behavior_observations if o.category == "persistence"]
        if pers_obs:
            self.assertEqual(pers_obs[0].claim_status, "insufficient_evidence")

    # Test Case 12 — End-to-End Validation
    def test_case_12_end_to_end_validation(self):
        agent2_context = {
            "claims": [
                {
                    "claim_id": "CLM-AG2-001",
                    "summary": "Correlated PowerShell Execution and C2 Network Connection via 192.168.1.50",
                    "cited_evidence_ids": ["FIR-E2E-01", "FIR-E2E-02"]
                }
            ]
        }
        fir_findings = [
            {
                "finding_id": "FIR-E2E-01",
                "fact": "powershell.exe executed with payload hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "category": "process"
            },
            {
                "finding_id": "FIR-E2E-02",
                "fact": "update.exe created HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run Updater",
                "category": "registry"
            },
            {
                "finding_id": "FIR-E2E-03",
                "fact": "Established network socket connection to 192.168.001.050 transferring 450KB",
                "category": "network"
            }
        ]
        yara_matches = [
            {
                "finding_id": "FIR-E2E-01",
                "rule_name": "Suspicious_Powershell_Loader",
                "file_path": "powershell.exe"
            }
        ]

        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-E2E-FULL",
            agent2_input=agent2_context,
            fir_findings=fir_findings,
            yara_matches=yara_matches
        )

        # Assertions for End-to-End completeness
        self.assertEqual(output.execution_status, ExecutionStatus.SUCCESS)
        self.assertGreaterEqual(len(output.behavior_observations), 1)  # Behavior Matrix
        self.assertGreaterEqual(len(output.mitre_tactics), 1)           # MITRE Mapping
        self.assertIn("192.168.1.50", output.ioc_collection.ips)        # Normalized IOC Extraction
        self.assertIsNotNone(output.malware_profile)                   # Malware Profile
        self.assertGreaterEqual(len(output.graph_updates), 1)           # Knowledge Graph Triplets
        self.assertIsNotNone(output.agent5_input_summary)               # Agent 5 Summary Handoff
        self.assertIsNotNone(output.model_dump())                       # No Schema Errors


if __name__ == "__main__":
    unittest.main()
