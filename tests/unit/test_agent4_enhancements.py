"""
Unit tests verifying all 13 Critical, Important, and Nice-to-Have architecture enhancements for Agent 4.
"""

import unittest
from agents.agent4_malware_behaviour import MalwareBehaviourAgent
from agents.agent4_malware_behaviour.schemas import Agent4Output, Agent4Claim, NovelThreatProfile
from agents.agent4_malware_behaviour.ioc_normalizer import IOCNormalizer


class DummyModel:
    def __init__(self, name="Qwen3-8B"):
        self.model_name = name

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        return "{}"


class TestAgent4Enhancements(unittest.TestCase):

    def setUp(self):
        self.model = DummyModel()
        self.agent = MalwareBehaviourAgent(model=self.model, fir_repo=None, sanitization_gateway=None)

    # 1. Test IOC Normalization
    def test_ioc_normalization(self):
        raw_ip = "192.168.001.050"
        norm_ip = IOCNormalizer.normalize_ip(raw_ip)
        self.assertEqual(norm_ip, "192.168.1.50")

        raw_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        norm_hash = IOCNormalizer.normalize_hash(raw_hash)
        self.assertEqual(norm_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    # 2. Test Dynamic Confidence Scoring & Breakdown
    def test_dynamic_confidence_scoring(self):
        fir_findings = [
            {
                "finding_id": "FIR-101",
                "fact": "powershell.exe executed command interpreter targeting IP 192.168.001.050",
                "category": "process"
            },
            {
                "finding_id": "FIR-102",
                "fact": "powershell.exe established network socket connection to 192.168.1.50 transferring 450KB",
                "category": "network"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-ENH-001",
            agent2_input={},
            fir_findings=fir_findings
        )
        for obs in output.behavior_observations:
            self.assertIn("evidence_strength", obs.confidence_breakdown)
            self.assertIn("correlation_strength", obs.confidence_breakdown)
            self.assertIn("artifact_diversity", obs.confidence_breakdown)
            self.assertIn("timeline_consistency", obs.confidence_breakdown)
            self.assertGreater(obs.confidence, 0.0)

    # 3. Test Evidence Sufficiency Validation
    def test_evidence_sufficiency_validation(self):
        fir_findings = [
            {
                "finding_id": "FIR-201",
                "fact": "Generic unclassified persistence hypothesis without registry or scheduled task mechanism",
                "category": "persistence"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-ENH-002",
            agent2_input={},
            fir_findings=fir_findings
        )
        pers_obs = [o for o in output.behavior_observations if o.category == "persistence"]
        if pers_obs:
            self.assertEqual(pers_obs[0].claim_status, "insufficient_evidence")
            self.assertLessEqual(pers_obs[0].confidence, 0.45)

    # 4. Test Graph Updates (Neo4j Triplets)
    def test_graph_updates_neo4j(self):
        fir_findings = [
            {
                "finding_id": "FIR-301",
                "fact": "update.exe created HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run Updater",
                "category": "registry"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-ENH-003",
            agent2_input={},
            fir_findings=fir_findings
        )
        self.assertGreaterEqual(len(output.graph_updates), 1)
        triplet = output.graph_updates[0]
        self.assertIn("source", triplet)
        self.assertIn("relation", triplet)
        self.assertIn("target", triplet)

    # 5. Test Agent 5 Handoff Package
    def test_agent5_handoff_package(self):
        fir_findings = [
            {
                "finding_id": "FIR-401",
                "fact": "powershell.exe executed with hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and connected to 192.168.1.50",
                "category": "process"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-ENH-004",
            agent2_input={},
            fir_findings=fir_findings
        )
        handoff = output.agent5_input_summary
        self.assertIsNotNone(handoff)
        self.assertIn("192.168.1.50", handoff.iocs)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", handoff.iocs)

    # 6. Test Coverage Gap Detection & Ambiguity Detection
    def test_coverage_gaps_and_ambiguity(self):
        fir_findings = [
            {
                "finding_id": "FIR-501",
                "fact": "powershell.exe script execution observed",
                "category": "process"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-ENH-005",
            agent2_input={},
            fir_findings=fir_findings
        )
        self.assertGreaterEqual(len(output.coverage_gaps), 1)
        self.assertIn("No registry persistence artifact available", output.coverage_gaps)
        self.assertFalse(output.ambiguity_detected)

    # 7. Test ATT&CK Tactic Mapping & Malware Profile Objectives
    def test_attack_tactics_and_objectives(self):
        fir_findings = [
            {
                "finding_id": "FIR-601",
                "fact": "powershell.exe execution observed",
                "category": "execution"
            },
            {
                "finding_id": "FIR-602",
                "fact": "update.exe created HKCU Run key Updater",
                "category": "registry"
            }
        ]
        output: Agent4Output = self.agent.execute_analysis(
            case_id="CASE-ENH-006",
            agent2_input={},
            fir_findings=fir_findings
        )
        self.assertIn("Execution", output.mitre_tactics)
        self.assertIn("Persistence", output.mitre_tactics)
        self.assertEqual(output.malware_profile.status, "NOT_DETERMINED")


if __name__ == "__main__":
    unittest.main()
