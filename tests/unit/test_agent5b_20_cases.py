"""
Unit Test Suite for Agent 5b — Campaign & Behavior Similarity + Validated Case RAG
==================================================================================
Comprehensive verification of all 20 specified Agent 5b Test Cases:
1. Strong behavioral similarity
2. Weak behavioral similarity
3. Strong attack-pattern similarity
4. Different malware but similar attack
5. Same malware family with different behavior
6. Unknown malware family
7. Agent 5a confidence low
8. Agent 5a sources disagree
9. No historical match
10. Multiple similar historical cases
11. Duplicate historical cases
12. Novel behavior detection
13. Common/new/different classification
14. Tenant isolation
15. Unvalidated case excluded
16. Historical case cannot override current evidence
17. Qdrant unavailable
18. Embedding failure
19. Malformed retrieval payload
20. Invalid evidence references
"""

import unittest
from unittest.mock import MagicMock, patch

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


class DummyModel:
    def __init__(self, name="Qwen3-8B"):
        self.model_name = name

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        return "{}"


def make_validated_case(
    case_id: str,
    tenant_id: str = "tenant_alpha",
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


class TestAgent5bTwentyCases(unittest.TestCase):

    def setUp(self):
        self.model = DummyModel()
        self.vector_engine = MultiVectorEngine()
        self.repo = ValidatedCaseRepository(vector_engine=self.vector_engine)
        self.agent = CampaignSimilarityAgent(
            model=self.model,
            tenant_id="tenant_alpha",
            vector_repo=self.repo,
            vector_engine=self.vector_engine
        )

    # -------------------------------------------------------------
    # 1. Strong behavioral similarity
    # -------------------------------------------------------------
    def test_01_strong_behavioral_similarity(self):
        hist_case = make_validated_case("HIST-001", "tenant_alpha", family="RedLine")
        self.repo.add_case(hist_case)

        agent4_out = {
            "behavior_fingerprint": {
                "execution": ["PowerShell Execution (powershell.exe)"],
                "persistence": ["Registry Run Key (Run)"],
                "credential_access": ["Browser credential theft"],
                "command_and_control": ["HTTPS C2 communication"]
            },
            "evidence_ids": ["FIR-101", "FIR-102"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-001",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertGreaterEqual(len(hs.retrieved_cases), 1)
        self.assertGreaterEqual(hs.behavior_similarity, 0.70)
        self.assertGreaterEqual(hs.composite_similarity, 0.65)
        self.assertIn("PowerShell Execution (powershell.exe)", hs.common_behaviors)

    # -------------------------------------------------------------
    # 2. Weak behavioral similarity
    # -------------------------------------------------------------
    def test_02_weak_behavioral_similarity(self):
        hist_case = make_validated_case("HIST-002", "tenant_alpha", family="RedLine")
        self.repo.add_case(hist_case)

        # Completely unrelated behaviors
        agent4_out = {
            "behavior_fingerprint": {
                "impact": ["Disk wiper raw drive overwriting"],
                "defense_evasion": ["Log clearing wevtutil"],
                "discovery": ["Network share SMB scanning"]
            },
            "evidence_ids": ["FIR-201"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-002",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertLess(hs.behavior_similarity, 0.40)
        self.assertEqual(len(hs.common_behaviors), 0)

    # -------------------------------------------------------------
    # 3. Strong attack-pattern similarity
    # -------------------------------------------------------------
    def test_03_strong_attack_pattern_similarity(self):
        hist_case = make_validated_case("HIST-003", "tenant_alpha")
        self.repo.add_case(hist_case)

        agent3_out = {
            "infection_source": "Phishing email",
            "stages": ["Initial Access", "Execution", "Credential Theft", "Exfiltration"],
            "path": ["Phishing", "PowerShell", "Browser Stealer", "C2"],
            "evidence_ids": ["FIR-301"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-003",
            agent3_output=agent3_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertGreaterEqual(len(hs.retrieved_cases), 1)
        self.assertGreaterEqual(hs.attack_similarity, 0.70)

    # -------------------------------------------------------------
    # 4. Different malware but similar attack
    # -------------------------------------------------------------
    def test_04_different_malware_but_similar_attack(self):
        # Historical: Stealer with browser theft
        hist_case = make_validated_case("HIST-004", "tenant_alpha", family="RedLine")
        self.repo.add_case(hist_case)

        # Current: Ransomware behavior, but identical attack stages
        agent3_out = {
            "infection_source": "Phishing email",
            "stages": ["Initial Access", "Execution", "Credential Theft", "Exfiltration"],
            "path": ["Phishing", "PowerShell", "Browser Stealer", "C2"],
            "evidence_ids": ["FIR-401"]
        }
        agent4_out = {
            "behavior_fingerprint": {
                "impact": ["Volume Shadow Copy Deletion (vssadmin)"],
                "execution": ["cmd.exe batch loop"]
            },
            "evidence_ids": ["FIR-402"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-004",
            agent3_output=agent3_out,
            agent4_output=agent4_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertGreater(hs.attack_similarity, hs.behavior_similarity)
        self.assertGreaterEqual(hs.attack_similarity, 0.60)

    # -------------------------------------------------------------
    # 5. Same malware family with different behavior
    # -------------------------------------------------------------
    def test_05_same_malware_family_with_different_behavior(self):
        hist_case = make_validated_case(
            "HIST-005", "tenant_alpha", family="AsyncRAT",
            fingerprint={
                "persistence": ["Registry Run Key (RunOnce)"],
                "defense_evasion": ["Process Hollowing"]
            }
        )
        self.repo.add_case(hist_case)

        # Current case is AsyncRAT according to 5a, but persistence is Scheduled Task
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

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-005",
            agent4_output=agent4_out,
            agent5a_output=agent5a_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertGreaterEqual(len(hs.different_behaviors), 1)
        pers_diff = [d for d in hs.different_behaviors if d.category == "persistence"]
        self.assertGreaterEqual(len(pers_diff), 1)
        self.assertIn("Scheduled Task", pers_diff[0].current_behavior)

    # -------------------------------------------------------------
    # 6. Unknown malware family
    # -------------------------------------------------------------
    def test_06_unknown_malware_family(self):
        hist_case = make_validated_case("HIST-006", "tenant_alpha", family="LokiBot")
        self.repo.add_case(hist_case)

        # Agent 5a has unknown malware family
        agent5a_out = {
            "threat_intelligence": {
                "candidate_malware_families": ["Unknown"],
                "confidence": 0.50
            },
            "evidence_ids": ["FIR-601"]
        }
        agent4_out = {
            "behavior_fingerprint": {
                "credential_access": ["Browser credential theft"],
                "command_and_control": ["HTTPS C2 communication"]
            },
            "evidence_ids": ["FIR-602"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-006",
            agent4_output=agent4_out,
            agent5a_output=agent5a_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertGreaterEqual(len(hs.retrieved_cases), 1)
        # Contextual family suggestion provided from historical reference
        self.assertGreaterEqual(len(hs.similar_malware_families), 1)
        self.assertEqual(hs.similar_malware_families[0].family_name, "LokiBot")
        self.assertIn("not proof", hs.similar_malware_families[0].caveat.lower())

    # -------------------------------------------------------------
    # 7. Agent 5a confidence low
    # -------------------------------------------------------------
    def test_07_agent_5a_confidence_low(self):
        hist_case = make_validated_case("HIST-007", "tenant_alpha")
        self.repo.add_case(hist_case)

        agent5a_low = {
            "threat_intelligence": {
                "candidate_malware_families": ["RedLine"],
                "confidence": 0.20  # Very low confidence
            },
            "evidence_ids": ["FIR-701"]
        }
        agent4_out = {
            "behavior_fingerprint": {
                "execution": ["PowerShell Execution (powershell.exe)"]
            },
            "evidence_ids": ["FIR-702"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-007",
            agent4_output=agent4_out,
            agent5a_output=agent5a_low,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        # Confidence penalized by low 5a confidence
        self.assertLess(hs.confidence, hs.composite_similarity)

    # -------------------------------------------------------------
    # 8. Agent 5a sources disagree
    # -------------------------------------------------------------
    def test_08_agent_5a_sources_disagree(self):
        hist_case = make_validated_case("HIST-008", "tenant_alpha")
        self.repo.add_case(hist_case)

        agent5a_conflict = {
            "threat_intelligence": {
                "candidate_malware_families": ["RedLine", "Vidar"],
                "confidence": 0.80,
                "intelligence_conflicts": [
                    {"conflict": "Source A reports RedLine, Source B reports Vidar for hash H-10"}
                ]
            },
            "evidence_ids": ["FIR-801"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-008",
            agent5a_output=agent5a_conflict,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        # Confidence penalized by conflicts
        self.assertLess(hs.confidence, 0.80)

    # -------------------------------------------------------------
    # 9. No historical match
    # -------------------------------------------------------------
    def test_09_no_historical_match(self):
        # Empty repository for this tenant
        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-009",
            agent4_output={"behavior_fingerprint": {"execution": ["Unique Custom Kernel Driver"]}},
            tenant_id="empty_tenant"
        )

        hs = output.historical_similarity
        self.assertEqual(len(hs.retrieved_cases), 0)
        self.assertEqual(hs.composite_similarity, 0.0)
        self.assertTrue(hs.novelty.detected)
        self.assertIn("No matching validated historical investigations found", output.claim)

    # -------------------------------------------------------------
    # 10. Multiple similar historical cases
    # -------------------------------------------------------------
    def test_10_multiple_similar_historical_cases(self):
        case1 = make_validated_case("HIST-010-A", "tenant_alpha", family="RedLine")
        case2 = make_validated_case("HIST-010-B", "tenant_alpha", family="Vidar")
        case3 = make_validated_case("HIST-010-C", "tenant_alpha", family="Raccoon")
        self.repo.add_case(case1)
        self.repo.add_case(case2)
        self.repo.add_case(case3)

        agent4_out = {
            "behavior_fingerprint": {
                "execution": ["PowerShell Execution (powershell.exe)"],
                "credential_access": ["Browser credential theft"]
            },
            "evidence_ids": ["FIR-1001"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-010",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha",
            top_k=3
        )

        hs = output.historical_similarity
        self.assertGreaterEqual(len(hs.retrieved_cases), 2)
        # Check sorted descending
        for i in range(len(hs.retrieved_cases) - 1):
            self.assertGreaterEqual(
                hs.retrieved_cases[i].similarity_score,
                hs.retrieved_cases[i + 1].similarity_score
            )

    # -------------------------------------------------------------
    # 11. Duplicate historical cases
    # -------------------------------------------------------------
    def test_11_duplicate_historical_cases(self):
        case_a = make_validated_case("HIST-011-DUP", "tenant_alpha")
        self.repo.add_case(case_a)
        # Add again
        self.repo.add_case(case_a)

        agent4_out = {
            "behavior_fingerprint": {"execution": ["PowerShell Execution (powershell.exe)"]},
            "evidence_ids": ["FIR-1101"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-011",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        ids = [c.case_id for c in hs.retrieved_cases]
        self.assertEqual(len(ids), len(set(ids)), "Duplicates should be purged from retrieved cases")

    # -------------------------------------------------------------
    # 12. Novel behavior detection
    # -------------------------------------------------------------
    def test_12_novel_behavior_detection(self):
        hist_case = make_validated_case("HIST-012", "tenant_alpha")
        self.repo.add_case(hist_case)

        agent4_out = {
            "behavior_fingerprint": {
                "execution": ["PowerShell Execution (powershell.exe)"],
                "exfiltration": ["Cloud-storage exfiltration via rclone to mega.nz"]
            },
            "evidence_ids": ["FIR-1201"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-012",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertTrue(hs.novelty.detected)
        self.assertTrue(any("rclone" in m for m in hs.novelty.novel_mechanisms))
        self.assertIn("Cloud-storage exfiltration via rclone to mega.nz", hs.new_behaviors)

    # -------------------------------------------------------------
    # 13. Common/new/different classification
    # -------------------------------------------------------------
    def test_13_common_new_different_classification(self):
        hist_case = make_validated_case(
            "HIST-013", "tenant_alpha",
            fingerprint={
                "execution": ["PowerShell Execution (powershell.exe)"],
                "persistence": ["Registry Run Key (RunOnce)"]
            }
        )
        self.repo.add_case(hist_case)

        agent4_out = {
            "behavior_fingerprint": {
                "execution": ["PowerShell Execution (powershell.exe)"],      # COMMON
                "persistence": ["Scheduled Task (schtasks /create)"],       # DIFFERENT (same category)
                "command_and_control": ["Discord webhook C2 channel"]        # NEW
            },
            "evidence_ids": ["FIR-1301"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-013",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha"
        )

        hs = output.historical_similarity
        self.assertIn("PowerShell Execution (powershell.exe)", hs.common_behaviors)
        self.assertIn("Discord webhook C2 channel", hs.new_behaviors)
        diff_cats = [d.category for d in hs.different_behaviors]
        self.assertIn("persistence", diff_cats)

    # -------------------------------------------------------------
    # 14. Tenant isolation
    # -------------------------------------------------------------
    def test_14_tenant_isolation(self):
        case_a = make_validated_case("HIST-TENANT-A", tenant_id="tenant_a")
        case_b = make_validated_case("HIST-TENANT-B", tenant_id="tenant_b")
        self.repo.add_case(case_a)
        self.repo.add_case(case_b)

        agent4_out = {
            "behavior_fingerprint": {"execution": ["PowerShell Execution (powershell.exe)"]},
            "evidence_ids": ["FIR-1401"]
        }

        # Query as Tenant A
        out_a: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-T-A",
            agent4_output=agent4_out,
            tenant_id="tenant_a"
        )
        retrieved_a = [c.case_id for c in out_a.historical_similarity.retrieved_cases]
        self.assertIn("HIST-TENANT-A", retrieved_a)
        self.assertNotIn("HIST-TENANT-B", retrieved_a)

        # Query as Tenant B
        out_b: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-T-B",
            agent4_output=agent4_out,
            tenant_id="tenant_b"
        )
        retrieved_b = [c.case_id for c in out_b.historical_similarity.retrieved_cases]
        self.assertIn("HIST-TENANT-B", retrieved_b)
        self.assertNotIn("HIST-TENANT-A", retrieved_b)

    # -------------------------------------------------------------
    # 15. Unvalidated case excluded
    # -------------------------------------------------------------
    def test_15_unvalidated_case_excluded(self):
        # Case with status = 'pending' or 'rejected'
        with self.assertRaises(ValueError):
            unval_case = make_validated_case("HIST-UNVAL", "tenant_alpha", status="pending")
            self.repo.add_case(unval_case)

        with self.assertRaises(ValueError):
            no_approver = make_validated_case("HIST-NO-APP", "tenant_alpha", status="approved", approved_by=None)
            self.repo.add_case(no_approver)

    # -------------------------------------------------------------
    # 16. Historical case cannot override current evidence
    # -------------------------------------------------------------
    def test_16_historical_case_cannot_override_current_evidence(self):
        hist_case = make_validated_case("HIST-016", "tenant_alpha", family="RedLine")
        self.repo.add_case(hist_case)

        agent5a_out = {
            "threat_intelligence": {
                "candidate_malware_families": ["LokiBot"],
                "confidence": 0.90
            },
            "evidence_ids": ["FIR-1601"]
        }

        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-016",
            agent5a_output=agent5a_out,
            tenant_id="tenant_alpha"
        )

        claim_lower = output.claim.lower()
        self.assertNotIn("proves that this is redline", claim_lower)
        self.assertIn("historical cases serve as investigative context", claim_lower)

    # -------------------------------------------------------------
    # 17. Qdrant unavailable
    # -------------------------------------------------------------
    def test_17_qdrant_unavailable(self):
        # Mock search_similar raising connection error
        mock_repo = MagicMock(spec=ValidatedCaseRepository)
        mock_repo.search_similar.side_effect = ConnectionError("Failed to reach Qdrant on port 6333")

        agent_failover = CampaignSimilarityAgent(
            model=self.model,
            tenant_id="tenant_alpha",
            vector_repo=mock_repo
        )

        output: Agent5bOutput = agent_failover.execute_analysis(
            case_id="CURR-017",
            agent4_output={"behavior_fingerprint": {"execution": ["cmd.exe"]}},
            tenant_id="tenant_alpha"
        )

        self.assertEqual(output.execution_status, "degraded")
        self.assertIn("Qdrant unavailable", output.error_message)
        self.assertTrue(any("unavailable" in lim.lower() for lim in output.historical_similarity.limitations))

    # -------------------------------------------------------------
    # 18. Embedding failure
    # -------------------------------------------------------------
    def test_18_embedding_failure(self):
        mock_embedder = MagicMock()
        mock_embedder.encode.side_effect = RuntimeError("CUDA out of memory in EmbeddingLoader")

        engine = MultiVectorEngine(embedder=mock_embedder)
        sig = CaseBehavioralSignature(case_id="CURR-018", tenant_id="tenant_alpha")

        # Fallback handles cleanly and returns normalized vectors
        mvec = engine.generate_vectors(sig)
        self.assertEqual(len(mvec.composite_vector), MultiVectorEngine.VECTOR_DIM)
        self.assertEqual(len(mvec.behavior_vector), MultiVectorEngine.VECTOR_DIM)

    # -------------------------------------------------------------
    # 19. Malformed retrieval payload
    # -------------------------------------------------------------
    def test_19_malformed_retrieval_payload(self):
        # Insert a malformed payload into Qdrant client directly
        if self.repo.client and hasattr(self.repo.client, "upsert"):
            col_name = self.repo._get_collection_name("tenant_alpha")
            self.repo.ensure_collection("tenant_alpha")
            from qdrant_client import models
            # Corrupted payload missing required fields
            bad_point = models.PointStruct(
                id="00000000-0000-0000-0000-000000000999",
                vector={
                    "behavior": [0.1] * 384,
                    "attack": [0.1] * 384,
                    "threat_intel": [0.1] * 384,
                    "composite": [0.1] * 384
                },
                payload={"corrupt_data": True, "broken": 123}
            )
            self.repo.client.upsert(col_name, points=[bad_point])

        qvecs = self.vector_engine.generate_vectors(CaseBehavioralSignature(case_id="C", tenant_id="tenant_alpha"))
        # Should skip malformed payload without raising exception
        results = self.repo.search_similar("tenant_alpha", qvecs)
        self.assertIsInstance(results, list)

    # -------------------------------------------------------------
    # 20. Invalid evidence references
    # -------------------------------------------------------------
    def test_20_invalid_evidence_references(self):
        hist_case = make_validated_case("HIST-020", "tenant_alpha")
        self.repo.add_case(hist_case)

        agent4_out = {
            "behavior_fingerprint": {"execution": ["cmd.exe"]},
            "evidence_ids": ["FIR-VALID-1", "FIR-VALID-2"]
        }

        # Simulate agent execution with valid evidence IDs
        output: Agent5bOutput = self.agent.execute_analysis(
            case_id="CURR-020",
            agent4_output=agent4_out,
            tenant_id="tenant_alpha",
            evidence_ids=["FIR-VALID-1", "FIR-VALID-2"]
        )

        # Inject fake evidence id into output manually and re-validate
        output.evidence_ids.append("FIR-FAKE-HALLUCINATED")
        from agents.agent5b_campaign_similarity.validator import Agent5bValidator
        refined = Agent5bValidator.validate_and_refine(output, valid_evidence_ids={"FIR-VALID-1", "FIR-VALID-2"})

        self.assertNotIn("FIR-FAKE-HALLUCINATED", refined.evidence_ids)
        self.assertIn("FIR-VALID-1", refined.evidence_ids)
        self.assertIn("FIR-VALID-2", refined.evidence_ids)


if __name__ == "__main__":
    unittest.main()
