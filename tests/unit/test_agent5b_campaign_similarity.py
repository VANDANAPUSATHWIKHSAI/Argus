from agents.agent5b_campaign_similarity.agent import CampaignSimilarityAgent, build_case_signature
from agents.agent5b_campaign_similarity.schemas import SimilarityExecutionStatus


class Embeddings:
    def encode(self, texts):
        assert len(texts) == 1
        return [[0.2, 0.4, 0.8]]


class VectorStore:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return self.results


class Model:
    model_name = "test-model"

    def generate(self, prompt):
        assert "Historical cases are context only" in prompt
        return "Similarity is contextual only."


def agent():
    return CampaignSimilarityAgent(None, None, lambda text, field: text, tenant_id="tenant-1")


def test_builds_signature_from_agents_3_4_and_5a():
    signature = build_case_signature(
        {
            "agent3_output": {
                "attack_pattern": ["initial access", "lateral movement"],
                "evidence_ids": ["F-1"],
            },
            "agent4_output": {
                "persistence": ["registry run key"],
                "c2": ["HTTPS"],
                "evidence_ids": ["F-2"],
            },
            "agent5a_output": {
                "mitre_mappings": ["T1059"],
                "cve_references": ["CVE-2024-1234"],
                "evidence_ids": ["F-3"],
            },
        }
    )

    assert "initial access" in signature.attack_pattern
    assert "registry run key" in signature.behavior
    assert "F-1" in signature.evidence_ids


def test_returns_structured_similarity_and_enforces_tenant_and_validation_filter():
    store = VectorStore(
        [
            {
                "score": 0.9,
                "payload": {
                    "case_id": "CASE-18",
                    "tenant_id": "tenant-1",
                    "validation_status": "approved",
                    "signature": {
                        "behavior": ["registry run key", "HTTPS"],
                        "attack_pattern": ["initial access"],
                        "intelligence": ["T1059"],
                    },
                    "malware_family": "ExampleFamily",
                    "evidence_ids": ["H-1"],
                },
            }
        ]
    )
    result = agent().run(
        "CASE-1",
        {
            "tenant_id": "tenant-1",
            "agent3_output": {"attack_pattern": ["initial access"]},
            "agent4_output": {"persistence": ["registry run key"], "c2": ["HTTPS"]},
            "agent5a_output": {"mitre_mappings": ["T1059"]},
            "embedding_provider": Embeddings(),
            "vector_store": store,
        },
    )

    assert result["execution_status"] == SimilarityExecutionStatus.SUCCESS.value
    assert result["historical_similarity"]["retrieved_cases"][0]["case_id"] == "CASE-18"
    assert result["historical_similarity"]["behavior_similarity"] > 0
    assert store.calls[0]["filters"] == {
        "tenant_id": "tenant-1",
        "validation.status": "approved",
    }


def test_unavailable_qdrant_is_explicit_failure():
    result = agent().run(
        "CASE-1",
        {
            "tenant_id": "tenant-1",
            "embedding_provider": Embeddings(),
        },
    )

    assert result["execution_status"] == SimilarityExecutionStatus.FAILED.value
    assert "vector_store is required" in result["error_details"][0]
