from __future__ import annotations

from typing import Any, Iterable

from agents.base_agent import BaseAgent
from agents.agent5b_campaign_similarity.schemas import (
    Agent5bOutput,
    CaseSignature,
    HistoricalCaseReference,
    HistoricalSimilarity,
    SimilarityExecutionStatus,
)


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value if isinstance(value, dict) else {}


def _values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        return value.values()
    if isinstance(value, list):
        return value
    return [value]


def _strings(value: Any) -> list[str]:
    result: list[str] = []
    for item in _values(value):
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
        elif isinstance(item, (dict, list)):
            result.extend(_strings(item))
    return result


def _unique(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value})


def _section(data: dict[str, Any], names: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for name in names:
        if name in data:
            values.extend(_strings(data[name]))
    return _unique(values)


def build_case_signature(context: dict[str, Any]) -> CaseSignature:
    agent3 = _as_dict(context.get("agent3_output", {}))
    agent4 = _as_dict(context.get("agent4_output", {}))
    agent5a = _as_dict(context.get("agent5a_output", {}))

    behavior = _section(
        agent4,
        (
            "behavior",
            "behaviors",
            "behavior_chain",
            "persistence",
            "credential_access",
            "privilege_escalation",
            "defense_evasion",
            "discovery",
            "command_and_control",
            "c2",
            "collection",
            "exfiltration",
            "impact",
        ),
    )
    attack_pattern = _section(
        agent3,
        (
            "attack_pattern",
            "attack_path",
            "attack_stages",
            "kill_chain",
            "techniques",
            "timeline",
            "lateral_movement",
        ),
    )
    intelligence = _section(
        agent5a,
        (
            "ioc_matches",
            "mitre_mappings",
            "vulnerability_matches",
            "cisa_kev_results",
            "threat_reports",
            "candidate_malware_families",
            "intelligence_conflicts",
        ),
    )
    yara = _section(agent4, ("yara", "yara_matches", "matched_rules", "rule_categories"))
    evidence_ids = _unique(
        [
            str(item)
            for output in (agent3, agent4, agent5a)
            for item in output.get("evidence_ids", [])
        ]
    )
    return CaseSignature(
        behavior=behavior,
        attack_pattern=attack_pattern,
        intelligence=intelligence,
        yara=yara,
        evidence_ids=evidence_ids,
    )


def _payload(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result.get("payload", result)
    payload = getattr(result, "payload", None)
    return payload if isinstance(payload, dict) else {}


def _score(result: Any) -> float:
    value = result.get("score", 0.0) if isinstance(result, dict) else getattr(result, "score", 0.0)
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _similarity(current: list[str], historical: Any) -> tuple[float, list[str], list[str], list[str]]:
    current_set = set(current)
    historical_set = set(_strings(historical))
    common = sorted(current_set & historical_set)
    new = sorted(current_set - historical_set)
    different = sorted(historical_set - current_set)
    denominator = len(current_set | historical_set)
    return (len(common) / denominator if denominator else 0.0, common, new, different)


class CampaignSimilarityAgent(BaseAgent):
    """Compare structured current-case signatures with approved case knowledge."""

    collection = "validated_cases"
    top_k = 5

    def run(self, case_id: str, context: dict) -> dict:
        tenant_id = str(context.get("tenant_id", self.tenant_id or "default"))
        signature = build_case_signature(context)
        base = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "current_signature": signature,
            "evidence_ids": signature.evidence_ids,
        }
        vector_store = context.get("vector_store")
        if vector_store is None:
            return self._failure(base, "vector_store is required")

        try:
            embedding_provider = context.get("embedding_provider")
            if embedding_provider is None:
                from models.embeddings import EmbeddingLoader

                embedding_provider = EmbeddingLoader()
            vectors = embedding_provider.encode([signature.to_text()])
            if not vectors or not isinstance(vectors[0], list):
                raise ValueError("embedding provider returned no vector")
            results = vector_store.search(
                collection=self.collection,
                query_vector=vectors[0],
                top_k=self.top_k,
                filters={
                    "tenant_id": tenant_id,
                    "validation.status": "approved",
                },
            )
            if not isinstance(results, list):
                raise TypeError("vector store returned a non-list result")
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return self._failure(base, f"retrieval failed: {type(exc).__name__}: {exc}")

        references = [self._reference(result, signature) for result in results]
        historical = self._aggregate(references)
        reasoning = self._reason(signature, historical)
        if reasoning:
            historical.explanations.append(reasoning)
        status = (
            SimilarityExecutionStatus.SUCCESS
            if references
            else SimilarityExecutionStatus.PARTIAL_SUCCESS
        )
        output = Agent5bOutput(
            **base,
            execution_status=status,
            historical_similarity=historical,
            claim=(
                f"Historical similarity completed with status {status.value}; "
                f"{len(references)} validated cases retrieved. Similarity is contextual only."
            ),
            model_used=getattr(self.model, "model_name", None),
        )
        return output.model_dump(mode="json")

    def _reference(self, result: Any, signature: CaseSignature) -> HistoricalCaseReference:
        payload = _payload(result)
        historical = payload.get("signature", payload)
        behavior_score, common, new, different = _similarity(
            signature.behavior,
            historical.get("behavior", historical.get("malware_behavior_fingerprint", [])),
        )
        attack_score, _, _, _ = _similarity(
            signature.attack_pattern,
            historical.get("attack_pattern", []),
        )
        intelligence_score, _, _, _ = _similarity(
            signature.intelligence,
            historical.get("intelligence", historical.get("threat_intelligence", [])),
        )
        return HistoricalCaseReference(
            case_id=str(payload.get("case_id", payload.get("source_case_id", "unknown"))),
            score=_score(result),
            behavior_similarity=behavior_score,
            attack_similarity=attack_score,
            intelligence_similarity=intelligence_score,
            validation_status=str(
                payload.get("validation_status", _as_dict(payload.get("validation", {})).get("status", "unknown"))
            ),
            malware_family=payload.get("malware_family")
            or _as_dict(payload.get("malware_identity", {})).get("family"),
            campaign=payload.get("campaign"),
            evidence_ids=_unique(str(item) for item in payload.get("evidence_ids", [])),
            common=common,
            new=new,
            different=different,
            limitations=["Historical similarity is not proof of identity or attribution."],
        )

    @staticmethod
    def _aggregate(references: list[HistoricalCaseReference]) -> HistoricalSimilarity:
        if not references:
            return HistoricalSimilarity(
                novelty_detected=True,
                novelty_observations=["No approved historical case matched the current signature."],
                confidence=0.0,
                limitations=["No historical comparison was available."],
            )
        behavior = sum(item.behavior_similarity for item in references) / len(references)
        attack = sum(item.attack_similarity for item in references) / len(references)
        intelligence = sum(item.intelligence_similarity for item in references) / len(references)
        composite = (0.45 * behavior) + (0.35 * attack) + (0.20 * intelligence)
        common = _unique(item for ref in references for item in ref.common)
        new = _unique(item for ref in references for item in ref.new)
        different = _unique(item for ref in references for item in ref.different)
        return HistoricalSimilarity(
            retrieved_cases=references,
            behavior_similarity=behavior,
            attack_similarity=attack,
            intelligence_similarity=intelligence,
            composite_similarity=composite,
            common_behaviors=common,
            new_behaviors=new,
            different_behaviors=different,
            historical_only_behaviors=different,
            similar_malware_families=_unique(
                ref.malware_family for ref in references if ref.malware_family
            ),
            similar_campaigns=_unique(ref.campaign for ref in references if ref.campaign),
            novelty_detected=bool(new),
            novelty_observations=["Current behavior differs from retrieved historical signatures."]
            if new
            else [],
            confidence=composite,
            limitations=["Historical cases are references and context, not current-case proof."],
            historical_case_references=[ref.case_id for ref in references],
        )

    def _reason(
        self,
        signature: CaseSignature,
        historical: HistoricalSimilarity,
    ) -> str | None:
        if self.model is None or not hasattr(self.model, "generate"):
            return None
        prompt = (
            "Summarize historical similarity for an analyst. Historical cases are context only; "
            "do not identify the current malware, campaign, or actor solely from similarity. "
            f"Current signature: {signature.model_dump()}\n"
            f"Similarity: {historical.model_dump()}\n"
        )
        try:
            return str(self.model.generate(prompt))
        except (RuntimeError, TypeError, ValueError) as exc:
            return f"Model reasoning unavailable: {type(exc).__name__}: {exc}"

    @staticmethod
    def _failure(base: dict[str, Any], error: str) -> dict:
        output = Agent5bOutput(
            **base,
            execution_status=SimilarityExecutionStatus.FAILED,
            error_details=[error],
            claim="Historical similarity failed; no historical conclusion was generated.",
            historical_similarity=HistoricalSimilarity(
                limitations=["Historical similarity was unavailable."]
            ),
        )
        return output.model_dump(mode="json")
