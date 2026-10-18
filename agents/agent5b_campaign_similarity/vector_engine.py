"""
Agent 5b — Multi-Vector Engine
==============================
Generates multi-vector representations for cases across:
1. Behavior vector
2. Attack-pattern vector
3. Threat-intelligence vector
4. Composite case vector

Supports embedding model injection with deterministic semantic fallback,
and provides cosine similarity calculation.
"""

from typing import List, Dict, Any, Optional
import math
import hashlib
import re
import logging
from agents.agent5b_campaign_similarity.schemas import (
    CaseBehavioralSignature,
    MultiVector
)

logger = logging.getLogger(__name__)


class MultiVectorEngine:
    """
    Transforms CaseBehavioralSignature into multi-dimensional vectors.
    """

    VECTOR_DIM = 384  # Standard embedding dimension (matches MiniLM / Qwen embedding projection)

    def __init__(self, embedder=None):
        self.fallback_reason = None
        if embedder is not None:
            self.embedder = embedder
            self.is_fallback = getattr(embedder, "is_fallback", False)
            self.fallback_reason = getattr(embedder, "fallback_reason", None)
        else:
            try:
                from models.embeddings import EmbeddingLoader
                self.embedder = EmbeddingLoader()
                self.is_fallback = getattr(self.embedder, "is_fallback", False)
                self.fallback_reason = getattr(self.embedder, "fallback_reason", None)
            except Exception as e:
                logger.info("EmbeddingLoader not available (%s); defaulting to semantic feature projection fallback.", e)
                self.embedder = None
                self.is_fallback = True
                self.fallback_reason = f"EmbeddingLoader initialization error: {e}"

    def generate_vectors(self, signature: CaseBehavioralSignature) -> MultiVector:
        """
        Creates all four vector representations for a given signature.
        """
        beh_text = self._build_behavior_text(signature)
        attack_text = self._build_attack_text(signature)
        ti_text = self._build_threat_intel_text(signature)
        comp_text = f"BEHAVIOR: {beh_text}\nATTACK: {attack_text}\nTHREAT_INTEL: {ti_text}"

        beh_vec = self.encode_text(beh_text)
        attack_vec = self.encode_text(attack_text)
        ti_vec = self.encode_text(ti_text)
        comp_vec = self.encode_text(comp_text)

        return MultiVector(
            behavior_vector=beh_vec,
            attack_pattern_vector=attack_vec,
            threat_intel_vector=ti_vec,
            composite_vector=comp_vec
        )

    def encode_text(self, text: str) -> List[float]:
        """
        Encodes a single text string into a normalized dense vector.
        Uses injected embedder if available, else semantic hashing fallback in dev/test.
        Fails closed in production if embedder fails or is unavailable.
        """
        if not text.strip():
            return [0.0] * self.VECTOR_DIM

        if self.embedder is not None:
            try:
                # Check if embedder has encode method
                if hasattr(self.embedder, "encode"):
                    res = self.embedder.encode([text])
                    if isinstance(res, list) and len(res) > 0:
                        vec = res[0]
                        if hasattr(vec, "tolist"):
                            vec = vec.tolist()
                        return self._normalize(vec)
            except Exception as e:
                from config.settings import settings
                is_prod = getattr(settings, "app_env", "development") == "production"
                if is_prod:
                    raise RuntimeError(f"Embedding encoding failed in production mode: {e}") from e
                logger.warning(f"Embedding model failed: {e}. Falling back to semantic vectorizer.")
                self.is_fallback = True
                self.fallback_reason = f"Runtime embedder encoding exception: {e}"

        from config.settings import settings
        is_prod = getattr(settings, "app_env", "development") == "production"
        if is_prod:
            raise RuntimeError("CRITICAL: Unapproved semantic projection hash fallback in production mode.")

        self.is_fallback = True
        if not self.fallback_reason:
            self.fallback_reason = "Deterministic token-weighted semantic feature projection"
        return self._semantic_hash_vector(text)


    @classmethod
    def cosine_similarity(cls, vec1: List[float], vec2: List[float]) -> float:
        """
        Computes cosine similarity between two vectors. Clamped to [0.0, 1.0].
        """
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0

        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))

        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0

        sim = dot / (norm1 * norm2)
        # Normalize from [-1, 1] to [0, 1] or clamp
        return max(0.0, min(1.0, float(sim)))

    @classmethod
    def _semantic_hash_vector(cls, text: str) -> List[float]:
        """
        Deterministic, token-weighted semantic feature projection vectorizer.
        Ensures consistent cosine similarity in the absence of GPU/weights.
        """
        tokens = re.findall(r'[a-zA-Z0-9_\-\.]+', text.lower())
        vec = [0.0] * cls.VECTOR_DIM

        for token in tokens:
            # Deterministic hash to map token to dimension buckets
            h = int(hashlib.sha256(token.encode('utf-8')).hexdigest(), 16)
            idx1 = h % cls.VECTOR_DIM
            idx2 = (h >> 16) % cls.VECTOR_DIM
            sign = 1.0 if ((h >> 32) & 1) else -1.0
            weight = 1.0 + math.log(1.0 + len(token))

            vec[idx1] += weight * sign
            vec[idx2] += (weight * 0.5) * (-sign)

        return cls._normalize(vec)

    @staticmethod
    def _normalize(vec: List[float]) -> List[float]:
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return [0.0] * len(vec)
        return [float(v / norm) for v in vec]

    @staticmethod
    def _build_behavior_text(sig: CaseBehavioralSignature) -> str:
        mb = sig.malware_behavior
        parts = []
        for cat in [
            "execution", "persistence", "credential_access", "privilege_escalation",
            "defense_evasion", "discovery", "collection", "command_and_control",
            "exfiltration", "impact"
        ]:
            items = getattr(mb, cat, [])
            if items:
                parts.append(f"{cat}: {', '.join(items)}")
        return " | ".join(parts)

    @staticmethod
    def _build_attack_text(sig: CaseBehavioralSignature) -> str:
        ap = sig.attack_pattern
        parts = []
        if ap.infection_source:
            parts.append(f"infection_source: {ap.infection_source}")
        if ap.attack_path:
            parts.append(f"path: {' -> '.join(ap.attack_path)}")
        if ap.attack_stages:
            parts.append(f"stages: {', '.join(ap.attack_stages)}")
        if ap.kill_chain_steps:
            parts.append(f"kill_chain: {' -> '.join(ap.kill_chain_steps)}")
        if ap.lateral_movement:
            parts.append(f"lateral_movement: {', '.join(ap.lateral_movement)}")
        return " | ".join(parts)

    @staticmethod
    def _build_threat_intel_text(sig: CaseBehavioralSignature) -> str:
        ti = sig.threat_intelligence
        parts = []
        if ti.candidate_malware_families:
            parts.append(f"families: {', '.join(ti.candidate_malware_families)}")
        if ti.mitre_techniques:
            parts.append(f"mitre: {', '.join(ti.mitre_techniques)}")
        if ti.cve_references:
            parts.append(f"cves: {', '.join(ti.cve_references)}")
        if ti.ioc_matches:
            iocs = [str(i.get("indicator", i)) for i in ti.ioc_matches]
            parts.append(f"iocs: {', '.join(iocs)}")
        return " | ".join(parts)
