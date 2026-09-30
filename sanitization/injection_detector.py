"""
Prompt Injection Detector
=========================
Fast heuristic-only defense system using regex/keyword checks for
forensic-specific prompt injections (e.g., "ignore these messages",
"say no evidence", "flag as benign").

Heuristic checks are applied to all text fields.
"""

import re
import logging
from typing import Dict, List, Tuple, Any
from models.classifiers import ClassifierLoader

class ModelUnavailableError(Exception):
    """Raised when an ML model is required but unavailable in production fail-closed mode."""
    pass


class InjectionDetector:
    """
    Detects malicious prompt injections in raw digital forensic text fields
    (e.g., attacker-controlled log entries, emails, command lines).
    Uses fast compiled regex heuristics only — no ML model overhead.
    """

    # ── Forensic-specific attack patterns (heuristics) ───────────────────────
    FORENSIC_INJECTION_KEYWORDS = [
        # Override/ignore instructions
        r"ignore\s+(?:all\s+)?(?:previous\s+)?(?:instructions|messages|rules|prompts)",
        r"disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|messages|rules|evidence|prompts)",
        r"override\s+(?:system\s+)?(?:instructions|settings|rules|prompts)",
        r"follow\s+(?:these|the\s+following)\s+(?:instructions|rules|commands)",
        
        # Evidence denial / manipulation
        r"say\s+(?:there\s+is\s+)?no\s+evidence",
        r"report\s+as\s+(?:safe|benign|clean|legitimate|authorized)",
        r"flag\s+as\s+(?:safe|benign|clean|legitimate|authorized)",
        r"mark\s+as\s+(?:safe|benign|clean|legitimate|authorized)",
        
        # Attribution / Malware name manipulation
        r"say\s+wrong\s+malware\s+name",
        r"change\s+malware\s+name\s+to",
        r"rename\s+malware\s+to",
        r"say\s+the\s+malware\s+is",
        r"do\s+not\s+mention\s+malware",
        
        # System instructions hijack & prompt extraction
        r"assistant\s+instructions:",
        r"new\s+instructions:",
        r"system\s+prompt\s+override",
        r"system\s+message:",
        r"developer\s+message:",
        r"user\s+message:",
        r"reveal\s+(?:your\s+)?(?:system\s+)?prompt",
        r"you\s+must\s+say\s+that",
        
        # Chain-of-custody / verification bypass
        r"skip\s+(?:all\s+)?verification",
        r"skip\s+audit",
        r"bypass\s+verification",
        r"verification\s+approved",
        r"audit\s+bypass",
        r"file\s+was\s+reviewed\s+and\s+approved",
        r"skip\s+(?:the\s+)?verification\s+step",

        # Role / persona hijack & jailbreak
        r"you\s+are\s+now\s+(?:dan|unrestricted|jailbroken|chatgpt|an?\s+ai)",
        r"you\s+are\s+chatgpt",
        r"jailbreak",
        r"act\s+as\s+(?:an?\s+)?unrestricted",
        r"assistant\s+mode\s+bypass",

        # Context / Delimiter / XML boundary confusion
        r"</?evidence_data\b",
        r"</?evidence\b",
        r"</?instruction\b",
        r"</?system\b",
        r"<!\[CDATA\[",
        r"###\s*instruction",
    ]

    def __init__(self):
        # Compile all regex patterns for high-performance heuristic checks
        self.heuristics = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.FORENSIC_INJECTION_KEYWORDS
        ]

    def check_heuristics(self, text: str) -> Tuple[bool, List[str]]:
        """
        Runs fast keyword/regex matching.
        Returns: (is_malicious, matched_patterns)
        """
        matched = []
        for pattern in self.heuristics:
            if pattern.search(text):
                matched.append(pattern.pattern)
        return len(matched) > 0, matched

    def check_model(self, text: str) -> Tuple[bool, float]:
        """
        Runs ML model prompt injection detection on text.
        Raises ModelUnavailableError in fail-closed mode when the classifier cannot be loaded.
        """
        import os
        from config.settings import settings
        from models.classifiers import ClassifierLoader
        
        app_env = os.getenv("APP_ENV") or getattr(settings, "app_env", "development")
        fail_closed = app_env == "production" or os.getenv("ARGUS_FAIL_CLOSED") == "1"

        loader = ClassifierLoader()
        try:
            active = loader.verify_semantic_layer()
        except Exception as e:
            raise ModelUnavailableError(f"ML model unavailable: {e}") from e

        if not active:
            raise ModelUnavailableError("Semantic ML layer is inactive or unavailable.")

        try:
            detector = loader.load_injection_detector()
            res = detector(text[:512])
            if res and isinstance(res, list):
                label = str(res[0].get("label", "")).lower()
                score = float(res[0].get("score", 0.0))
                is_inj = label in ("injection", "malicious", "label_1", "1")
                return is_inj, score
        except Exception as e:
            if isinstance(e, ModelUnavailableError):
                raise e
            raise ModelUnavailableError(f"Injection classification failed: {e}") from e

        return False, 0.0

    def is_injection(self, text: str, is_unstructured: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """
        Runs heuristic injection detection and ML model checks on text.
        """
        if not text:
            return False, {"reason": "empty"}

        # ── 1. Heuristics (Instant - Run on ALL fields) ──────────────
        heuristic_hit, matched_rules = self.check_heuristics(text)
        if heuristic_hit:
            return True, {
                "layer": "heuristic",
                "reason": "matched_forensic_override_patterns",
                "matched_patterns": matched_rules,
                "confidence": 1.0
            }

        # ── 2. Model-based Check ──────────────────────────────────
        is_model_inj, score = self.check_model(text)
        if is_model_inj:
            return True, {
                "layer": "model",
                "reason": "neural_injection_classifier_flagged",
                "confidence": score
            }

        return False, {"status": "clean"}
