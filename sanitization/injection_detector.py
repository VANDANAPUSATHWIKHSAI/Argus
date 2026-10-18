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
from typing import Dict, List, Tuple, Any, Optional

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

    def __init__(self, safety_classifier: Optional[Any] = None):
        # Compile all regex patterns for high-performance heuristic checks
        self.heuristics = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.FORENSIC_INJECTION_KEYWORDS
        ]
        self.safety_classifier = safety_classifier

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
        Evaluates secondary safety classifier if configured, returning (is_flagged, score).
        """
        if self.safety_classifier is not None:
            res = self.safety_classifier.evaluate_with_guardrails(text)
            return res.is_flagged, res.score
        return False, 0.0

    def is_injection(
        self,
        text: str,
        is_unstructured: bool = False,
        tenant_id: str = "default"
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Runs layered prompt injection detection:
        1. Fast regex heuristics (MANDATORY, primary deterministic defense).
        2. Optional secondary ML safety classifier (additive secondary defense).
        """
        if not text:
            return False, {"reason": "empty"}

        # ── 1. Deterministic Heuristics (Instant - Run on ALL fields) ──
        heuristic_hit, matched_rules = self.check_heuristics(text)
        if heuristic_hit:
            return True, {
                "layer": "heuristic",
                "reason": "matched_forensic_override_patterns",
                "matched_patterns": matched_rules,
                "confidence": 1.0,
            }

        # ── 2. Secondary ML Safety Classifier (Additive) ──────────────
        if self.safety_classifier is not None:
            res = self.safety_classifier.evaluate_with_guardrails(text, tenant_id=tenant_id)
            if res.is_flagged:
                return True, {
                    "layer": "ml_secondary_classifier",
                    "reason": f"ml_classifier_flagged_{res.risk_category.lower()}",
                    "confidence": res.score,
                    "ml_score": res.score,
                    "classifier_name": res.classifier_name,
                    "classifier_version": res.classifier_version,
                    "threshold_used": res.threshold_used,
                    "risk_category": res.risk_category,
                    "latency_ms": res.latency_ms,
                }

        return False, {"status": "clean"}
