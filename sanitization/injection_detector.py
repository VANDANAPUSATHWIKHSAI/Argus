"""
Prompt Injection Detector
=========================
A two-layer defense system:
  1. Heuristic Layer: Fast regex/keyword checks for forensic-specific prompt injections
     (e.g., "ignore these messages", "say no evidence", "flag as benign").
  2. Model Layer: Deep learning classifier (DeBERTa-v3-base-prompt-injection-v2).

Heuristic checks are applied to all fields.
Model checks are applied only to unstructured/conversational human text fields
(e.g. email bodies, chat transcripts) to prevent false positives on structured system logs.
"""

import re
import logging
from typing import Dict, List, Tuple, Any
from models.classifiers import ClassifierLoader

logger = logging.getLogger(__name__)


class ModelUnavailableError(Exception):
    """Exception raised when the ML classifier model is unavailable."""
    pass


class InjectionDetector:
    """
    Detects malicious prompt injections in raw digital forensic text fields
    (e.g., attacker-controlled log entries, emails, command lines).
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
        self.classifier_loader = ClassifierLoader()

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
        Invokes the pre-trained DeBERTa injection classifier.
        Returns: (is_malicious, confidence_score)
        """
        try:
            detector = self.classifier_loader.load_injection_detector()
            result = detector(text)[0]
            
            # protectai model returns label 'INJECTION' or 'SAFE'
            is_malicious = result["label"].upper() == "INJECTION"
            confidence = result["score"]
            
            # Set high threshold for model to reduce false positives
            if is_malicious and confidence > 0.92:
                return True, confidence
            return False, confidence
        except Exception as e:
            logger.error(f"DeBERTa model inference failed: {e}", exc_info=True)
            raise ModelUnavailableError(f"DeBERTa model inference failed: {e}") from e

    def is_injection(self, text: str, is_unstructured: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """
        Runs the full layered detection pipeline.
        
        If is_unstructured is True, it runs both Heuristics and DeBERTa.
        If is_unstructured is False, it runs ONLY Heuristics to prevent false positives
        on raw log/system strings.
        """
        if not text:
            return False, {"reason": "empty"}

        # ── Layer 1: Heuristics (Instant - Run on ALL fields) ──────────────
        heuristic_hit, matched_rules = self.check_heuristics(text)
        if heuristic_hit:
            return True, {
                "layer": "heuristic",
                "reason": "matched_forensic_override_patterns",
                "matched_patterns": matched_rules,
                "confidence": 1.0
            }

        # ── Layer 2: DeBERTa (Deep Learning - Only for human conversational text) ──
        if is_unstructured:
            model_hit, confidence = self.check_model(text)
            if model_hit:
                return True, {
                    "layer": "model",
                    "reason": "deberta_prompt_injection_prediction",
                    "confidence": confidence
                }

        return False, {"status": "clean"}
