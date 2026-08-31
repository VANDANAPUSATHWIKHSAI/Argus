from pydantic import BaseModel
from typing import Dict, Any, Optional
from sanitization.injection_detector import InjectionDetector

class InjectionCheckResult(BaseModel):
    injection_flagged: bool
    injection_score: float
    layer: Optional[str] = None
    reason: Optional[str] = None
    details: Dict[str, Any] = {}

class InjectionGate:
    """
    InjectionGate handles prompt-time injection checks.
    Evaluates untrusted inputs dynamically without caching.
    """

    UNSTRUCTURED_FIELD_KEYWORDS = {
        "body", "subject", "message", "chat", "email", "comment", "description",
        "raw_text", "unstructured"
    }

    def __init__(self):
        self.detector = InjectionDetector()

    def check(self, text: str, field_name: str) -> InjectionCheckResult:
        """
        Runs injection gate heuristic and neural classifier checks.
        Returns a structured InjectionCheckResult.
        """
        if not text:
            return InjectionCheckResult(
                injection_flagged=False,
                injection_score=0.0,
                reason="empty"
            )

        field_lower = field_name.lower()
        is_unstructured = any(kw in field_lower for kw in self.UNSTRUCTURED_FIELD_KEYWORDS)

        is_malicious, details = self.detector.is_injection(text, is_unstructured=is_unstructured)

        if is_malicious:
            score = details.get("confidence", 1.0)
            return InjectionCheckResult(
                injection_flagged=True,
                injection_score=score,
                layer=details.get("layer"),
                reason=details.get("reason"),
                details=details
            )

        return InjectionCheckResult(
            injection_flagged=False,
            injection_score=0.0,
            details=details
        )
