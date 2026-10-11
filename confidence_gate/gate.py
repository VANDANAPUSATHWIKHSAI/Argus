"""
Confidence Gate — Human Review Maker-Checker Router
===================================================
Routes cases based on Agent 7 verification outputs:
- Routine Analyst Review:
    High confidence (>= threshold, default 0.85), all claims fully verified,
    no divergence flags, and no high-severity attribution claims.
- Mandatory Senior / Dual Review:
    Low confidence (< threshold), any unverified claim, divergence flag present,
    or high-severity attribution claim.
"""

from typing import Dict, Any, List, Optional


class ReviewRoute:
    ROUTINE = "routine"
    SENIOR_DUAL = "senior_dual"


class ConfidenceGate:
    """
    Confidence Gate routes cases to Routine vs Senior/Dual review.
    """

    DEFAULT_THRESHOLD = 0.85

    def __init__(self, confidence_threshold: Optional[float] = None):
        self.confidence_threshold = (
            float(confidence_threshold) if confidence_threshold is not None else self.DEFAULT_THRESHOLD
        )

    def route(self, verification_output: Dict[str, Any]) -> str:
        """
        Determines the review route string ('routine' or 'senior_dual').
        """
        details = self.evaluate(verification_output)
        return details["route"]

    def evaluate(self, verification_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates verification outputs with structured rationale, attention items,
        and routing decision.
        """
        confidence_score = float(
            verification_output.get("confidence_score")
            or verification_output.get("investigation_confidence_score")
            or 0.0
        )
        ver_results = verification_output.get("verification_results") or []
        claims = verification_output.get("claims") or []
        divergence_flags = list(verification_output.get("divergence_flags") or [])

        reasons: List[str] = []
        attention_items: List[str] = []

        # 1. Check verified vs unverified claims
        unverified_claims = [r for r in ver_results if not r.get("verified", False)]
        verified_claims = [r for r in ver_results if r.get("verified", False)]

        for uv in unverified_claims:
            cid = uv.get("claim_id", "UNKNOWN")
            flags = uv.get("flags", [])
            flag_str = "; ".join(flags) if flags else "Failed verification checks"
            reasons.append(f"Unverified claim [{cid}]: {flag_str}")
            attention_items.append(f"Requires manual analyst confirmation: Claim [{cid}]")

        # 2. Check Divergence Flags across verification checks
        for r in ver_results:
            checks = r.get("checks", {})
            if checks.get("divergence") is False:
                cid = r.get("claim_id", "UNKNOWN")
                reasons.append(f"Narrative divergence flagged on claim [{cid}]: contradicts deterministic finding")
                attention_items.append(f"Divergence alert on claim [{cid}]")
            for flag in r.get("flags", []):
                if "divergence" in str(flag).lower():
                    divergence_flags.append(str(flag))

        if divergence_flags:
            for df in divergence_flags:
                reasons.append(f"Deterministic layer divergence: {df}")

        # 3. Check Investigation Confidence Score strictly against threshold
        # Boundary: >= threshold passes; < threshold triggers senior/dual review
        if confidence_score < self.confidence_threshold:
            reasons.append(
                f"Low investigation confidence score ({confidence_score:.3f} < threshold {self.confidence_threshold:.3f})"
            )
            attention_items.append("Low overall confidence score requires dual reviewer sign-off")

        # 4. Check High-Severity Threat Actor Attribution Claims
        all_claims_dict = {c.get("claim_id"): c for c in claims if isinstance(c, dict)}
        for r in ver_results:
            cid = r.get("claim_id")
            c_meta = all_claims_dict.get(cid) or r
            is_attr = c_meta.get("is_attribution", False)
            sev = str(c_meta.get("severity", "")).lower()
            if is_attr and sev in ("critical", "high"):
                reasons.append(
                    f"High-severity attribution claim [{cid}] asserted ({sev.upper()} severity)"
                )
                attention_items.append(f"High-severity attribution on [{cid}] requires Senior Reviewer verification")

        # Determine route
        if not reasons:
            route = ReviewRoute.ROUTINE
            requires_senior = False
            reasons.append("All claims fully verified, high confidence, no divergence, routine criteria satisfied.")
        else:
            route = ReviewRoute.SENIOR_DUAL
            requires_senior = True

        return {
            "route": route,
            "requires_senior_review": requires_senior,
            "reasons": reasons,
            "attention_items": attention_items,
            "investigation_confidence_score": confidence_score,
            "confidence_threshold": self.confidence_threshold,
            "verified_claim_count": len(verified_claims),
            "unverified_claim_count": len(unverified_claims),
        }
