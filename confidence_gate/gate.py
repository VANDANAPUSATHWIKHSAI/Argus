# Confidence Gate — routes based on Agent 7 Call 2 output
# High confidence + fully verified + no divergence → Routine Analyst Review
# Low confidence / any unverified claim / divergence / high-severity → Senior/Dual Review

class ReviewRoute:
    ROUTINE = 'routine'
    SENIOR_DUAL = 'senior_dual'

class ConfidenceGate:
    def route(self, verification_output: dict) -> str:
        # Returns ReviewRoute
        raise NotImplementedError
