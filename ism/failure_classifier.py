# Classifies failure type: infra crash / parser error / AI agent failure
# Each type is routed/handled differently

class FailureType:
    INFRA_CRASH = 'infra_crash'
    PARSER_ERROR = 'parser_error'
    AI_AGENT_FAILURE = 'ai_agent_failure'

class FailureClassifier:
    def classify(self, error: Exception) -> str: ...
