# Human Review — inline citation badges (verified vs unverified)
# Report UI shows badges so reviewer attention goes to what needs checking.
# Review outcomes tracked over time — if one agent is frequently corrected,
# that is a signal to retrain/adjust that agent's prompt.
class AnalystReview:
    def submit_decision(self, case_id: str, decision: str, notes: str): ...
    # decision: 'approved' | 'revision_required'
