# Maker-Checker: a SEPARATE senior reviewer must explicitly sign off
# before a case enters the Validated Case Repository.
# Routine approval closes a case; promotion into the reusable knowledge base
# needs this additional, higher-bar approval.
class MakerChecker:
    def approve(self, case_id: str, senior_reviewer: str): ...
    def reject(self, case_id: str, reason: str): ...
