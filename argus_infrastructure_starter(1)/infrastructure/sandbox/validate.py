"""
OWNER: Person 2 (hardest sub-component -- pair with Person 1 if you finish early)
STAGE: Sandboxed Intake Validation

INPUT:  an Evidence object with status=UPLOADED
OUTPUT: the same Evidence, with sandbox_result filled in, and status updated
        to either SANDBOXED (passed) or VALIDATION_FAILED (rejected)

Goal for a first working version (don't over-build on day one):
  - Open/read the file in a way that can't crash or hang the rest of the
    pipeline (basic timeout + try/except is enough to start; real
    microVM/container isolation is a stretch goal once this works end-to-end)
  - Check for obvious red flags: file way bigger than expected, zip bomb
    patterns, wrong extension vs actual file type
  - Record what you found in SandboxResult.flags, even if you don't reject it

If validation fails, DO NOT continue the pipeline for this evidence --
return it with status=VALIDATION_FAILED and stop there.
"""

from infrastructure.schemas import Evidence, EvidenceStatus, SandboxResult


def sandbox_validate(evidence: Evidence) -> Evidence:
    # TODO (Person 2):
    #   1. Load evidence.file_path safely (timeout, size limit, exception handling)
    #   2. Run whatever checks you have time for -- start simple, harden later
    #   3. Fill in evidence.sandbox_result
    #   4. Set evidence.status to SANDBOXED or VALIDATION_FAILED

    raise NotImplementedError("sandbox_validate: Person 2 to implement")

    # Example of what you're building toward:
    # result = SandboxResult(passed=True, flags=[], execution_time_ms=120)
    # evidence.sandbox_result = result
    # evidence.status = EvidenceStatus.SANDBOXED if result.passed else EvidenceStatus.VALIDATION_FAILED
    # return evidence
