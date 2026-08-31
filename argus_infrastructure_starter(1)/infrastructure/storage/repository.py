"""
OWNER: Person 5
STAGE: Case ID/Session Setup + Original Evidence Repository + Audit Logging

Two responsibilities:
  1. create_case_session() -- called ONCE per investigation, before any
     evidence is uploaded (this is what gives everyone else a case_id to
     attach evidence to)
  2. store_evidence() -- the LAST step of the Infrastructure Layer, called
     after Person 4's stage. Moves the evidence from the temp intake
     location into the permanent Original Evidence Repository, and appends
     an audit log entry.

INPUT (store_evidence): an Evidence object with status=METADATA_EXTRACTED
OUTPUT: the same Evidence, with repository_path filled in and an
        AuditLogEntry appended, status updated to STORED -- this is the
        final state; once you see STORED, the Infrastructure Layer is done
        for that piece of evidence.
"""

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession, AuditLogEntry


def create_case_session(tenant_id: str, created_by: str) -> CaseSession:
    # TODO (Person 5):
    #   Just construct and return a CaseSession -- schemas.py already
    #   generates the case_id and timestamp for you.
    raise NotImplementedError("create_case_session: Person 5 to implement")

    # Example of what you're building toward:
    # return CaseSession(tenant_id=tenant_id, created_by=created_by)


def store_evidence(evidence: Evidence, case: CaseSession) -> Evidence:
    # TODO (Person 5):
    #   1. Move/copy the file from evidence.file_path to a permanent
    #      repository location, e.g. f"/data/repository/{case.case_id}/{evidence.evidence_id}"
    #   2. Set evidence.repository_path to that location
    #   3. Append an AuditLogEntry to evidence.audit_log
    #   4. Set evidence.status = EvidenceStatus.STORED

    raise NotImplementedError("store_evidence: Person 5 to implement")

    # Example of what you're building toward:
    # repo_path = f"/data/repository/{case.case_id}/{evidence.evidence_id}"
    # # ... move the file from evidence.file_path to repo_path ...
    # evidence.repository_path = repo_path
    # evidence.audit_log.append(AuditLogEntry(
    #     event="evidence_stored",
    #     tenant_id=case.tenant_id,
    # ))
    # evidence.status = EvidenceStatus.STORED
    # return evidence
