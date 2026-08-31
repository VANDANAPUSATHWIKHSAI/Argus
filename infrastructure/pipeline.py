"""
Infrastructure Layer pipeline — chains all 5 sub-components in order.

This is your END-OF-DAY TEST -- once everyone's stub is implemented, running
this file on a real test file should take you from raw bytes all the way to
status=STORED. If it doesn't, that's today's actual "done" bar, not just
having 5 files pushed to GitHub.

How to run:
    python -m infrastructure.pipeline

Expected output:
    [DONE] test_evidence.txt -> status=stored, hash=<sha256>, repository_path=<path>
"""

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession, AuditLogEntry
from infrastructure.upload.intake import upload_evidence
from infrastructure.sandbox.intake_validator import sandbox_validate
from infrastructure.integrity.hash_encrypt import hash_and_encrypt
from infrastructure.custody.metadata_custody import extract_metadata_and_log_custody
from infrastructure.repository.evidence_store import create_case_session, store_evidence


def run_infrastructure_layer(
    file_bytes: bytes,
    filename: str,
    case: CaseSession,
    uploaded_by: str,
) -> Evidence:
    """
    Runs the full Infrastructure Layer pipeline in order.
    Returns the final Evidence object (status=STORED if all stages pass).
    """
    # Stage 1 — Person 1
    evidence = upload_evidence(file_bytes, filename, case.case_id, uploaded_by)
    evidence.audit_log.append(AuditLogEntry(
        event="stage_intake_complete",
        tenant_id=case.tenant_id,
        detail={"evidence_id": evidence.evidence_id, "filename": filename}
    ))

    # Stage 2 — Person 2 (stops pipeline if validation fails)
    evidence = sandbox_validate(evidence)
    if evidence.status == EvidenceStatus.VALIDATION_FAILED:
        evidence.audit_log.append(AuditLogEntry(
            event="stage_sandbox_failed",
            tenant_id=case.tenant_id,
            detail={"evidence_id": evidence.evidence_id, "flags": evidence.sandbox_result.flags if evidence.sandbox_result else []}
        ))
        print(
            f"[STOPPED] {evidence.filename} failed sandbox validation: "
            f"{evidence.sandbox_result.flags if evidence.sandbox_result else 'unknown'}"
        )
        return evidence

    evidence.audit_log.append(AuditLogEntry(
        event="stage_sandbox_complete",
        tenant_id=case.tenant_id,
        detail={"evidence_id": evidence.evidence_id}
    ))

    # Stage 3 — Person 3
    evidence = hash_and_encrypt(evidence)
    evidence.audit_log.append(AuditLogEntry(
        event="stage_integrity_complete",
        tenant_id=case.tenant_id,
        detail={"evidence_id": evidence.evidence_id, "sha256_hash": evidence.sha256_hash}
    ))

    # Stage 4 — Person 4
    evidence = extract_metadata_and_log_custody(evidence)
    evidence.audit_log.append(AuditLogEntry(
        event="stage_metadata_complete",
        tenant_id=case.tenant_id,
        detail={"evidence_id": evidence.evidence_id}
    ))

    # Stage 5 — Person 5
    evidence = store_evidence(evidence, case)

    print(
        f"[DONE] {evidence.filename} -> "
        f"status={evidence.status.value}, "
        f"hash={evidence.sha256_hash}, "
        f"repository_path={evidence.repository_path}"
    )
    return evidence


if __name__ == "__main__":
    # Quick manual smoke test -- run this once everyone's stubs are filled in:
    #   python -m infrastructure.pipeline
    test_case = create_case_session(tenant_id="dev-team", created_by="team-lead")
    fake_bytes = b"this is a fake evidence file for testing the pipeline"
    result = run_infrastructure_layer(
        file_bytes=fake_bytes,
        filename="test_evidence.txt",
        case=test_case,
        uploaded_by="team-lead",
    )
    print(result.model_dump_json(indent=2))
