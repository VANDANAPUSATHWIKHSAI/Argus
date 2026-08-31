"""
Chains all 5 sub-components together in order.

This is your END-OF-DAY TEST -- once everyone's stub is implemented, running
this file on a real test file should take you from raw bytes all the way to
status=STORED. If it doesn't, that's today's actual "done" bar, not just
having 5 files pushed to GitHub.
"""

from infrastructure.schemas import Evidence, EvidenceStatus, CaseSession
from infrastructure.upload.intake import upload_evidence
from infrastructure.sandbox.validate import sandbox_validate
from infrastructure.integrity.hash_encrypt import hash_and_encrypt
from infrastructure.custody.metadata_custody import extract_metadata_and_log_custody
from infrastructure.storage.repository import create_case_session, store_evidence


def run_infrastructure_layer(
    file_bytes: bytes, filename: str, case: CaseSession, uploaded_by: str
) -> Evidence:
    evidence = upload_evidence(file_bytes, filename, case.case_id, uploaded_by)

    evidence = sandbox_validate(evidence)
    if evidence.status == EvidenceStatus.VALIDATION_FAILED:
        print(f"[STOPPED] {evidence.filename} failed sandbox validation: "
              f"{evidence.sandbox_result.flags if evidence.sandbox_result else 'unknown'}")
        return evidence

    evidence = hash_and_encrypt(evidence)
    evidence = extract_metadata_and_log_custody(evidence)
    evidence = store_evidence(evidence, case)

    print(f"[DONE] {evidence.filename} -> status={evidence.status.value}, "
          f"hash={evidence.sha256_hash}, repository_path={evidence.repository_path}")
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
