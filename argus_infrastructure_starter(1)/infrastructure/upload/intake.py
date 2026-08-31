"""
OWNER: Person 1
STAGE: Evidence Upload

INPUT:  raw file bytes + who's uploading + which case it belongs to
OUTPUT: an Evidence object with status=UPLOADED, file_path pointing to where
        you saved the raw bytes (a temp/intake directory, NOT the final
        repository -- that comes later, after sandboxing and hashing)

Do NOT do any validation, hashing, or parsing here -- that's other people's
stages. This function's only job is: accept the file, write it to disk
somewhere, return a filled-in Evidence object.
"""

from infrastructure.schemas import Evidence, EvidenceStatus


def upload_evidence(file_bytes: bytes, filename: str, case_id: str, uploaded_by: str) -> Evidence:
    # TODO (Person 1):
    #   1. Write file_bytes to a temp intake location, e.g. f"/data/intake/{case_id}/{filename}"
    #   2. Construct and return the Evidence object below with that file_path

    raise NotImplementedError("upload_evidence: Person 1 to implement")

    # Example of what you're building toward:
    # file_path = f"/data/intake/{case_id}/{filename}"
    # with open(file_path, "wb") as f:
    #     f.write(file_bytes)
    # return Evidence(
    #     case_id=case_id,
    #     filename=filename,
    #     file_path=file_path,
    #     uploaded_by=uploaded_by,
    #     status=EvidenceStatus.UPLOADED,
    # )
