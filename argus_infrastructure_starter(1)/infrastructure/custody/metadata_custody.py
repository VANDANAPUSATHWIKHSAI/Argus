"""
OWNER: Person 4
STAGE: Metadata Extraction + Chain of Custody

INPUT:  an Evidence object with status=HASHED
OUTPUT: the same Evidence, with metadata filled in and a new CustodyLogEntry
        appended (never remove or edit existing entries -- custody log is
        append-only, that's the whole point of it), status updated to
        METADATA_EXTRACTED

Goal for a first working version:
  - metadata: basic file info is enough to start -- size, file type/extension,
    original filename, upload timestamp. Deeper format-specific metadata
    (EXIF, PCAP headers, etc.) is a stretch goal, not day-one scope
  - custody_log: append ONE entry recording that this stage touched the
    evidence -- actor="metadata_custody", action="metadata_extracted"
"""

import os
from infrastructure.schemas import Evidence, EvidenceStatus, CustodyLogEntry


def extract_metadata_and_log_custody(evidence: Evidence) -> Evidence:
    # TODO (Person 4):
    #   1. Pull basic file metadata from evidence.file_path
    #   2. Fill in evidence.metadata (a plain dict)
    #   3. Append a CustodyLogEntry to evidence.custody_log
    #   4. Set evidence.status = EvidenceStatus.METADATA_EXTRACTED

    raise NotImplementedError("extract_metadata_and_log_custody: Person 4 to implement")

    # Example of what you're building toward:
    # evidence.metadata = {
    #     "size_bytes": os.path.getsize(evidence.file_path),
    #     "extension": os.path.splitext(evidence.filename)[1],
    # }
    # evidence.custody_log.append(CustodyLogEntry(
    #     actor="metadata_custody",
    #     action="metadata_extracted",
    # ))
    # evidence.status = EvidenceStatus.METADATA_EXTRACTED
    # return evidence
