"""
Unit & Regression Tests for sanitize_uuid
========================================
Validates that sanitize_uuid removes URL encoding, surrounding quotes, and handles
null/empty values without truncating valid identifiers (specifically cases ending in '2').
"""

import uuid
import pytest
from api.routes.evidence import sanitize_uuid


def test_sanitize_uuid_preserves_trailing_two():
    """Verify case IDs ending in '2' are NEVER truncated."""
    assert sanitize_uuid("CASE-02") == "CASE-02"
    assert sanitize_uuid("CASE-2") == "CASE-2"
    assert sanitize_uuid("CASE-2026-002") == "CASE-2026-002"
    assert sanitize_uuid("CASE-AUDIT-TEST-02") == "CASE-AUDIT-TEST-02"
    assert sanitize_uuid("INCIDENT-122") == "INCIDENT-122"


def test_sanitize_uuid_removes_url_encoding():
    """Verify %22 and percent-encoded quotation marks are cleanly stripped."""
    assert sanitize_uuid("%22CASE-02%22") == "CASE-02"
    assert sanitize_uuid("%22CASE-2%22") == "CASE-2"
    assert sanitize_uuid("%22CASE-100%22") == "CASE-100"
    assert sanitize_uuid("%22%22CASE-99%22%22") == "CASE-99"


def test_sanitize_uuid_removes_quotes():
    """Verify raw double quotes and single quotes are stripped."""
    assert sanitize_uuid('"CASE-02"') == "CASE-02"
    assert sanitize_uuid("'CASE-02'") == "CASE-02"
    assert sanitize_uuid('""CASE-ALPHA-2""') == "CASE-ALPHA-2"


def test_sanitize_uuid_standard_uuids():
    """Verify standard UUID strings are preserved as-is."""
    raw_uuid = str(uuid.uuid4())
    assert sanitize_uuid(raw_uuid) == raw_uuid

    deterministic_uuid = "88888888-8888-8888-8888-888888888882"
    assert sanitize_uuid(deterministic_uuid) == deterministic_uuid


def test_sanitize_uuid_ordinary_case_identifiers():
    """Verify standard alphanumeric case identifiers with hyphens and underscores."""
    assert sanitize_uuid("CASE-2026-001") == "CASE-2026-001"
    assert sanitize_uuid("SEC_OPS_INVESTIGATION_99") == "SEC_OPS_INVESTIGATION_99"
    assert sanitize_uuid("   CASE-TRIMMED   ") == "CASE-TRIMMED"


def test_sanitize_uuid_empty_and_null_fallbacks():
    """Verify None, empty strings, and placeholder strings generate fresh UUIDs."""
    res_none = sanitize_uuid(None)
    assert uuid.UUID(res_none)

    res_empty = sanitize_uuid("")
    assert uuid.UUID(res_empty)

    res_string = sanitize_uuid("string")
    assert uuid.UUID(res_string)

    res_null = sanitize_uuid("null")
    assert uuid.UUID(res_null)

    res_none_str = sanitize_uuid("none")
    assert uuid.UUID(res_none_str)
