"""
FIR Schema Coercion & Provenance Tests
=======================================
Verifies FIRFinding.evidence_reference handling for list[str], legacy string coercion,
warning emissions, and invalid input enforcement.
"""

import pytest
import logging
from datetime import datetime, timezone
from fir.schemas import FIRFinding, ReviewStatus


def test_evidence_reference_list_input_unchanged(caplog):
    now = datetime.now(timezone.utc)
    with caplog.at_level(logging.WARNING):
        finding = FIRFinding(
            finding_id="F-101",
            case_id="CASE-1",
            tenant_id="tenant-1",
            fact="Forensic anomaly",
            confidence=0.9,
            severity="high",
            timestamp=now,
            evidence_reference=["CORR-00101", "CORR-00102"],
            layer="network.dns_analyzer"
        )
    assert finding.evidence_reference == ["CORR-00101", "CORR-00102"]
    assert "received legacy scalar string" not in caplog.text


def test_evidence_reference_single_string_coercion_and_warning(caplog):
    now = datetime.now(timezone.utc)
    with caplog.at_level(logging.WARNING):
        finding = FIRFinding(
            finding_id="F-102",
            case_id="CASE-1",
            tenant_id="tenant-1",
            fact="Forensic anomaly",
            confidence=0.9,
            severity="high",
            timestamp=now,
            evidence_reference="CORR-00101",
            layer="network.dns_analyzer"
        )
    assert finding.evidence_reference == ["CORR-00101"]
    assert "FIRFinding.evidence_reference received legacy scalar string; coercing to list[str]." in caplog.text


def test_evidence_reference_comma_separated_string_coercion_and_warning(caplog):
    now = datetime.now(timezone.utc)
    with caplog.at_level(logging.WARNING):
        finding = FIRFinding(
            finding_id="F-103",
            case_id="CASE-1",
            tenant_id="tenant-1",
            fact="Forensic anomaly",
            confidence=0.9,
            severity="high",
            timestamp=now,
            evidence_reference="CORR-00101, CORR-00102",
            layer="network.dns_analyzer"
        )
    assert finding.evidence_reference == ["CORR-00101", "CORR-00102"]
    assert "FIRFinding.evidence_reference received legacy scalar string; coercing to list[str]." in caplog.text


def test_evidence_reference_empty_input_validation():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        FIRFinding(
            finding_id="F-104",
            case_id="CASE-1",
            tenant_id="tenant-1",
            fact="Forensic anomaly",
            confidence=0.9,
            severity="high",
            timestamp=now,
            evidence_reference=[],
            layer="network.dns_analyzer"
        )

    with pytest.raises(ValueError):
        FIRFinding(
            finding_id="F-105",
            case_id="CASE-1",
            tenant_id="tenant-1",
            fact="Forensic anomaly",
            confidence=0.9,
            severity="high",
            timestamp=now,
            evidence_reference=None,
            layer="network.dns_analyzer"
        )
