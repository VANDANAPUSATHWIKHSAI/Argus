from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from agents.agent5a_threat_intelligence.agent import ThreatIntelligenceAgent, extract_indicators
from agents.agent5a_threat_intelligence.schemas import Agent5aOutput, ExecutionStatus, FeedState, IndicatorType


class Gateway:
    def sanitize(self, text: str, field_name: str) -> str:
        return f"<evidence_data field=\"{field_name}\">{text}</evidence_data>"


class Stix:
    last_updated = datetime.now(timezone.utc)
    max_age_seconds = 3600

    def check_ioc(self, ioc):
        return {"id": f"stix-{ioc}", "description": "known indicator", "tags": ["malware"]}


class Mitre:
    def get_technique(self, technique_id):
        return {"id": technique_id, "name": "Command and Scripting Interpreter", "description": "technique"}


class Cve:
    def lookup_cve(self, cve_id):
        return {"id": cve_id, "description": "vulnerability"}

    def get_cisa_kev(self):
        return [{"cveID": "CVE-2024-1234", "vendorProject": "Example"}]


def agent():
    return ThreatIntelligenceAgent(None, None, Gateway(), tenant_id="tenant-1")


def test_extracts_and_deduplicates_supported_indicators():
    findings = [
        {
            "finding_id": "F-1",
            "fact": "Connected to 192.0.2.10 and https://evil.example/a; hash "
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
            "CVE-2024-1234 T1059 payload.exe",
        },
        {"finding_id": "F-2", "fact": "Repeated 192.0.2.10 CVE-2024-1234 T1059"},
    ]
    indicators = extract_indicators(findings)
    values = {(item.indicator_type, item.normalized_value): item for item in indicators}

    assert (IndicatorType.IP, "192.0.2.10") in values
    assert (IndicatorType.URL, "https://evil.example/a") in values
    assert (IndicatorType.CVE, "cve-2024-1234") in values
    assert values[(IndicatorType.IP, "192.0.2.10")].finding_ids == ["F-1", "F-2"]
    assert values[(IndicatorType.MITRE_TECHNIQUE, "t1059")].finding_ids == ["F-1", "F-2"]


def test_run_returns_structured_success_and_persistence_shape():
    result = agent().run(
        "CASE-1",
        {
            "tenant_id": "tenant-1",
            "fir_findings": [{"finding_id": "F-1", "fact": "192.0.2.10 CVE-2024-1234 T1059"}],
            "agent2_output": {"claims": [{"cited_evidence_ids": ["F-1"]}], "graph_metrics": {"total_nodes": 2}},
            "stix_client": Stix(),
            "mitre_client": Mitre(),
            "cve_client": Cve(),
        },
    )

    assert result["execution_status"] == ExecutionStatus.SUCCESS.value
    assert result["tenant_id"] == "tenant-1"
    assert result["evidence_ids"] == ["F-1"]
    assert result["mitre_mappings"][0]["enrichment_only"] is True
    persisted = Agent5aOutput.model_validate(result).to_agent_output_record()
    assert set(("case_id", "agent_id", "claim", "evidence_ids", "flags")) <= persisted.keys()


def test_external_description_crosses_sanitization_boundary():
    class RecordingGateway(Gateway):
        def __init__(self):
            self.calls = []

        def sanitize(self, text, field_name):
            self.calls.append((text, field_name))
            return "[SANITISED: Potential prompt injection blocked]"

    recording = RecordingGateway()
    result = ThreatIntelligenceAgent(None, None, recording, tenant_id="tenant-1").run(
        "CASE-1",
        {
            "tenant_id": "tenant-1",
            "fir_findings": [{"finding_id": "F-1", "fact": "192.0.2.10"}],
            "stix_client": Stix(),
        },
    )
    assert recording.calls == [("known indicator", "description")]
    assert result["sanitization_summary"]["fields_sanitized"] == 1
    assert result["ioc_matches"][0]["indicator"]["finding_ids"] == ["F-1"]


def test_missing_feed_is_explicit_partial_or_failed_not_empty_success():
    result = agent().run(
        "CASE-1",
        {"tenant_id": "tenant-1", "fir_findings": [{"finding_id": "F-1", "fact": "192.0.2.10"}]},
    )
    assert result["execution_status"] == ExecutionStatus.FAILED.value
    assert any(item["state"] == FeedState.UNAVAILABLE.value for item in result["feed_status"])
    assert result["error_details"]


def test_stale_feed_is_reported():
    stale = Stix()
    stale.last_updated = datetime.now(timezone.utc) - timedelta(hours=2)
    stale.max_age_seconds = 60
    result = agent().run(
        "CASE-1",
        {
            "tenant_id": "tenant-1",
            "fir_findings": [{"finding_id": "F-1", "fact": "192.0.2.10"}],
            "stix_client": stale,
        },
    )
    assert result["feed_status"][0]["state"] == FeedState.STALE.value


def test_timeout_is_explicit():
    class Slow(Stix):
        def check_ioc(self, ioc):
            time.sleep(0.05)
            return {"description": "late"}

    current = agent()
    current.timeout_seconds = 0.001
    result = current.run(
        "CASE-1",
        {
            "tenant_id": "tenant-1",
            "fir_findings": [{"finding_id": "F-1", "fact": "192.0.2.10"}],
            "stix_client": Slow(),
        },
    )
    assert result["execution_status"] == ExecutionStatus.FAILED.value
    assert result["feed_status"][0]["state"] == FeedState.TIMEOUT.value
