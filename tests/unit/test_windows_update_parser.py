"""
Unit tests for WindowsUpdateLogParser and router integration.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from preprocessing.parsers.windows_update_parser import (
    WindowsUpdateLogParser,
    WindowsUpdateLogNotFoundError,
    WindowsUpdateLogParserError,
)
from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence


SAMPLE_WU_LOG = """2026-08-28 10:15:30:123 1234 5678 Agent * START * Installing update KB5034123 (Package_for_KB5034123~31bf3856ad364e35~amd64~~10.0.19041.1)
2026-08-28 10:16:45:500 1234 5678 Agent * END * Installation succeeded for KB5034123
2026-08-28 10:20:00:000 1234 5678 Agent * FAILED * Installation failed for KB5039999 with error 0x80070005
"""

SAMPLE_CBS_LOG = """2026-08-28 11:00:00, Info CBS Exec: Processing package Package_for_KB5034123~31bf3856ad364e35~amd64~~10.0.19041.1 state: Installed
2026-08-28 11:05:00, Info CBS Exec: Reboot required for Package_for_KB5038888 state: Pending
"""

SAMPLE_WU_JSON = [
    {
        "KBNumber": "KB5034123",
        "Title": "Security Update for Windows 10 (KB5034123)",
        "Result": "Succeeded",
        "Date": "2026-08-28T10:15:30Z"
    }
]


class TestWindowsUpdateLogParserUnit:
    """Test suite for WindowsUpdateLogParser."""

    def test_parse_text_log_file(self, tmp_path):
        log_file = tmp_path / "WindowsUpdate.log"
        log_file.write_text(SAMPLE_WU_LOG, encoding="utf-8")

        parser = WindowsUpdateLogParser()
        artifacts = parser.parse(str(log_file), evidence_id="ev_wu_1")

        assert len(artifacts) == 3
        art1 = artifacts[0]
        assert art1.source_tool == "windows_update_log_parser"
        assert art1.artifact_type == "windows_update"
        assert art1.timestamp_type == "logged"
        assert art1.timestamp is not None
        assert art1.timestamp.year == 2026

        # Check raw fields
        assert art1.raw_fields["kb_number"] == "KB5034123"
        assert art1.raw_fields["status"] == "Installing"

        # Check normalized fields
        norm1 = art1.normalized_fields
        assert norm1.file_name == "WindowsUpdate.log"
        assert norm1.process_command_line == "Package_for_KB5034123~31bf3856ad364e35~amd64~~10.0.19041.1"
        assert norm1.rule_name == "windows_update_log"

    def test_parse_cbs_log_file(self, tmp_path):
        cbs_file = tmp_path / "CBS.log"
        cbs_file.write_text(SAMPLE_CBS_LOG, encoding="utf-8")

        parser = WindowsUpdateLogParser()
        artifacts = parser.parse(str(cbs_file), evidence_id="ev_cbs_1")

        assert len(artifacts) == 2
        assert artifacts[0].raw_fields["kb_number"] == "KB5034123"
        assert artifacts[0].raw_fields["status"] == "Installed"
        assert artifacts[1].raw_fields["status"] == "Pending"

    def test_parse_json_history_file(self, tmp_path):
        json_file = tmp_path / "update_history.json"
        json_file.write_text(json.dumps(SAMPLE_WU_JSON), encoding="utf-8")

        parser = WindowsUpdateLogParser()
        artifacts = parser.parse(str(json_file), evidence_id="ev_wu_json")

        assert len(artifacts) == 1
        art = artifacts[0]
        assert art.raw_fields["KBNumber"] == "KB5034123"
        assert art.normalized_fields.process_command_line == "Security Update for Windows 10 (KB5034123)"

    def test_parse_content_in_memory(self):
        parser = WindowsUpdateLogParser()
        artifacts = parser.parse_content(SAMPLE_WU_LOG, evidence_id="ev_mem")

        assert len(artifacts) == 3
        assert artifacts[1].raw_fields["status"] == "Installed"

    def test_missing_file_raises_file_not_found(self):
        parser = WindowsUpdateLogParser()
        with pytest.raises(WindowsUpdateLogNotFoundError):
            parser.parse("C:\\non_existent_WindowsUpdate.log")

    def test_empty_file_raises_parser_error(self, tmp_path):
        empty_file = tmp_path / "empty_WindowsUpdate.log"
        empty_file.write_text("", encoding="utf-8")

        parser = WindowsUpdateLogParser()
        with pytest.raises(WindowsUpdateLogParserError):
            parser.parse(str(empty_file))


class TestWindowsUpdateRouterIntegration:
    """Test suite for WindowsUpdateLogParser router integration."""

    def test_router_windows_update_log_routing(self, tmp_path):
        wu_file = tmp_path / "WindowsUpdate.log"
        wu_file.write_text(SAMPLE_WU_LOG, encoding="utf-8")

        evidence = Evidence(
            evidence_id="ev_wu_route",
            case_id="case_1",
            source_type="file",
            uploaded_by="analyst",
            file_path=str(wu_file),
            filename="WindowsUpdate.log",
        )

        router = ParserRouter()
        result = router.determine_routing(evidence)
        assert result.status == "ROUTED"
        assert result.target_parser == "WindowsUpdateLogParser"

    def test_router_cbs_log_routing(self, tmp_path):
        cbs_file = tmp_path / "CBS.log"
        cbs_file.write_text(SAMPLE_CBS_LOG, encoding="utf-8")

        evidence = Evidence(
            evidence_id="ev_cbs_route",
            case_id="case_1",
            source_type="file",
            uploaded_by="analyst",
            file_path=str(cbs_file),
            filename="CBS.log",
        )

        router = ParserRouter()
        result = router.determine_routing(evidence)
        assert result.status == "ROUTED"
        assert result.target_parser == "WindowsUpdateLogParser"
