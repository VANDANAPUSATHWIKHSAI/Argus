"""
Unit tests for ScheduledTaskParser and router integration.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from preprocessing.parsers.scheduled_task_parser import ScheduledTaskParser, ScheduledTaskParseError
from preprocessing.router import ParserRouter, RoutingResult, UnroutableEvidenceError
from infrastructure.schemas import Evidence


SAMPLE_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-08-28T10:00:00Z</Date>
    <Author>SYSTEM</Author>
    <Description>Argus Scheduled Maintenance Task</Description>
    <URI>\\Microsoft\\Windows\\ArgusTask</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-08-28T10:00:00Z</StartBoundary>
      <EndBoundary>2027-08-28T10:00:00Z</EndBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
    <LogonTrigger>
      <StartBoundary>2026-08-28T10:05:00Z</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <Account>LocalSystem</Account>
      <LogonType>ServiceAccount</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Windows\\System32\\powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File C:\\Scripts\\maint.ps1</Arguments>
      <WorkingDirectory>C:\\Scripts</WorkingDirectory>
    </Exec>
    <Exec>
      <Command>C:\\Windows\\System32\\cmd.exe</Command>
      <Arguments>/c echo Done</Arguments>
    </Exec>
  </Actions>
</Task>
"""

GENERIC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Bookstore>
  <Book>
    <Title>Forensics 101</Title>
    <Price>29.99</Price>
  </Book>
</Bookstore>
"""


class TestScheduledTaskParser:
    """Test suite for ScheduledTaskParser execution and router compliance."""

    def test_basic_xml_parsing(self, tmp_path):
        task_file = tmp_path / "ArgusTask.xml"
        task_file.write_text(SAMPLE_TASK_XML, encoding="utf-8")

        parser = ScheduledTaskParser()
        artifacts = parser.parse(str(task_file), evidence_id="ev_task_1")

        assert len(artifacts) == 1
        art = artifacts[0]
        assert art.artifact_type == "scheduled_task"
        assert art.source_tool == "scheduled_task_parser"
        assert art.timestamp_type == "created"
        assert art.timestamp is not None
        assert art.timestamp.year == 2026

        # Check raw fields
        raw = art.raw_fields
        assert raw["task_name"] == "ArgusTask.xml"
        assert raw["author"] == "SYSTEM"
        assert raw["description"] == "Argus Scheduled Maintenance Task"
        assert raw["user_id"] == "S-1-5-18"
        assert raw["account"] == "LocalSystem"
        assert raw["run_level"] == "HighestAvailable"
        assert raw["enabled"] is True
        assert raw["hidden"] is False

        # Check multiple triggers
        assert len(raw["triggers"]) == 2
        assert raw["triggers"][0]["trigger_type"] == "CalendarTrigger"
        assert raw["triggers"][1]["trigger_type"] == "LogonTrigger"

        # Check multiple actions
        assert len(raw["actions"]) == 2
        assert raw["actions"][0]["command"] == "C:\\Windows\\System32\\powershell.exe"
        assert raw["actions"][0]["arguments"] == "-ExecutionPolicy Bypass -File C:\\Scripts\\maint.ps1"
        assert raw["actions"][0]["working_directory"] == "C:\\Scripts"
        assert raw["actions"][1]["command"] == "C:\\Windows\\System32\\cmd.exe"

        # Check normalized fields
        norm = art.normalized_fields
        assert norm.process_name == "powershell.exe"
        assert norm.process_command_line == "C:\\Windows\\System32\\powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\maint.ps1"
        assert norm.user == "S-1-5-18"
        assert norm.rule_name == "scheduled_task_xml"

    def test_read_only_behavior(self, tmp_path):
        task_file = tmp_path / "ReadOnlyTask.xml"
        task_file.write_text(SAMPLE_TASK_XML, encoding="utf-8")
        orig_stat = task_file.stat()

        parser = ScheduledTaskParser()
        parser.parse(str(task_file))

        new_stat = task_file.stat()
        assert orig_stat.st_mtime == new_stat.st_mtime
        assert orig_stat.st_size == new_stat.st_size

    def test_missing_file_raises_file_not_found(self):
        parser = ScheduledTaskParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("C:\\non_existent_scheduled_task.xml")

    def test_malformed_xml_raises_parse_error(self, tmp_path):
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("<Task><UnclosedTag>", encoding="utf-8")

        parser = ScheduledTaskParser()
        with pytest.raises(ScheduledTaskParseError):
            parser.parse(str(bad_xml))

    def test_non_task_root_raises_parse_error(self, tmp_path):
        wrong_root = tmp_path / "wrong.xml"
        wrong_root.write_text("<Configuration><Item>1</Item></Configuration>", encoding="utf-8")

        parser = ScheduledTaskParser()
        with pytest.raises(ScheduledTaskParseError):
            parser.parse(str(wrong_root))

    def test_router_scheduled_task_path_routing(self, tmp_path):
        task_dir = tmp_path / "Windows" / "System32" / "Tasks"
        task_dir.mkdir(parents=True, exist_ok=True)
        task_file = task_dir / "UpdateTask"
        task_file.write_text(SAMPLE_TASK_XML, encoding="utf-8")

        evidence = Evidence(
            evidence_id="ev_task_path",
            case_id="case_1",
            source_type="file",
            uploaded_by="analyst",
            file_path=str(task_file),
            filename="UpdateTask",
        )

        router = ParserRouter()
        result = router.determine_routing(evidence)
        assert result.status == "ROUTED"
        assert result.target_parser == "ScheduledTaskParser"

    def test_router_scheduled_task_xml_content_routing(self, tmp_path):
        xml_file = tmp_path / "my_custom_task.xml"
        xml_file.write_text(SAMPLE_TASK_XML, encoding="utf-8")

        evidence = Evidence(
            evidence_id="ev_task_xml",
            case_id="case_1",
            source_type="file",
            uploaded_by="analyst",
            file_path=str(xml_file),
            filename="my_custom_task.xml",
        )

        router = ParserRouter()
        result = router.determine_routing(evidence)
        assert result.status == "ROUTED"
        assert result.target_parser == "ScheduledTaskParser"

    def test_router_generic_xml_remains_unrouted(self, tmp_path):
        gen_xml = tmp_path / "books.xml"
        gen_xml.write_text(GENERIC_XML, encoding="utf-8")

        evidence = Evidence(
            evidence_id="ev_generic_xml",
            case_id="case_1",
            source_type="file",
            uploaded_by="analyst",
            file_path=str(gen_xml),
            filename="books.xml",
        )

        router = ParserRouter()
        result = router.determine_routing(evidence)
        assert result.status != "ROUTED" or result.target_parser != "ScheduledTaskParser"
