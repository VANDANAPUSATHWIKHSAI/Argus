"""
Unit tests for SBECmdParser (ShellBags parser) and router integration.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from preprocessing.parsers.sbecmd_parser import (
    SBECmdParser,
    SbecmdNotFoundError,
    SbecmdExecutionError,
)
from preprocessing.router import ParserRouter
from infrastructure.schemas import Evidence


SAMPLE_SBECMD_CSV = """AbsolutePath,ShellBagType,CreatedOn,ModifiedOn,AccessedOn,LastInteracted,MFTEntryNumber,MFTSequenceNumber
C:\\Users\\Analyst\\Documents\\Forensics,Directory,2026-08-28 10:00:00,2026-08-28 10:15:00,2026-08-28 10:30:00,2026-08-28 10:30:00,12345,1
C:\\Users\\Analyst\\Downloads,Directory,2026-08-28 09:00:00,2026-08-28 09:30:00,2026-08-28 09:45:00,2026-08-28 09:45:00,67890,2
"""

SAMPLE_SBECMD_JSON = [
    {
        "AbsolutePath": "C:\\Users\\Analyst\\Desktop\\SecretFolder",
        "ShellBagType": "Directory",
        "Created": "2026-08-28T10:00:00Z",
        "Modified": "2026-08-28T10:15:00Z",
        "Accessed": "2026-08-28T10:30:00Z",
        "LastInteracted": "2026-08-28T10:30:00Z",
        "User": "Analyst",
        "MFTEntryNumber": 54321
    }
]


class TestSBECmdParserUnit:
    """Test suite for SBECmdParser."""

    def test_parse_csv_file(self, tmp_path):
        csv_file = tmp_path / "sbecmd_export.csv"
        csv_file.write_text(SAMPLE_SBECMD_CSV, encoding="utf-8")

        parser = SBECmdParser()
        artifacts = parser.parse(str(csv_file), evidence_id="ev_sb_csv")

        assert len(artifacts) == 2
        art1 = artifacts[0]
        assert art1.source_tool == "sbecmd"
        assert art1.artifact_type == "shellbags"
        assert art1.timestamp_type == "accessed"
        assert art1.timestamp is not None
        assert art1.timestamp.year == 2026

        # Check raw preservation
        assert art1.raw_fields["AbsolutePath"] == "C:\\Users\\Analyst\\Documents\\Forensics"
        assert art1.raw_fields["MFTEntryNumber"] == "12345"

        # Check normalized fields
        norm1 = art1.normalized_fields
        assert norm1.file_path == "C:\\Users\\Analyst\\Documents\\Forensics"
        assert norm1.file_name == "Forensics"
        assert norm1.user == "Analyst"
        assert norm1.rule_name == "shellbags_sbecmd"

    def test_parse_json_file(self, tmp_path):
        json_file = tmp_path / "sbecmd_export.json"
        json_file.write_text(json.dumps(SAMPLE_SBECMD_JSON), encoding="utf-8")

        parser = SBECmdParser()
        artifacts = parser.parse(str(json_file), evidence_id="ev_sb_json")

        assert len(artifacts) == 1
        art = artifacts[0]
        assert art.source_tool == "sbecmd"
        assert art.artifact_type == "shellbags"
        assert art.timestamp_type == "accessed"
        assert art.raw_fields["User"] == "Analyst"
        assert art.normalized_fields.user == "Analyst"
        assert art.normalized_fields.file_name == "SecretFolder"

    def test_parse_content_in_memory(self):
        parser = SBECmdParser()
        artifacts = parser.parse_content(SAMPLE_SBECMD_CSV, evidence_id="ev_mem")

        assert len(artifacts) == 2
        assert artifacts[0].normalized_fields.file_name == "Forensics"

    def test_timestamp_type_never_executed(self, tmp_path):
        # Ensure timestamp_type is accessed/modified/created, NOT executed
        data = [
            {
                "AbsolutePath": "C:\\Windows\\System32",
                "CreatedOn": "2026-01-01 00:00:00"
            }
        ]
        json_file = tmp_path / "created_only.json"
        json_file.write_text(json.dumps(data), encoding="utf-8")

        parser = SBECmdParser()
        artifacts = parser.parse(str(json_file))
        assert artifacts[0].timestamp_type in ("accessed", "modified", "created")
        assert artifacts[0].timestamp_type != "executed"

    def test_missing_file_raises_file_not_found(self):
        parser = SBECmdParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("C:\\non_existent_shellbags_hive.dat")

    def test_missing_binary_raises_not_found_error(self, tmp_path):
        hive_file = tmp_path / "NTUSER.DAT"
        hive_file.write_bytes(b"reg_hive_dummy_bytes")

        parser = SBECmdParser()
        with patch("shutil.which", return_value=None):
            with pytest.raises(SbecmdNotFoundError):
                parser.parse(str(hive_file))

    def test_execution_error_on_non_zero_exit(self, tmp_path):
        hive_file = tmp_path / "usrclass.dat"
        hive_file.write_bytes(b"dummy")

        parser = SBECmdParser()
        fake_proc = MagicMock(returncode=1, stdout="Error loading hive", stderr="Corrupt hive header")

        with patch("shutil.which", return_value="C:\\Tools\\SBECmd.exe"):
            with patch("subprocess.run", return_value=fake_proc):
                with pytest.raises(SbecmdExecutionError):
                    parser.parse(str(hive_file))

    def test_execution_timeout_raises_error(self, tmp_path):
        hive_file = tmp_path / "usrclass.dat"
        hive_file.write_bytes(b"dummy")

        parser = SBECmdParser()
        with patch("shutil.which", return_value="C:\\Tools\\SBECmd.exe"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("SBECmd.exe", 300)):
                with pytest.raises(SbecmdExecutionError):
                    parser.parse(str(hive_file))


class TestSBECmdRouterIntegration:
    """Test suite for SBECmdParser router integration."""

    def test_router_shellbags_path_routing(self, tmp_path):
        sb_file = tmp_path / "shellbags_export.csv"
        sb_file.write_text(SAMPLE_SBECMD_CSV, encoding="utf-8")

        evidence = Evidence(
            evidence_id="ev_sb_route",
            case_id="case_1",
            source_type="file",
            uploaded_by="analyst",
            file_path=str(sb_file),
            filename="shellbags_export.csv",
        )

        router = ParserRouter()
        result = router.determine_routing(evidence)
        assert result.status == "ROUTED"
        assert result.target_parser == "SBECmdParser"
