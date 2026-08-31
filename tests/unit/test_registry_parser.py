"""
Unit tests for RegistryParser (RECmd primary + RegRipper fallback, all 6 hives, 9 artifact families, UserAssist ROT13 decoding).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from preprocessing.parsers.registry_parser import (
    RegistryParser,
    RECmdNotFoundError,
    RECmdExecutionError,
    RegRipperNotFoundError,
    RegRipperExecutionError,
    parse_filetime,
    rot13,
)
from preprocessing.schemas import Artifact, NormalizedFields


class TestRegistryParserUnit:
    """Test suite for RECmd and RegRipper registry extraction."""

    def test_rot13_decoding(self):
        encoded = "p:\\jvaqbjf\\flfgrz32\\pzq.rkr"
        decoded = rot13(encoded)
        assert decoded == "c:\\windows\\system32\\cmd.exe"

    def test_parse_filetime(self):
        # 133548973310000000 -> 2024-03-15 08:22:11 UTC (approx)
        ft = 133548973310000000
        dt = parse_filetime(ft)
        assert dt is not None
        assert dt.tzinfo == timezone.utc

        # Invalid filetime returns None
        assert parse_filetime(0) is None
        assert parse_filetime(-100) is None
        assert parse_filetime("invalid") is None

    @patch("shutil.which")
    def test_recmd_binary_discovery(self, mock_which):
        mock_which.side_effect = lambda bin_name: "C:\\Tools\\RECmd.exe" if "RECmd" in bin_name else None
        parser = RegistryParser()
        binary = parser._find_recmd_binary()
        assert binary == "C:\\Tools\\RECmd.exe"

    @patch.object(RegistryParser, "_find_recmd_binary", return_value="C:\\Tools\\RECmd.exe")
    @patch.object(RegistryParser, "_run_recmd")
    def test_recmd_execution_and_all_artifact_families(self, mock_run, mock_find, tmp_path):
        hive_file = tmp_path / "NTUSER.DAT"
        hive_file.write_bytes(b"dummy hive data")

        def fake_recmd_run(binary, hive_path, out_dir):
            recmd_output = [
                # 1. registry_key
                {
                    "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "ValueName": "MalwareApp",
                    "ValueData": "C:\\Users\\Public\\malware.exe",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "Run",
                },
                # 2. userassist
                {
                    "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count",
                    "ValueName": "p:\\jvaqbjf\\flfgrz32\\pzq.rkr",
                    "ValueData": "Run count: 5",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "UserAssist",
                },
                # 3. scheduled_task
                {
                    "KeyPath": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{TASK_GUID}",
                    "ValueName": "Path",
                    "ValueData": "\\Microsoft\\Windows\\UpdateCheck",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "Tasks",
                },
                # 4. recentdocs
                {
                    "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pdf",
                    "ValueName": "0",
                    "ValueData": "confidential.pdf",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "RecentDocs",
                },
                # 5. bam_dam
                {
                    "KeyPath": "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1234",
                    "ValueName": "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe",
                    "ValueData": "133548973310000000",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "BAM",
                },
                # 6. muicache
                {
                    "KeyPath": "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                    "ValueName": "C:\\Program Files\\App\\app.exe.FriendlyAppName",
                    "ValueData": "App Display Name",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "MUICache",
                },
                # 7. windows_service
                {
                    "KeyPath": "SYSTEM\\CurrentControlSet\\Services\\EvilService",
                    "ValueName": "ImagePath",
                    "ValueData": "C:\\Windows\\System32\\evil.exe",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "Services",
                },
                # 8. network_configuration
                {
                    "KeyPath": "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{IF_GUID}",
                    "ValueName": "IPAddress",
                    "ValueData": "192.168.1.100",
                    "LastWriteTime": 133548973310000000,
                    "PluginName": "Network",
                },
            ]
            (out_dir / "RECmd_Output.json").write_text(json.dumps(recmd_output))

        mock_run.side_effect = fake_recmd_run

        parser = RegistryParser()
        artifacts = parser.parse(str(hive_file), evidence_id="ev_recmd_1")

        assert len(artifacts) >= 8
        recmd_arts = [a for a in artifacts if a.source_tool == "recmd"]
        assert len(recmd_arts) == 8

        types = set(a.artifact_type for a in recmd_arts)
        assert "registry_key" in types
        assert "userassist" in types
        assert "scheduled_task" in types
        assert "recentdocs" in types
        assert "bam_dam" in types
        assert "muicache" in types
        assert "windows_service" in types
        assert "network_configuration" in types

        # Check UserAssist ROT13 decoding
        ua_art = next(a for a in recmd_arts if a.artifact_type == "userassist")
        assert ua_art.timestamp_type == "execution"
        assert ua_art.raw_fields["encoded_value"] == "p:\\jvaqbjf\\flfgrz32\\pzq.rkr: Run count: 5"
        assert ua_art.raw_fields["decoded_value"] == "c:\\windows\\system32\\cmd.exe: Eha pbhag: 5"
        assert ua_art.raw_fields["decoding_method"] == "ROT13"

    @patch.object(RegistryParser, "_find_recmd_binary", return_value=None)
    @patch.object(RegistryParser, "_find_binary", return_value="rip.exe")
    @patch.object(RegistryParser, "_run_regripper")
    def test_regripper_fallback(self, mock_rr, mock_find_rr, mock_find_recmd, tmp_path):
        hive_file = tmp_path / "SYSTEM"
        hive_file.write_bytes(b"dummy system hive")

        def fake_rr_run(binary, hive_path, profile):
            if profile == "system":
                return (
                    "Launching services v.20200101\n"
                    "SYSTEM\\CurrentControlSet\\Services\\TestSvc\n"
                    "ImagePath : C:\\Windows\\test.exe\n"
                )
            return None

        mock_rr.side_effect = fake_rr_run

        parser = RegistryParser()
        artifacts = parser.parse(str(hive_file), evidence_id="ev_rr_fallback")

        rr_arts = [a for a in artifacts if a.source_tool == "regripper"]
        assert len(rr_arts) >= 1
        svc_art = next(a for a in rr_arts if a.artifact_type == "windows_service")
        assert svc_art.normalized_fields.process_command_line == "C:\\Windows\\test.exe"

    def test_missing_hive_raises_file_not_found(self):
        parser = RegistryParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("C:\\non_existent_registry_hive.dat")

    @patch("subprocess.run")
    def test_recmd_execution_error_raises_typed_exception(self, mock_sub, tmp_path):
        hive_file = tmp_path / "SOFTWARE"
        hive_file.write_bytes(b"dummy data")

        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stdout = "RECmd fatal crash"
        mock_res.stderr = ""
        mock_sub.return_value = mock_res

        parser = RegistryParser()
        with pytest.raises(RECmdExecutionError):
            parser._run_recmd("RECmd.exe", hive_file, tmp_path)
