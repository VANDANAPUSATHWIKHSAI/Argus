"""
Unit tests for MemoryParser (Volatility 3 multi-plugin execution and schema compliance).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from preprocessing.parsers.memory_parser import (
    MemoryParser,
    VolatilityNotFoundError,
    VolatilityExecutionError,
    VolatilitySymbolError,
    _PLUGINS,
)
from preprocessing.schemas import Artifact, NormalizedFields


class TestMemoryParserAllPlugins:
    """Test suite covering all 11 required Volatility 3 plugins."""

    def test_all_11_plugins_defined(self):
        plugin_names = [p[0] for p in _PLUGINS]
        expected = [
            "windows.pslist",
            "windows.pstree",
            "windows.psscan",
            "windows.cmdline",
            "windows.cmdscan",
            "windows.netscan",
            "windows.malfind",
            "windows.dlllist",
            "windows.handles",
            "windows.filescan",
            "windows.hivelist",
        ]
        assert plugin_names == expected

    @patch.object(MemoryParser, "_run_vol")
    def test_parse_invokes_all_11_plugins(self, mock_run_vol, tmp_path):
        dump_file = tmp_path / "mem.raw"
        dump_file.write_bytes(b"dummy memory contents")

        # Mock _run_vol to return empty JSON for each plugin
        mock_run_vol.return_value = json.dumps({"columns": [], "rows": []})

        parser = MemoryParser()
        artifacts = parser.parse(str(dump_file), evidence_id="ev_mem_11")

        # Every plugin runs with --output=json first
        assert mock_run_vol.call_count == 11
        called_plugins = [call.args[1] for call in mock_run_vol.call_args_list]
        expected_plugins = [p[0] for p in _PLUGINS]
        assert called_plugins == expected_plugins

    @patch.object(MemoryParser, "_run_vol")
    def test_full_11_plugin_json_extraction(self, mock_run_vol, tmp_path):
        dump_file = tmp_path / "mem.raw"
        dump_file.write_bytes(b"dummy memory contents")

        def plugin_json_side_effect(dump_path, plugin, json_output=True):
            if not json_output:
                return ""
            if plugin == "windows.pslist":
                return json.dumps({
                    "columns": ["PID", "PPID", "ImageFileName", "CreateTime", "ExitTime"],
                    "rows": [[100, 4, "explorer.exe", "2026-08-28 10:00:00.000000 UTC", None]]
                })
            elif plugin == "windows.pstree":
                return json.dumps({
                    "columns": ["PID", "PPID", "ImageFileName", "CreateTime"],
                    "rows": [[100, 4, "explorer.exe", "2026-08-28 10:00:00.000000 UTC"]]
                })
            elif plugin == "windows.psscan":
                return json.dumps({
                    "columns": ["PID", "PPID", "ImageFileName", "CreateTime"],
                    "rows": [[500, 100, "malware_unlinked.exe", "2026-08-28 10:05:00.000000 UTC"]]
                })
            elif plugin == "windows.cmdline":
                return json.dumps({
                    "columns": ["PID", "Process", "Args"],
                    "rows": [[100, "explorer.exe", "explorer.exe /factory"]]
                })
            elif plugin == "windows.cmdscan":
                return json.dumps({
                    "columns": ["PID", "Process", "CommandHistory"],
                    "rows": [[200, "cmd.exe", "whoami /all"]]
                })
            elif plugin == "windows.netscan":
                return json.dumps({
                    "columns": ["PID", "Owner", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "Created"],
                    "rows": [[100, "explorer.exe", "192.168.1.50", 49152, "10.0.0.1", 443, "ESTABLISHED", "2026-08-28 10:01:00.000000 UTC"]]
                })
            elif plugin == "windows.malfind":
                return json.dumps({
                    "columns": ["PID", "Process", "Protection", "Tag"],
                    "rows": [[300, "svchost.exe", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_READWRITE"]]
                })
            elif plugin == "windows.dlllist":
                return json.dumps({
                    "columns": ["PID", "Process", "Path", "LoadTime"],
                    "rows": [[100, "explorer.exe", "C:\\Windows\\System32\\shell32.dll", "2026-08-28 10:00:05.000000 UTC"]]
                })
            elif plugin == "windows.handles":
                return json.dumps({
                    "columns": ["PID", "Process", "Type", "Name"],
                    "rows": [[100, "explorer.exe", "File", "C:\\Users\\Public\\secret.txt"]]
                })
            elif plugin == "windows.filescan":
                return json.dumps({
                    "columns": ["Offset", "Name"],
                    "rows": [["0x80000000", "\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe"]]
                })
            elif plugin == "windows.hivelist":
                return json.dumps({
                    "columns": ["Offset", "FileFullPath"],
                    "rows": [["0x90000000", "\\Device\\HarddiskVolume1\\Windows\\System32\\config\\SYSTEM"]]
                })
            return json.dumps({"columns": [], "rows": []})

        mock_run_vol.side_effect = plugin_json_side_effect

        parser = MemoryParser()
        artifacts = parser.parse(str(dump_file), evidence_id="ev_full_11")

        types_produced = [a.artifact_type for a in artifacts]
        assert "process_record" in types_produced
        assert "process_tree_record" in types_produced
        assert "unlinked_process_record" in types_produced
        assert "command_line_record" in types_produced
        assert "console_command_record" in types_produced
        assert "network_connection" in types_produced
        assert "injection_indicator" in types_produced
        assert "dll_record" in types_produced
        assert "handle_record" in types_produced
        assert "file_scan_record" in types_produced
        assert "hive_record" in types_produced

        # Check netscan artifact normalized fields
        net_art = next(a for a in artifacts if a.artifact_type == "network_connection")
        assert net_art.normalized_fields.src_ip == "192.168.1.50"
        assert net_art.normalized_fields.src_port == 49152
        assert net_art.normalized_fields.dst_ip == "10.0.0.1"
        assert net_art.normalized_fields.dst_port == 443
        assert net_art.timestamp_type == "event"

        # Check cmdline artifact normalized fields
        cmd_art = next(a for a in artifacts if a.artifact_type == "command_line_record")
        assert cmd_art.normalized_fields.process_command_line == "explorer.exe /factory"
        assert cmd_art.timestamp_type == "execution"

        # Check handles artifact normalized fields
        h_art = next(a for a in artifacts if a.artifact_type == "handle_record")
        assert h_art.normalized_fields.file_path == "C:\\Users\\Public\\secret.txt"

    def test_missing_memory_file_raises_file_not_found(self):
        parser = MemoryParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("C:\\non_existent_memory_dump_xyz.raw")

    @patch("subprocess.run")
    def test_vol_not_found_raises_typed_error(self, mock_sub, tmp_path):
        dump_file = tmp_path / "mem.raw"
        dump_file.write_bytes(b"dummy memory contents")
        mock_sub.side_effect = FileNotFoundError("vol not on path")

        parser = MemoryParser()
        with pytest.raises(VolatilityNotFoundError):
            parser.parse(str(dump_file))

    @patch("subprocess.run")
    def test_symbol_error_raises_typed_error(self, mock_sub, tmp_path):
        dump_file = tmp_path / "mem.raw"
        dump_file.write_bytes(b"dummy memory contents")

        mock_proc = MagicMock()
        mock_proc.return_code = 1
        mock_proc.stdout = "Symbol table download failed: unable to locate symbols for OS build"
        mock_proc.stderr = "SymbolError: missing symbol"
        mock_sub.return_value = mock_proc

        parser = MemoryParser()
        with pytest.raises(VolatilitySymbolError):
            parser.parse(str(dump_file))

    @patch("subprocess.run")
    def test_execution_error_raises_typed_error(self, mock_sub, tmp_path):
        dump_file = tmp_path / "mem.raw"
        dump_file.write_bytes(b"dummy memory contents")

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Fatal error reading memory dump"
        mock_sub.return_value = mock_proc

        parser = MemoryParser()
        with pytest.raises(VolatilityExecutionError):
            parser.parse(str(dump_file))
