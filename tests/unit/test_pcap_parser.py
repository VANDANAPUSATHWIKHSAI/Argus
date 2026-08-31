"""
Unit tests for PcapParser (Zeek 6-log & Suricata multi-event type execution and schema compliance).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from preprocessing.parsers.pcap_parser import (
    PcapParser,
    ZeekNotFoundError,
    ZeekExecutionError,
    SuricataNotFoundError,
    SuricataExecutionError,
    _ZEEK_LOGS,
)
from preprocessing.schemas import Artifact, NormalizedFields


class TestPcapParserZeekAndSuricata:
    """Test suite covering Zeek logs and Suricata EVE event types."""

    def test_all_6_zeek_logs_defined(self):
        log_names = [l[0] for l in _ZEEK_LOGS]
        expected = [
            "conn.log",
            "dns.log",
            "http.log",
            "ssl.log",
            "files.log",
            "weird.log",
        ]
        assert log_names == expected

    @patch.object(PcapParser, "_run_zeek")
    @patch.object(PcapParser, "_run_suricata")
    def test_zeek_all_6_logs_parsed(self, mock_suricata, mock_zeek, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"dummy pcap data")

        # Mock Zeek pass to generate all 6 log files in cwd
        def fake_zeek_run(pcap_path, cwd):
            (cwd / "conn.log").write_text(
                "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\n"
                "1710490931.123\tC12345\t192.168.1.10\t50000\t10.0.0.1\t80\n"
            )
            (cwd / "dns.log").write_text(
                "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\n"
                "1710490932.123\tC12346\t192.168.1.10\t10.0.0.53\tmalicious.com\n"
            )
            (cwd / "http.log").write_text(
                "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\thost\turi\n"
                "1710490933.123\tC12347\t192.168.1.10\t10.0.0.1\t80\tmalicious.com\t/payload.exe\n"
            )
            (cwd / "ssl.log").write_text(
                "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\tversion\n"
                "1710490934.123\tC12348\t192.168.1.10\t50001\t10.0.0.2\t443\tsecure.com\tTLSv13\n"
            )
            (cwd / "files.log").write_text(
                "#separator \\x09\n#fields\tts\tfuid\tfilename\tsha256\n"
                "1710490935.123\tF12349\tpayload.exe\te3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            )
            (cwd / "weird.log").write_text(
                "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tname\tnotice\n"
                "1710490936.123\tC12350\t192.168.1.10\t50002\t10.0.0.3\t80\tactive_connection_reuse\tF\n"
            )

        mock_zeek.side_effect = fake_zeek_run

        parser = PcapParser()
        artifacts = parser.parse(str(pcap_file), evidence_id="ev_zeek_6")

        zeek_arts = [a for a in artifacts if a.source_tool == "zeek"]
        types_produced = set(a.artifact_type for a in zeek_arts)
        assert "network_connection" in types_produced
        assert "dns_query" in types_produced
        assert "http_request" in types_produced
        assert "ssl_handshake" in types_produced
        assert "file_transfer" in types_produced
        assert "network_anomaly" in types_produced

        # Verify ssl.log normalization
        ssl_art = next(a for a in zeek_arts if a.artifact_type == "ssl_handshake")
        assert ssl_art.normalized_fields.src_ip == "192.168.1.10"
        assert ssl_art.normalized_fields.dst_ip == "10.0.0.2"
        assert ssl_art.normalized_fields.domain == "secure.com"

        # Verify files.log normalization and raw hash retention
        files_art = next(a for a in zeek_arts if a.artifact_type == "file_transfer")
        assert files_art.normalized_fields.file_name == "payload.exe"
        assert files_art.raw_fields["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    @patch.object(PcapParser, "_run_zeek")
    @patch.object(PcapParser, "_run_suricata")
    def test_suricata_non_alert_events_preserved(self, mock_suricata, mock_zeek, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"dummy pcap data")

        def fake_suricata_run(pcap_path, log_dir):
            eve_content = "\n".join([
                json.dumps({"timestamp": "2026-08-28T10:00:00.000000+0000", "event_type": "alert", "src_ip": "192.168.1.10", "src_port": 5000, "dest_ip": "10.0.0.1", "dest_port": 80, "alert": {"signature": "ET TROJAN Malware Action", "severity": 1}}),
                json.dumps({"timestamp": "2026-08-28T10:01:00.000000+0000", "event_type": "flow", "src_ip": "192.168.1.10", "src_port": 5000, "dest_ip": "10.0.0.1", "dest_port": 80, "flow": {"pkts_toserver": 10, "bytes_toserver": 1024}}),
                json.dumps({"timestamp": "2026-08-28T10:02:00.000000+0000", "event_type": "dns", "src_ip": "192.168.1.10", "src_port": 5001, "dest_ip": "10.0.0.53", "dest_port": 53, "dns": {"rrname": "badsite.org"}}),
                json.dumps({"timestamp": "2026-08-28T10:03:00.000000+0000", "event_type": "http", "src_ip": "192.168.1.10", "src_port": 5002, "dest_ip": "10.0.0.1", "dest_port": 80, "http": {"hostname": "badsite.org", "url": "/mal.bin"}}),
                json.dumps({"timestamp": "2026-08-28T10:04:00.000000+0000", "event_type": "tls", "src_ip": "192.168.1.10", "src_port": 5003, "dest_ip": "10.0.0.2", "dest_port": 443, "tls": {"sni": "secure.badsite.org"}}),
                json.dumps({"timestamp": "2026-08-28T10:05:00.000000+0000", "event_type": "fileinfo", "src_ip": "192.168.1.10", "src_port": 5004, "dest_ip": "10.0.0.1", "dest_port": 80, "fileinfo": {"filename": "mal.bin", "sha256": "aaaa1111bbbb2222"}}),
                json.dumps({"timestamp": "2026-08-28T10:06:00.000000+0000", "event_type": "ssh", "src_ip": "192.168.1.10", "src_port": 5005, "dest_ip": "10.0.0.4", "dest_port": 22, "ssh": {"client": "OpenSSH"}}),
            ])
            (log_dir / "eve.json").write_text(eve_content)

        mock_suricata.side_effect = fake_suricata_run

        parser = PcapParser()
        artifacts = parser.parse(str(pcap_file), evidence_id="ev_suri_non_alert")

        suri_arts = [a for a in artifacts if a.source_tool == "suricata"]
        assert len(suri_arts) == 7   # ALL 7 records preserved, NONE dropped!

        types_produced = set(a.artifact_type for a in suri_arts)
        assert "ids_alert" in types_produced
        assert "network_flow" in types_produced
        assert "dns_query" in types_produced
        assert "http_request" in types_produced
        assert "ssl_handshake" in types_produced
        assert "file_transfer" in types_produced
        assert "network_event" in types_produced   # ssh event mapped gracefully

        # Check alert severity
        alert_art = next(a for a in suri_arts if a.artifact_type == "ids_alert")
        assert alert_art.normalized_fields.severity == "high"

        # Check http URL
        http_art = next(a for a in suri_arts if a.artifact_type == "http_request")
        assert http_art.normalized_fields.url == "http://badsite.org/mal.bin"

    def test_missing_pcap_file_raises_file_not_found(self):
        parser = PcapParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("C:\\non_existent_pcap_file.pcap")

    @patch("subprocess.run")
    def test_zeek_not_found_raises_typed_error(self, mock_sub, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"dummy pcap data")
        mock_sub.side_effect = FileNotFoundError("zeek not found")

        parser = PcapParser()
        with pytest.raises(ZeekNotFoundError):
            parser.parse(str(pcap_file))

    @patch("subprocess.run")
    def test_suricata_not_found_raises_typed_error(self, mock_sub, tmp_path):
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"dummy pcap data")

        def sub_side_effect(cmd, **kwargs):
            cmd_str = " ".join(str(c) for c in cmd)
            if "zeek" in cmd_str:
                m = MagicMock()
                m.returncode = 0
                m.stdout = "/usr/bin/zeek"
                return m
            raise FileNotFoundError("suricata not found")

        mock_sub.side_effect = sub_side_effect

        parser = PcapParser()
        with pytest.raises(SuricataNotFoundError):
            parser.parse(str(pcap_file))
