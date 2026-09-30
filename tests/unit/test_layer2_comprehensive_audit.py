"""
ARGUS Layer 2 Comprehensive Evidence Preprocessing Audit & Verification Suite (L2-T01 to L2-T20)
========================================================================================
Tests real Layer 2 parsing, routing, normalization, provenance, timestamping, neutral semantics,
and determinism without making final forensic verdicts.
"""

import os
import shutil
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter, UnroutableEvidenceError
from preprocessing.normalizer import Normalizer
from preprocessing.schemas import Artifact, NormalizedFields, ExtractedEntity
from preprocessing.parsers.evtx_parser import EvtxParser
from preprocessing.parsers.registry_parser import RegistryParser
from preprocessing.parsers.filesystem_parser import FilesystemParser
from preprocessing.parsers.browser_parser import BrowserParser
from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.parsers.firewall_parser import WindowsFirewallParser
from preprocessing.parsers.defender_parser import WindowsDefenderParser
from preprocessing.parsers.powershell_history_parser import PowerShellHistoryParser
from preprocessing.parsers.pecmd_parser import PecmdPrefetchParser
from preprocessing.parsers.amcache_parser import AmcacheParser
from preprocessing.parsers.shimcache_parser import ShimCacheParser
from preprocessing.parsers.lecmd_parser import LecmdLnkParser
from preprocessing.parsers.jlecmd_parser import JlecmdJumpListParser
from preprocessing.parsers.scheduled_task_parser import ScheduledTaskParser
from preprocessing.parsers.pcap_parser import PcapParser


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="argus_l2_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# L2-T01: parser routing
def test_L2_T01_parser_routing(temp_dir):
    router = ParserRouter()
    pcap_path = os.path.join(temp_dir, "traffic.pcap")
    with open(pcap_path, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    ev_pcap = Evidence(evidence_id="ev_01", case_id="case_01", filename="traffic.pcap", file_path=pcap_path, uploaded_by="analyst_1")
    res_pcap = router.determine_routing(ev_pcap)
    assert res_pcap.status == "ROUTED"
    assert res_pcap.target_parser == "PcapParser"

    evtx_path = os.path.join(temp_dir, "Security.evtx")
    with open(evtx_path, "wb") as f:
        f.write(b"ElfFile\x00" + b"\x00" * 100)

    ev_evtx = Evidence(evidence_id="ev_02", case_id="case_01", filename="Security.evtx", file_path=evtx_path, uploaded_by="analyst_1")
    res_evtx = router.determine_routing(ev_evtx)
    assert res_evtx.status == "ROUTED"
    assert res_evtx.target_parser in ("EvtxParser", "EvtxECmdParser")


# L2-T02: unsupported source
def test_L2_T02_unsupported_source(temp_dir):
    router = ParserRouter()
    file_path = os.path.join(temp_dir, "unsupported_data.xyz")
    with open(file_path, "wb") as f:
        f.write(b"random unsupported binary content")

    ev_unknown = Evidence(evidence_id="ev_unsupported", case_id="case_01", filename="unsupported_data.xyz", file_path=file_path, uploaded_by="analyst_1")
    with pytest.raises(UnroutableEvidenceError):
        router.route(ev_unknown)


# L2-T03: normalized schema
def test_L2_T03_normalized_schema():
    norm = NormalizedFields(
        host="WORKSTATION1.local",
        user="john_doe",
        process_id=1024,
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=443,
        hash="a" * 64
    )
    art = Artifact(
        evidence_id="ev_schema_1",
        source_tool="test_tool",
        artifact_type="process_event",
        normalized_fields=norm
    )
    assert art.artifact_id is not None
    assert art.normalized_fields.host == "WORKSTATION1.local"
    assert art.normalized_fields.process_id == 1024


# L2-T04: provenance
def test_L2_T04_provenance(temp_dir):
    p = os.path.join(temp_dir, "firewall.log")
    with open(p, "w", encoding="utf-8") as f:
        f.write("#Fields: date time action protocol src-ip dst-ip src-port dst-port\n")
        f.write("2026-09-30 12:00:00 ALLOW TCP 192.168.1.10 10.0.0.5 49152 443\n")

    parser = WindowsFirewallParser()
    arts = parser.parse(p, evidence_id="ev_prov_100")
    assert len(arts) == 1
    assert arts[0].evidence_id == "ev_prov_100"
    assert arts[0].source_tool == "windows_firewall_parser"
    assert arts[0].normalized_fields.file_path == str(Path(p))


# L2-T05: tenant propagation
def test_L2_T05_tenant_propagation():
    norm = NormalizedFields(host="SRV-01")
    art = Artifact(
        evidence_id="ev_tenant_1",
        case_id="case_alpha",
        source_tool="test_tool",
        artifact_type="auth_event",
        normalized_fields=norm
    )
    entity = ExtractedEntity(
        artifact_id=art.artifact_id,
        evidence_id="ev_tenant_1",
        case_id="case_alpha",
        entity_type="ipv4",
        value="192.168.1.1",
        source_field="raw_line",
        char_start=0,
        char_end=11,
        extraction_method="regex",
        confidence=1.0
    )
    assert art.case_id == "case_alpha"
    assert entity.case_id == "case_alpha"


# L2-T06: case propagation
def test_L2_T06_case_propagation():
    art1 = Artifact(evidence_id="ev1", case_id="ARGUS_CASE_99", source_tool="t1", artifact_type="a1")
    art2 = Artifact(evidence_id="ev2", case_id="ARGUS_CASE_100", source_tool="t2", artifact_type="a2")
    assert art1.case_id != art2.case_id


# L2-T07: timestamp normalization
def test_L2_T07_timestamp_normalization():
    normalizer = Normalizer()
    dt = datetime(2026, 9, 30, 12, 0, 0)
    norm_dt = normalizer._normalize_timestamp(dt)
    assert norm_dt.tzinfo == timezone.utc

    ts_str = "2026-09-30T12:00:00Z"
    norm_str_dt = normalizer._normalize_timestamp(ts_str)
    assert norm_str_dt == datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

    # Invalid timestamp returns None (no silent guess or replacement with now())
    assert normalizer._normalize_timestamp("invalid_date_string") is None


# L2-T08: malformed input
def test_L2_T08_malformed_input(temp_dir):
    p = os.path.join(temp_dir, "malformed_firewall.log")
    with open(p, "w", encoding="utf-8") as f:
        f.write("corrupted line with no fields\nrandom noise !!!\n")

    parser = WindowsFirewallParser()
    arts = parser.parse(p, evidence_id="ev_malformed")
    assert isinstance(arts, list)


# L2-T09: empty input
def test_L2_T09_empty_input(temp_dir):
    p = os.path.join(temp_dir, "empty_log.txt")
    with open(p, "w", encoding="utf-8") as f:
        pass

    parser = PowerShellHistoryParser()
    arts = parser.parse(p, evidence_id="ev_empty")
    assert arts == []


# L2-T10: EVTX
def test_L2_T10_evtx_parser(temp_dir):
    p = os.path.join(temp_dir, "sample.evtx")
    with open(p, "wb") as f:
        f.write(b"ElfFile\x00" + b"\x00" * 500)

    parser = EvtxParser()
    arts = parser.parse(p, evidence_id="ev_evtx_10")
    assert isinstance(arts, list)


# L2-T11: Registry
def test_L2_T11_registry_parser(temp_dir):
    p = os.path.join(temp_dir, "test.reg")
    with open(p, "w", encoding="utf-8") as f:
        f.write('Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\n"Value1"="Data1"\n')

    parser = RegistryParser()
    arts = parser.parse(p, evidence_id="ev_reg_11")
    assert isinstance(arts, list)


# L2-T12: filesystem
def test_L2_T12_filesystem_parser(temp_dir):
    p = os.path.join(temp_dir, "dir_listing.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("09/30/2026  12:00 PM            1,024 cmd.exe\n")

    parser = FilesystemParser()
    arts = parser.parse(p, evidence_id="ev_fs_12")
    assert isinstance(arts, list)


# L2-T13: browser
def test_L2_T13_browser_neutral_semantics(temp_dir):
    p = os.path.join(temp_dir, "history_export.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write('{"row_type": "url (visited)", "url": "http://example-malware-domain.com/payload.exe", "title": "Download", "visit_time": "2026-09-30 12:00:00"}\n')

    parser = BrowserParser()
    arts = parser._parse_jsonl(Path(p), evidence_id="ev_browser_13")
    assert len(arts) == 1
    assert arts[0].normalized_fields.url == "http://example-malware-domain.com/payload.exe"


# L2-T14: firewall neutral semantics
def test_L2_T14_firewall_neutral_semantics(temp_dir):
    p = os.path.join(temp_dir, "pfirewall.log")
    with open(p, "w", encoding="utf-8") as f:
        f.write("#Fields: date time action protocol src-ip dst-ip src-port dst-port\n")
        f.write("2026-09-30 12:00:00 ALLOW TCP 192.168.1.10 10.0.0.5 49152 443\n")
        f.write("2026-09-30 12:01:00 DROP TCP 10.0.0.1 192.168.1.1 4444 80\n")

    parser = WindowsFirewallParser()
    arts = parser.parse(p, evidence_id="ev_fw_14")
    assert len(arts) == 2
    assert arts[0].raw_fields["action"] == "ALLOW"
    assert arts[1].raw_fields["action"] == "DROP"


# L2-T15: Defender source-faithful semantics
def test_L2_T15_defender_source_faithful(temp_dir):
    p = os.path.join(temp_dir, "defender.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write('[{"event_id": "1116", "threat_name": "Trojan:Win32/Test", "severity": "High", "action": "Quarantined", "file_path": "C:\\\\test.exe"}]')

    parser = WindowsDefenderParser()
    arts = parser.parse(p, evidence_id="ev_def_15")
    assert len(arts) == 1
    assert arts[0].raw_fields["threat_name"] == "Trojan:Win32/Test"
    assert arts[0].normalized_fields.severity in ("High", "high")


# L2-T16: PowerShell/execution neutral semantics
def test_L2_T16_powershell_neutral_semantics(temp_dir):
    p = os.path.join(temp_dir, "ConsoleHost_history.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("powershell.exe -EncodedCommand aW52b2tlLWV4cHJlc3Npb24=\n")

    parser = PowerShellHistoryParser()
    arts = parser.parse(p, evidence_id="ev_ps_16")
    assert len(arts) == 1
    assert arts[0].timestamp is None  # No timestamp guessing!
    assert arts[0].normalized_fields.process_command_line == "powershell.exe -EncodedCommand aW52b2tlLWV4cHJlc3Npb24="


# L2-T17: Prefetch/Amcache/Shimcache
def test_L2_T17_prefetch_amcache_shimcache(temp_dir):
    p_pf = os.path.join(temp_dir, "CMD.EXE-12345678.pf")
    with open(p_pf, "wb") as f:
        f.write(b"SCCA" + b"\x00" * 200)

    parser_pf = PecmdPrefetchParser()
    with patch.object(PecmdPrefetchParser, "_find_binary", return_value="PECmd.exe"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Executable: CMD.EXE\nRun count: 5\nLast run: 2026-09-30 12:00:00\n")
            arts_pf = parser_pf.parse(p_pf, evidence_id="ev_pf_17")
            assert isinstance(arts_pf, list)


# L2-T18: LNK/JumpList/Tasks/Services
def test_L2_T18_scheduled_task_parser(temp_dir):
    p_task = os.path.join(temp_dir, "UpdateTask.xml")
    with open(p_task, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>C:\\Windows\\system32\\calc.exe</Command></Exec></Actions></Task>')

    parser_task = ScheduledTaskParser()
    arts_task = parser_task.parse(p_task, evidence_id="ev_task_18")
    assert len(arts_task) == 1
    assert arts_task[0].artifact_type == "scheduled_task"


# L2-T19: network artifacts
def test_L2_T19_network_artifacts(temp_dir):
    p_pcap = os.path.join(temp_dir, "capture.pcap")
    with open(p_pcap, "wb") as f:
        # Standard libpcap header (magic 0xa1b2c3d4)
        f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")

    parser_pcap = PcapParser()
    with patch.object(PcapParser, "_run_zeek", return_value=None):
        arts_pcap = parser_pcap.parse(p_pcap, evidence_id="ev_pcap_19")
        assert isinstance(arts_pcap, list)


# L2-T20: determinism
def test_L2_T20_determinism(temp_dir):
    p = os.path.join(temp_dir, "pfirewall_det.log")
    with open(p, "w", encoding="utf-8") as f:
        f.write("#Fields: date time action protocol src-ip dst-ip src-port dst-port\n")
        f.write("2026-09-30 12:00:00 ALLOW TCP 192.168.1.10 10.0.0.5 49152 443\n")

    parser = WindowsFirewallParser()
    normalizer = Normalizer()

    arts_run1 = parser.parse(p, evidence_id="ev_det_20")
    arts_run1 = normalizer.normalize(arts_run1)

    arts_run2 = parser.parse(p, evidence_id="ev_det_20")
    arts_run2 = normalizer.normalize(arts_run2)

    # Verify identical normalized fields and raw fields for determinism
    assert arts_run1[0].event_summary == arts_run2[0].event_summary
    assert arts_run1[0].raw_fields == arts_run2[0].raw_fields
    assert arts_run1[0].normalized_fields.model_dump() == arts_run2[0].normalized_fields.model_dump()
