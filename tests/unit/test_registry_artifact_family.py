"""
Unit tests for Windows Registry Artifact Family (Sources #6, #21, #23, #24, #26, #27, #28, #34)
===========================================================================================
- Source #6:  Windows Registry (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat)
- Source #21: Scheduled Tasks
- Source #23: UserAssist (ROT13 decoding, execution timestamps)
- Source #24: RecentDocs (MRU ordering, user interaction)
- Source #26: BAM / DAM (background execution)
- Source #27: MUICache
- Source #28: Services
- Source #34: Network Configuration
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter
from preprocessing.parsers.registry_parser import (
    RegistryParser,
    RegRipperNotFoundError,
    RegRipperExecutionError,
    rot13,
    parse_filetime,
)


class TestRegistryArtifactFamilyUnit(unittest.TestCase):
    """Unit tests for Windows Registry Artifact Family parsing and normalization."""

    def setUp(self) -> None:
        self.parser = RegistryParser(profiles=["ntuser", "system", "software", "sam"])
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.hive_file = Path(self.tmp_dir.name) / "NTUSER.DAT"
        self.hive_file.write_bytes(b"regf" + b"\x00" * 1024)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ── 1-6. Hive Profile Handling & Raw Field Preservation ─────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_general_registry_hive_parsing(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching ntuser v.20200517
ntuser v.20200517
(NTUSER.DAT)
-----------------------------------------
HKEY_CURRENT_USER\\Software\\TestApp
2026-08-27 10:00:00Z
Setting: ValueData123
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_reg_01")
        self.assertGreater(len(artifacts), 0)

        art = [a for a in artifacts if a.raw_fields.get("plugin") == "ntuser"][0]
        self.assertEqual(art.source_tool, "regripper")
        self.assertEqual(art.artifact_type, "registry_key")
        self.assertEqual(art.evidence_id, "ev_reg_01")
        self.assertEqual(art.normalized_fields.registry_value, "Setting")
        self.assertEqual(art.normalized_fields.registry_value_data, "ValueData123")
        self.assertIn("plugin_text", art.raw_fields)

    def test_rot13_and_filetime_helpers(self) -> None:
        # Test ROT13 helper
        encoded = "HRZR_EHACNGU:P:\\Jvaqbjf\\abgrcnq.rkr"
        decoded = rot13(encoded)
        self.assertEqual(decoded, "UEME_RUNPATH:C:\\Windows\\notepad.exe")

        # Test FILETIME helper
        ft_val = 133682976000000000  # ~2024 timestamp
        dt = parse_filetime(ft_val)
        self.assertIsInstance(dt, datetime)
        self.assertEqual(dt.tzinfo, timezone.utc)

    # ── 18-22. UserAssist Artifact Extraction ─────────────────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_userassist_rot13_decoding_and_execution_timestamp(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching userassist v.20200517
userassist v.20200517
(NTUSER.DAT)
-----------------------------------------
Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEB85E6D-3788-44E0-992C-0B2741300726}\\Count
2026-08-27 12:00:00Z
HRZR_EHACNGU:P:\\Jvaqbjf\\abgrcnq.rkr: Count: 5
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_ua_01")
        ua_arts = [a for a in artifacts if a.artifact_type == "userassist"]
        self.assertGreater(len(ua_arts), 0)

        art = ua_arts[0]
        self.assertEqual(art.artifact_type, "userassist")
        self.assertEqual(art.timestamp_type, "execution")
        self.assertEqual(art.raw_fields["decoding_method"], "ROT13")
        self.assertIn("UEME_RUNPATH", art.raw_fields["decoded_value"])
        self.assertIn("notepad.exe", art.raw_fields["decoded_value"])

    # ── 12-17. Scheduled Tasks Artifact Extraction ──────────────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_scheduled_tasks_extraction(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching schtasks v.20200517
schtasks v.20200517
(SOFTWARE)
-----------------------------------------
Microsoft\\Windows\\Schedule\\TaskCache\\Tasks\\{12345678-1234-1234-1234-1234567890AB}
2026-08-20 08:30:00Z
Action: C:\\Windows\\System32\\cmd.exe /c calc.exe
Author: SYSTEM
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_st_01")
        st_arts = [a for a in artifacts if a.artifact_type == "scheduled_task"]
        self.assertGreater(len(st_arts), 0)

        art = st_arts[0]
        self.assertEqual(art.artifact_type, "scheduled_task")
        self.assertEqual(art.timestamp_type, "created")
        self.assertIn("cmd.exe", art.normalized_fields.process_command_line)

    # ── 23-26. RecentDocs Artifact Extraction ─────────────────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_recentdocs_extraction(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching recentdocs v.20200517
recentdocs v.20200517
(NTUSER.DAT)
-----------------------------------------
Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.pdf
2026-08-26 14:15:00Z
MRUListEx: 0, 1, 2
0: Confidential_Report.pdf
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_rd_01")
        rd_arts = [a for a in artifacts if a.artifact_type == "recentdocs"]
        self.assertGreater(len(rd_arts), 0)

        art = rd_arts[0]
        self.assertEqual(art.artifact_type, "recentdocs")
        self.assertEqual(art.timestamp_type, "accessed")
        self.assertIn("RecentDocs", art.normalized_fields.file_path)

    # ── 27-29. BAM/DAM Artifact Extraction ────────────────────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_bam_dam_extraction(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching bam v.20200517
bam v.20200517
(SYSTEM)
-----------------------------------------
SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1234567890-1001
2026-08-26 18:00:00Z
C:\\Program Files\\ExampleApp\\app.exe: 2026-08-26 18:00:00Z
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_bam_01")
        bam_arts = [a for a in artifacts if a.artifact_type == "bam_dam"]
        self.assertGreater(len(bam_arts), 0)

        art = bam_arts[0]
        self.assertEqual(art.artifact_type, "bam_dam")
        self.assertEqual(art.timestamp_type, "execution")

    # ── 30-31. MUICache Artifact Extraction ───────────────────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_muicache_extraction(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching muicache v.20200517
muicache v.20200517
(UsrClass.dat)
-----------------------------------------
Software\\Classes\\Local Settings\\MuiCache
2026-08-25 11:20:00Z
C:\\Windows\\System32\\notepad.exe.ApplicationCompany: Microsoft Corporation
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_mui_01")
        mui_arts = [a for a in artifacts if a.artifact_type == "muicache"]
        self.assertGreater(len(mui_arts), 0)

        art = mui_arts[0]
        self.assertEqual(art.artifact_type, "muicache")

    # ── 32-35. Services Artifact Extraction ───────────────────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_services_extraction(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching services v.20200517
services v.20200517
(SYSTEM)
-----------------------------------------
System\\CurrentControlSet\\Services\\MaliciousSvc
2026-08-26 20:00:00Z
ImagePath: C:\\Windows\\Temp\\svc.exe
ObjectName: LocalSystem
Start: 2
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_svc_01")
        svc_arts = [a for a in artifacts if a.artifact_type == "windows_service"]
        self.assertGreater(len(svc_arts), 0)

        art = [a for a in svc_arts if a.normalized_fields.registry_value == "ImagePath"][0]
        self.assertEqual(art.artifact_type, "windows_service")
        self.assertIn("svc.exe", art.normalized_fields.process_command_line)

    # ── 36-38. Network Configuration Artifact Extraction ──────────────────

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_network_configuration_extraction(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        fixture = """\
Launching network v.20200517
network v.20200517
(SYSTEM)
-----------------------------------------
System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{12345678-1234}
2026-08-27 08:00:00Z
IPAddress: 192.168.1.150
SubnetMask: 255.255.255.0
"""
        mock_run.return_value = MagicMock(returncode=0, stdout=fixture, stderr="")

        artifacts = self.parser.parse(str(self.hive_file), evidence_id="ev_net_01")
        net_arts = [a for a in artifacts if a.artifact_type == "network_configuration"]
        self.assertGreater(len(net_arts), 0)

        art = [a for a in net_arts if a.normalized_fields.registry_value == "IPAddress"][0]
        self.assertEqual(art.artifact_type, "network_configuration")
        self.assertEqual(art.normalized_fields.src_ip, "192.168.1.150")

    # ── 9-11. Error Handling Tests ────────────────────────────────────────

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run", return_value=MagicMock(returncode=1))
    def test_missing_tool_raises_not_found(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        with self.assertRaises(RegRipperNotFoundError):
            self.parser.parse(str(self.hive_file))

    @patch("shutil.which", return_value="/usr/bin/rip.pl")
    @patch("subprocess.run")
    def test_all_profiles_failing_raises_execution_error(self, mock_run: MagicMock, mock_which: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        with self.assertRaises(RegRipperExecutionError):
            self.parser.parse(str(self.hive_file))


class TestRegistryRouterIntegration(unittest.TestCase):
    """Routing tests for Registry family (Points 39-43)."""

    def setUp(self) -> None:
        self.router = ParserRouter()

    def test_system_hive_routes_to_registry(self) -> None:
        ev = Evidence(evidence_id="e_sys", case_id="c1", filename="SYSTEM", file_path="/evidence/SYSTEM", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")

    def test_software_hive_routes_to_registry(self) -> None:
        ev = Evidence(evidence_id="e_soft", case_id="c1", filename="SOFTWARE", file_path="/evidence/SOFTWARE", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")

    def test_ntuser_hive_routes_to_registry(self) -> None:
        ev = Evidence(evidence_id="e_ntu", case_id="c1", filename="NTUSER.DAT", file_path="/evidence/NTUSER.DAT", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")

    def test_usrclass_hive_routes_to_registry(self) -> None:
        ev = Evidence(evidence_id="e_usr", case_id="c1", filename="UsrClass.dat", file_path="/evidence/UsrClass.dat", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")

    def test_generic_dat_file_remains_ambiguous(self) -> None:
        ev = Evidence(evidence_id="e_dat", case_id="c1", filename="data.dat", file_path="/evidence/data.dat", uploaded_by="analyst")
        res = self.router.determine_routing(ev)
        self.assertIn(res.status, ("AMBIGUOUS", "UNKNOWN"))


if __name__ == "__main__":
    unittest.main()
