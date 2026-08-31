"""
Parser Router Unit Tests — 42-Source Audit & Security Suite
============================================================
Validates the repaired ParserRouter against all authoritative ARGUS evidence sources,
layered detection precedence, security edge cases, and ambiguous/unsupported scenarios.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from infrastructure.schemas import Evidence
from preprocessing.router import ParserRouter, RoutingResult, UnroutableEvidenceError
from preprocessing.parsers.evtx_parser import EvtxParser
from preprocessing.parsers.evtxecmd_parser import EvtxECmdParser
from preprocessing.parsers.memory_parser import MemoryParser
from preprocessing.parsers.pcap_parser import PcapParser
from preprocessing.parsers.registry_parser import RegistryParser
from preprocessing.parsers.browser_parser import BrowserParser
from preprocessing.parsers.email_parser import EmailParser
from preprocessing.parsers.filesystem_parser import FilesystemParser
from preprocessing.parsers.firefox_parser import FirefoxParser
from preprocessing.parsers.msg_parser import MsgEmailParser
from preprocessing.parsers.mftecmd_parser import MfteCmdMftParser
from preprocessing.parsers.pecmd_parser import PecmdPrefetchParser
from preprocessing.parsers.lecmd_parser import LecmdLnkParser
from preprocessing.parsers.jlecmd_parser import JlecmdJumpListParser
from preprocessing.parsers.rbcmd_parser import RbcmdRecycleBinParser
from preprocessing.parsers.amcache_parser import AmcacheParser
from preprocessing.parsers.srum_parser import SrumECmdParser
from preprocessing.parsers.usn_parser import UsnLogFileParser
from preprocessing.parsers.shimcache_parser import ShimCacheParser
from preprocessing.parsers.powershell_history_parser import PowerShellHistoryParser
from preprocessing.parsers.wmi_persistence_parser import WmiPersistenceParser
from preprocessing.parsers.timeline_parser import ActivitiesCacheParser
from preprocessing.parsers.stickynotes_parser import StickyNotesParser
from preprocessing.parsers.notification_parser import NotificationDbParser
from preprocessing.parsers.windows_search_parser import WindowsSearchParser
from preprocessing.parsers.wer_parser import WerReportParser
from preprocessing.parsers.firewall_parser import WindowsFirewallParser
from preprocessing.parsers.defender_parser import WindowsDefenderParser
from preprocessing.parsers.gpo_parser import GroupPolicyLogParser
from preprocessing.parsers.dpapi_parser import DpapiVaultParser
from preprocessing.parsers.vss_parser import VssWorkflow


class TestParserRouter42Sources(unittest.TestCase):

    def setUp(self) -> None:
        self.router = ParserRouter()

    def _make_evidence(self, filename: str, path: str = "", metadata: dict | None = None) -> Evidence:
        return Evidence(
            case_id="case-100",
            uploaded_by="analyst@argus.local",
            evidence_id="ev-test-001",
            filename=filename,
            file_path=path or filename,
            metadata=metadata or {}
        )

    # ── 1. Implemented Core Parsers ─────────────────────────────────────────

    def test_evtx_threat_hunted_routing(self):
        ev = self._make_evidence("Security.evtx")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EvtxParser")
        self.assertIsInstance(self.router.route(ev), EvtxParser)

    def test_pcap_routing(self):
        ev = self._make_evidence("traffic.pcap")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "PcapParser")
        self.assertIsInstance(self.router.route(ev), PcapParser)

    def test_pcapng_routing(self):
        ev = self._make_evidence("capture.pcapng")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "PcapParser")

    def test_registry_hive_ntuser_dat(self):
        ev = self._make_evidence("NTUSER.DAT")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")
        self.assertIsInstance(self.router.route(ev), RegistryParser)

    def test_registry_hive_system(self):
        ev = self._make_evidence("SYSTEM")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RegistryParser")

    def test_chrome_browser_history(self):
        ev = self._make_evidence("History", path="/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "BrowserParser")
        self.assertIsInstance(self.router.route(ev), BrowserParser)

    def test_eml_email_routing(self):
        ev = self._make_evidence("phish.eml")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EmailParser")
        self.assertIsInstance(self.router.route(ev), EmailParser)

    def test_filesystem_e01_image(self):
        ev = self._make_evidence("disk.E01")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "FilesystemParser")
        self.assertIsInstance(self.router.route(ev), FilesystemParser)

    def test_filesystem_dd_image(self):
        ev = self._make_evidence("evidence.dd")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "FilesystemParser")

    # ── 2. Unimplemented 42-Source Registration Targets ─────────────────────

    def test_evtx_raw_stream(self):
        ev = self._make_evidence("Security.evtx", metadata={"stream": "raw"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EvtxECmdParser")
        self.assertIsInstance(self.router.route(ev), EvtxECmdParser)

    def test_firefox_places_sqlite(self):
        ev = self._make_evidence("places.sqlite", path="/home/user/.mozilla/firefox/profile/places.sqlite")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "FirefoxParser")
        self.assertIsInstance(self.router.route(ev), FirefoxParser)

    def test_msg_outlook_email(self):
        ev = self._make_evidence("email.msg")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MsgEmailParser")
        self.assertIsInstance(self.router.route(ev), MsgEmailParser)

    def test_mft_ntfs(self):
        ev = self._make_evidence("$MFT")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MfteCmdMftParser")
        self.assertIsInstance(self.router.route(ev), MfteCmdMftParser)

    def test_prefetch(self):
        ev = self._make_evidence("CMD.EXE-A1B2C3D4.pf")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "PecmdPrefetchParser")
        self.assertIsInstance(self.router.route(ev), PecmdPrefetchParser)

    def test_lnk_file(self):
        ev = self._make_evidence("cmd.exe.lnk")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "LecmdLnkParser")
        self.assertIsInstance(self.router.route(ev), LecmdLnkParser)

    def test_jump_lists(self):
        ev = self._make_evidence("1b4dd67f29cbd55f.automaticDestinations-ms")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "JlecmdJumpListParser")
        self.assertIsInstance(self.router.route(ev), JlecmdJumpListParser)

    def test_recycle_bin(self):
        ev = self._make_evidence("$I123456.exe", path="C:\\$Recycle.Bin\\S-1-5-21\\$I123456.exe")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "RbcmdRecycleBinParser")
        self.assertIsInstance(self.router.route(ev), RbcmdRecycleBinParser)

    def test_amcache(self):
        ev = self._make_evidence("Amcache.hve")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "AmcacheParser")
        self.assertIsInstance(self.router.route(ev), AmcacheParser)

    def test_srum(self):
        ev = self._make_evidence("SRUDB.dat")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "SrumECmdParser")
        self.assertIsInstance(self.router.route(ev), SrumECmdParser)

    def test_usn_journal(self):
        ev = self._make_evidence("$UsnJrnl")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "UsnLogFileParser")
        self.assertIsInstance(self.router.route(ev), UsnLogFileParser)

    def test_logfile(self):
        ev = self._make_evidence("$LogFile")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "UsnLogFileParser")
        self.assertIsInstance(self.router.route(ev), UsnLogFileParser)

    def test_shimcache(self):
        ev = self._make_evidence("AppCompatCache.bin")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "ShimCacheParser")
        self.assertIsInstance(self.router.route(ev), ShimCacheParser)

    def test_powershell_history(self):
        ev = self._make_evidence("ConsoleHost_history.txt")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "PowerShellHistoryParser")
        self.assertIsInstance(self.router.route(ev), PowerShellHistoryParser)

    def test_wmi_persistence(self):
        ev = self._make_evidence("OBJECTS.DATA")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WmiPersistenceParser")
        self.assertIsInstance(self.router.route(ev), WmiPersistenceParser)

    def test_activities_cache_timeline(self):
        ev = self._make_evidence("ActivitiesCache.db")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "ActivitiesCacheParser")
        self.assertIsInstance(self.router.route(ev), ActivitiesCacheParser)

    def test_windows_search(self):
        ev = self._make_evidence("Windows.edb")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WindowsSearchParser")
        self.assertIsInstance(self.router.route(ev), WindowsSearchParser)

    def test_sticky_notes(self):
        ev = self._make_evidence("plum.sqlite")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "StickyNotesParser")
        self.assertIsInstance(self.router.route(ev), StickyNotesParser)

    def test_notification_db(self):
        ev = self._make_evidence("wpndatabase.db")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "NotificationDbParser")
        self.assertIsInstance(self.router.route(ev), NotificationDbParser)

    def test_firewall_log(self):
        ev = self._make_evidence("pfirewall.log")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WindowsFirewallParser")
        self.assertIsInstance(self.router.route(ev), WindowsFirewallParser)

    def test_wer_report(self):
        ev = self._make_evidence("Report.wer")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WerReportParser")
        self.assertIsInstance(self.router.route(ev), WerReportParser)

    def test_windows_update_log(self):
        ev = self._make_evidence("CBS.log")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WindowsUpdateLogParser")
        self.assertEqual(res.parser_instance.__class__.__name__, "WindowsUpdateLogParser")

    def test_gpo_routing(self):
        ev = self._make_evidence("gpesvc.log")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "GroupPolicyLogParser")
        self.assertIsInstance(self.router.route(ev), GroupPolicyLogParser)

    def test_dpapi_vault_routing(self):
        ev = self._make_evidence("PREFERRED", path="C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-1234\\PREFERRED")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "DpapiVaultParser")
        self.assertIsInstance(self.router.route(ev), DpapiVaultParser)

    # ── 3. Ambiguous & Unknown Scenarios ───────────────────────────────────

    def test_ambiguous_raw_file(self):
        ev = self._make_evidence("evidence.raw")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "AMBIGUOUS")
        self.assertIn("ambiguous", res.reason.lower())

    def test_generic_dat_file(self):
        ev = self._make_evidence("random_data.dat")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "AMBIGUOUS")
        self.assertIn("generic .dat", res.reason.lower())

    def test_unknown_file_type(self):
        ev = self._make_evidence("unknown_blob.xyz")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "UNKNOWN")
        with self.assertRaises(UnroutableEvidenceError) as ctx:
            self.router.route(ev)
        self.assertEqual(ctx.exception.status, "UNKNOWN")

    # ── 4. Security & Path Edge Cases ──────────────────────────────────────

    def test_null_byte_filename_rejection(self):
        ev = self._make_evidence("test.evtx\x00.exe")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "UNKNOWN")
        self.assertIn("null-byte", res.reason.lower())

    def test_paths_with_spaces_and_unicode(self):
        ev = self._make_evidence("Security.evtx", path="/Forensic Workspace/Case #101/Evidence 📁/Security.evtx")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EvtxParser")

    def test_case_insensitive_matching(self):
        ev = self._make_evidence("SECURITY.EVTX")
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "EvtxParser")

    def test_explicit_metadata_overrides_extension(self):
        # Metadata says evidence is memory dump, but extension is .bin
        ev = self._make_evidence("dump.bin", metadata={"evidence_type": "memory_dump"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "MemoryParser")
        self.assertEqual(res.detection_method, "explicit_metadata")

    def test_vss_workflow_routing(self):
        ev = self._make_evidence("shadowcopy", metadata={"evidence_type": "vss"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "VssWorkflow")
        self.assertIsInstance(self.router.route(ev), VssWorkflow)

    def test_defender_routing(self):
        ev = self._make_evidence("MpCmdRun.log", metadata={"evidence_type": "defender"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WindowsDefenderParser")
        self.assertIsInstance(self.router.route(ev), WindowsDefenderParser)

    def test_firewall_routing(self):
        ev = self._make_evidence("pfirewall.log", metadata={"evidence_type": "firewall"})
        res = self.router.determine_routing(ev)
        self.assertEqual(res.status, "ROUTED")
        self.assertEqual(res.target_parser, "WindowsFirewallParser")
        self.assertIsInstance(self.router.route(ev), WindowsFirewallParser)

    def test_amcache_signature_routing(self):
        with tempfile.NamedTemporaryFile(suffix="amcache.hve", delete=False) as f:
            f.write(b"regf\x00\x00\x00\x00")
            fpath = f.name
        try:
            ev = self._make_evidence("amcache.hve", path=fpath)
            res = self.router.determine_routing(ev)
            self.assertEqual(res.status, "ROUTED")
            self.assertEqual(res.target_parser, "AmcacheParser")
        finally:
            if os.path.exists(fpath):
                os.remove(fpath)


if __name__ == "__main__":
    unittest.main()

